//! CBOR-over-UNIX-socket listener for the mlsh-control plane.
//!
//! The control node terminates the bi-streams that signal relays for it
//! on ALPN `mlsh-control`. Every admin call has moved to the REST API
//! (ADR-035 Phase E); the operations dispatched here are now strictly
//! bootstrap + cache infrastructure (ADR-035 Phase G):
//!   - [`ControlRequest::AdoptConfirm`] — register a new node before it
//!     has an overlay address.
//!   - [`ControlRequest::Subscribe`] — push `ControlEvent`s to drive the
//!     daemon's peer-name cache and the UI live-updates panel.
//!   - [`ControlRequest::ListNodes`] — seed the daemon's peer-name cache
//!     at reconnect time (still pre-overlay so it can't go REST).
//!
//! New admin endpoints go to `api/*`, never here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mlsh_protocol::control::{ControlAuthHeader, ControlNodeInfo, ControlRequest, ControlResponse};
use mlsh_protocol::framing;
use sqlx::SqlitePool;
use tokio::net::{UnixListener, UnixStream};

use crate::control::events::EventHub;
use crate::control::nodes;

/// How often a live `Subscribe` stream refreshes its row's `last_seen`. Must
/// be comfortably below `ONLINE_TTL` in `api/nodes.rs` so a brief stall
/// between ticks never flips a healthy daemon to offline.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

pub fn default_socket_path() -> PathBuf {
    crate::tund::tunnel::control_plane_socket_path()
}

#[derive(Clone)]
pub struct StreamState {
    pub pool: SqlitePool,
    pub events: EventHub,
    /// UUID of the node that hosts this control plane — i.e. the node
    /// running this very mlshtund process. Used to flag the matching row
    /// in `ListNodes` responses so daemons resolving `control.<cluster>`
    /// can find the right IP. ADR-030 §2 keeps this single-valued
    /// (one control node per cluster in v1).
    pub control_node_uuid: String,
}

pub async fn serve(socket_path: &Path, state: StreamState) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path).ok();
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(path = %socket_path.display(), "mlsh-control CBOR socket listening");

    let state = Arc::new(state);
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_one(stream, &state).await {
                        tracing::debug!(error = %e, "control CBOR session ended with error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "control socket accept failed");
                return Err(e.into());
            }
        }
    }
}

async fn handle_one(mut stream: UnixStream, state: &StreamState) -> Result<()> {
    let (mut rd, mut wr) = stream.split();

    let header: ControlAuthHeader = framing::read_msg(&mut rd).await?;
    let request: ControlRequest = framing::read_msg(&mut rd).await?;

    // Every authenticated CBOR session is a liveness signal. Bumping
    // last_seen here covers AdoptConfirm / ListNodes / Subscribe at
    // connect-time; the Subscribe loop refreshes it on its own ticker.
    if let Err(e) =
        nodes::touch_last_seen(&state.pool, cluster_key(&header), &header.caller_node_uuid).await
    {
        tracing::debug!(error = %e, "control: touch_last_seen on connect failed");
    }

    if matches!(request, ControlRequest::Subscribe) {
        return run_subscribe(
            &mut wr,
            &state.events,
            &state.pool,
            cluster_key(&header),
            &header.caller_node_uuid,
        )
        .await;
    }

    let response = dispatch(state, &header, &request).await;
    framing::write_msg(&mut wr, &response).await?;
    Ok(())
}

/// Stream `ControlEvent` records to a subscriber until the connection drops or
/// the hub evicts us (slow consumer). While the stream is alive, periodically
/// bumps `nodes.last_seen` so the API can derive a real online/offline flag
/// from staleness rather than registration state.
async fn run_subscribe(
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    hub: &EventHub,
    pool: &SqlitePool,
    cluster_key: &str,
    node_uuid: &str,
) -> Result<()> {
    let (_handle, mut rx) = hub.register(cluster_key).await;
    tracing::debug!(cluster = %cluster_key, "control: subscribe stream opened");

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    // First tick fires immediately — already touched in handle_one, skip it.
    heartbeat.tick().await;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                let Some(event) = maybe_event else { break };
                if let Err(e) = framing::write_msg(wr, &*event).await {
                    tracing::debug!(cluster = %cluster_key, error = %e, "control: subscribe write failed; closing");
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if let Err(e) = nodes::touch_last_seen(pool, cluster_key, node_uuid).await {
                    tracing::debug!(error = %e, "control: heartbeat touch_last_seen failed");
                }
            }
        }
    }
    tracing::debug!(cluster = %cluster_key, "control: subscribe stream closed");
    Ok(())
}

/// Storage key used in the `nodes.cluster_id` column. Always the UUID —
/// REST routes look rows up by `state.cluster.cluster_id` so the CBOR
/// insert path must agree.
fn cluster_key(auth: &ControlAuthHeader) -> &str {
    &auth.cluster_id
}

async fn dispatch(
    state: &StreamState,
    auth: &ControlAuthHeader,
    req: &ControlRequest,
) -> ControlResponse {
    let pool = &state.pool;
    match req {
        ControlRequest::AdoptConfirm {
            node_uuid,
            fingerprint,
            public_key,
            display_name,
            invite_token: _,
        } => match nodes::upsert(
            pool,
            cluster_key(auth),
            node_uuid,
            fingerprint,
            public_key,
            display_name,
            if node_uuid == &auth.caller_node_uuid {
                &auth.caller_role
            } else {
                "node"
            },
        )
        .await
        {
            Ok(()) => ControlResponse::AdoptAck {
                accepted: true,
                message: None,
            },
            Err(e) => ControlResponse::error("internal", &format!("upsert failed: {e:#}")),
        },

        ControlRequest::ListNodes => match nodes::list(pool, cluster_key(auth)).await {
            Ok(rows) => ControlResponse::Nodes {
                nodes: rows
                    .into_iter()
                    .map(|r| node_row_to_info(r, &state.control_node_uuid))
                    .collect(),
            },
            Err(e) => ControlResponse::error("internal", &format!("list failed: {e:#}")),
        },

        ControlRequest::Subscribe => {
            // Handled in handle_one before dispatch is called.
            ControlResponse::error("internal", "Subscribe must not reach dispatch")
        }
    }
}

fn node_row_to_info(r: nodes::NodeRow, control_node_uuid: &str) -> ControlNodeInfo {
    let is_control_node = r.node_uuid == control_node_uuid;
    ControlNodeInfo {
        node_uuid: r.node_uuid,
        fingerprint: r.fingerprint,
        display_name: r.display_name,
        role: r.role,
        status: r.status,
        last_seen: r.last_seen,
        is_control_node,
    }
}
