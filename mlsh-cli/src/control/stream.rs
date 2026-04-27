//! CBOR-over-UNIX-socket listener for the mlsh-control plane (ADR-033).
//!
//! mlshtund relays QUIC streams arriving on its `mlsh-control` ALPN connection
//! by forwarding them to this UNIX socket. Each connection carries one
//! request/response pair:
//!
//!   1. mlshtund writes a `ControlAuthHeader` (1 length-prefixed CBOR frame)
//!      describing the authenticated caller — signal vouched for it.
//!   2. mlshtund writes a `ControlRequest` (1 frame).
//!   3. mlsh-control writes a `ControlResponse` (1 frame).
//!   4. Connection is closed.
//!
//! Auth is delegated: the control plane trusts mlshtund's auth header, so
//! checks against the caller's role come from `header.caller_role`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use mlsh_protocol::control::{
    ControlAuthHeader, ControlNodeInfo, ControlRequest, ControlResponse,
};
use mlsh_protocol::framing;
use sqlx::SqlitePool;
use tokio::net::{UnixListener, UnixStream};

use crate::control::nodes;

/// Default path of the control plane CBOR IPC socket.
pub fn default_socket_path() -> PathBuf {
    super::db::data_dir().join("control.sock")
}

#[derive(Clone)]
pub struct StreamState {
    pub pool: SqlitePool,
}

/// Run the UNIX socket listener. Returns when the listener fails (caller
/// can decide whether to restart).
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

    let response = dispatch(&state.pool, &header, &request).await;
    framing::write_msg(&mut wr, &response).await?;
    Ok(())
}

/// Cluster key used in mlsh-control's `nodes` table — prefer the human name
/// (so the bundled UI's `whoami.cluster` matches), fall back to the UUID for
/// older signal builds that didn't populate `cluster_name`.
fn cluster_key(auth: &ControlAuthHeader) -> &str {
    if !auth.cluster_name.is_empty() {
        &auth.cluster_name
    } else {
        &auth.cluster_id
    }
}

async fn dispatch(
    pool: &SqlitePool,
    auth: &ControlAuthHeader,
    req: &ControlRequest,
) -> ControlResponse {
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
            // The control plane learns the role from signal's auth header
            // for V1 — signal already validated the invite and assigned a role.
            // Bootstrap node arrives here as caller==target with role=admin.
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
                nodes: rows.into_iter().map(node_row_to_info).collect(),
            },
            Err(e) => ControlResponse::error("internal", &format!("list failed: {e:#}")),
        },

        ControlRequest::Rename {
            target_node_uuid,
            new_display_name,
        } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can rename");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            match nodes::set_display_name(pool, key, &uuid, new_display_name).await {
                Ok(true) => ControlResponse::Ok,
                Ok(false) => ControlResponse::error("not_found", "Node not found"),
                Err(e) => ControlResponse::error("internal", &format!("rename failed: {e:#}")),
            }
        }

        ControlRequest::Promote {
            target_node_uuid,
            new_role,
        } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can promote");
            }
            if new_role != "admin" && new_role != "node" {
                return ControlResponse::error("bad_role", "role must be 'admin' or 'node'");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            match nodes::set_role(pool, key, &uuid, new_role).await {
                Ok(true) => ControlResponse::Ok,
                Ok(false) => ControlResponse::error("not_found", "Node not found"),
                Err(e) => ControlResponse::error("internal", &format!("promote failed: {e:#}")),
            }
        }

        ControlRequest::Revoke { target_node_uuid } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can revoke");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            match nodes::set_status(pool, key, &uuid, "revoked").await {
                Ok(true) => ControlResponse::Ok,
                Ok(false) => ControlResponse::error("not_found", "Node not found"),
                Err(e) => ControlResponse::error("internal", &format!("revoke failed: {e:#}")),
            }
        }
    }
}

fn node_row_to_info(r: nodes::NodeRow) -> ControlNodeInfo {
    ControlNodeInfo {
        node_uuid: r.node_uuid,
        fingerprint: r.fingerprint,
        display_name: r.display_name,
        role: r.role,
        status: r.status,
        last_seen: r.last_seen,
    }
}
