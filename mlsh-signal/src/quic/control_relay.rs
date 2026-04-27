//! ALPN `mlsh-control` connection handler — relays streams to the cluster's
//! control node (ADR-033).
//!
//! Flow per stream:
//! 1. Caller opens a bi-stream on its `mlsh-control` connection to signal.
//! 2. Signal authenticates the caller via mTLS fingerprint, looks up its
//!    cluster_id and role, finds the cluster's control node (oldest admin).
//! 3. Signal opens a fresh bi-stream on the control node's existing
//!    `mlsh-signal` QUIC connection.
//! 4. Signal writes a `ControlAuthHeader` as the first frame on that outgoing
//!    stream — the control plane trusts signal to authenticate the caller.
//! 5. Signal splices the two streams bidirectionally until either side closes.

use std::sync::Arc;

use mlsh_protocol::control::ControlAuthHeader;
use tracing::{debug, info, warn};

use super::listener::QuicState;

/// Long-running handler for a node's `mlsh-control` QUIC connection. Accepts
/// bi-streams and relays each one to the cluster's control node.
pub async fn handle_control_connection(conn: quinn::Connection, state: Arc<QuicState>) {
    let caller_fp = match super::session::extract_peer_fingerprint(&conn) {
        Some(fp) => fp,
        None => {
            warn!("control: no client cert presented; closing");
            conn.close(quinn::VarInt::from_u32(2), b"client cert required");
            return;
        }
    };

    // Register this connection so other nodes can be relayed toward it when
    // the caller is the cluster's control node. Multi-node clusters will end
    // up with one entry per fingerprint.
    {
        let mut g = state.control_conns.lock().await;
        g.insert(caller_fp.clone(), conn.clone());
    }
    info!(fp = %caller_fp, "control: connection registered");

    let result = accept_loop(conn.clone(), &caller_fp, state.clone()).await;
    let _ = result;

    // Deregister on close.
    {
        let mut g = state.control_conns.lock().await;
        g.remove(&caller_fp);
    }
    debug!(fp = %caller_fp, "control: connection deregistered");
}

async fn accept_loop(
    conn: quinn::Connection,
    caller_fp: &str,
    state: Arc<QuicState>,
) -> anyhow::Result<()> {
    loop {
        let stream = tokio::select! {
            s = conn.accept_bi() => s,
            _ = conn.closed() => {
                debug!(fp = %caller_fp, "control: connection closed");
                return Ok(());
            }
        };
        let (cli_send, cli_recv) = match stream {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                debug!(fp = %caller_fp, "control: peer closed");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, "control: accept_bi failed");
                return Err(e.into());
            }
        };

        let state = state.clone();
        let caller_fp = caller_fp.to_string();
        tokio::spawn(async move {
            if let Err(e) = relay_one_stream(cli_send, cli_recv, &caller_fp, &state).await {
                debug!(error = %e, "control: stream relay finished with error");
            }
        });
    }
}

async fn relay_one_stream(
    mut cli_send: quinn::SendStream,
    mut cli_recv: quinn::RecvStream,
    caller_fp: &str,
    state: &QuicState,
) -> anyhow::Result<()> {
    // The caller has presented an mTLS client cert. We must locate the node it
    // belongs to to know its cluster and role. We scan all known nodes —
    // there's no global fingerprint index in V1, but the operation runs once
    // per stream and node counts are small.
    let caller = match find_node_by_fingerprint(&state.db, caller_fp).await? {
        Some(n) => n,
        None => {
            return reject(&mut cli_send, "auth_failed", "Unknown fingerprint").await;
        }
    };

    let control = match crate::db::find_control_node(&state.db, &caller.cluster_id).await? {
        Some(n) => n,
        None => {
            return reject(
                &mut cli_send,
                "no_control",
                "No control node available for this cluster",
            )
            .await;
        }
    };

    // Find the control node's `mlsh-control` ALPN connection (NOT its
    // `mlsh-signal` one — those carry a different protocol).
    let control_conn = {
        let g = state.control_conns.lock().await;
        g.get(&control.fingerprint).cloned()
    };
    let control_conn = match control_conn {
        Some(c) if c.close_reason().is_none() => c,
        _ => {
            return reject(
                &mut cli_send,
                "control_offline",
                "Control node has no live mlsh-control session",
            )
            .await;
        }
    };

    let cluster_name = crate::db::get_cluster_name_by_id(&state.db, &caller.cluster_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    info!(
        cluster_id = %caller.cluster_id,
        from = %caller.node_id,
        to = %control.node_id,
        "control: relaying stream to control node"
    );

    let (mut ctrl_send, mut ctrl_recv) = control_conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open bi-stream on control: {e}"))?;

    let header = ControlAuthHeader {
        cluster_id: caller.cluster_id.clone(),
        cluster_name,
        caller_node_uuid: caller.node_id.clone(),
        caller_fingerprint: caller.fingerprint.clone(),
        caller_role: caller.role.clone(),
    };
    mlsh_protocol::framing::write_msg(&mut ctrl_send, &header).await?;

    let cli_to_ctrl = tokio::io::copy(&mut cli_recv, &mut ctrl_send);
    let ctrl_to_cli = tokio::io::copy(&mut ctrl_recv, &mut cli_send);
    let (r1, r2) = tokio::join!(cli_to_ctrl, ctrl_to_cli);
    debug!(
        cli_to_ctrl = ?r1.ok(),
        ctrl_to_cli = ?r2.ok(),
        "control: stream splice finished"
    );

    Ok(())
}

async fn find_node_by_fingerprint(
    pool: &sqlx::SqlitePool,
    fingerprint: &str,
) -> anyhow::Result<Option<crate::db::NodeRecord>> {
    // No multi-cluster fingerprint index in V1 — scan clusters via a single
    // query on the nodes table.
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT cluster_id, node_id, fingerprint, overlay_ip, role, display_name
         FROM nodes WHERE fingerprint = ?1 LIMIT 1",
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(cid, nid, fp, ip, role, dn)| crate::db::NodeRecord {
        cluster_id: cid,
        node_id: nid,
        fingerprint: fp,
        overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        role,
        display_name: dn,
    }))
}

async fn reject(send: &mut quinn::SendStream, code: &str, msg: &str) -> anyhow::Result<()> {
    let resp = mlsh_protocol::control::ControlResponse::error(code, msg);
    mlsh_protocol::framing::write_msg(send, &resp).await?;
    let _ = send.finish();
    Ok(())
}
