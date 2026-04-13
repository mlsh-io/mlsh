//! Relay handler: splices a peer's bi-stream to another peer's bi-stream.
//!
//! When direct connection between peers fails (NAT, firewall), a node opens
//! a relay through signal. Signal opens a new bi-stream on the target peer's
//! QUIC connection and copies bytes bidirectionally.

use anyhow::Context;
use tracing::{debug, info};

use super::listener::QuicState;
use crate::protocol::RelayMessage;

async fn reject(send: &mut quinn::SendStream, code: &str, msg: &str) -> anyhow::Result<()> {
    let resp = crate::protocol::ServerMessage::error(code, msg);
    crate::protocol::write_message(send, &resp).await?;
    send.finish()?;
    Ok(())
}

/// Handle a relay request from a node.
///
/// 1. Authenticate the caller via TLS client certificate
/// 2. Identify the caller node (to avoid relaying to self)
/// 3. Find the target peer's QUIC connection
/// 4. Open a bi-stream on the target's connection
/// 5. Handshake: relay_incoming → relay_accepted
/// 6. Splice bytes bidirectionally
pub async fn handle_relay(
    mut cli_send: quinn::SendStream,
    mut cli_recv: quinn::RecvStream,
    conn: &quinn::Connection,
    state: &QuicState,
    cluster_id: &str,
    node_id: &str,
    target_node_id: &str,
) -> anyhow::Result<()> {
    // Authenticate the caller via TLS client certificate fingerprint
    let caller_fp = match super::session::extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => {
            reject(&mut cli_send, "auth_failed", "Client certificate required").await?;
            return Ok(());
        }
    };

    // Verify the claimed node_id matches the TLS cert fingerprint
    let caller_node =
        match crate::db::lookup_node_by_fingerprint(&state.db, cluster_id, &caller_fp).await {
            Ok(Some(n)) if n.node_id == node_id => n,
            Ok(Some(_)) => {
                reject(
                    &mut cli_send,
                    "auth_failed",
                    "Node ID does not match certificate",
                )
                .await?;
                return Ok(());
            }
            Ok(None) => {
                reject(&mut cli_send, "auth_failed", "Unknown fingerprint").await?;
                return Ok(());
            }
            Err(_) => {
                reject(&mut cli_send, "internal", "Database error").await?;
                return Ok(());
            }
        };

    let caller_node_id = &caller_node.node_id;

    // Find the target peer's connection
    let (target_conn, actual_target_id) = if !target_node_id.is_empty() {
        // Specific target requested
        match state
            .sessions
            .get_node_connection(cluster_id, target_node_id)
            .await
        {
            Some(conn) => {
                info!(
                    cluster_id,
                    from = %caller_node_id,
                    to = target_node_id,
                    "Opening relay stream to target peer"
                );
                (conn, target_node_id.to_string())
            }
            None => {
                reject(
                    &mut cli_send,
                    "peer_offline",
                    &format!("Peer '{}' is not connected", target_node_id),
                )
                .await?;
                return Ok(());
            }
        }
    } else {
        // No specific target — pick any other peer in the cluster
        match state
            .sessions
            .get_other_node_connection(cluster_id, caller_node_id)
            .await
        {
            Some((peer_id, conn)) => {
                info!(
                    cluster_id,
                    from = %caller_node_id,
                    to = %peer_id,
                    "Opening relay stream to peer (auto-selected)"
                );
                (conn, peer_id)
            }
            None => {
                reject(
                    &mut cli_send,
                    "no_peers",
                    "No other peers connected to relay to",
                )
                .await?;
                return Ok(());
            }
        }
    };

    // Open bi-stream on target peer's connection
    let (mut target_send, mut target_recv) = target_conn
        .open_bi()
        .await
        .context("Failed to open bi-stream on target peer's connection")?;

    // Send relay_incoming header with source node identity
    let header = RelayMessage::RelayIncoming {
        from_node_id: caller_node_id.to_string(),
    };
    mlsh_protocol::framing::write_msg(&mut target_send, &header).await?;

    // Read target's response
    let resp: RelayMessage = mlsh_protocol::framing::read_msg(&mut target_recv)
        .await
        .context("Invalid relay response from target")?;

    if !matches!(resp, RelayMessage::RelayAccepted) {
        anyhow::bail!("Target rejected relay: {:?}", resp);
    }

    info!(cluster_id, "Relay accepted, splicing streams");

    // Send RelayReady to the initiator
    crate::protocol::write_message(&mut cli_send, &crate::protocol::ServerMessage::RelayReady)
        .await?;

    // Set up real-time byte counters
    // caller → target direction: caller TX, target RX
    let (caller_tx, _) = state.metrics.node_counters(cluster_id, node_id).await;
    let (_, target_rx) = state
        .metrics
        .node_counters(cluster_id, &actual_target_id)
        .await;
    // target → caller direction: target TX, caller RX
    let (target_tx, _) = state
        .metrics
        .node_counters(cluster_id, &actual_target_id)
        .await;
    let (_, caller_rx) = state.metrics.node_counters(cluster_id, node_id).await;

    // Wrap writers to count bytes in real-time
    let caller_tx_counter = crate::metrics::DualCounter(caller_tx, target_rx);
    let target_tx_counter = crate::metrics::DualCounter(target_tx, caller_rx);
    let mut counting_target_send =
        crate::metrics::CountingWriter::new(&mut target_send, caller_tx_counter);
    let mut counting_cli_send =
        crate::metrics::CountingWriter::new(&mut cli_send, target_tx_counter);

    let cli_to_target = tokio::io::copy(&mut cli_recv, &mut counting_target_send);
    let target_to_cli = tokio::io::copy(&mut target_recv, &mut counting_cli_send);

    let (r1, r2) = tokio::join!(cli_to_target, target_to_cli);
    debug!(
        cluster_id,
        cli_to_target = ?r1.ok(),
        target_to_cli = ?r2.ok(),
        "Relay splice finished"
    );

    drop(counting_target_send);
    drop(counting_cli_send);
    let _ = cli_send.finish();
    let _ = target_send.finish();

    info!(cluster_id, "Relay session ended");
    Ok(())
}
