//! Handle incoming relay streams from signal.
//!
//! When signal opens a bidirectional stream on our connection with a
//! `relay_incoming` header, we accept it, establish a TLS session over the
//! relay stream (same mTLS as direct connections), and forward encrypted
//! packets. Signal sees only TLS ciphertext.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use mlsh_protocol::framing;
use mlsh_protocol::messages::RelayMessage;

use super::peer_fsm::{Event, FsmRegistry};
use super::peer_table::{self, PeerTable};
use super::relay_tls;

pub struct IncomingRelay {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub device: Arc<tun_rs::AsyncDevice>,
    pub peer_table: PeerTable,
    pub identity: mlsh_crypto::identity::NodeIdentity,
    pub from_node_id: String,
    pub fsm_registry: FsmRegistry,
}

/// Handle an incoming relay stream from signal (responder side).
///
/// Wraps the stream in TLS (as server) for E2E encryption; the peer
/// (initiator) connects as TLS client and verifies our certificate
/// fingerprint. `from_node_id` is parsed by the caller from the
/// `RelayIncoming` header.
pub async fn handle_incoming_relay(relay: IncomingRelay) -> anyhow::Result<()> {
    let IncomingRelay {
        mut send,
        recv,
        device,
        peer_table,
        identity,
        from_node_id,
        fsm_registry,
    } = relay;

    tracing::info!("Relay stream accepted (from: {})", from_node_id);
    framing::write_msg(&mut send, &RelayMessage::RelayAccepted).await?;

    let peer_ip = lookup_peer_ip(&from_node_id, &peer_table).await;

    let tls_stream = relay_tls::wrap_responder(send, recv, &identity).await?;

    // Verify the peer's fingerprint after TLS handshake
    if let Some(peer_fp) = relay_tls::extract_peer_fingerprint_server(&tls_stream) {
        let known_fp = peer_table
            .known_peers()
            .await
            .iter()
            .find(|p| p.node_id == from_node_id)
            .map(|p| p.fingerprint.clone());

        if let Some(expected) = known_fp {
            if peer_fp != expected {
                anyhow::bail!(
                    "Relay peer {} fingerprint mismatch (TLS={}, expected={})",
                    from_node_id,
                    &peer_fp[..16],
                    &expected[..16],
                );
            }
        }
    }

    tracing::info!(
        "Relay TLS established with {} (E2E encrypted)",
        from_node_id
    );

    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    // Create channel for outbound (TUN reader → relay)
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    if let Some(ip) = peer_ip {
        peer_table.insert_relay(ip, outbound_tx.clone()).await;
        fsm_registry.notify(ip, Event::RelayReady).await;
    }

    // Inbound: TLS → TUN
    let device_in = device.clone();
    let pt_rx = peer_table.clone();
    let inbound = tokio::spawn(async move {
        let mut pkt_buf = vec![0u8; 65536];
        loop {
            let mut len_buf = [0u8; 4];
            if tls_read.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let plen = u32::from_be_bytes(len_buf) as usize;
            if !(20..=65536).contains(&plen) {
                continue;
            }
            if tls_read.read_exact(&mut pkt_buf[..plen]).await.is_err() {
                break;
            }
            let pkt = &pkt_buf[..plen];
            if !peer_table::validate_inbound_packet(pkt) {
                continue;
            }
            pt_rx.record_rx(plen);
            let _ = device_in.send(pkt).await;
        }
    });

    // Outbound: channel → TLS
    let outbound = tokio::spawn(async move {
        while let Some(packet) = outbound_rx.recv().await {
            let len = (packet.len() as u32).to_be_bytes();
            if tls_write.write_all(&len).await.is_err() {
                break;
            }
            if tls_write.write_all(&packet).await.is_err() {
                break;
            }
        }
        let _ = tls_write.shutdown().await;
    });

    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }

    if let Some(ip) = peer_ip {
        if peer_table.remove_relay_only(ip).await {
            tracing::info!("Relay route to {} removed", ip);
        }
        fsm_registry.notify(ip, Event::RelayClosed).await;
    }

    drop(outbound_tx);
    tracing::info!("Relay TLS stream ended");
    Ok(())
}

async fn lookup_peer_ip(from_node_id: &str, peer_table: &PeerTable) -> Option<Ipv4Addr> {
    if from_node_id.is_empty() {
        return None;
    }
    for attempt in 0..5 {
        let peers = peer_table.known_peers().await;
        if let Some(p) = peers.iter().find(|p| p.node_id == from_node_id) {
            return p.overlay_ip.parse().ok();
        }
        if attempt < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    tracing::warn!("Relay from {}: peer not found", from_node_id);
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn relay_module_compiles() {}
}
