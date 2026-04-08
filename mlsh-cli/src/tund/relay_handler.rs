//! Handle incoming relay streams from signal.
//!
//! When signal opens a bidirectional stream on our connection with a
//! `relay_incoming` header, we accept it and set up bidirectional forwarding:
//! - Inbound (relay → TUN): read packets from the relay stream, write to TUN
//! - Outbound (TUN → relay): via PeerTable channel, written by the single TUN reader

use std::net::Ipv4Addr;
use std::sync::Arc;

use mlsh_protocol::framing;
use mlsh_protocol::messages::RelayMessage;

use super::peer_table::{self, PeerTable};

/// Handle an incoming relay stream from signal.
///
/// Reads the `relay_incoming` header (which may include `from_node_id`),
/// responds with `relay_accepted`, then:
/// - Creates an mpsc channel for outbound packets
/// - Inserts a `PeerRoute::Relay` into the PeerTable (keyed by peer's overlay IP)
/// - Runs inbound (relay → TUN) and outbound (channel → relay) tasks
/// - Cleans up the route when the relay ends
pub async fn handle_incoming_relay(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    device: Arc<tun_rs::AsyncDevice>,
    _my_ip: Ipv4Addr,
    peer_table: PeerTable,
) -> anyhow::Result<()> {
    // Read header from signal
    let header: RelayMessage = framing::read_msg(&mut recv).await?;

    let from_node_id = match &header {
        RelayMessage::RelayIncoming { from_node_id } => from_node_id.as_str(),
        other => anyhow::bail!("Expected RelayIncoming, got: {:?}", other),
    };

    tracing::info!("Relay stream accepted (from: {})", from_node_id);

    // Respond with relay_accepted
    framing::write_msg(&mut send, &RelayMessage::RelayAccepted).await?;

    // Look up the peer's overlay IP from the known peers list.
    // Relay streams can arrive before the auth response populates the peer
    // list (race on reconnect), so retry a few times with a short delay.
    let peer_ip = if !from_node_id.is_empty() {
        let mut ip = None;
        for attempt in 0..5 {
            let peers = peer_table.known_peers().await;
            ip = peers
                .iter()
                .find(|p| p.node_id == from_node_id)
                .and_then(|p| p.overlay_ip.parse::<Ipv4Addr>().ok());
            if ip.is_some() {
                break;
            }
            if attempt < 4 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        if ip.is_none() {
            tracing::warn!("Relay from {}: peer not found in known peers", from_node_id);
        }
        ip
    } else {
        None
    };

    // Create channel for outbound (TUN reader → relay stream)
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // Insert relay route into PeerTable if we know the peer's IP
    if let Some(ip) = peer_ip {
        peer_table.insert_relay(ip, outbound_tx.clone()).await;
        tracing::info!("Inserted relay route to {} via signal", ip);
    }

    // Inbound: relay → TUN
    let device_in = device.clone();
    let peer_table_rx = peer_table.clone();
    let inbound = tokio::spawn(async move {
        let mut pkt_buf = vec![0u8; 65536];
        loop {
            let mut len_buf = [0u8; 4];
            if recv.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let plen = u32::from_be_bytes(len_buf) as usize;
            if !(20..=65536).contains(&plen) {
                continue;
            }
            if recv.read_exact(&mut pkt_buf[..plen]).await.is_err() {
                break;
            }
            let pkt = &pkt_buf[..plen];
            if !peer_table::validate_inbound_packet(pkt) {
                continue;
            }
            peer_table_rx.record_rx(plen);
            let _ = device_in.send(pkt).await;
        }
    });

    // Outbound: channel → relay
    let outbound = tokio::spawn(async move {
        while let Some(packet) = outbound_rx.recv().await {
            let len_bytes = (packet.len() as u32).to_be_bytes();
            if send.write_all(&len_bytes).await.is_err() {
                break;
            }
            if send.write_all(&packet).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }

    // Clean up route only if it's still a relay (a direct connection may have replaced it)
    if let Some(ip) = peer_ip {
        if peer_table.remove_relay_only(ip).await {
            tracing::info!("Relay route to {} removed", ip);
        } else {
            tracing::debug!("Relay to {} ended, keeping active direct route", ip);
        }
    }

    drop(outbound_tx);
    tracing::info!("Relay stream ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn relay_module_compiles() {
        // Integration tests require a QUIC connection; this is a smoke test.
    }
}
