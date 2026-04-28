//! Initiator side of a TLS-E2E-encrypted relay session through signal.
//! The receiver counterpart lives in `relay_handler`.

use std::sync::Arc;

use anyhow::{Context, Result};

use super::peer_table::{self, PeerTable};

pub struct RelayInitiator {
    pub signal_conn: quinn::Connection,
    pub cluster_id: String,
    pub my_node_id: String,
    pub peer_node_id: String,
    pub peer_fingerprint: String,
    pub identity_dir: std::path::PathBuf,
    pub device: Arc<tun_rs::AsyncDevice>,
    pub peer_table: PeerTable,
    pub events_tx: tokio::sync::mpsc::UnboundedSender<super::peer_fsm::Event>,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Opens a relay stream through signal, wraps it in TLS, and runs the I/O
/// tasks. Emits `__RelayReadyWith` once up and `RelayClosed` on exit.
pub async fn run_relay_initiator(r: RelayInitiator) {
    use super::peer_fsm::Event;
    let RelayInitiator {
        signal_conn,
        cluster_id,
        my_node_id,
        peer_node_id,
        peer_fingerprint,
        identity_dir,
        device,
        peer_table,
        events_tx,
        cancel,
    } = r;

    let (send, recv) =
        match open_relay_to_peer(&signal_conn, &cluster_id, &my_node_id, &peer_node_id).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to open relay to {}: {}", peer_node_id, e);
                return;
            }
        };

    let identity = match mlsh_crypto::identity::load_or_generate(&identity_dir, &my_node_id) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("Failed to load identity for relay TLS: {}", e);
            return;
        }
    };

    let tls_stream =
        match super::relay_tls::wrap_initiator(send, recv, &identity, &peer_fingerprint).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Relay TLS handshake to {} failed: {}", peer_node_id, e);
                return;
            }
        };

    tracing::info!("Relay to {} via signal (TLS E2E encrypted)", peer_node_id);

    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    let _ = events_tx.send(Event::__RelayReadyWith(Box::new(outbound_tx.clone())));

    let dev_in = device.clone();
    let pt_rx = peer_table.clone();
    let inbound = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
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
            let _ = dev_in.send(pkt).await;
        }
    });

    let outbound = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
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
        _ = cancel.cancelled() => {}
    }

    let _ = events_tx.send(Event::RelayClosed);
}

/// Open a relay stream to a specific peer through signal.
async fn open_relay_to_peer(
    signal_conn: &quinn::Connection,
    cluster_id: &str,
    node_id: &str,
    target_node_id: &str,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = signal_conn
        .open_bi()
        .await
        .context("Failed to open relay stream")?;

    let msg = mlsh_protocol::messages::StreamMessage::RelayOpen {
        cluster_id: cluster_id.to_string(),
        node_id: node_id.to_string(),
        target_node_id: target_node_id.to_string(),
    };
    mlsh_protocol::framing::write_msg(&mut send, &msg).await?;

    // Read RelayReady
    let resp: mlsh_protocol::messages::ServerMessage =
        mlsh_protocol::framing::read_msg(&mut recv).await?;

    match resp {
        mlsh_protocol::messages::ServerMessage::RelayReady => {}
        mlsh_protocol::messages::ServerMessage::Error { code, message } => {
            anyhow::bail!("Relay failed ({}): {}", code, message);
        }
        other => {
            anyhow::bail!("Unexpected relay response: {:?}", other);
        }
    }

    Ok((send, recv))
}
