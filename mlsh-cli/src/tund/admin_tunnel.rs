//! Admin tunnel — `ssh -L`-style port forwarding through the overlay.
//!
//! The admin runs `mlsh control open <cluster> <node>`; their mlshtund binds
//! a local TCP listener and, for each accept, opens a bi stream on the
//! existing peer overlay connection. The stream is preceded by a 6-byte
//! marker (`MARKER`) so the target's overlay accept loop can distinguish
//! admin tunnels from anything else that might land on a bi stream later.
//!
//! On the target side, mlshtund verifies the caller's role from its peer
//! table (populated by signal). Non-admin peers are dropped. Admin peers
//! get spliced to the local mlsh-control on `127.0.0.1:8443`.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use super::peer_table::PeerTable;

/// Marker prefix sent on every admin bi stream. Long enough to be unlikely
/// to collide with any other future stream type, short enough to be cheap.
pub const MARKER: &[u8] = b"ADMIN1";
const CONTROL_LOCAL_ADDR: &str = "127.0.0.1:8443";

/// Bind a fresh `127.0.0.1:0` listener and forward every accepted TCP
/// connection through a bi stream on the QUIC connection to `target_ip`.
/// Returns the locally-bound port; the spawned task runs until the
/// listener is dropped (which happens when this future's task is aborted).
pub async fn spawn_listener(peer_table: PeerTable, target_ip: Ipv4Addr) -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("Failed to bind admin tunnel listener")?;
    let local_port = listener.local_addr()?.port();

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!(error = %e, "admin tunnel: accept failed");
                    continue;
                }
            };

            let table = peer_table.clone();
            tokio::spawn(async move {
                if let Err(e) = forward_connection(table, target_ip, tcp).await {
                    tracing::debug!(error = %e, %target_ip, "admin tunnel: forward failed");
                }
            });
        }
    });

    Ok(local_port)
}

async fn forward_connection(
    peer_table: PeerTable,
    target_ip: Ipv4Addr,
    mut tcp: tokio::net::TcpStream,
) -> Result<()> {
    let conn = peer_table
        .get_direct(target_ip)
        .await
        .with_context(|| format!("No direct overlay connection to {}", target_ip))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open bi stream to target")?;
    send.write_all(MARKER).await?;

    let (mut tcp_r, mut tcp_w) = tcp.split();
    tokio::select! {
        _ = tokio::io::copy(&mut tcp_r, &mut send) => {}
        _ = tokio::io::copy(&mut recv, &mut tcp_w) => {}
    }
    Ok(())
}

/// Accept incoming bi streams on a peer overlay connection and dispatch
/// admin-marked streams to the local mlsh-control. Caller is the QUIC
/// server's per-connection task; this future returns when the connection
/// closes.
pub async fn run_inbound_acceptor(
    conn: quinn::Connection,
    peer_fingerprint: Option<String>,
    peer_table: PeerTable,
) {
    let fp = match peer_fingerprint {
        Some(f) => f,
        None => return,
    };
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let mut marker = [0u8; MARKER.len()];
        if recv.read_exact(&mut marker).await.is_err() {
            continue;
        }
        if marker != *MARKER {
            let _ = send.finish();
            continue;
        }

        let fp = fp.clone();
        let table = peer_table.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_admin_stream(send, recv, &fp, &table).await {
                tracing::debug!(error = %e, "admin stream error");
            }
        });
    }
}

async fn handle_admin_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer_fingerprint: &str,
    peer_table: &PeerTable,
) -> Result<()> {
    // Source of truth: peer_table is populated from signal's peer list, and
    // signal is the authority on roles.
    let peers = peer_table.known_peers().await;
    let role = peers
        .iter()
        .find(|p| p.fingerprint == peer_fingerprint)
        .map(|p| p.role.as_str())
        .unwrap_or("");

    if role != "admin" {
        tracing::warn!(
            fingerprint = %peer_fingerprint,
            role,
            "admin tunnel: rejecting non-admin peer"
        );
        let _ = send.finish();
        return Ok(());
    }

    let mut tcp = tokio::net::TcpStream::connect(CONTROL_LOCAL_ADDR)
        .await
        .with_context(|| {
            format!(
                "Failed to connect to mlsh-control at {}",
                CONTROL_LOCAL_ADDR
            )
        })?;

    let (mut tcp_r, mut tcp_w) = tcp.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv, &mut tcp_w) => {}
        _ = tokio::io::copy(&mut tcp_r, &mut send) => {}
    }
    Ok(())
}
