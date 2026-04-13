//! QUIC accept loop with ALPN-based routing.
//!
//! Dispatches incoming connections to the appropriate handler based on ALPN:
//! - `mlsh-signal` → session handler (NodeAuth, Adopt, Revoke)

use std::net::SocketAddr;
use std::sync::Arc;

use super::alpn;
use crate::sessions::SessionStore;

/// Shared state for the QUIC server.
pub struct QuicState {
    pub db: sqlx::SqlitePool,
    pub sessions: Arc<SessionStore>,
    pub config: Arc<crate::config::Config>,
    pub overlay_subnet: crate::db::OverlaySubnet,
    pub metrics: Arc<crate::metrics::Metrics>,
}

/// QUIC accept loop. Runs until the endpoint is closed or the shutdown receiver fires.
pub async fn run(
    bind_addr: SocketAddr,
    server_config: quinn::ServerConfig,
    state: Arc<QuicState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    tracing::info!("QUIC server listening on {}", bind_addr);

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let remote = incoming.remote_address();
                let state = state.clone();

                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::debug!("QUIC handshake failed from {}: {}", remote, e);
                            return;
                        }
                    };

                    let alpn = conn
                        .handshake_data()
                        .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                        .and_then(|hd| hd.protocol);

                    match alpn.as_deref() {
                        Some(alpn::ALPN_SIGNAL) => {
                            tracing::info!("Signal connection from {}", remote);
                            super::session::handle_signal_connection(conn, state).await;
                        }
                        Some(other) => {
                            tracing::warn!(
                                "Unknown ALPN {:?} from {}",
                                String::from_utf8_lossy(other),
                                remote
                            );
                            conn.close(quinn::VarInt::from_u32(2), b"unknown alpn");
                        }
                        None => {
                            tracing::warn!("No ALPN from {}", remote);
                            conn.close(quinn::VarInt::from_u32(3), b"alpn required");
                        }
                    }
                });
            }
            _ = shutdown.changed() => {
                break;
            }
        }
    }

    tracing::info!(
        "Closing QUIC endpoint, notifying {} peers...",
        endpoint.open_connections()
    );
    endpoint.close(quinn::VarInt::from_u32(1), b"server shutting down");
    endpoint.wait_idle().await;
    tracing::info!("QUIC server shut down");
    Ok(())
}
