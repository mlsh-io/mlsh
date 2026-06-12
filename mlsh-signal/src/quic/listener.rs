//! QUIC accept loop with ALPN-based routing.
//!
//! Dispatches incoming connections to the appropriate handler based on ALPN:
//! - `mlsh-signal` → session handler (NodeAuth, Adopt, Revoke)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use mlsh_protocol::alpn;

use crate::sessions::SessionStore;

/// Shared state for the QUIC server.
pub struct QuicState {
    pub db: sqlx::SqlitePool,
    pub sessions: Arc<SessionStore>,
    pub config: Arc<crate::config::Config>,
    pub overlay_subnet: crate::db::OverlaySubnet,
    pub metrics: Arc<crate::metrics::Metrics>,
    /// Active mlsh-control ALPN connections keyed by mTLS fingerprint.
    pub control_conns: Arc<Mutex<HashMap<String, quinn::Connection>>>,
    /// Outbound HTTP client for cloud calls (quota check).
    pub http_client: reqwest::Client,
    /// Serializes quota check + node registration so concurrent adoptions
    /// cannot both pass the quota check.
    pub adopt_lock: Mutex<()>,
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

    // cap concurrent connections per source IP.
    const MAX_CONNS_PER_IP: usize = 32;
    let per_ip = Arc::new(std::sync::Mutex::new(
        HashMap::<std::net::IpAddr, usize>::new(),
    ));

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let remote = incoming.remote_address();
                {
                    let mut map = per_ip.lock().unwrap();
                    let count = map.entry(remote.ip()).or_insert(0);
                    if *count >= MAX_CONNS_PER_IP {
                        drop(map);
                        tracing::warn!("Refusing connection from {}: per-IP limit reached", remote);
                        incoming.refuse();
                        continue;
                    }
                    *count += 1;
                }
                let state = state.clone();
                let per_ip = per_ip.clone();

                tokio::spawn(async move {
                    let _guard = PerIpGuard(per_ip, remote.ip());
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
                        Some(alpn::ALPN_CONTROL) => {
                            tracing::info!("Control relay connection from {}", remote);
                            super::control_relay::handle_control_connection(conn, state).await;
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

/// Decrements the per-IP connection count when the connection task ends.
struct PerIpGuard(
    Arc<std::sync::Mutex<HashMap<std::net::IpAddr, usize>>>,
    std::net::IpAddr,
);

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap();
        if let Some(c) = m.get_mut(&self.1) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.1);
            }
        }
    }
}
