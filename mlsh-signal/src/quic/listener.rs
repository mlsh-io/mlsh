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
    /// Recent "control node offline" verdicts, keyed by cluster id. Entries
    /// hold the wanted control fingerprint and when the verdict was made, so
    /// relay attempts can be rejected cheaply until the control reconnects
    /// or the entry expires (`limits.control_offline_cache_secs`).
    pub control_offline: std::sync::Mutex<HashMap<String, (String, std::time::Instant)>>,
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

    let limits = state.config.limits.clone();
    let per_ip = Arc::new(std::sync::Mutex::new(
        HashMap::<std::net::IpAddr, IpStat>::new(),
    ));

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let remote = incoming.remote_address();
                {
                    let mut map = per_ip.lock().unwrap();
                    if map.len() > 4096 {
                        map.retain(|_, s| s.active > 0 || s.window.elapsed() < RATE_WINDOW);
                    }
                    let stat = map.entry(remote.ip()).or_default();
                    if stat.window.elapsed() >= RATE_WINDOW {
                        stat.window = std::time::Instant::now();
                        stat.in_window = 0;
                    }
                    stat.in_window = stat.in_window.saturating_add(1);
                    if stat.active >= limits.max_conns_per_ip {
                        drop(map);
                        tracing::warn!("Refusing connection from {}: per-IP limit reached", remote);
                        incoming.refuse();
                        continue;
                    }
                    if limits.new_conns_per_ip_per_min > 0
                        && stat.in_window > limits.new_conns_per_ip_per_min
                    {
                        // Warn once per window, then refuse silently.
                        if stat.in_window == limits.new_conns_per_ip_per_min + 1 {
                            tracing::warn!(
                                "Rate-limiting connections from {}: more than {}/min",
                                remote,
                                limits.new_conns_per_ip_per_min
                            );
                        }
                        drop(map);
                        incoming.refuse();
                        continue;
                    }
                    stat.active += 1;
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

/// Window over which `new_conns_per_ip_per_min` is counted.
const RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// Per-source-IP accounting: concurrent connections and new-connection rate.
struct IpStat {
    active: usize,
    window: std::time::Instant,
    in_window: u32,
}

impl Default for IpStat {
    fn default() -> Self {
        Self {
            active: 0,
            window: std::time::Instant::now(),
            in_window: 0,
        }
    }
}

/// Decrements the per-IP connection count when the connection task ends.
struct PerIpGuard(
    Arc<std::sync::Mutex<HashMap<std::net::IpAddr, IpStat>>>,
    std::net::IpAddr,
);

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap();
        if let Some(s) = m.get_mut(&self.1) {
            s.active = s.active.saturating_sub(1);
            if s.active == 0 && s.window.elapsed() >= RATE_WINDOW {
                m.remove(&self.1);
            }
        }
    }
}
