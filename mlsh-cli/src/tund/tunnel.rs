//! Per-cluster tunnel lifecycle: connect, forward, reconnect.
//!
//! `ManagedTunnel` owns a TUN device and manages the transport via a persistent
//! signal session. The TUN device outlives transport changes — reconnection
//! swaps the transport without destroying the TUN.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::dns;
use super::peer_table::{self, PeerTable};
use super::protocol::{TunnelState, TunnelStatus};
use mlsh_protocol::types::{Candidate, PeerInfo};

use super::signal_session::{self, SignalCredentials};

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Cluster configuration loaded from a cluster TOML + identity directory.
pub struct ClusterConfig {
    pub name: String,
    pub signal_endpoint: String,
    pub signal_fingerprint: String,
    pub overlay_ip: Option<String>,
    /// Overlay subnet in CIDR notation (e.g. "100.64.0.0/10" or "10.0.10.0/24").
    pub overlay_subnet: Option<String>,
    pub cluster_id: String,
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    /// Root admin fingerprint for peer-side admission cert verification.
    pub root_fingerprint: String,
    /// Path to the identity directory containing cert.pem and key.pem.
    pub identity_dir: std::path::PathBuf,
}

impl ClusterConfig {
    /// Build signal session credentials from this config.
    pub fn signal_credentials(&self) -> Result<SignalCredentials> {
        let cert_pem = std::fs::read_to_string(self.identity_dir.join("cert.pem"))
            .context("Missing identity cert.pem")?;
        let key_pem = std::fs::read_to_string(self.identity_dir.join("key.pem"))
            .context("Missing identity key.pem")?;

        Ok(SignalCredentials {
            signal_endpoint: self.signal_endpoint.clone(),
            signal_fingerprint: self.signal_fingerprint.clone(),
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            fingerprint: self.fingerprint.clone(),
            public_key: self.public_key.clone(),
            cert_pem,
            key_pem,
            root_fingerprint: self.root_fingerprint.clone(),
        })
    }
}

/// Shared mutable state between the tunnel task and the manager.
#[derive(Default)]
struct SharedInfo {
    transport: Option<String>,
    connected_at: Option<Instant>,
    last_error: Option<String>,
}

/// A managed tunnel for a single cluster.
pub struct ManagedTunnel {
    pub cluster_name: String,
    state_rx: watch::Receiver<TunnelState>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    overlay_ip: Option<Ipv4Addr>,
    info: Arc<std::sync::Mutex<SharedInfo>>,
}

impl ManagedTunnel {
    /// Start a new tunnel for the given cluster.
    pub fn start(config: ClusterConfig) -> Result<Self> {
        let (state_tx, state_rx) = watch::channel(TunnelState::Connecting);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let bytes_tx = Arc::new(AtomicU64::new(0));
        let bytes_rx = Arc::new(AtomicU64::new(0));
        let info = Arc::new(std::sync::Mutex::new(SharedInfo::default()));

        let overlay_ip: Ipv4Addr = config
            .overlay_ip
            .as_deref()
            .unwrap_or("100.64.0.1")
            .parse()
            .context("Invalid overlay IP in cluster config")?;

        let cluster_name = config.name.clone();
        let info_task = info.clone();

        let tx_counter = bytes_tx.clone();
        let rx_counter = bytes_rx.clone();
        let task = tokio::spawn(async move {
            tunnel_task(
                config,
                overlay_ip,
                state_tx,
                shutdown_rx,
                info_task,
                tx_counter,
                rx_counter,
            )
            .await;
        });

        Ok(Self {
            cluster_name,
            state_rx,
            shutdown_tx,
            task: Some(task),
            bytes_tx,
            bytes_rx,
            overlay_ip: Some(overlay_ip),
            info,
        })
    }

    /// Shut down this tunnel.
    pub async fn stop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(std::time::Duration::from_millis(500), &mut task)
                .await
                .is_err()
            {
                tracing::warn!(
                    "Tunnel '{}' didn't stop in 500ms, aborting",
                    self.cluster_name
                );
                task.abort();
            }
        }
        dns::remove_resolver(&self.cluster_name);
    }

    /// Current state.
    pub fn state(&self) -> TunnelState {
        *self.state_rx.borrow()
    }

    /// Build a status snapshot.
    pub fn status(&self) -> TunnelStatus {
        let info = self.info.lock().unwrap_or_else(|e| e.into_inner());
        let uptime = info.connected_at.map(|t| t.elapsed().as_secs());
        TunnelStatus {
            cluster: self.cluster_name.clone(),
            state: self.state(),
            transport: info.transport.clone(),
            overlay_ip: self.overlay_ip.map(|ip| ip.to_string()),
            uptime_secs: uptime,
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            last_error: info.last_error.clone(),
        }
    }
}

/// Long-running task that manages the tunnel lifecycle with reconnection.
async fn tunnel_task(
    config: ClusterConfig,
    overlay_ip: Ipv4Addr,
    state_tx: watch::Sender<TunnelState>,
    mut shutdown_rx: watch::Receiver<bool>,
    info: Arc<std::sync::Mutex<SharedInfo>>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
) {
    let mut backoff = Duration::from_secs(1);

    shutdown_rx.borrow_and_update();

    // Parse overlay prefix length from subnet config (e.g. "100.64.0.0/10" → 10)
    let overlay_prefix_len: u8 = config
        .overlay_subnet
        .as_deref()
        .unwrap_or("100.64.0.0/10")
        .split('/')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // Create TUN device once — it outlives transport changes.
    // On Linux, clean up any orphaned mlsh0 device before creating a new one.
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", "mlsh0"])
            .output();
    }

    #[cfg(target_os = "linux")]
    let device = {
        tun_rs::DeviceBuilder::new()
            .name("mlsh0")
            .ipv4(overlay_ip.to_string(), overlay_prefix_len, None)
            .mtu(1400)
            .build_async()
            .map(Arc::new)
    };
    #[cfg(not(target_os = "linux"))]
    let device = tun_rs::DeviceBuilder::new()
        .ipv4(overlay_ip.to_string(), overlay_prefix_len, None)
        .mtu(1400)
        .build_async()
        .map(Arc::new);

    let device = match device {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to create TUN device: {} (need root?)", e);
            let _ = state_tx.send(TunnelState::Disconnected);
            if let Ok(mut i) = info.lock() {
                i.last_error = Some(format!("TUN creation failed: {}", e));
            }
            return;
        }
    };

    tracing::info!(
        "TUN device created for {} with overlay IP {}/{}",
        config.name,
        overlay_ip,
        overlay_prefix_len
    );

    // DNS bind address: macOS uses localhost:53535, Linux uses overlay_ip:53.
    // macOS: packets to TUN IP aren't delivered to local listeners.
    // Linux: local delivery works, and resolvectl requires port 53.
    #[cfg(target_os = "macos")]
    let dns_bind =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53535);
    #[cfg(not(target_os = "macos"))]
    let dns_bind = std::net::SocketAddr::new(std::net::IpAddr::V4(overlay_ip), 53);

    // Install DNS resolver
    if let Err(e) = dns::install_resolver(&config.name, &dns_bind.ip().to_string(), dns_bind.port())
    {
        tracing::warn!("DNS setup failed: {}", e);
    }

    // Shared routing table — used by TUN outbound, quic_server, relay_handler, and DNS.
    let mut peer_table = PeerTable::new();
    peer_table.bytes_rx = bytes_rx.clone();

    // Cancellation token — cancelled on shutdown to stop all spawned tasks and release resources.
    let cancel = tokio_util::sync::CancellationToken::new();

    // Create a shared QUIC endpoint for overlay server + signal client + direct peer connections.
    // A single UDP socket ensures signal sees the correct remote_address for srflx candidates.
    let (endpoint, overlay_port) = match create_shared_endpoint(&config.identity_dir) {
        Ok((ep, port)) => {
            tracing::info!("QUIC endpoint listening on port {}", port);
            super::quic_server::start(
                ep.clone(),
                device.clone(),
                peer_table.clone(),
                cancel.clone(),
            );
            (ep, port)
        }
        Err(e) => {
            tracing::error!("Failed to create QUIC endpoint: {} — cannot continue", e);
            return;
        }
    };

    // Spawn ONE signal session — it handles its own reconnection internally.
    // Pass the PeerTable so incoming relay streams can register routes.
    let session = signal_session::spawn(
        match config.signal_credentials() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to load identity: {}", e);
                return;
            }
        },
        endpoint.clone(),
        cancel.clone(),
        Some(device.clone()),
        peer_table.clone(),
        overlay_port,
        overlay_prefix_len,
    );
    let dns_config = super::overlay_dns::DnsConfig {
        bind_addr: dns_bind,
        zone: config.name.clone(),
        ttl: 60,
    };
    let dns_node_id = config.node_id.clone();
    let dns_table = peer_table.clone();
    let (dns_shutdown_tx, dns_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(e) = super::overlay_dns::run(
            dns_config,
            overlay_ip,
            dns_node_id,
            dns_table,
            dns_shutdown_rx,
        )
        .await
        {
            tracing::warn!("Overlay DNS server error: {}", e);
        }
    });

    // Background task: keep peer table in sync with signal session
    let sync_peers_rx = session.peers.clone();
    let sync_table = peer_table.clone();
    tokio::spawn(async move {
        let mut rx = sync_peers_rx;
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let peers = Arc::clone(&rx.borrow());
            sync_table.update_peers(peers).await;
        }
    });

    loop {
        let _ = state_tx.send(TunnelState::Connecting);
        if let Ok(mut i) = info.lock() {
            i.transport = None;
            i.connected_at = None;
        }

        let run_ctx = TunnelRunContext {
            config: &config,
            cancel: &cancel,
            endpoint: &endpoint,
            overlay_ip,
            device: &device,
            session: &session,
            peer_table: &peer_table,
            state_tx: &state_tx,
            info: &info,
            bytes_tx: &bytes_tx,
        };
        match establish_and_run(&run_ctx, &mut shutdown_rx).await {
            Ok(ShutdownReason::UserRequested) => {
                tracing::info!("Tunnel {} shut down by user", config.name);
                let _ = state_tx.send(TunnelState::Disconnected);
                break;
            }
            Ok(ShutdownReason::ConnectionLost(reason)) => {
                tracing::warn!(
                    "Tunnel {} connection lost: {}, reconnecting...",
                    config.name,
                    reason,
                );
                let _ = state_tx.send(TunnelState::Reconnecting);
                if let Ok(mut i) = info.lock() {
                    i.last_error = Some(reason);
                    i.transport = None;
                    i.connected_at = None;
                }
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                let err_msg = format!("{:#}", e);
                tracing::warn!(
                    "Tunnel {} failed: {}, reconnecting in {:?}",
                    config.name,
                    err_msg,
                    backoff
                );
                let _ = state_tx.send(TunnelState::Reconnecting);
                if let Ok(mut i) = info.lock() {
                    i.last_error = Some(err_msg);
                    i.transport = None;
                    i.connected_at = None;
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    let _ = state_tx.send(TunnelState::Disconnected);
                    break;
                }
            }
        }

        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    // Shutdown: cancel all tasks, close endpoint, cleanup DNS
    cancel.cancel();
    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    session.shutdown();
    let _ = dns_shutdown_tx.send(true);
    dns::remove_resolver(&config.name);
}

enum ShutdownReason {
    UserRequested,
    ConnectionLost(String),
}

const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_STAGGER: Duration = Duration::from_millis(100);

struct TunnelRunContext<'a> {
    config: &'a ClusterConfig,
    cancel: &'a tokio_util::sync::CancellationToken,
    endpoint: &'a quinn::Endpoint,
    overlay_ip: Ipv4Addr,
    device: &'a Arc<tun_rs::AsyncDevice>,
    session: &'a signal_session::SignalSessionHandle,
    peer_table: &'a PeerTable,
    state_tx: &'a watch::Sender<TunnelState>,
    info: &'a Arc<std::sync::Mutex<SharedInfo>>,
    bytes_tx: &'a Arc<AtomicU64>,
}

/// Wait for signal session to be ready, then run the multi-peer forwarding loop.
async fn establish_and_run(
    ctx: &TunnelRunContext<'_>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<ShutdownReason> {
    let config = ctx.config;
    let overlay_ip = ctx.overlay_ip;
    let device = ctx.device;
    let session = ctx.session;
    let peer_table = ctx.peer_table;
    let state_tx = ctx.state_tx;
    let info = ctx.info;
    let bytes_tx = ctx.bytes_tx;
    // Wait for signal session to be authenticated (overlay IP assigned)
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    let mut ip_rx = session.overlay_ip.clone();

    loop {
        if session.overlay_ip().is_some() {
            break;
        }
        tokio::select! {
            _ = &mut deadline => {
                anyhow::bail!("Timed out waiting for signal auth");
            }
            _ = ip_rx.changed() => {
                if session.overlay_ip().is_some() {
                    break;
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(ShutdownReason::UserRequested);
                }
            }
        }
    }

    let assigned_ip = session.overlay_ip().unwrap();
    tracing::info!(
        "Signal authenticated: overlay_ip={}, {} peer(s)",
        assigned_ip,
        session.peers().len()
    );

    let _ = state_tx.send(TunnelState::Connected);
    if let Ok(mut i) = info.lock() {
        i.transport = Some("mesh".to_string());
        i.connected_at = Some(Instant::now());
        i.last_error = None;
    }

    // Single TUN reader — routes packets via PeerTable
    let tun_device = device.clone();
    let tun_table = peer_table.clone();
    let tx_counter = bytes_tx.clone();
    let tun_outbound = tokio::spawn(async move {
        run_tun_outbound(&tun_device, &tun_table, overlay_ip, &tx_counter).await;
    });

    // Connection manager — watches peer list, establishes connections per peer
    let cm_session_peers = session.peers.clone();
    let cm_session_conn = session.connection.clone();
    let cm_cancel = ctx.cancel.clone();
    let cm_table = peer_table.clone();
    let cm_device = device.clone();
    let cm_node_id = config.node_id.clone();
    let cm_cluster_id = config.cluster_id.clone();
    let cm_identity_dir = config.identity_dir.clone();
    let cm_overlay_ip = overlay_ip;
    let cm_endpoint = ctx.endpoint.clone();
    let conn_manager = tokio::spawn(async move {
        let cm_ctx = ConnectionManagerContext {
            cancel: &cm_cancel,
            endpoint: &cm_endpoint,
            peer_table: &cm_table,
            device: &cm_device,
            overlay_ip: cm_overlay_ip,
            my_node_id: &cm_node_id,
            cluster_id: &cm_cluster_id,
            identity_dir: &cm_identity_dir,
        };
        run_connection_manager(cm_session_peers, cm_session_conn, &cm_ctx).await;
    });

    // Wait for shutdown or session death
    let reason = tokio::select! {
        _ = shutdown_rx.changed() => {
            if *shutdown_rx.borrow() {
                ShutdownReason::UserRequested
            } else {
                ShutdownReason::ConnectionLost("shutdown".into())
            }
        }
        _ = async {
            let mut peers_rx = session.peers.clone();
            loop {
                if peers_rx.changed().await.is_err() {
                    break;
                }
            }
        } => {
            ShutdownReason::ConnectionLost("signal session closed".into())
        }
    };

    tun_outbound.abort();
    conn_manager.abort();
    let _ = tun_outbound.await;
    let _ = conn_manager.await;

    Ok(reason)
}

/// Result of a successful candidate probe: connection + description of the winning candidate.
struct ProbeResult {
    conn: quinn::Connection,
    /// e.g. "host:192.168.1.73:47710"
    via: String,
}

/// Create a shared QUIC endpoint that serves as both overlay server and client
/// for signal + direct peer connections. A single UDP socket ensures signal
/// observes the correct remote_address for srflx candidates.
fn create_shared_endpoint(identity_dir: &std::path::Path) -> Result<(quinn::Endpoint, u16)> {
    let cert_pem =
        std::fs::read_to_string(identity_dir.join("cert.pem")).context("Missing identity cert")?;
    let key_pem =
        std::fs::read_to_string(identity_dir.join("key.pem")).context("Missing identity key")?;
    let cert_der = super::quic_server::pem_to_der(&cert_pem)?;
    let server_config = super::quic_server::build_server_config(&cert_der, &key_pem)?;

    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .context("Failed to bind QUIC endpoint")?;
    let port = endpoint.local_addr()?.port();

    Ok((endpoint, port))
}

/// Try direct QUIC connection to peer candidates (happy eyeballs).
async fn probe_candidates(
    endpoint: &quinn::Endpoint,
    candidates: &[Candidate],
    expected_fingerprint: &str,
    identity_dir: &std::path::Path,
) -> Result<ProbeResult> {
    use std::net::SocketAddr;
    use tokio::sync::oneshot;

    if candidates.is_empty() {
        anyhow::bail!("No candidates to probe");
    }

    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    let (winner_tx, winner_rx) = oneshot::channel::<ProbeResult>();
    let winner_tx = Arc::new(std::sync::Mutex::new(Some(winner_tx)));
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut handles = Vec::new();

    for (i, candidate) in sorted.iter().enumerate() {
        let addr_str = candidate.addr.clone();
        let kind = candidate.kind.clone();
        let fp = expected_fingerprint.to_string();
        let id_dir = identity_dir.to_path_buf();
        let ep = endpoint.clone();
        let tx = winner_tx.clone();
        let token = cancel.clone();

        let handle = tokio::spawn(async move {
            if i > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(PROBE_STAGGER * i as u32) => {}
                    _ = token.cancelled() => return,
                }
            }
            if token.is_cancelled() {
                return;
            }

            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => return,
            };

            tracing::debug!("Probing {} candidate {}", kind, addr);

            match connect_overlay_direct(&ep, addr, &fp, &id_dir).await {
                Ok(conn) => {
                    let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(sender) = guard.take() {
                        let via = format!("{}:{}", kind, addr);
                        let _ = sender.send(ProbeResult { conn, via });
                        token.cancel();
                    }
                }
                Err(e) => {
                    tracing::debug!("Candidate {} ({}) failed: {}", addr, kind, e);
                }
            }
        });
        handles.push(handle);
    }

    let result =
        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT + Duration::from_secs(1), winner_rx).await;

    cancel.cancel();
    for h in handles {
        h.abort();
    }

    match result {
        Ok(Ok(probe)) => Ok(probe),
        _ => anyhow::bail!("All candidates failed"),
    }
}

/// Connect directly to a peer via QUIC with fingerprint verification.
async fn connect_overlay_direct(
    endpoint: &quinn::Endpoint,
    addr: std::net::SocketAddr,
    expected_fingerprint: &str,
    identity_dir: &std::path::Path,
) -> Result<quinn::Connection> {
    let cert_pem = std::fs::read_to_string(identity_dir.join("cert.pem"))
        .context("Missing identity cert for overlay")?;
    let key_pem = std::fs::read_to_string(identity_dir.join("key.pem"))
        .context("Missing identity key for overlay")?;

    let cert_der = {
        use base64::Engine;
        let b64: String = cert_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .context("Invalid cert PEM")?
    };
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(expected_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_OVERLAY.to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30 * 60)).unwrap(),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));

    let sni = addr.ip().to_string();
    let conn = tokio::time::timeout(
        DIRECT_CONNECT_TIMEOUT,
        endpoint.connect_with(client_config, addr, &sni)?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timeout"))??;

    Ok(conn)
}

/// Single TUN reader — reads packets from the TUN device and routes them
/// to the correct peer via PeerTable lookup on destination IP.
async fn run_tun_outbound(
    device: &Arc<tun_rs::AsyncDevice>,
    peer_table: &PeerTable,
    overlay_ip: Ipv4Addr,
    bytes_tx: &AtomicU64,
) {
    let mut buf = vec![0u8; 65536];
    loop {
        match device.recv(&mut buf).await {
            Ok(n) if n >= 20 => {
                // Only route IPv4 packets
                if buf[0] >> 4 != 4 {
                    continue;
                }
                let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                if dst == overlay_ip {
                    continue;
                }
                let sent = peer_table.send_packet(dst, &buf[..n]).await;
                if sent {
                    bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    tracing::debug!("TUN outbound: {}B to {} dropped (no route)", n, dst);
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::task::yield_now().await;
            }
            Err(e) => {
                tracing::error!("TUN read error: {}", e);
                break;
            }
        }
    }
}

/// Watches the peer list from signal and manages per-peer connections.
/// For each peer: tries direct QUIC, falls back to relay, spawns inbound task.
struct ConnectionManagerContext<'a> {
    cancel: &'a tokio_util::sync::CancellationToken,
    endpoint: &'a quinn::Endpoint,
    peer_table: &'a PeerTable,
    device: &'a Arc<tun_rs::AsyncDevice>,
    overlay_ip: Ipv4Addr,
    my_node_id: &'a str,
    cluster_id: &'a str,
    identity_dir: &'a std::path::Path,
}

async fn run_connection_manager(
    mut peers_rx: watch::Receiver<Arc<Vec<PeerInfo>>>,
    conn_rx: watch::Receiver<Option<quinn::Connection>>,
    ctx: &ConnectionManagerContext<'_>,
) {
    use std::collections::HashMap;

    // Track active peer tasks and their overlay IPs for cleanup
    let mut active_peers: HashMap<String, (tokio::task::JoinHandle<()>, Ipv4Addr)> = HashMap::new();
    let mut signal_conn_rx = conn_rx.clone();
    signal_conn_rx.borrow_and_update();

    // Process current peer list, then react to changes
    loop {
        let peers = Arc::clone(&peers_rx.borrow_and_update());

        // Find peers that left — cancel their tasks and remove routes
        let current_ids: std::collections::HashSet<&str> = peers
            .iter()
            .filter(|p| p.node_id != ctx.my_node_id)
            .map(|p| p.node_id.as_str())
            .collect();

        let removed: Vec<String> = active_peers
            .keys()
            .filter(|id| !current_ids.contains(id.as_str()))
            .cloned()
            .collect();

        for node_id in removed {
            if let Some((handle, _ip)) = active_peers.remove(&node_id) {
                tracing::info!("Peer {} left, aborting connection task", node_id);
                handle.abort();
                // Don't remove the route here — the quic_server may have
                // inserted a newer direct route for this peer. Routes are
                // cleaned up when the actual QUIC connection closes (in
                // establish_peer_connection or quic_server::accept_loop).
            }
        }

        // Clean up finished tasks so they can be retried
        active_peers.retain(|node_id, (handle, _ip)| {
            if handle.is_finished() {
                tracing::debug!("Connection task for {} finished, will retry", node_id);
                false
            } else {
                true
            }
        });

        // Find peers that need connections (new or finished tasks to retry)
        for peer in peers.iter() {
            if peer.node_id == ctx.my_node_id || active_peers.contains_key(&peer.node_id) {
                continue;
            }

            let peer_ip: Ipv4Addr = match peer.overlay_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            // Skip if we already have a working route (e.g. from relay_handler or quic_server)
            if ctx.peer_table.has_route(peer_ip).await {
                continue;
            }

            // Spawn a task to establish connection to this peer
            let peer_info = peer.clone();
            let cancel = ctx.cancel.clone();
            let ep = ctx.endpoint.clone();
            let table = ctx.peer_table.clone();
            let dev = ctx.device.clone();
            let cid = ctx.cluster_id.to_string();
            let nid = ctx.my_node_id.to_string();
            let signal_conn = conn_rx.borrow().clone();
            let id_dir = ctx.identity_dir.to_path_buf();
            let overlay_ip = ctx.overlay_ip;

            let handle = tokio::spawn(async move {
                establish_peer_connection(PeerConnectionContext {
                    cancel,
                    endpoint: ep,
                    peer: peer_info,
                    peer_ip,
                    overlay_ip,
                    peer_table: table,
                    device: dev,
                    signal_conn,
                    cluster_id: cid,
                    my_node_id: nid,
                    identity_dir: id_dir,
                })
                .await;
            });

            active_peers.insert(peer.node_id.clone(), (handle, peer_ip));
        }

        // Wait for peer list change OR signal reconnection (new connection available)
        tokio::select! {
            result = peers_rx.changed() => {
                if result.is_err() { break; }
            }
            _ = signal_conn_rx.changed() => {
                // Signal reconnected — retry peers with finished tasks
                tracing::debug!("Signal connection changed, re-evaluating peer connections");
            }
            _ = ctx.cancel.cancelled() => { break; }
            // Periodically check for finished tasks to retry
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }

    // Clean up all active peer tasks
    for (_, (handle, _)) in active_peers {
        handle.abort();
    }
}

/// Establish a connection to a single peer: try direct, fallback to relay.
/// Runs until the connection drops.
/// Owned context for a peer connection task (must be Send + 'static for tokio::spawn).
struct PeerConnectionContext {
    cancel: tokio_util::sync::CancellationToken,
    endpoint: quinn::Endpoint,
    peer: PeerInfo,
    peer_ip: Ipv4Addr,
    overlay_ip: Ipv4Addr,
    peer_table: PeerTable,
    device: Arc<tun_rs::AsyncDevice>,
    signal_conn: Option<quinn::Connection>,
    cluster_id: String,
    my_node_id: String,
    identity_dir: std::path::PathBuf,
}

async fn establish_peer_connection(ctx: PeerConnectionContext) {
    let peer = &ctx.peer;
    let peer_ip = ctx.peer_ip;
    let overlay_ip = ctx.overlay_ip;
    let peer_table = &ctx.peer_table;
    let device = &ctx.device;
    let identity_dir = &ctx.identity_dir;
    let my_node_id = &ctx.my_node_id;
    // Try direct connection first if peer has candidates
    if !peer.candidates.is_empty() {
        let summary: Vec<String> = peer
            .candidates
            .iter()
            .map(|c| format!("{}:{}", c.kind, c.addr))
            .collect();
        tracing::info!(
            "Connecting to {} ({}) — candidates: [{}]",
            peer.node_id,
            peer_ip,
            summary.join(", ")
        );

        match probe_candidates(
            &ctx.endpoint,
            &peer.candidates,
            &peer.fingerprint,
            identity_dir,
        )
        .await
        {
            Ok(probe) => {
                tracing::info!(
                    "Direct connection to {} ({}) via {}",
                    peer.node_id,
                    peer_ip,
                    probe.via
                );
                let conn = probe.conn;
                peer_table.insert_direct(peer_ip, conn.clone()).await;

                // Run inbound task — reads from peer's QUIC streams, writes to TUN
                tokio::select! {
                    _ = spawn_peer_inbound(conn.clone(), device.clone(), peer_table.clone()) => {}
                    _ = ctx.cancel.cancelled() => {}
                }

                // Connection ended — remove route
                peer_table.remove_route(peer_ip).await;
                tracing::info!("Direct connection to {} ended", peer.node_id);
                return;
            }
            Err(e) => {
                tracing::debug!("Direct to {} failed: {}, trying relay", peer.node_id, e);
            }
        }
    }

    // Fallback: relay via signal
    // Tiebreaker: lower IP initiates the relay stream
    if overlay_ip > peer_ip {
        // We have higher IP — wait for the peer to initiate relay.
        // The relay_handler (via signal_session) will insert the route when
        // an incoming relay arrives.
        tracing::debug!(
            "Waiting for relay from {} (they have lower IP)",
            peer.node_id
        );
        return;
    }

    let signal_conn = match &ctx.signal_conn {
        Some(c) => c,
        None => {
            tracing::warn!("No signal connection for relay to {}", peer.node_id);
            return;
        }
    };

    match open_relay_to_peer(signal_conn, &ctx.cluster_id, my_node_id, &peer.node_id).await {
        Ok((send, recv)) => {
            // Load identity for TLS
            let identity = match mlsh_crypto::identity::load_or_generate(identity_dir, my_node_id) {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!("Failed to load identity for relay TLS: {}", e);
                    return;
                }
            };

            // Wrap relay in TLS (we are the initiator = TLS client)
            let tls_stream =
                match super::relay_tls::wrap_initiator(send, recv, &identity, &peer.fingerprint)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Relay TLS handshake to {} failed: {}", peer.node_id, e);
                        return;
                    }
                };

            tracing::info!("Relay to {} via signal (TLS E2E encrypted)", peer.node_id);

            let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

            let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            peer_table.insert_relay(peer_ip, outbound_tx).await;

            // Inbound: TLS → TUN
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

            // Outbound: channel → TLS
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
                _ = ctx.cancel.cancelled() => {}
            }

            if peer_table.remove_relay_only(peer_ip).await {
                tracing::info!("Relay to {} ended", peer.node_id);
            } else {
                tracing::debug!(
                    "Relay to {} ended, keeping active direct route",
                    peer.node_id
                );
            }
        }
        Err(e) => {
            tracing::warn!("Failed to open relay to {}: {}", peer.node_id, e);
        }
    }
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

/// Read packets from a peer's QUIC connection and write them to the TUN device.
/// Delegates to the shared `quic_server::run_inbound` implementation.
async fn spawn_peer_inbound(
    conn: quinn::Connection,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
) {
    super::quic_server::run_inbound(conn, &device, &peer_table).await;
}

/// Read packets from a relay stream and write them to the TUN device.
/// Parse a ClusterConfig from TOML contents and an identity directory.
/// Used by the daemon when receiving config from the CLI via Connect message.
pub fn parse_cluster_config(
    toml_contents: &str,
    identity_dir: &std::path::Path,
) -> Result<ClusterConfig> {
    let table: toml::Value = toml::from_str(toml_contents)?;
    parse_cluster_config_from_toml(&table, identity_dir)
}

/// Load cluster config from disk under the given base directory.
/// The base directory should contain `clusters/` and `identity/` subdirs.
pub fn load_cluster_config(name: &str, base_dir: &std::path::Path) -> Result<ClusterConfig> {
    let cluster_name = if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name).to_string()
    } else {
        name.to_string()
    };

    let cluster_file = base_dir
        .join("clusters")
        .join(format!("{}.toml", cluster_name));

    if !cluster_file.exists() {
        let clusters_dir = base_dir.join("clusters");
        let available = if clusters_dir.exists() {
            std::fs::read_dir(&clusters_dir)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| {
                            e.path()
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        if available.is_empty() {
            anyhow::bail!(
                "Cluster '{}' not found. No clusters configured.\n\
                 Run 'mlsh setup' to bootstrap or 'mlsh adopt <url>' to join.",
                cluster_name
            );
        } else {
            anyhow::bail!(
                "Cluster '{}' not found. Available clusters: {}",
                cluster_name,
                available
            );
        }
    }

    let contents = std::fs::read_to_string(&cluster_file)?;
    let identity_dir = base_dir.join("identity");
    parse_cluster_config(&contents, &identity_dir)
}

/// Parse a ClusterConfig from a TOML table and an identity directory.
fn parse_cluster_config_from_toml(
    table: &toml::Value,
    identity_dir: &std::path::Path,
) -> Result<ClusterConfig> {
    let cluster = table.get("cluster").context("Missing [cluster] section")?;

    let name = cluster
        .get("name")
        .and_then(|v| v.as_str())
        .context("Missing cluster.name")?
        .to_string();

    let signal_endpoint = cluster
        .get("signal_endpoint")
        .and_then(|v| v.as_str())
        .context("Missing cluster.signal_endpoint")?
        .to_string();

    let signal_fingerprint = cluster
        .get("signal_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let root_fingerprint = cluster
        .get("root_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let cluster_id = cluster
        .get("id")
        .and_then(|v| v.as_str())
        .context("Missing cluster.id")?
        .to_string();

    let node_auth = table
        .get("node_auth")
        .context("Missing [node_auth] section. Is this cluster configured with 'mlsh setup' (mode 2) or 'mlsh adopt'?")?;

    let node_id = node_auth
        .get("node_id")
        .and_then(|v| v.as_str())
        .context("Missing node_auth.node_id")?
        .to_string();

    let fingerprint = node_auth
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .context("Missing node_auth.fingerprint")?
        .to_string();

    let overlay_ip = table
        .get("overlay")
        .and_then(|o| o.get("ip"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let overlay_subnet = table
        .get("overlay")
        .and_then(|o| o.get("subnet"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Derive public_key from the node's identity certificate
    let public_key =
        if let Ok(identity) = mlsh_crypto::identity::load_or_generate(identity_dir, &node_id) {
            mlsh_crypto::invite::extract_public_key_from_cert_pem(&identity.cert_pem)
                .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
                .unwrap_or_default()
        } else {
            String::new()
        };

    Ok(ClusterConfig {
        name,
        signal_endpoint,
        signal_fingerprint,
        overlay_ip,
        overlay_subnet,
        cluster_id,
        node_id,
        fingerprint,
        public_key,
        root_fingerprint,
        identity_dir: identity_dir.to_path_buf(),
    })
}
