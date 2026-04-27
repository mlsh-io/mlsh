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

use super::control_session::ControlSession;
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
    /// UUID assigned by signal at adopt/setup time.
    pub node_uuid: String,
    /// Human-readable display name for this node (defaults to node_uuid when absent).
    pub display_name: String,
    /// Legacy field kept for backward compatibility with existing TOML files.
    /// New files store `node_uuid` instead.
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    /// Root admin fingerprint for peer-side admission cert verification.
    pub root_fingerprint: String,
    /// Roles this node holds: `node` (always), optionally `admin` and `control`
    /// (ADR-030). When `control` is present, mlshtund forks `mlsh-control`.
    pub roles: Vec<String>,
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
            display_name: self.display_name.clone(),
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
    /// Cluster UUID — needed to build signal-facing messages (Revoke/Rename/
    /// Promote) that the daemon forwards on behalf of the CLI.
    pub cluster_id: String,
    state_rx: watch::Receiver<TunnelState>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    overlay_ip: Option<Ipv4Addr>,
    info: Arc<std::sync::Mutex<SharedInfo>>,
    /// Watch exposing the currently-active signal QUIC connection. Used by
    /// the ACME client to publish HTTP-01 challenge responses via signal.
    signal_conn_rx: Option<watch::Receiver<Option<quinn::Connection>>>,
    /// Forked `mlsh-control` child process, when this node holds the
    /// `control` role (ADR-030 §1).
    control_child: Option<tokio::process::Child>,
    control_session: ControlSession,
}

impl ManagedTunnel {
    /// Start a new tunnel for the given cluster.
    pub fn start(config: ClusterConfig) -> Result<Self> {
        let (state_tx, state_rx) = watch::channel(TunnelState::Connecting);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (signal_conn_tx, signal_conn_rx) = watch::channel(None::<quinn::Connection>);
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
        let cluster_id = config.cluster_id.clone();
        let info_task = info.clone();

        // Spawn mlsh-control if this node holds the `control` role.
        // The child runs as the current user with no extra privileges.
        // Lifecycle is tied to this ManagedTunnel — killed on stop().
        let control_child = if config.roles.iter().any(|r| r == "control") {
            spawn_control_child(&cluster_name)
        } else {
            None
        };

        // Build the mlsh-control session and warm it up so AdoptConfirm fires.
        let creds = config.signal_credentials()?;
        let control_socket = crate::control::stream::default_socket_path();
        let control_session = ControlSession::new(creds, control_socket)?;
        let warmup = control_session.clone();
        tokio::spawn(async move {
            if let Err(e) = warmup.ensure_connected().await {
                tracing::debug!(error = %e, "mlsh-control warmup failed (will retry on demand)");
            }
        });

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
                signal_conn_tx,
            )
            .await;
        });

        Ok(Self {
            cluster_name,
            cluster_id,
            state_rx,
            shutdown_tx,
            task: Some(task),
            bytes_tx,
            bytes_rx,
            overlay_ip: Some(overlay_ip),
            info,
            signal_conn_rx: Some(signal_conn_rx),
            control_child,
            control_session,
        })
    }

    /// Return the current signal QUIC connection, if one is active.
    pub fn signal_connection(&self) -> Option<quinn::Connection> {
        self.signal_conn_rx
            .as_ref()
            .and_then(|rx| rx.borrow().clone())
    }

    /// Whether the control-plane child process is currently running.
    pub fn has_control_child(&self) -> bool {
        self.control_child.is_some()
    }

    /// Clone of the persistent mlsh-control session handle.
    pub fn control_session(&self) -> ControlSession {
        self.control_session.clone()
    }

    /// Start the `mlsh-control` child process for this tunnel. No-op if
    /// already running.
    pub fn start_control(&mut self) {
        if self.control_child.is_some() {
            return;
        }
        self.control_child = spawn_control_child(&self.cluster_name);
    }

    /// Stop the `mlsh-control` child process for this tunnel. No-op if not
    /// running. Awaits the kill so the caller can be sure the port is
    /// released before returning.
    pub async fn stop_control(&mut self) {
        if let Some(mut child) = self.control_child.take() {
            tracing::info!("Stopping mlsh-control for '{}'", self.cluster_name);
            let _ = child.kill().await;
        }
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
        if let Some(mut child) = self.control_child.take() {
            tracing::info!("Stopping mlsh-control for '{}'", self.cluster_name);
            let _ = child.kill().await;
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

/// Spawn `mlsh-control` as a child process for the given cluster.
///
/// Re-execs the same binary with `MLSH_RUN_AS=control` (the binary's main
/// dispatch detects the env var and runs the control plane). Child runs as
/// the current user with no extra privileges (ADR-030 §1).
///
/// Returns `None` and logs a warning if spawning fails — the tunnel itself
/// continues to work, only the admin UI is unavailable.
fn spawn_control_child(cluster: &str) -> Option<tokio::process::Child> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "current_exe() failed; mlsh-control not spawned");
            return None;
        }
    };

    let mut cmd = tokio::process::Command::new(&exe);
    cmd.env("MLSH_RUN_AS", "control")
        .env("MLSH_CONTROL_CLUSTER", cluster)
        .kill_on_drop(true);

    match cmd.spawn() {
        Ok(child) => {
            tracing::info!(cluster, exe = %exe.display(), "mlsh-control forked");
            Some(child)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to spawn mlsh-control; admin UI unavailable");
            None
        }
    }
}

/// Long-running task that manages the tunnel lifecycle with reconnection.
#[allow(clippy::too_many_arguments)]
async fn tunnel_task(
    config: ClusterConfig,
    overlay_ip: Ipv4Addr,
    state_tx: watch::Sender<TunnelState>,
    mut shutdown_rx: watch::Receiver<bool>,
    info: Arc<std::sync::Mutex<SharedInfo>>,
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    signal_conn_tx: watch::Sender<Option<quinn::Connection>>,
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

    // Use /32 (point-to-point) on the TUN interface — like Tailscale.
    // The overlay subnet prefix is only used for candidate filtering & IP allocation,
    // not for the interface netmask. Per-peer /32 routes are added dynamically.
    let tun_prefix_len: u8 = 32;

    #[cfg(target_os = "linux")]
    let device = {
        tun_rs::DeviceBuilder::new()
            .name("mlsh0")
            .ipv4(overlay_ip.to_string(), tun_prefix_len, None)
            .mtu(1400)
            .build_async()
            .map(Arc::new)
    };
    #[cfg(not(target_os = "linux"))]
    let device = tun_rs::DeviceBuilder::new()
        .ipv4(overlay_ip.to_string(), tun_prefix_len, None)
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

    let tun_name = match device.name() {
        Ok(name) => {
            tracing::info!(
                "TUN device {} created for {} with overlay IP {}/32 (subnet {})",
                name,
                config.name,
                overlay_ip,
                overlay_prefix_len
            );
            name
        }
        Err(e) => {
            tracing::warn!("Could not get TUN device name: {}", e);
            #[cfg(target_os = "linux")]
            let fallback = "mlsh0".to_string();
            #[cfg(not(target_os = "linux"))]
            let fallback = "utun".to_string();
            fallback
        }
    };

    // DNS bind address: macOS uses localhost:53535, Linux uses overlay_ip:53.
    // macOS: packets to TUN IP aren't delivered to local listeners.
    // Linux: local delivery works, and resolvectl requires port 53.
    #[cfg(target_os = "macos")]
    let dns_bind =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53535);
    #[cfg(not(target_os = "macos"))]
    let dns_bind = std::net::SocketAddr::new(std::net::IpAddr::V4(overlay_ip), 53);

    // Install DNS resolver
    if let Err(e) = dns::install_resolver(
        &config.name,
        &dns_bind.ip().to_string(),
        dns_bind.port(),
        &config.node_uuid,
        &tun_name,
    ) {
        tracing::warn!("DNS setup failed: {}", e);
    }

    // Shared routing table — used by TUN outbound, quic_server, relay_handler, and DNS.
    let mut peer_table = PeerTable::with_tun_name(tun_name);
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

    let fsm_registry = super::peer_fsm::FsmRegistry::new();

    // Spawn ONE signal session — it handles its own reconnection internally.
    // Pass the PeerTable so incoming relay streams can register routes.
    let session = signal_session::spawn(signal_session::SpawnParams {
        creds: match config.signal_credentials() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to load identity: {}", e);
                return;
            }
        },
        endpoint: endpoint.clone(),
        cancel: cancel.clone(),
        tun_device: Some(device.clone()),
        peer_table: peer_table.clone(),
        overlay_port,
        overlay_prefix_len,
        initial_display_name: config.display_name.clone(),
        fsm_registry: fsm_registry.clone(),
    });
    let dns_config = super::overlay_dns::DnsConfig {
        bind_addr: dns_bind,
        zone: config.name.clone(),
        ttl: 60,
    };
    let dns_node_id = config.node_id.clone();
    let dns_table = peer_table.clone();
    let dns_display_name = session.display_name.clone();
    let (dns_shutdown_tx, dns_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(e) = super::overlay_dns::run(
            dns_config,
            overlay_ip,
            dns_node_id,
            dns_display_name,
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
        // Seed with the current value: borrow_and_update marks it as seen so
        // the next changed() awaits the *next* update — without this, an
        // initial peer list pushed before this task is scheduled is dropped.
        let initial = Arc::clone(&rx.borrow_and_update());
        sync_table.update_peers(initial).await;
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let peers = Arc::clone(&rx.borrow());
            sync_table.update_peers(peers).await;
        }
    });

    // Mirror the signal session's current QUIC connection into our own watch
    // so ACME (and future features) can piggyback control messages on the
    // existing authenticated channel.
    let signal_conn_in = session.connection.clone();
    let signal_conn_out = signal_conn_tx.clone();
    tokio::spawn(async move {
        let mut rx = signal_conn_in;
        loop {
            let _ = signal_conn_out.send(rx.borrow().clone());
            if rx.changed().await.is_err() {
                break;
            }
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
            overlay_prefix_len,
            device: &device,
            session: &session,
            peer_table: &peer_table,
            state_tx: &state_tx,
            info: &info,
            bytes_tx: &bytes_tx,
            fsm_registry: &fsm_registry,
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
const RELAY_GRACE: Duration = Duration::from_millis(200);
/// How often a peer on relay re-attempts a direct probe in the background.
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(60);

struct TunnelRunContext<'a> {
    config: &'a ClusterConfig,
    cancel: &'a tokio_util::sync::CancellationToken,
    endpoint: &'a quinn::Endpoint,
    overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
    device: &'a Arc<tun_rs::AsyncDevice>,
    session: &'a signal_session::SignalSessionHandle,
    peer_table: &'a PeerTable,
    state_tx: &'a watch::Sender<TunnelState>,
    info: &'a Arc<std::sync::Mutex<SharedInfo>>,
    bytes_tx: &'a Arc<AtomicU64>,
    fsm_registry: &'a super::peer_fsm::FsmRegistry,
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
    let cm_fsm_registry = ctx.fsm_registry.clone();
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
            fsm_registry: &cm_fsm_registry,
        };
        run_connection_manager(cm_session_peers, cm_session_conn, &cm_ctx).await;
    });

    let _net_watcher = super::net_watcher::spawn(
        session.clone(),
        ctx.fsm_registry.clone(),
        ctx.endpoint.clone(),
        super::net_filter::OverlayNet::new(overlay_ip, ctx.overlay_prefix_len),
        ctx.cancel.clone(),
    );

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
    fsm_registry: &'a super::peer_fsm::FsmRegistry,
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

            let fsm_registry = ctx.fsm_registry.clone();
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
                    fsm_registry,
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
                // Signal reconnected. Peer tasks captured the old signal_conn
                // at spawn time; abort them so the next iteration respawns
                // them with the fresh connection. Routes they installed are
                // cleaned up as part of their Cancelled transition.
                tracing::debug!("Signal connection changed, aborting peer tasks");
                for (node_id, (handle, ip)) in active_peers.drain() {
                    handle.abort();
                    ctx.peer_table.remove_route(ip).await;
                    ctx.fsm_registry.unregister(ip).await;
                    tracing::debug!("Aborted peer task for {node_id}");
                }
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
    fsm_registry: super::peer_fsm::FsmRegistry,
}

/// Drives the peer FSM in [`super::peer_fsm`]: executes effects as spawned
/// tasks and feeds their outcomes back as events.
async fn establish_peer_connection(ctx: PeerConnectionContext) {
    use super::peer_fsm::{initial_effects, transition, Effect, Event, State};

    let peer_ip = ctx.peer_ip;
    let is_initiator = ctx.overlay_ip < peer_ip;

    if !ctx.peer.candidates.is_empty() {
        let summary: Vec<String> = ctx
            .peer
            .candidates
            .iter()
            .map(|c| format!("{}:{}", c.kind, c.addr))
            .collect();
        tracing::info!(
            "Connecting to {} ({}) — candidates: [{}]",
            ctx.peer.node_id,
            peer_ip,
            summary.join(", ")
        );
    }

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    ctx.fsm_registry.register(peer_ip, events_tx.clone()).await;

    let mut pending_direct_conn: Option<quinn::Connection> = None;
    let mut pending_relay_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>> = None;

    let mut probe_cancel = tokio_util::sync::CancellationToken::new();
    let mut relay_cancel = tokio_util::sync::CancellationToken::new();
    let mut direct_lifecycle: Option<tokio::task::JoinHandle<()>> = None;

    let probe_retry_ticker = {
        let ev = events_tx.clone();
        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROBE_RETRY_INTERVAL);
            interval.tick().await; // skip the immediate first tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if ev.send(Event::ProbeRetryTick).is_err() {
                            break;
                        }
                    }
                    _ = cancel.cancelled() => break,
                }
            }
        })
    };

    let mut state = State::Probing;
    let mut effects_to_run = initial_effects(is_initiator);

    'outer: loop {
        for effect in effects_to_run.drain(..) {
            match effect {
                Effect::SpawnProbe => {
                    if ctx.peer.candidates.is_empty() {
                        let _ = events_tx.send(Event::ProbeFailed);
                        continue;
                    }
                    probe_cancel = tokio_util::sync::CancellationToken::new();
                    let endpoint = ctx.endpoint.clone();
                    let candidates = ctx.peer.candidates.clone();
                    let fp = ctx.peer.fingerprint.clone();
                    let id_dir = ctx.identity_dir.clone();
                    let ev = events_tx.clone();
                    let cancel = probe_cancel.clone();
                    let peer_ip_copy = peer_ip;
                    let peer_node_id = ctx.peer.node_id.clone();
                    tokio::spawn(async move {
                        let result = tokio::select! {
                            r = probe_candidates(&endpoint, &candidates, &fp, &id_dir) => r,
                            _ = cancel.cancelled() => return,
                        };
                        match result {
                            Ok(probe) => {
                                tracing::info!(
                                    "Direct connection to {} ({}) via {}",
                                    peer_node_id,
                                    peer_ip_copy,
                                    probe.via
                                );
                                let _ = ev.send(Event::__ProbeSucceededWith(Box::new(probe.conn)));
                            }
                            Err(e) => {
                                tracing::debug!("Direct to {} failed: {}", peer_node_id, e);
                                let _ = ev.send(Event::ProbeFailed);
                            }
                        }
                    });
                }

                Effect::StartRelayGraceTimer => {
                    let ev = events_tx.clone();
                    let cancel = ctx.cancel.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = tokio::time::sleep(RELAY_GRACE) => {
                                let _ = ev.send(Event::RelayGraceElapsed);
                            }
                            _ = cancel.cancelled() => {}
                        }
                    });
                }

                Effect::InitiateRelay => {
                    let Some(signal_conn) = ctx.signal_conn.clone() else {
                        tracing::warn!("No signal connection for relay to {}", ctx.peer.node_id);
                        continue;
                    };
                    relay_cancel = tokio_util::sync::CancellationToken::new();
                    let r = RelayInitiator {
                        signal_conn,
                        cluster_id: ctx.cluster_id.clone(),
                        my_node_id: ctx.my_node_id.clone(),
                        peer_node_id: ctx.peer.node_id.clone(),
                        peer_fingerprint: ctx.peer.fingerprint.clone(),
                        identity_dir: ctx.identity_dir.clone(),
                        device: ctx.device.clone(),
                        peer_table: ctx.peer_table.clone(),
                        events_tx: events_tx.clone(),
                        cancel: relay_cancel.clone(),
                    };
                    tokio::spawn(async move {
                        run_relay_initiator(r).await;
                    });
                }

                Effect::InsertDirectRoute => {
                    if let Some(conn) = pending_direct_conn.take() {
                        ctx.peer_table.insert_direct(peer_ip, conn.clone()).await;
                        let dev = ctx.device.clone();
                        let pt = ctx.peer_table.clone();
                        let cancel = ctx.cancel.clone();
                        let ev = events_tx.clone();
                        direct_lifecycle = Some(tokio::spawn(async move {
                            tokio::select! {
                                _ = spawn_peer_inbound(conn, dev, pt) => {}
                                _ = cancel.cancelled() => {}
                            }
                            let _ = ev.send(Event::DirectConnectionLost);
                        }));
                    }
                }

                Effect::InsertRelayRoute => {
                    if let Some(tx) = pending_relay_tx.take() {
                        ctx.peer_table.insert_relay(peer_ip, tx).await;
                    }
                }

                Effect::RemoveRoute => {
                    ctx.peer_table.remove_route(peer_ip).await;
                }

                Effect::RemoveRelayOnly => {
                    if ctx.peer_table.remove_relay_only(peer_ip).await {
                        tracing::info!("Relay to {} ended", ctx.peer.node_id);
                    } else {
                        tracing::debug!(
                            "Relay to {} ended, keeping active direct route",
                            ctx.peer.node_id
                        );
                    }
                }

                Effect::AbortRelayTask => relay_cancel.cancel(),
                Effect::AbortProbeTask => probe_cancel.cancel(),
                Effect::LogDirect => {} // already logged when the probe succeeded
                Effect::LogRelay => {}  // logged by run_relay_initiator
            }
        }

        if state == State::Done {
            break 'outer;
        }

        let event = tokio::select! {
            maybe = events_rx.recv() => match maybe {
                Some(e) => e,
                None => break 'outer,
            },
            _ = ctx.cancel.cancelled() => Event::Cancelled,
        };

        // Carrier variants hand runtime handles to the driver, then the
        // pure equivalent is passed to `transition`.
        let fsm_event = match event {
            Event::__ProbeSucceededWith(conn) => {
                pending_direct_conn = Some(*conn);
                Event::ProbeSucceeded
            }
            Event::__RelayReadyWith(tx) => {
                pending_relay_tx = Some(*tx);
                Event::RelayReady
            }
            other => other,
        };

        let (new_state, new_effects) = transition(state, fsm_event, is_initiator);
        state = new_state;
        effects_to_run = new_effects;
    }

    probe_cancel.cancel();
    relay_cancel.cancel();
    probe_retry_ticker.abort();
    if let Some(h) = direct_lifecycle {
        h.abort();
    }
    ctx.fsm_registry.unregister(peer_ip).await;
}

struct RelayInitiator {
    signal_conn: quinn::Connection,
    cluster_id: String,
    my_node_id: String,
    peer_node_id: String,
    peer_fingerprint: String,
    identity_dir: std::path::PathBuf,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
    events_tx: tokio::sync::mpsc::UnboundedSender<super::peer_fsm::Event>,
    cancel: tokio_util::sync::CancellationToken,
}

/// Opens a relay stream through signal, wraps it in TLS, and runs the I/O
/// tasks. Emits `__RelayReadyWith` once up and `RelayClosed` on exit.
async fn run_relay_initiator(r: RelayInitiator) {
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

    // Accept both `node_uuid` (new) and `node_id` (legacy) for backward compatibility.
    let node_uuid = node_auth
        .get("node_uuid")
        .and_then(|v| v.as_str())
        .or_else(|| node_auth.get("node_id").and_then(|v| v.as_str()))
        .context("Missing node_auth.node_uuid (or legacy node_auth.node_id)")?
        .to_string();

    // display_name falls back to node_uuid when absent (pre-rename TOML files).
    let display_name = node_auth
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&node_uuid)
        .to_string();

    // Keep node_id as an alias pointing at node_uuid for code that hasn't migrated yet.
    let node_id = node_uuid.clone();

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

    // Roles default to ["node"] when absent (legacy configs).
    let roles: Vec<String> = node_auth
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["node".to_string()]);

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
        node_uuid,
        display_name,
        node_id,
        fingerprint,
        public_key,
        root_fingerprint,
        roles,
        identity_dir: identity_dir.to_path_buf(),
    })
}
