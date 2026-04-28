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
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::tund::control::protocol::{TunnelState, TunnelStatus};
use crate::tund::net::dns;
use crate::tund::overlay::peer_table::PeerTable;

use super::signal_session;
use crate::tund::control::session::ControlSession;

pub use super::cluster_config::{load_cluster_config, parse_cluster_config, ClusterConfig};

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Live status published by the tunnel task and observed by the manager.
#[derive(Clone, Default)]
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
    info_rx: watch::Receiver<SharedInfo>,
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
        let (info_tx, info_rx) = watch::channel(SharedInfo::default());

        let overlay_ip: Ipv4Addr = config
            .overlay_ip
            .as_deref()
            .unwrap_or("100.64.0.1")
            .parse()
            .context("Invalid overlay IP in cluster config")?;

        let config = Arc::new(config);
        let cluster_name = config.name.clone();
        let cluster_id = config.cluster_id.clone();

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
                info_tx,
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
            info_rx,
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
        let info = self.info_rx.borrow();
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
/// Long-running task that manages the tunnel lifecycle with reconnection.
#[allow(clippy::too_many_arguments)]
async fn tunnel_task(
    config: Arc<ClusterConfig>,
    overlay_ip: Ipv4Addr,
    state_tx: watch::Sender<TunnelState>,
    mut shutdown_rx: watch::Receiver<bool>,
    info: watch::Sender<SharedInfo>,
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
            info.send_modify(|i| i.last_error = Some(format!("TUN creation failed: {}", e)));
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
            crate::tund::overlay::quic::start(
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

    let fsm_registry = crate::tund::overlay::fsm::FsmRegistry::new();

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
    let dns_config = crate::tund::net::overlay_dns::DnsConfig {
        bind_addr: dns_bind,
        zone: config.name.clone(),
        ttl: 60,
    };
    let dns_node_id = config.node_id.clone();
    let dns_table = peer_table.clone();
    let dns_display_name = session.display_name.clone();
    let (dns_shutdown_tx, dns_shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if let Err(e) = crate::tund::net::overlay_dns::run(
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
        info.send_modify(|i| {
            i.transport = None;
            i.connected_at = None;
        });

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
                info.send_modify(|i| {
                    i.last_error = Some(reason);
                    i.transport = None;
                    i.connected_at = None;
                });
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
                info.send_modify(|i| {
                    i.last_error = Some(err_msg);
                    i.transport = None;
                    i.connected_at = None;
                });
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

use crate::tund::control::child::spawn_control_child;
use crate::tund::overlay::quic::create_shared_endpoint;
use crate::tund::overlay::supervisor::{run_connection_manager, ConnectionManagerContext};

struct TunnelRunContext<'a> {
    config: &'a Arc<ClusterConfig>,
    cancel: &'a tokio_util::sync::CancellationToken,
    endpoint: &'a quinn::Endpoint,
    overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
    device: &'a Arc<tun_rs::AsyncDevice>,
    session: &'a signal_session::SignalSessionHandle,
    peer_table: &'a PeerTable,
    state_tx: &'a watch::Sender<TunnelState>,
    info: &'a watch::Sender<SharedInfo>,
    bytes_tx: &'a Arc<AtomicU64>,
    fsm_registry: &'a crate::tund::overlay::fsm::FsmRegistry,
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
    info.send_modify(|i| {
        i.transport = Some("mesh".to_string());
        i.connected_at = Some(Instant::now());
        i.last_error = None;
    });

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
    let cm_config = config.clone();
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
            my_node_id: &cm_config.node_id,
            cluster_id: &cm_config.cluster_id,
            identity_dir: &cm_config.identity_dir,
            fsm_registry: &cm_fsm_registry,
        };
        run_connection_manager(cm_session_peers, cm_session_conn, &cm_ctx).await;
    });

    let _net_watcher = crate::tund::net::watcher::spawn(
        session.clone(),
        ctx.fsm_registry.clone(),
        ctx.endpoint.clone(),
        crate::tund::net::filter::OverlayNet::new(overlay_ip, ctx.overlay_prefix_len),
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
