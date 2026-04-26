//! Persistent QUIC session to mlsh-signal.
//!
//! Maintains a long-lived connection to signal, authenticates via mTLS client
//! certificate, receives peer list updates (PeerJoined/PeerLeft), and reports
//! host candidates. Reconnects automatically on disconnection.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;

use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use mlsh_protocol::types::{Candidate, PeerInfo};

const PING_INTERVAL: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_INITIAL: Duration = Duration::from_millis(200);
const RECONNECT_MAX: Duration = Duration::from_secs(10);
const RECONNECT_JITTER: Duration = Duration::from_millis(100);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Credentials for connecting to signal.
#[derive(Clone)]
pub struct SignalCredentials {
    pub signal_endpoint: String,
    pub signal_fingerprint: String,
    pub cluster_id: String,
    pub node_id: String,
    pub display_name: String,
    pub fingerprint: String,
    pub public_key: String,
    /// PEM-encoded client certificate (for mTLS auth to signal).
    pub cert_pem: String,
    /// PEM-encoded private key (for mTLS auth to signal).
    pub key_pem: String,
    /// Root admin fingerprint for admission cert verification.
    pub root_fingerprint: String,
}

/// Handle to a running signal session. Provides reactive access to
/// overlay IP and peer list via watch channels.
#[derive(Clone)]
pub struct SignalSessionHandle {
    pub overlay_ip: watch::Receiver<Option<Ipv4Addr>>,
    pub peers: watch::Receiver<Arc<Vec<PeerInfo>>>,
    pub connection: watch::Receiver<Option<quinn::Connection>>,
    pub display_name: watch::Receiver<String>,
    shutdown_tx: watch::Sender<bool>,
    kick_tx: watch::Sender<u64>,
    candidates_port_tx: watch::Sender<u16>,
}

impl SignalSessionHandle {
    /// Get the current overlay IP (blocks until assigned by signal).
    pub fn overlay_ip(&self) -> Option<Ipv4Addr> {
        *self.overlay_ip.borrow()
    }

    /// Get the current peer list (cheap Arc clone).
    pub fn peers(&self) -> Arc<Vec<PeerInfo>> {
        Arc::clone(&self.peers.borrow())
    }

    /// Get the signal QUIC connection (for opening relay streams).
    pub fn connection(&self) -> Option<quinn::Connection> {
        self.connection.borrow().clone()
    }

    /// Signal the session to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Drop the current connection (if any) and reconnect immediately,
    /// skipping any remaining backoff.
    pub fn kick_reconnect(&self) {
        self.kick_tx.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Re-gather host candidates for the given QUIC port and push them to
    /// signal on the existing session stream. Used after path migration when
    /// our local port has changed.
    pub fn report_candidates(&self, quic_port: u16) {
        self.candidates_port_tx.send_modify(|v| *v = quic_port);
    }
}

/// Shared state for the signal session loop.
struct SessionContext {
    creds: SignalCredentials,
    endpoint: quinn::Endpoint,
    cancel: tokio_util::sync::CancellationToken,
    ip_tx: watch::Sender<Option<Ipv4Addr>>,
    peers_tx: watch::Sender<Arc<Vec<PeerInfo>>>,
    conn_tx: watch::Sender<Option<quinn::Connection>>,
    display_name_tx: watch::Sender<String>,
    my_node_id: String,
    tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: super::peer_table::PeerTable,
    overlay_port: u16,
    overlay_prefix_len: u8,
    /// Built once per session handle so TLS session tickets survive reconnects.
    client_config: quinn::ClientConfig,
    fsm_registry: super::peer_fsm::FsmRegistry,
    kick_rx: watch::Receiver<u64>,
    /// When changed, the session re-gathers host candidates using this port
    /// and sends a fresh `ReportCandidates` on the existing stream. Used
    /// after a path-migration rebind.
    candidates_port_rx: watch::Receiver<u16>,
    /// Last resolved signal address. Used as a warm fallback when the system
    /// resolver is temporarily unresponsive (e.g. just after a wake).
    last_resolved_addr: Option<SocketAddr>,
}

pub struct SpawnParams {
    pub creds: SignalCredentials,
    pub endpoint: quinn::Endpoint,
    pub cancel: tokio_util::sync::CancellationToken,
    /// If provided, incoming relay bi-streams from signal are accepted and
    /// forwarded via the shared `peer_table`.
    pub tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    pub peer_table: super::peer_table::PeerTable,
    pub overlay_port: u16,
    pub overlay_prefix_len: u8,
    pub initial_display_name: String,
    pub fsm_registry: super::peer_fsm::FsmRegistry,
}

/// Spawn a persistent signal session as a background task.
pub fn spawn(params: SpawnParams) -> SignalSessionHandle {
    let (ip_tx, ip_rx) = watch::channel(None);
    let (peers_tx, peers_rx) = watch::channel(Arc::new(Vec::new()));
    let (conn_tx, conn_rx) = watch::channel(None);
    let (display_name_tx, display_name_rx) = watch::channel(params.initial_display_name);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (kick_tx, kick_rx) = watch::channel::<u64>(0);
    let (candidates_port_tx, candidates_port_rx) = watch::channel::<u16>(params.overlay_port);

    let my_node_id = params.creds.node_id.clone();
    let client_config = match build_client_config(&params.creds) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!("Failed to build signal client config: {e:#}");
            return SignalSessionHandle {
                overlay_ip: ip_rx,
                peers: peers_rx,
                connection: conn_rx,
                display_name: display_name_rx,
                shutdown_tx,
                kick_tx,
                candidates_port_tx,
            };
        }
    };
    let ctx = SessionContext {
        creds: params.creds,
        endpoint: params.endpoint,
        cancel: params.cancel,
        ip_tx,
        peers_tx,
        conn_tx,
        display_name_tx,
        my_node_id,
        tun_device: params.tun_device,
        peer_table: params.peer_table,
        overlay_port: params.overlay_port,
        overlay_prefix_len: params.overlay_prefix_len,
        client_config,
        fsm_registry: params.fsm_registry,
        kick_rx,
        candidates_port_rx,
        last_resolved_addr: None,
    };

    tokio::spawn(session_loop(ctx, shutdown_rx));

    SignalSessionHandle {
        overlay_ip: ip_rx,
        peers: peers_rx,
        connection: conn_rx,
        display_name: display_name_rx,
        shutdown_tx,
        kick_tx,
        candidates_port_tx,
    }
}

async fn session_loop(mut ctx: SessionContext, mut shutdown_rx: watch::Receiver<bool>) {
    shutdown_rx.borrow_and_update();
    ctx.kick_rx.borrow_and_update();

    let mut error_backoff = RECONNECT_INITIAL;

    loop {
        let delay = match run_session(&mut ctx, &mut shutdown_rx).await {
            Ok(true) => {
                tracing::info!("Signal session shut down by user");
                break;
            }
            Ok(false) => {
                error_backoff = RECONNECT_INITIAL;
                let jitter = rand_jitter(RECONNECT_JITTER);
                tracing::info!("Signal session closed, reconnecting in {jitter:?}");
                jitter
            }
            Err(e) => {
                let d = error_backoff;
                tracing::warn!("Signal session error: {e:#}, reconnecting in {d:?}");
                error_backoff = (error_backoff.saturating_mul(2)).min(RECONNECT_MAX);
                d
            }
        };

        if delay.is_zero() {
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
            _ = ctx.kick_rx.changed() => {
                tracing::debug!("Reconnect backoff interrupted by kick");
            }
        }
    }
}

fn rand_jitter(max: Duration) -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let factor = 0.5 + (nanos as f64 / u32::MAX as f64) * 0.5;
    Duration::from_secs_f64(max.as_secs_f64() * factor)
}

/// Run a single session. Returns Ok(true) if user requested shutdown,
/// Ok(false) if connection was lost, Err on failure.
async fn run_session(
    ctx: &mut SessionContext,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<bool> {
    let creds = &ctx.creds;
    let ip_tx = &ctx.ip_tx;
    let peers_tx = &ctx.peers_tx;
    let conn_tx = &ctx.conn_tx;
    let tun_device = &ctx.tun_device;
    let peer_table = &ctx.peer_table;
    let overlay_port = ctx.overlay_port;
    let overlay_prefix_len = ctx.overlay_prefix_len;

    let addr = match resolve_addr(&creds.signal_endpoint).await {
        Ok(a) => a,
        Err(e) => match ctx.last_resolved_addr {
            Some(a) => {
                tracing::warn!("DNS failed ({e:#}), retrying with cached {a}");
                a
            }
            None => return Err(e),
        },
    };
    let conn = connect_to_signal(
        &ctx.endpoint,
        ctx.client_config.clone(),
        addr,
        &creds.signal_endpoint,
    )
    .await?;
    ctx.last_resolved_addr = Some(addr);

    // Expose connection to the tunnel for relay/direct streams
    let _ = conn_tx.send(Some(conn.clone()));

    tracing::info!("Connected to signal at {}", creds.signal_endpoint);

    // Open session stream and authenticate
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    // Send NodeAuth — identity is proven by the TLS client certificate;
    // signal extracts the fingerprint from the QUIC handshake.
    let auth_msg = StreamMessage::NodeAuth {
        cluster_id: creds.cluster_id.clone(),
        public_key: creds.public_key.clone(),
    };
    framing::write_msg(&mut send, &auth_msg).await?;

    // Read response
    let resp: ServerMessage = framing::read_msg(&mut recv).await?;

    let (overlay_ip, initial_peers) = match resp {
        ServerMessage::Error { code, message } => {
            anyhow::bail!("Signal auth failed ({}): {}", code, message);
        }
        ServerMessage::NodeAuthOk {
            overlay_ip, peers, ..
        } => {
            let ip: Ipv4Addr = overlay_ip.parse().context("Invalid overlay IP")?;
            (ip, peers)
        }
        other => {
            anyhow::bail!("Unexpected signal response: {:?}", other);
        }
    };
    let _ = ip_tx.send(Some(overlay_ip));
    let _ = peers_tx.send(Arc::new(initial_peers));

    tracing::info!(
        "Signal authenticated: overlay_ip={}, peers={}",
        overlay_ip,
        peers_tx.borrow().len()
    );

    // Report host candidates
    let candidates = gather_host_candidates(overlay_port, overlay_ip, overlay_prefix_len);
    if !candidates.is_empty() {
        let report = StreamMessage::ReportCandidates {
            candidates: candidates.clone(),
        };
        framing::write_msg(&mut send, &report).await?;
        tracing::info!("Reported {} host candidate(s)", candidates.len());
    }

    // Message loop — also accept incoming bi-streams (relay from signal)
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut last_ping = std::time::Instant::now();
    let conn_for_accept = conn.clone();

    ctx.kick_rx.borrow_and_update();
    ctx.candidates_port_rx.borrow_and_update();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    conn.close(quinn::VarInt::from_u32(0), b"shutdown");
                    return Ok(true);
                }
            }
            reason = conn.closed() => {
                tracing::warn!("Signal connection lost: {}", reason);
                return Ok(false);
            }
            _ = ctx.candidates_port_rx.changed() => {
                let port = *ctx.candidates_port_rx.borrow();
                let candidates = gather_host_candidates(port, overlay_ip, overlay_prefix_len);
                if !candidates.is_empty() {
                    let report = StreamMessage::ReportCandidates {
                        candidates: candidates.clone(),
                    };
                    if let Err(e) = framing::write_msg(&mut send, &report).await {
                        tracing::warn!("Failed to re-report candidates: {e:#}");
                    } else {
                        tracing::info!(
                            "Re-reporting {} host candidate(s) after migration",
                            candidates.len()
                        );
                    }
                }
            }
            _ = ctx.kick_rx.changed() => {
                tracing::info!("Signal session kicked; forcing reconnect");
                conn.close(quinn::VarInt::from_u32(0), b"kick-reconnect");
                return Ok(false);
            }
            // Accept incoming bi-streams from signal.
            // First RelayMessage discriminates:
            //   - RelayIncoming   → overlay relay (TLS-wrapped E2E)
            //   - IngressForward  → public ingress for a domain
            stream = conn_for_accept.accept_bi() => {
                match stream {
                    Ok((mut relay_send, mut relay_recv)) => {
                        let relay_cancel = ctx.cancel.clone();
                        let tun_device_for_task = tun_device.clone();
                        let peer_table_for_task = peer_table.clone();
                        let fsm_registry_for_task = ctx.fsm_registry.clone();
                        let relay_identity = mlsh_crypto::identity::NodeIdentity {
                            cert_der: vec![],
                            cert_pem: creds.cert_pem.clone(),
                            key_pem: creds.key_pem.clone(),
                            fingerprint: creds.fingerprint.clone(),
                        };
                        tokio::spawn(async move {
                            let header: mlsh_protocol::messages::RelayMessage =
                                match framing::read_msg(&mut relay_recv).await {
                                    Ok(m) => m,
                                    Err(e) => {
                                        tracing::debug!("Incoming bi-stream header read failed: {}", e);
                                        return;
                                    }
                                };
                            match header {
                                mlsh_protocol::messages::RelayMessage::RelayIncoming { from_node_id } => {
                                    let Some(dev) = tun_device_for_task else {
                                        tracing::warn!("Relay stream received but no TUN device available");
                                        return;
                                    };
                                    tokio::select! {
                                        result = super::relay_handler::handle_incoming_relay(
                                            super::relay_handler::IncomingRelay {
                                                send: relay_send,
                                                recv: relay_recv,
                                                device: dev,
                                                peer_table: peer_table_for_task,
                                                identity: relay_identity,
                                                from_node_id,
                                                fsm_registry: fsm_registry_for_task,
                                            },
                                        ) => {
                                            if let Err(e) = result {
                                                tracing::debug!("Incoming relay error: {}", e);
                                            }
                                        }
                                        _ = relay_cancel.cancelled() => {}
                                    }
                                }
                                mlsh_protocol::messages::RelayMessage::IngressForward { domain, client_ip } => {
                                    // Acknowledge and splice to local upstream.
                                    if let Err(e) = framing::write_msg(
                                        &mut relay_send,
                                        &mlsh_protocol::messages::RelayMessage::IngressAccepted,
                                    )
                                    .await
                                    {
                                        tracing::debug!("Ingress accept write failed: {}", e);
                                        return;
                                    }
                                    tokio::select! {
                                        result = super::ingress::handle_ingress_stream(
                                            relay_send, relay_recv, domain.clone(), client_ip,
                                        ) => {
                                            if let Err(e) = result {
                                                tracing::debug!(%domain, "Ingress stream error: {}", e);
                                            }
                                        }
                                        _ = relay_cancel.cancelled() => {}
                                    }
                                }
                                other => {
                                    tracing::debug!("Unexpected RelayMessage on incoming bi-stream: {:?}", other);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Accept bi-stream error: {}", e);
                        return Ok(false);
                    }
                }
            }
            msg = framing::read_msg_opt::<ServerMessage>(&mut recv) => {
                match msg {
                    Ok(Some(msg)) => {
                        handle_push_message(&msg, peers_tx, &ctx.display_name_tx, &ctx.my_node_id, &creds.root_fingerprint);
                    }
                    Ok(None) => {
                        tracing::info!("Signal stream closed");
                        return Ok(false);
                    }
                    Err(e) => {
                        tracing::warn!("Signal read error: {}", e);
                        return Ok(false);
                    }
                }
            }
            _ = ping_interval.tick() => {
                let elapsed = last_ping.elapsed();
                last_ping = std::time::Instant::now();

                // If a 15s tick took >45s, system likely slept — reconnect
                if elapsed > Duration::from_secs(45) {
                    tracing::warn!(
                        "Detected system sleep (ping drift: {:.0}s) — forcing reconnection",
                        elapsed.as_secs_f64()
                    );
                    conn.close(quinn::VarInt::from_u32(1), b"sleep-detected");
                    return Ok(false);
                }

                if framing::write_msg(&mut send, &StreamMessage::Ping).await.is_err() {
                    return Ok(false);
                }
            }
        }
    }
}

/// Verify a peer's admission certificate before accepting it into the peer list.
///
/// Returns `true` if the cert is valid, `false` if it should be rejected.
/// Signal stripped admission-cert storage in ADR-030 (the field is empty
/// from the wire); when admission certs are reintroduced via the daemon
/// path, this function does the verification.
fn verify_admission(
    peer: &PeerInfo,
    peers_tx: &watch::Sender<Arc<Vec<PeerInfo>>>,
    root_fingerprint: &str,
) -> bool {
    if peer.admission_cert.is_empty() {
        return true;
    }

    let cert: mlsh_crypto::invite::AdmissionCert = match serde_json::from_str(&peer.admission_cert)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Peer {} has malformed admission cert: {}", peer.node_id, e);
            return false;
        }
    };

    // Verify fingerprint in cert matches the peer's fingerprint
    if cert.fingerprint != peer.fingerprint {
        tracing::warn!(
            "Peer {} admission cert fingerprint mismatch (cert={}, peer={})",
            peer.node_id,
            &cert.fingerprint[..16.min(cert.fingerprint.len())],
            &peer.fingerprint[..16.min(peer.fingerprint.len())],
        );
        return false;
    }

    if cert.sponsor_node_uuid == cert.node_id {
        // Self-signed — must be the root admin
        if root_fingerprint.is_empty() {
            tracing::warn!(
                "Cannot verify root admin {} — no root_fingerprint in config",
                peer.node_id
            );
            return true; // accept if we don't have root_fingerprint yet
        }
        // Find the peer's public key to verify the signature
        // For self-signed certs, the root_fingerprint check is sufficient:
        // the root fingerprint was pinned at setup/adopt time from a trusted
        // source (setup token or signed invite), outside signal's control.
        if cert.fingerprint == root_fingerprint {
            return true;
        }
        tracing::warn!(
            "Peer {} claims to be root admin but fingerprint doesn't match root_fingerprint",
            peer.node_id,
        );
        return false;
    }

    // Sponsored cert — verify the invite signature against the sponsor's public key
    let peers = peers_tx.borrow();
    let sponsor = peers.iter().find(|p| p.node_id == cert.sponsor_node_uuid);
    match sponsor {
        Some(sponsor_peer) if !sponsor_peer.public_key.is_empty() => {
            let pubkey_bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                &sponsor_peer.public_key,
            ) {
                Ok(b) => b,
                Err(_) => {
                    tracing::warn!(
                        "Sponsor {} has invalid public key encoding",
                        cert.sponsor_node_uuid
                    );
                    return false;
                }
            };
            match mlsh_crypto::invite::verify_sponsored_admission_cert(&cert, &pubkey_bytes) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(
                        "Peer {} admission cert failed verification: {}",
                        peer.node_id,
                        e,
                    );
                    false
                }
            }
        }
        Some(_) => {
            // Sponsor known but has no public key — accept with warning
            tracing::warn!(
                "Peer {} sponsor {} has no public key — cannot verify admission cert",
                peer.node_id,
                cert.sponsor_node_uuid,
            );
            true
        }
        None => {
            // Sponsor not in our peer list yet — can happen if peers arrive out of order.
            tracing::debug!(
                "Peer {} sponsor {} not yet known — accepting provisionally",
                peer.node_id,
                cert.sponsor_node_uuid,
            );
            true
        }
    }
}

fn handle_push_message(
    msg: &ServerMessage,
    peers_tx: &watch::Sender<Arc<Vec<PeerInfo>>>,
    display_name_tx: &watch::Sender<String>,
    my_node_id: &str,
    root_fingerprint: &str,
) {
    match msg {
        ServerMessage::PeerJoined { peer } => {
            if !verify_admission(peer, peers_tx, root_fingerprint) {
                tracing::warn!("Rejected peer {} — invalid admission cert", peer.node_id);
                return;
            }
            // Signal sends PeerJoined a second time when a peer reports host
            // candidates; treat that as an update rather than a fresh join.
            let already_known = peers_tx.borrow().iter().any(|p| p.node_id == peer.node_id);
            if already_known {
                tracing::debug!("Peer updated: {} ({})", peer.node_id, peer.overlay_ip);
            } else {
                tracing::info!("Peer joined: {} ({})", peer.node_id, peer.overlay_ip);
            }
            let mut new_peers: Vec<PeerInfo> = peers_tx
                .borrow()
                .iter()
                .filter(|p| p.node_id != peer.node_id)
                .cloned()
                .collect();
            new_peers.push(peer.clone());
            let _ = peers_tx.send(Arc::new(new_peers));
        }
        ServerMessage::PeerLeft { node_id, .. } => {
            tracing::info!("Peer left: {}", node_id);
            let new_peers: Vec<PeerInfo> = peers_tx
                .borrow()
                .iter()
                .filter(|p| p.node_id != *node_id)
                .cloned()
                .collect();
            let _ = peers_tx.send(Arc::new(new_peers));
        }
        ServerMessage::PeerRenamed {
            node_id,
            new_display_name,
        } => {
            tracing::info!("Peer renamed: {} → {}", node_id, new_display_name);
            if node_id == my_node_id {
                let _ = display_name_tx.send(new_display_name.clone());
            }
            let new_peers: Vec<PeerInfo> = peers_tx
                .borrow()
                .iter()
                .map(|p| {
                    if p.node_id == *node_id {
                        let mut updated = p.clone();
                        updated.display_name = new_display_name.clone();
                        updated
                    } else {
                        p.clone()
                    }
                })
                .collect();
            let _ = peers_tx.send(Arc::new(new_peers));
        }
        ServerMessage::Pong => {} // keepalive response
        other => {
            tracing::debug!("Signal: unhandled push message: {:?}", other);
        }
    }
}

// --- QUIC connection helpers

/// Built once per handle so TLS 1.3 session tickets are reused across reconnects.
fn build_client_config(creds: &SignalCredentials) -> Result<quinn::ClientConfig> {
    let cert_der = {
        let b64: String = creds
            .cert_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .context("Invalid identity cert PEM")?
    };
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut creds.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(&creds.signal_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_SIGNAL.to_vec()];
    tls_config.resumption = rustls::client::Resumption::in_memory_sessions(8);
    tls_config.enable_early_data = true;

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(IDLE_TIMEOUT)?));
    transport.keep_alive_interval(Some(PING_INTERVAL));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

async fn connect_to_signal(
    endpoint: &quinn::Endpoint,
    client_config: quinn::ClientConfig,
    addr: SocketAddr,
    endpoint_str: &str,
) -> Result<quinn::Connection> {
    let sni_host = endpoint_str.split(':').next().unwrap_or(endpoint_str);

    let conn = tokio::time::timeout(
        CONNECT_TIMEOUT,
        endpoint.connect_with(client_config, addr, sni_host)?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timed out connecting to signal"))?
    .context("Failed to connect to signal")?;

    Ok(conn)
}

// --- Candidate gathering

fn gather_host_candidates(
    quic_port: u16,
    overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
) -> Vec<Candidate> {
    let overlay = super::net_filter::OverlayNet::new(overlay_ip, overlay_prefix_len);
    let mut candidates = Vec::new();

    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in &interfaces {
            if let std::net::IpAddr::V4(v4) = ip {
                if !super::net_filter::is_interesting_ip(*v4, Some(name), overlay) {
                    continue;
                }
                candidates.push(Candidate {
                    kind: "host".into(),
                    addr: format!("{}:{}", v4, quic_port),
                    priority: 100,
                });
            }
        }
    }

    candidates
}

async fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = endpoint.rsplit_once(':').unwrap_or((endpoint, "4433"));
    let port: u16 = port.parse().unwrap_or_else(|_| {
        tracing::warn!("Invalid port '{port}' in endpoint '{endpoint}', defaulting to 4433");
        4433
    });

    let host = host.to_string();
    let resolved = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("DNS lookup timed out after {DNS_TIMEOUT:?}: {endpoint}"))?
        .with_context(|| format!("Failed to resolve: {endpoint}"))?;

    let mut addrs: Vec<_> = resolved.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.pop())
        .with_context(|| format!("No addresses for: {endpoint}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_peer_joined_updates_list() {
        let (tx, _rx) = watch::channel(Arc::new(Vec::new()));
        let msg = ServerMessage::PeerJoined {
            peer: PeerInfo {
                node_id: "nas".into(),
                fingerprint: "abc123".into(),
                overlay_ip: "100.64.0.1".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
                role: String::new(),
            },
        };
        let (dn_tx, _dn_rx) = watch::channel(String::new());
        handle_push_message(&msg, &tx, &dn_tx, "", "");
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(tx.borrow()[0].node_id, "nas");
    }

    #[test]
    fn handle_peer_left_removes_from_list() {
        let (tx, _rx) = watch::channel(Arc::new(vec![PeerInfo {
            node_id: "nas".into(),
            fingerprint: "abc".into(),
            overlay_ip: "100.64.0.1".into(),
            candidates: vec![],
            public_key: String::new(),
            admission_cert: String::new(),
            display_name: String::new(),
            role: String::new(),
        }]));
        let msg = ServerMessage::PeerLeft {
            node_id: "nas".into(),
            cluster_id: "c1".into(),
        };
        let (dn_tx, _dn_rx) = watch::channel(String::new());
        handle_push_message(&msg, &tx, &dn_tx, "", "");
        assert!(tx.borrow().is_empty());
    }

    #[test]
    fn peer_joined_replaces_existing() {
        let (tx, _rx) = watch::channel(Arc::new(vec![PeerInfo {
            node_id: "nas".into(),
            fingerprint: "old-fp".into(),
            overlay_ip: "100.64.0.1".into(),
            candidates: vec![],
            public_key: String::new(),
            admission_cert: String::new(),
            display_name: String::new(),
            role: String::new(),
        }]));
        let msg = ServerMessage::PeerJoined {
            peer: PeerInfo {
                node_id: "nas".into(),
                fingerprint: "new-fp".into(),
                overlay_ip: "100.64.0.1".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
                role: String::new(),
            },
        };
        let (dn_tx, _dn_rx) = watch::channel(String::new());
        handle_push_message(&msg, &tx, &dn_tx, "", "");
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(tx.borrow()[0].fingerprint, "new-fp");
    }

    #[tokio::test]
    async fn resolve_addr_with_port() {
        let addr = resolve_addr("127.0.0.1:5555").await.unwrap();
        assert_eq!(addr.port(), 5555);
    }

    #[tokio::test]
    async fn resolve_addr_defaults_to_4433() {
        let addr = resolve_addr("127.0.0.1").await.unwrap();
        assert_eq!(addr.port(), 4433);
    }
}
