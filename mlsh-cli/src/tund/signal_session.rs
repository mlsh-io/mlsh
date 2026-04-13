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
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

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
pub struct SignalSessionHandle {
    pub overlay_ip: watch::Receiver<Option<Ipv4Addr>>,
    pub peers: watch::Receiver<Arc<Vec<PeerInfo>>>,
    pub connection: watch::Receiver<Option<quinn::Connection>>,
    shutdown_tx: watch::Sender<bool>,
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
}

/// Shared state for the signal session loop.
struct SessionContext {
    creds: SignalCredentials,
    endpoint: quinn::Endpoint,
    cancel: tokio_util::sync::CancellationToken,
    ip_tx: watch::Sender<Option<Ipv4Addr>>,
    peers_tx: watch::Sender<Arc<Vec<PeerInfo>>>,
    conn_tx: watch::Sender<Option<quinn::Connection>>,
    tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: super::peer_table::PeerTable,
    overlay_port: u16,
    overlay_prefix_len: u8,
}

/// Spawn a persistent signal session as a background task.
///
/// If `tun_device` is provided, incoming relay bi-streams from signal will be
/// accepted and forwarded via the shared `peer_table`.
pub fn spawn(
    creds: SignalCredentials,
    endpoint: quinn::Endpoint,
    cancel: tokio_util::sync::CancellationToken,
    tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: super::peer_table::PeerTable,
    overlay_port: u16,
    overlay_prefix_len: u8,
) -> SignalSessionHandle {
    let (ip_tx, ip_rx) = watch::channel(None);
    let (peers_tx, peers_rx) = watch::channel(Arc::new(Vec::new()));
    let (conn_tx, conn_rx) = watch::channel(None);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let ctx = SessionContext {
        creds,
        endpoint,
        cancel,
        ip_tx,
        peers_tx,
        conn_tx,
        tun_device,
        peer_table,
        overlay_port,
        overlay_prefix_len,
    };

    tokio::spawn(session_loop(ctx, shutdown_rx));

    SignalSessionHandle {
        overlay_ip: ip_rx,
        peers: peers_rx,
        connection: conn_rx,
        shutdown_tx,
    }
}

async fn session_loop(ctx: SessionContext, mut shutdown_rx: watch::Receiver<bool>) {
    shutdown_rx.borrow_and_update();

    loop {
        match run_session(&ctx, &mut shutdown_rx).await {
            Ok(true) => {
                tracing::info!("Signal session shut down by user");
                break;
            }
            Ok(false) => {
                tracing::info!("Signal session closed, reconnecting in {RECONNECT_DELAY:?}...");
            }
            Err(e) => {
                tracing::warn!("Signal session error: {e:#}, reconnecting in {RECONNECT_DELAY:?}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(RECONNECT_DELAY) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }
    }
}

/// Run a single session. Returns Ok(true) if user requested shutdown,
/// Ok(false) if connection was lost, Err on failure.
async fn run_session(
    ctx: &SessionContext,
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

    let addr = resolve_addr(&creds.signal_endpoint)?;
    let conn = connect_to_signal(&ctx.endpoint, addr, &creds.signal_endpoint, creds).await?;

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
            // Accept incoming bi-streams from signal (relay_incoming)
            stream = conn_for_accept.accept_bi() => {
                match stream {
                    Ok((relay_send, relay_recv)) => {
                        if let Some(ref dev) = tun_device {
                            let dev = dev.clone();
                            let table = peer_table.clone();
                            let my_ip = overlay_ip;
                            let relay_identity = mlsh_crypto::identity::NodeIdentity {
                                cert_der: vec![], // not needed for TLS config
                                cert_pem: creds.cert_pem.clone(),
                                key_pem: creds.key_pem.clone(),
                                fingerprint: creds.fingerprint.clone(),
                            };
                            let relay_cancel = ctx.cancel.clone();
                            tokio::spawn(async move {
                                tokio::select! {
                                    result = super::relay_handler::handle_incoming_relay(
                                        relay_send, relay_recv, dev, my_ip, table, relay_identity,
                                    ) => {
                                        if let Err(e) = result {
                                            tracing::debug!("Incoming relay error: {}", e);
                                        }
                                    }
                                    _ = relay_cancel.cancelled() => {}
                                }
                            });
                        } else {
                            tracing::warn!("Relay stream received but no TUN device available");
                        }
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
                        handle_push_message(&msg, peers_tx, &creds.root_fingerprint);
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
/// Peers without admission certs are accepted with a warning (backward compat).
fn verify_admission(
    peer: &PeerInfo,
    peers_tx: &watch::Sender<Arc<Vec<PeerInfo>>>,
    root_fingerprint: &str,
) -> bool {
    if peer.admission_cert.is_empty() {
        // No admission cert — accept with warning (backward compat with pre-admission nodes)
        tracing::warn!(
            "Peer {} has no admission cert — accepting (legacy)",
            peer.node_id
        );
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
    root_fingerprint: &str,
) {
    match msg {
        ServerMessage::PeerJoined { peer } => {
            // Verify admission cert before accepting the peer
            if !verify_admission(peer, peers_tx, root_fingerprint) {
                tracing::warn!("Rejected peer {} — invalid admission cert", peer.node_id,);
                return;
            }
            tracing::info!("Peer joined: {} ({})", peer.node_id, peer.overlay_ip);
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

async fn connect_to_signal(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    endpoint_str: &str,
    creds: &SignalCredentials,
) -> Result<quinn::Connection> {
    // Load identity for mTLS client auth
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

    // Verify signal's QUIC cert fingerprint + send our client cert
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(&creds.signal_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_SIGNAL.to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(IDLE_TIMEOUT)?));
    transport.keep_alive_interval(Some(PING_INTERVAL));
    client_config.transport_config(Arc::new(transport));

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
    let mut candidates = Vec::new();

    // Compute overlay subnet mask for filtering
    let overlay_mask: u32 = if overlay_prefix_len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - overlay_prefix_len)) - 1)
    };
    let overlay_network = u32::from(overlay_ip) & overlay_mask;

    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (name, ip) in &interfaces {
            if let std::net::IpAddr::V4(v4) = ip {
                if v4.is_loopback() || v4.is_link_local() {
                    continue;
                }
                let octets = v4.octets();
                // Skip Docker/Podman bridge networks (172.16-31.x.x)
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    continue;
                }
                // Skip overlay subnet — advertising overlay IPs as host
                // candidates creates routing loops: QUIC transport UDP goes
                // through the TUN, gets re-encapsulated as overlay traffic,
                // exhausts stream limits, and blocks all outbound.
                if u32::from(*v4) & overlay_mask == overlay_network {
                    continue;
                }
                // Skip TUN interfaces by name as a safety net
                if name.starts_with("mlsh") || name.starts_with("tun") {
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

fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = endpoint.rsplit_once(':').unwrap_or((endpoint, "4433"));
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                "Invalid port '{}' in endpoint '{}', defaulting to 4433",
                port,
                endpoint
            );
            4433
        }
    };
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .or_else(|| {
            (host, port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
        })
        .context(format!("Failed to resolve: {}", endpoint))
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
            },
        };
        handle_push_message(&msg, &tx, "");
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
        }]));
        let msg = ServerMessage::PeerLeft {
            node_id: "nas".into(),
            cluster_id: "c1".into(),
        };
        handle_push_message(&msg, &tx, "");
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
            },
        };
        handle_push_message(&msg, &tx, "");
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(tx.borrow()[0].fingerprint, "new-fp");
    }

    #[test]
    fn resolve_addr_with_port() {
        let addr = resolve_addr("127.0.0.1:5555").unwrap();
        assert_eq!(addr.port(), 5555);
    }

    #[test]
    fn resolve_addr_defaults_to_4433() {
        // localhost should resolve
        let addr = resolve_addr("127.0.0.1").unwrap();
        assert_eq!(addr.port(), 4433);
    }
}
