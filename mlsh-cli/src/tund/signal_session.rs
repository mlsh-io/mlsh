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

/// Credentials for connecting to signal.
#[derive(Clone)]
pub struct SignalCredentials {
    pub signal_endpoint: String,
    pub signal_fingerprint: String,
    pub cluster_id: String,
    pub node_id: String,
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

/// Spawn a persistent signal session as a background task.
///
/// If `tun_device` is provided, incoming relay bi-streams from signal will be
/// accepted and forwarded via the shared `peer_table`.
pub fn spawn(
    creds: SignalCredentials,
    tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: super::peer_table::PeerTable,
    overlay_port: u16,
    overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
) -> SignalSessionHandle {
    let (ip_tx, ip_rx) = watch::channel(None);
    let (peers_tx, peers_rx) = watch::channel(Arc::new(Vec::new()));
    let (conn_tx, conn_rx) = watch::channel(None);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(session_loop(
        creds,
        ip_tx,
        peers_tx,
        conn_tx,
        shutdown_rx,
        tun_device,
        peer_table,
        overlay_port,
        overlay_ip,
        overlay_prefix_len,
    ));

    SignalSessionHandle {
        overlay_ip: ip_rx,
        peers: peers_rx,
        connection: conn_rx,
        shutdown_tx,
    }
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    creds: SignalCredentials,
    ip_tx: watch::Sender<Option<Ipv4Addr>>,
    peers_tx: watch::Sender<Arc<Vec<PeerInfo>>>,
    conn_tx: watch::Sender<Option<quinn::Connection>>,
    mut shutdown_rx: watch::Receiver<bool>,
    tun_device: Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: super::peer_table::PeerTable,
    overlay_port: u16,
    overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    shutdown_rx.borrow_and_update();

    loop {
        match run_session(
            &creds,
            &ip_tx,
            &peers_tx,
            &conn_tx,
            &mut shutdown_rx,
            &tun_device,
            &peer_table,
            overlay_port,
            overlay_ip,
            overlay_prefix_len,
        )
        .await
        {
            Ok(true) => {
                tracing::info!("Signal session shut down by user");
                break;
            }
            Ok(false) => {
                tracing::info!("Signal session closed, reconnecting in {:?}...", backoff);
                // Don't reset backoff — if we're being evicted by ourselves
                // (duplicate session), the backoff prevents a reconnection storm.
            }
            Err(e) => {
                tracing::warn!(
                    "Signal session error: {:#}, reconnecting in {:?}",
                    e,
                    backoff
                );
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() { break; }
            }
        }

        backoff = (backoff * 2).min(max_backoff);
    }
}

/// Run a single session. Returns Ok(true) if user requested shutdown,
/// Ok(false) if connection was lost, Err on failure.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    creds: &SignalCredentials,
    ip_tx: &watch::Sender<Option<Ipv4Addr>>,
    peers_tx: &watch::Sender<Arc<Vec<PeerInfo>>>,
    conn_tx: &watch::Sender<Option<quinn::Connection>>,
    shutdown_rx: &mut watch::Receiver<bool>,
    tun_device: &Option<Arc<tun_rs::AsyncDevice>>,
    peer_table: &super::peer_table::PeerTable,
    overlay_port: u16,
    _overlay_ip: Ipv4Addr,
    overlay_prefix_len: u8,
) -> Result<bool> {
    let addr = resolve_addr(&creds.signal_endpoint)?;
    let conn = connect_to_signal(addr, &creds.signal_endpoint, &creds).await?;

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
                            tokio::spawn(async move {
                                if let Err(e) = super::relay_handler::handle_incoming_relay(
                                    relay_send, relay_recv, dev, my_ip, table,
                                ).await {
                                    tracing::debug!("Incoming relay error: {}", e);
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
        tracing::warn!("Peer {} has no admission cert — accepting (legacy)", peer.node_id);
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

    if cert.sponsor_node_id == cert.node_id {
        // Self-signed — must be the root admin
        if root_fingerprint.is_empty() {
            tracing::warn!("Cannot verify root admin {} — no root_fingerprint in config", peer.node_id);
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
    let sponsor = peers.iter().find(|p| p.node_id == cert.sponsor_node_id);
    match sponsor {
        Some(_sponsor_peer) => {
            // We'd need the sponsor's Ed25519 public key to verify.
            // Public keys aren't in PeerInfo currently — accept if sponsor is known.
            // Full signature verification requires public key exchange (Phase 4).
            true
        }
        None => {
            // Sponsor not in our peer list yet — this can happen if peers arrive
            // out of order. Accept for now; a full implementation would queue and
            // re-verify when the sponsor appears.
            tracing::debug!(
                "Peer {} sponsor {} not yet known — accepting provisionally",
                peer.node_id,
                cert.sponsor_node_id,
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
            if !verify_admission(&peer, peers_tx, root_fingerprint) {
                tracing::warn!(
                    "Rejected peer {} — invalid admission cert",
                    peer.node_id,
                );
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
        ServerMessage::Pong => {} // keepalive response
        other => {
            tracing::debug!("Signal: unhandled push message: {:?}", other);
        }
    }
}

// --- QUIC connection helpers

async fn connect_to_signal(
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

    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let sni_host = endpoint_str.split(':').next().unwrap_or(endpoint_str);

    let conn = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, sni_host)?)
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
                admission_cert: String::new(),
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
            admission_cert: String::new(),
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
            admission_cert: String::new(),
        }]));
        let msg = ServerMessage::PeerJoined {
            peer: PeerInfo {
                node_id: "nas".into(),
                fingerprint: "new-fp".into(),
                overlay_ip: "100.64.0.1".into(),
                candidates: vec![],
                admission_cert: String::new(),
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
