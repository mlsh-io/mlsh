//! TLS-E2E-encrypted relay sessions through signal.
//!
//! When a direct peer connection is impossible, peers tunnel their overlay
//! traffic through signal via a bidirectional QUIC stream wrapped in mTLS.
//! Signal sees only ciphertext.
//!
//! - [`run_relay_initiator`] : initiator side (we open the stream).
//! - [`handle_incoming_relay`] : responder side (signal opened it for us).
//! - [`DuplexStream`] / [`wrap_initiator`] / [`wrap_responder`] : TLS adapter
//!   shared by both sides (also reused by ingress).

use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use mlsh_protocol::framing;
use mlsh_protocol::messages::RelayMessage;

use super::peer_fsm::{Event, FsmRegistry};
use super::peer_table::{self, PeerTable};

// ---------------------------------------------------------------------------
// TLS adapter (ex-relay_tls.rs)
// ---------------------------------------------------------------------------

/// Bidirectional stream adapter: combines Quinn's SendStream + RecvStream into
/// a single AsyncRead + AsyncWrite, suitable for wrapping with tokio-rustls.
pub struct DuplexStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl DuplexStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }
}

/// Wrap a relay stream as TLS client (initiator side).
pub async fn wrap_initiator(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    identity: &mlsh_crypto::identity::NodeIdentity,
    peer_fingerprint: &str,
) -> Result<tokio_rustls::client::TlsStream<DuplexStream>> {
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(peer_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_OVERLAY.to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("mlsh-relay")
        .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

    let duplex = DuplexStream::new(send, recv);
    let tls_stream = connector
        .connect(server_name, duplex)
        .await
        .context("TLS handshake failed on relay (initiator)")?;

    Ok(tls_stream)
}

/// Wrap a relay stream as TLS server (responder side).
pub async fn wrap_responder(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    identity: &mlsh_crypto::identity::NodeIdentity,
) -> Result<tokio_rustls::server::TlsStream<DuplexStream>> {
    use rustls::pki_types::CertificateDer;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ClientCertVerifier for AcceptAnyCert {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }
        fn offer_client_auth(&self) -> bool {
            true
        }
        fn client_auth_mandatory(&self) -> bool {
            true
        }
        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            Ok(ClientCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General("TLS 1.2 not supported".into()))
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyCert))
        .with_single_cert(vec![cert], key)
        .context("Failed to set server cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_OVERLAY.to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let duplex = DuplexStream::new(send, recv);
    let tls_stream = acceptor
        .accept(duplex)
        .await
        .context("TLS handshake failed on relay (responder)")?;

    Ok(tls_stream)
}

/// Extract the peer's certificate fingerprint from a TLS server stream.
pub fn extract_peer_fingerprint_server(
    tls: &tokio_rustls::server::TlsStream<DuplexStream>,
) -> Option<String> {
    let (_, server_conn) = tls.get_ref();
    let certs = server_conn.peer_certificates()?;
    let cert = certs.first()?;
    Some(mlsh_crypto::identity::compute_fingerprint(cert.as_ref()))
}

// ---------------------------------------------------------------------------
// Initiator (ex-relay_initiator.rs)
// ---------------------------------------------------------------------------

pub struct RelayInitiator {
    pub signal_conn: quinn::Connection,
    pub cluster_id: String,
    pub my_node_id: String,
    pub peer_node_id: String,
    pub peer_fingerprint: String,
    pub identity_dir: std::path::PathBuf,
    pub device: Arc<tun_rs::AsyncDevice>,
    pub peer_table: PeerTable,
    pub events_tx: tokio::sync::mpsc::UnboundedSender<super::peer_fsm::Event>,
    pub cancel: tokio_util::sync::CancellationToken,
}

/// Opens a relay stream through signal, wraps it in TLS, and runs the I/O
/// tasks. Emits `__RelayReadyWith` once up and `RelayClosed` on exit.
pub async fn run_relay_initiator(r: RelayInitiator) {
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

    let tls_stream = match wrap_initiator(send, recv, &identity, &peer_fingerprint).await {
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

// ---------------------------------------------------------------------------
// Responder (ex-relay_handler.rs)
// ---------------------------------------------------------------------------

pub struct IncomingRelay {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub device: Arc<tun_rs::AsyncDevice>,
    pub peer_table: PeerTable,
    pub identity: mlsh_crypto::identity::NodeIdentity,
    pub from_node_id: String,
    pub fsm_registry: FsmRegistry,
}

/// Handle an incoming relay stream from signal (responder side).
pub async fn handle_incoming_relay(relay: IncomingRelay) -> anyhow::Result<()> {
    let IncomingRelay {
        mut send,
        recv,
        device,
        peer_table,
        identity,
        from_node_id,
        fsm_registry,
    } = relay;

    tracing::info!("Relay stream accepted (from: {})", from_node_id);
    framing::write_msg(&mut send, &RelayMessage::RelayAccepted).await?;

    let peer_ip = lookup_peer_ip(&from_node_id, &peer_table).await;

    let tls_stream = wrap_responder(send, recv, &identity).await?;

    if let Some(peer_fp) = extract_peer_fingerprint_server(&tls_stream) {
        let known_fp = peer_table
            .known_peers()
            .await
            .iter()
            .find(|p| p.node_id == from_node_id)
            .map(|p| p.fingerprint.clone());

        if let Some(expected) = known_fp {
            if peer_fp != expected {
                anyhow::bail!(
                    "Relay peer {} fingerprint mismatch (TLS={}, expected={})",
                    from_node_id,
                    &peer_fp[..16],
                    &expected[..16],
                );
            }
        }
    }

    tracing::info!(
        "Relay TLS established with {} (E2E encrypted)",
        from_node_id
    );

    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    if let Some(ip) = peer_ip {
        peer_table.insert_relay(ip, outbound_tx.clone()).await;
        fsm_registry.notify(ip, Event::RelayReady).await;
    }

    let device_in = device.clone();
    let pt_rx = peer_table.clone();
    let inbound = tokio::spawn(async move {
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
            let _ = device_in.send(pkt).await;
        }
    });

    let outbound = tokio::spawn(async move {
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
    }

    if let Some(ip) = peer_ip {
        if peer_table.remove_relay_only(ip).await {
            tracing::info!("Relay route to {} removed", ip);
        }
        fsm_registry.notify(ip, Event::RelayClosed).await;
    }

    drop(outbound_tx);
    tracing::info!("Relay TLS stream ended");
    Ok(())
}

async fn lookup_peer_ip(from_node_id: &str, peer_table: &PeerTable) -> Option<Ipv4Addr> {
    if from_node_id.is_empty() {
        return None;
    }
    for attempt in 0..5 {
        let peers = peer_table.known_peers().await;
        if let Some(p) = peers.iter().find(|p| p.node_id == from_node_id) {
            return p.overlay_ip.parse().ok();
        }
        if attempt < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    tracing::warn!("Relay from {}: peer not found", from_node_id);
    None
}
