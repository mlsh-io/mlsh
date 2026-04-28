//! Overlay QUIC plumbing: shared endpoint, direct peer connections, accept
//! loop for incoming peers, and active path migration on network changes.
//!
//! All overlay peers use the `mlsh-overlay` ALPN over a single shared UDP
//! socket. The same socket is the source for outbound `connect()` and the
//! sink for inbound `accept()` so signal observes a consistent srflx
//! candidate.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;

use mlsh_protocol::alpn::ALPN_OVERLAY;

use super::peer_table::{self, PeerTable};

pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_OVERLAY_CONNECTIONS: usize = 64;

// ---------------------------------------------------------------------------
// Endpoint creation (ex-quic_client.rs)
// ---------------------------------------------------------------------------

/// Create a shared QUIC endpoint that serves as both overlay server and client
/// for signal + direct peer connections. A single UDP socket ensures signal
/// observes the correct remote_address for srflx candidates.
pub fn create_shared_endpoint(identity_dir: &std::path::Path) -> Result<(quinn::Endpoint, u16)> {
    let cert_pem =
        std::fs::read_to_string(identity_dir.join("cert.pem")).context("Missing identity cert")?;
    let key_pem =
        std::fs::read_to_string(identity_dir.join("key.pem")).context("Missing identity key")?;
    let cert_der = pem_to_der(&cert_pem)?;
    let server_config = build_server_config(&cert_der, &key_pem)?;

    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .context("Failed to bind QUIC endpoint")?;
    let port = endpoint.local_addr()?.port();

    Ok((endpoint, port))
}

/// Connect directly to a peer via QUIC with fingerprint verification.
pub async fn connect_overlay_direct(
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
    tls_config.alpn_protocols = vec![ALPN_OVERLAY.to_vec()];

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

// ---------------------------------------------------------------------------
// Path migration (ex-endpoint_migrate.rs)
// ---------------------------------------------------------------------------

/// Active QUIC path migration (RFC 9000 §9): rebind the endpoint to a fresh
/// ephemeral UDP socket so every live connection migrates via PATH_CHALLENGE
/// to a new 4-tuple without closing/reconnecting.
pub fn try_migrate(endpoint: &quinn::Endpoint) -> anyhow::Result<u16> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let new_port = socket.local_addr()?.port();
    let open_conns = endpoint.open_connections();
    endpoint.rebind(socket)?;
    tracing::info!(
        "Path migration: rebound endpoint to 0.0.0.0:{new_port}, {open_conns} conn(s) migrating"
    );
    Ok(new_port)
}

// ---------------------------------------------------------------------------
// Server / accept loop (ex-quic_server.rs)
// ---------------------------------------------------------------------------

/// Start the overlay accept loop on a shared QUIC endpoint.
pub fn start(
    endpoint: quinn::Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
    cancel: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(accept_loop(endpoint, device, peer_table, cancel));
}

async fn accept_loop(
    endpoint: quinn::Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
    cancel: tokio_util::sync::CancellationToken,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_OVERLAY_CONNECTIONS));

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(i) => i,
                None => break,
            },
            _ = cancel.cancelled() => break,
        };
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("Overlay connection limit reached, rejecting");
                incoming.refuse();
                continue;
            }
        };
        let remote = incoming.remote_address();
        let device = device.clone();
        let table = peer_table.clone();

        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Overlay handshake failed from {}: {}", remote, e);
                continue;
            }
        };

        let alpn = conn
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol.clone());

        if alpn.as_deref() != Some(ALPN_OVERLAY) {
            tracing::warn!("Unexpected ALPN from {}", remote);
            conn.close(quinn::VarInt::from_u32(2), b"wrong alpn");
            continue;
        }

        let peer_fingerprint = extract_peer_fingerprint(&conn);

        tracing::info!(
            "Direct overlay connection from {} (fp={})",
            remote,
            peer_fingerprint.as_deref().unwrap_or("unknown")
        );

        let conn_cancel = cancel.clone();
        tokio::spawn(async move {
            let _permit = permit;

            let peer_ip = if let Some(fp) = &peer_fingerprint {
                find_peer_ip_by_fingerprint(&table, fp).await
            } else {
                None
            };

            if let Some(ip) = peer_ip {
                table.insert_direct(ip, conn.clone()).await;
                tracing::info!("Inserted direct route to {}", ip);

                tokio::select! {
                    _ = run_inbound(conn.clone(), &device, &table) => {}
                    _ = conn_cancel.cancelled() => {}
                }

                table.remove_route(ip).await;
                tracing::info!("Direct connection from {} ended", ip);
            } else {
                tracing::warn!("Could not identify peer from {}, closing", remote);
                conn.close(quinn::VarInt::from_u32(3), b"unknown peer");
            }
        });
    }
}

/// Read packets from a peer's QUIC connection and write to the TUN device.
pub async fn run_inbound(
    conn: quinn::Connection,
    device: &Arc<tun_rs::AsyncDevice>,
    peer_table: &PeerTable,
) {
    let mut pkt_buf = vec![0u8; 65536];
    loop {
        let mut stream = match conn.accept_uni().await {
            Ok(s) => s,
            Err(_) => break,
        };
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            continue;
        }
        let plen = u32::from_be_bytes(len_buf) as usize;
        if !(20..=65536).contains(&plen) {
            continue;
        }
        if stream.read_exact(&mut pkt_buf[..plen]).await.is_err() {
            continue;
        }
        let pkt = &pkt_buf[..plen];
        if !peer_table::validate_inbound_packet(pkt) {
            continue;
        }
        peer_table.record_rx(plen);
        let _ = device.send(pkt).await;
    }
}

fn extract_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let peer_certs = conn.peer_identity()?;
    let certs = peer_certs
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    Some(mlsh_crypto::identity::compute_fingerprint(cert.as_ref()))
}

async fn find_peer_ip_by_fingerprint(table: &PeerTable, fingerprint: &str) -> Option<Ipv4Addr> {
    let peers = table.known_peers().await;
    peers
        .iter()
        .find(|p| p.fingerprint == fingerprint)
        .and_then(|p| p.overlay_ip.parse().ok())
}

fn build_server_config(cert_der: &[u8], key_pem: &str) -> Result<quinn::ServerConfig> {
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
            Err(rustls::Error::General(
                "TLS 1.2 not supported for QUIC overlay".to_string(),
            ))
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

    let cert = CertificateDer::from(cert_der.to_vec());
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("Failed to parse private key PEM")?
        .context("No private key found in PEM")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyCert))
        .with_single_cert(vec![cert], key)
        .context("Failed to build TLS server config")?;

    tls_config.alpn_protocols = vec![ALPN_OVERLAY.to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .context("Failed to create QUIC server config")?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30 * 60)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(128));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(4));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let pem = pem.trim();
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("Invalid PEM encoding")
}
