//! QUIC overlay server for mlshtund.
//!
//! Accepts direct QUIC connections from other nodes on the `mlsh-overlay` ALPN.
//! Binds to a random port — the actual port is reported to signal as a host candidate.
//! Each incoming connection is identified by its TLS fingerprint and inserted
//! into the shared PeerTable for routing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};

use super::peer_table::{self, PeerTable};

use mlsh_protocol::alpn::ALPN_OVERLAY;

/// Result of starting the overlay server.
pub struct OverlayServer {
    /// Port the server is listening on.
    pub port: u16,
}

/// Start the QUIC overlay server on a random port.
pub fn start(
    _overlay_ip: Ipv4Addr,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
    identity_dir: &std::path::Path,
) -> Result<OverlayServer> {
    // Load identity
    let cert_pem =
        std::fs::read_to_string(identity_dir.join("cert.pem")).context("Missing identity cert")?;
    let key_pem =
        std::fs::read_to_string(identity_dir.join("key.pem")).context("Missing identity key")?;

    // Parse cert DER from PEM
    let cert_der = pem_to_der(&cert_pem)?;

    let server_config = build_server_config(&cert_der, &key_pem)?;

    // Bind to random port
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)
        .context("Failed to bind QUIC overlay server")?;

    let port = endpoint.local_addr()?.port();

    // Spawn accept loop
    tokio::spawn(accept_loop(endpoint, device, peer_table));

    Ok(OverlayServer { port })
}

const MAX_OVERLAY_CONNECTIONS: usize = 64;

async fn accept_loop(
    endpoint: quinn::Endpoint,
    device: Arc<tun_rs::AsyncDevice>,
    peer_table: PeerTable,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_OVERLAY_CONNECTIONS));

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
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

        // Verify ALPN
        let alpn = conn
            .handshake_data()
            .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|hd| hd.protocol.clone());

        if alpn.as_deref() != Some(ALPN_OVERLAY) {
            tracing::warn!("Unexpected ALPN from {}", remote);
            conn.close(quinn::VarInt::from_u32(2), b"wrong alpn");
            continue;
        }

        // Identify peer by TLS certificate fingerprint
        let peer_fingerprint = extract_peer_fingerprint(&conn);

        tracing::info!(
            "Direct overlay connection from {} (fp={})",
            remote,
            peer_fingerprint.as_deref().unwrap_or("unknown")
        );

        // Spawn per-connection handler — no TUN reader, only inbound (peer → TUN).
        // Outbound is handled by the single TUN reader via PeerTable.
        tokio::spawn(async move {
            let _permit = permit; // held for the lifetime of this connection

            // Look up peer's overlay IP from the known peers list
            let peer_ip = if let Some(fp) = &peer_fingerprint {
                find_peer_ip_by_fingerprint(&table, fp).await
            } else {
                None
            };

            if let Some(ip) = peer_ip {
                table.insert_direct(ip, conn.clone()).await;
                tracing::info!("Inserted direct route to {}", ip);

                // Inbound only: read packets from peer, write to TUN
                run_inbound(conn.clone(), &device, &table).await;

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

/// Extract the SHA-256 fingerprint from the peer's TLS certificate.
fn extract_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let peer_certs = conn.peer_identity()?;
    let certs = peer_certs
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    Some(mlsh_crypto::identity::compute_fingerprint(cert.as_ref()))
}

/// Look up a peer's overlay IP by matching their fingerprint against known peers.
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

    /// Accept any client certificate — we verify identity by fingerprint after handshake.
    /// The purpose is just to make the client SEND its cert so we can extract the fingerprint.
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
            // TLS 1.2 is not used with QUIC
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
            // Delegate to real rustls verification to prove the client holds the private key
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
    use base64::Engine;
    let pem = pem.trim();
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("Invalid PEM encoding")
}
