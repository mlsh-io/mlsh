//! QUIC client side for the overlay: shared endpoint creation and direct
//! peer connection with fingerprint verification.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

pub const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Create a shared QUIC endpoint that serves as both overlay server and client
/// for signal + direct peer connections. A single UDP socket ensures signal
/// observes the correct remote_address for srflx candidates.
pub fn create_shared_endpoint(identity_dir: &std::path::Path) -> Result<(quinn::Endpoint, u16)> {
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
