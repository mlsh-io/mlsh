//! Shared QUIC helpers for one-shot CLI→signal commands.
//!
//! Every user-facing `mlsh <cmd>` that sends a protocol message to signal
//! needs the same connect dance: build a rustls ClientConfig that pins
//! signal's fingerprint and presents the node identity as mTLS client cert,
//! bind an ephemeral UDP port, handshake with a 10s timeout.
//!
//! `tund::signal_session::connect_to_signal` is intentionally separate: it
//! reuses the long-lived overlay endpoint (so srflx candidates match) and
//! enables keep-alive/idle-timeout for the persistent session.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use super::verifier::FingerprintVerifier;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SIGNAL_PORT: u16 = 4433;

/// Open a QUIC connection to signal for a one-shot command.
///
/// * `addr` — resolved `SocketAddr` from [`resolve_addr`].
/// * `endpoint_str` — original `host[:port]` string, used for TLS SNI.
/// * `signal_fingerprint` — SHA-256 fingerprint of signal's server cert,
///   pinned via [`FingerprintVerifier`].
/// * `identity` — node identity used as mTLS client certificate.
pub async fn connect_to_signal(
    addr: SocketAddr,
    endpoint_str: &str,
    signal_fingerprint: &str,
    identity: &mlsh_crypto::identity::NodeIdentity,
) -> Result<quinn::Connection> {
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert PEM: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier::new(signal_fingerprint)))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_SIGNAL.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));

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

/// Resolve `host[:port]` to an IPv4 `SocketAddr` (fallback to IPv6). The
/// default port is 4433 (signal's QUIC port).
pub fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port_str) = endpoint.rsplit_once(':').unwrap_or((endpoint, "4433"));
    let port: u16 = port_str.parse().unwrap_or(DEFAULT_SIGNAL_PORT);
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .or_else(|| (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()))
        .context(format!("Failed to resolve: {}", endpoint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_with_explicit_port() {
        let a = resolve_addr("127.0.0.1:5555").unwrap();
        assert_eq!(a.port(), 5555);
    }

    #[test]
    fn resolve_defaults_to_signal_port() {
        let a = resolve_addr("127.0.0.1").unwrap();
        assert_eq!(a.port(), DEFAULT_SIGNAL_PORT);
    }

    #[test]
    fn resolve_ipv4_socketaddr_literal() {
        let a = resolve_addr("10.0.0.1:9999").unwrap();
        assert_eq!(a.port(), 9999);
        assert!(a.is_ipv4());
    }
}
