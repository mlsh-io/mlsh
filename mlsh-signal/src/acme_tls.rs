//! TLS-ALPN-01 (RFC 8737) challenge responder.
//!
//! mlshtund sends a self-signed cert via `TlsAlpnChallengeSet { domain,
//! cert_der, key_der }`; we keep it in memory, keyed by `domain`, with a
//! 15-minute TTL. When the ingress TCP listener sees a `ClientHello` with
//! `SNI = domain` and `ALPN = "acme-tls/1"`, it hands the socket off to
//! [`serve_challenge`], which performs a rustls handshake with the stored
//! cert and closes. Every other connection (missing SNI entry, different
//! ALPN, or expired challenge) follows the normal ingress relay path.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

pub const ACME_ALPN: &[u8] = b"acme-tls/1";
const TTL: Duration = Duration::from_secs(15 * 60);

struct Entry {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expires_at: Instant,
}

type Store = Arc<RwLock<HashMap<String, Entry>>>;

fn store() -> Store {
    static R: OnceLock<Store> = OnceLock::new();
    R.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

/// Publish a challenge cert for `domain`. Overwrites any existing entry.
pub fn set(domain: &str, cert_der: Vec<u8>, key_der: Vec<u8>) {
    let key = domain.to_ascii_lowercase();
    store().write().expect("acme_tls store poisoned").insert(
        key,
        Entry {
            cert_der,
            key_der,
            expires_at: Instant::now() + TTL,
        },
    );
    info!(domain, "TLS-ALPN-01 challenge published");
}

/// Drop any challenge cert registered for `domain`.
pub fn clear(domain: &str) {
    let key = domain.to_ascii_lowercase();
    store()
        .write()
        .expect("acme_tls store poisoned")
        .remove(&key);
    info!(domain, "TLS-ALPN-01 challenge cleared");
}

/// Return true if we have a non-expired challenge cert for this SNI.
pub fn has_challenge(domain: &str) -> bool {
    let key = domain.to_ascii_lowercase();
    let binding = store();
    let guard = binding.read().expect("acme_tls store poisoned");
    guard
        .get(&key)
        .map(|e| e.expires_at > Instant::now())
        .unwrap_or(false)
}

fn lookup(domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = domain.to_ascii_lowercase();
    let now = Instant::now();
    let binding = store();
    let guard = binding.read().expect("acme_tls store poisoned");
    let entry = guard.get(&key)?;
    if entry.expires_at <= now {
        return None;
    }
    Some((entry.cert_der.clone(), entry.key_der.clone()))
}

/// Terminate an incoming TLS handshake for `domain` using the stored challenge
/// cert. LE's validator performs the handshake, verifies the
/// `id-pe-acmeIdentifier` extension, then closes — we don't exchange any
/// application data.
pub async fn serve_challenge(socket: TcpStream, domain: &str) -> Result<()> {
    let (cert_der, key_der) = lookup(domain).context("No challenge cert for domain")?;

    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow::anyhow!("invalid challenge key: {}", e))?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("Failed to build ACME TLS ServerConfig")?;
    // LE's validator only accepts the connection if we advertise the
    // acme-tls/1 ALPN; anything else is rejected per RFC 8737.
    server_config.alpn_protocols = vec![ACME_ALPN.to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    match acceptor.accept(socket).await {
        Ok(_tls) => {
            debug!(domain, "TLS-ALPN-01 handshake completed");
            // LE closes after verifying the cert; we drop the connection.
        }
        Err(e) => {
            debug!(domain, error = %e, "TLS-ALPN-01 handshake failed");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_lookup_clear() {
        set("tls1.mlsh.io", vec![1, 2, 3], vec![4, 5, 6]);
        let (c, k) = lookup("tls1.mlsh.io").unwrap();
        assert_eq!(c, vec![1, 2, 3]);
        assert_eq!(k, vec![4, 5, 6]);
        assert!(has_challenge("TLS1.MLSH.IO"));
        clear("tls1.mlsh.io");
        assert!(lookup("tls1.mlsh.io").is_none());
        assert!(!has_challenge("tls1.mlsh.io"));
    }
}
