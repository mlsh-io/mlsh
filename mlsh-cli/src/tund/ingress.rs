//! mlshtund-side ingress plumbing.
//!
//! Terminates TLS locally with rustls/tokio-rustls and splices decrypted
//! bytes to the upstream. Cert + key are loaded from
//! `/var/lib/mlsh/ingress/certs/<domain>.{crt,key}`; missing files are auto-
//! generated as self-signed so smoke tests work without a real CA.
//!
//! The per-domain cert cache is keyed by hostname; callers invalidate it via
//! [`reload_cert`] after the cert files on disk are rewritten.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use super::relay::DuplexStream;

// -------------------------------------------------------------------------
// Target registry (domain → upstream URL)
// -------------------------------------------------------------------------

fn targets() -> Arc<RwLock<HashMap<String, String>>> {
    static R: OnceLock<Arc<RwLock<HashMap<String, String>>>> = OnceLock::new();
    R.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

/// Register (or replace) an ingress target for `domain`.
pub fn add(domain: &str, target: &str) {
    let key = domain.to_ascii_lowercase();
    let reg = targets();
    reg.write()
        .expect("ingress registry poisoned")
        .insert(key, target.to_string());
    info!(domain, target, "Ingress target registered");
}

/// Remove an ingress target for `domain` and invalidate its cached TLS context.
pub fn remove(domain: &str) {
    let key = domain.to_ascii_lowercase();
    targets()
        .write()
        .expect("ingress registry poisoned")
        .remove(&key);
    acceptors()
        .write()
        .expect("acceptor cache poisoned")
        .remove(&key);
    info!(domain, "Ingress target removed");
}

/// Look up an ingress target for `domain`.
fn lookup(domain: &str) -> Option<String> {
    let key = domain.to_ascii_lowercase();
    targets()
        .read()
        .expect("ingress registry poisoned")
        .get(&key)
        .cloned()
}

// -------------------------------------------------------------------------
// Per-domain TLS acceptor cache
// -------------------------------------------------------------------------

fn acceptors() -> Arc<RwLock<HashMap<String, TlsAcceptor>>> {
    static R: OnceLock<Arc<RwLock<HashMap<String, TlsAcceptor>>>> = OnceLock::new();
    R.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

/// Drop the cached TLS acceptor for `domain` so the next stream reloads the
/// cert files from disk. Call after ACME issues/renews a cert.
pub fn reload_cert(domain: &str) {
    let key = domain.to_ascii_lowercase();
    acceptors()
        .write()
        .expect("acceptor cache poisoned")
        .remove(&key);
    info!(
        domain,
        "Ingress TLS acceptor invalidated; next stream will reload cert"
    );
}

/// Get or build the `TlsAcceptor` for `domain`, loading cert/key from disk or
/// falling back to a freshly-generated self-signed pair.
fn get_or_build_acceptor(domain: &str) -> Result<TlsAcceptor> {
    let key = domain.to_ascii_lowercase();
    if let Some(a) = acceptors()
        .read()
        .expect("acceptor cache poisoned")
        .get(&key)
    {
        return Ok(a.clone());
    }

    let (cert_chain, private_key) = load_or_generate(&key)?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to build ingress rustls ServerConfig")?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    acceptors()
        .write()
        .expect("acceptor cache poisoned")
        .insert(key, acceptor.clone());
    Ok(acceptor)
}

/// Load the certificate chain + key for `domain` from disk, or generate a
/// self-signed fallback and persist it with restricted perms.
fn load_or_generate(
    domain: &str,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let dir = cert_dir();
    let crt_path = dir.join(format!("{}.crt", domain));
    let key_path = dir.join(format!("{}.key", domain));

    if !crt_path.exists() || !key_path.exists() {
        warn!(domain, path = %crt_path.display(), "Generating self-signed cert (Phase 2 stub)");
        let (crt_pem, key_pem) = generate_self_signed(&[domain])?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create cert dir {}", dir.display()))?;
        write_restricted(&crt_path, &crt_pem, 0o644)?;
        write_restricted(&key_path, &key_pem, 0o600)?;
    }

    let crt_bytes = std::fs::read(&crt_path)
        .with_context(|| format!("Failed to read cert {}", crt_path.display()))?;
    let key_bytes = std::fs::read(&key_path)
        .with_context(|| format!("Failed to read key {}", key_path.display()))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut crt_bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse cert PEM")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates in {}", crt_path.display());
    }
    let key = rustls_pemfile::private_key(&mut key_bytes.as_slice())
        .context("Failed to parse private key PEM")?
        .context("No private key in PEM")?;
    Ok((certs, key))
}

/// Build a self-signed cert + key PEM pair for the given DNS names.
/// First name is used as the Common Name; remaining names become SANs.
pub fn generate_self_signed(names: &[&str]) -> Result<(String, String)> {
    let cn = names.first().copied().unwrap_or("self-signed");
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .context("Failed to build self-signed cert params")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn cert_dir() -> PathBuf {
    PathBuf::from("/var/lib/mlsh/ingress/certs")
}

fn write_restricted(path: &Path, content: &str, mode: u32) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("cert path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".tmp_{}", std::process::id()));
    let mut f = {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(mode);
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
        o.open(&tmp)?
    };
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

// -------------------------------------------------------------------------
// Ingress stream handler
// -------------------------------------------------------------------------

/// Handle a `RelayMessage::IngressForward` bi-stream accepted on the signal
/// connection. The caller has already parsed the header and written
/// `IngressAccepted`.
///
/// Flow: accept TLS on the QUIC stream (using the domain's cert), then splice
/// decrypted bytes to the local upstream. Works for HTTP/1.1 upstreams; HTTP/2
/// and WebSocket upgrades work as long as the upstream speaks HTTP/1.1 to us.
pub async fn handle_ingress_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    domain: String,
    client_ip: String,
) -> Result<()> {
    let target = match lookup(&domain) {
        Some(t) => t,
        None => {
            debug!(%domain, "No ingress target registered — dropping");
            return Ok(());
        }
    };
    let upstream_addr = parse_upstream(&target)
        .with_context(|| format!("Invalid ingress target URL: {}", target))?;

    // Build a TLS acceptor for this SNI. Self-signed until ACME supplies one.
    let acceptor = get_or_build_acceptor(&domain)?;

    let quic_stream = DuplexStream::new(send, recv);
    let tls_stream = match acceptor.accept(quic_stream).await {
        Ok(s) => s,
        Err(e) => {
            debug!(%domain, error = %e, "TLS handshake failed");
            return Ok(());
        }
    };
    info!(%domain, %client_ip, upstream = %upstream_addr, "Ingress TLS established, splicing");

    let upstream = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("Failed to connect to upstream {}", upstream_addr))?;

    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let (mut u_read, mut u_write) = upstream.into_split();

    let c_to_u = tokio::io::copy(&mut tls_read, &mut u_write);
    let u_to_c = tokio::io::copy(&mut u_read, &mut tls_write);
    let (r1, r2) = tokio::join!(c_to_u, u_to_c);
    debug!(
        %domain,
        client_to_upstream = ?r1.ok(),
        upstream_to_client = ?r2.ok(),
        "Ingress splice done"
    );

    let _ = u_write.shutdown().await;
    let _ = tls_write.shutdown().await;
    Ok(())
}

/// Parse `http://host:port` or `host:port` into a SocketAddr.
fn parse_upstream(url: &str) -> Result<SocketAddr> {
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let hostport = stripped.split('/').next().unwrap_or(stripped);
    let (host, port_str) = hostport
        .rsplit_once(':')
        .context("Upstream must include :port")?;
    let port: u16 = port_str.parse().context("Invalid upstream port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .next()
        .context("Upstream resolve failed")
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_insert_and_lookup() {
        add("reg-test.mlsh.io", "http://localhost:1234");
        assert_eq!(
            lookup("reg-test.mlsh.io"),
            Some("http://localhost:1234".to_string())
        );
        remove("reg-test.mlsh.io");
        assert!(lookup("reg-test.mlsh.io").is_none());
    }

    #[test]
    fn parse_upstream_with_scheme() {
        let a = parse_upstream("http://127.0.0.1:3000").unwrap();
        assert_eq!(a.port(), 3000);
    }

    #[test]
    fn parse_upstream_without_scheme() {
        let a = parse_upstream("127.0.0.1:3000").unwrap();
        assert_eq!(a.port(), 3000);
    }

    #[test]
    fn parse_upstream_with_path_is_stripped() {
        let a = parse_upstream("http://127.0.0.1:3000/foo").unwrap();
        assert_eq!(a.port(), 3000);
    }

    #[test]
    fn generate_self_signed_roundtrip() {
        let (crt, key) = generate_self_signed(&["selfsigned.test.mlsh.io"]).unwrap();
        assert!(crt.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
        let _certs: Vec<_> = rustls_pemfile::certs(&mut crt.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        rustls_pemfile::private_key(&mut key.as_bytes())
            .unwrap()
            .unwrap();
    }
}
