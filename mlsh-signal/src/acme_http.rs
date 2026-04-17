//! HTTP-01 ACME challenge responder.
//!
//! Signal serves Let's Encrypt's HTTP-01 validation requests on a configurable
//! port (default `0.0.0.0:80`). When a node starts ACME issuance, it sends a
//! `StreamMessage::HttpChallengeSet { domain, token, key_auth }` via the
//! existing authenticated QUIC stream. Signal stores the `(domain, token) →
//! key_auth` mapping in memory and answers the exact LE HTTP request:
//!
//!   GET /.well-known/acme-challenge/<token>
//!   Host: <domain>
//!
//!   200 OK
//!   Content-Type: application/octet-stream
//!   <key_auth>
//!
//! Every other path / verb returns 404. Entries are TTL'd to 15 minutes so a
//! crashed ACME client can't leak secrets forever.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

const TTL: Duration = Duration::from_secs(15 * 60);
const MAX_REQUEST_BYTES: usize = 8192;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

struct Entry {
    key_auth: String,
    expires_at: Instant,
}

type Key = (String, String);
type Store = Arc<RwLock<HashMap<Key, Entry>>>;

fn store() -> Store {
    static R: OnceLock<Store> = OnceLock::new();
    R.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
        .clone()
}

/// Publish a challenge response. Overwrites any existing `(domain, token)`
/// entry. Expires automatically after 15 minutes.
pub fn set(domain: &str, token: &str, key_auth: &str) {
    let key = (domain.to_ascii_lowercase(), token.to_string());
    store().write().expect("acme_http store poisoned").insert(
        key,
        Entry {
            key_auth: key_auth.to_string(),
            expires_at: Instant::now() + TTL,
        },
    );
    info!(domain, token, "HTTP-01 challenge published");
}

/// Remove a challenge response. Safe to call even if the entry never existed
/// or has already expired.
pub fn clear(domain: &str, token: &str) {
    let key = (domain.to_ascii_lowercase(), token.to_string());
    store()
        .write()
        .expect("acme_http store poisoned")
        .remove(&key);
    info!(domain, token, "HTTP-01 challenge cleared");
}

/// Look up a challenge response, returning `None` if missing or expired.
fn lookup(domain: &str, token: &str) -> Option<String> {
    let key = (domain.to_ascii_lowercase(), token.to_string());
    let now = Instant::now();
    let binding = store();
    let guard = binding.read().expect("acme_http store poisoned");
    let entry = guard.get(&key)?;
    if entry.expires_at <= now {
        return None;
    }
    Some(entry.key_auth.clone())
}

/// Run the HTTP-01 listener until `shutdown` fires.
pub async fn run(
    bind_addr: SocketAddr,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind HTTP-01 listener on {}", bind_addr))?;
    info!("ACME HTTP-01 listener on {}", bind_addr);

    loop {
        tokio::select! {
            accept = listener.accept() => match accept {
                Ok((socket, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) = handle(socket, remote).await {
                            debug!(%remote, error = %e, "HTTP-01 connection ended");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "HTTP-01 accept error"),
            },
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("HTTP-01 listener shutting down");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn handle(mut socket: TcpStream, _remote: SocketAddr) -> Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_BYTES];
    let mut filled = 0usize;

    // Read until end-of-headers (`\r\n\r\n`) or the buffer is full.
    loop {
        let n = tokio::time::timeout(READ_TIMEOUT, socket.read(&mut buf[filled..]))
            .await
            .context("HTTP-01 read timed out")??;
        if n == 0 {
            break;
        }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if filled == buf.len() {
            break;
        }
    }

    let headers = &buf[..filled];
    let Some((host, path)) = parse_request_line_and_host(headers) else {
        return write_404(&mut socket).await;
    };

    let challenge_prefix = "/.well-known/acme-challenge/";
    if !path.starts_with(challenge_prefix) {
        return write_404(&mut socket).await;
    }
    let token = &path[challenge_prefix.len()..];

    match lookup(&host, token) {
        Some(key_auth) => write_challenge(&mut socket, &key_auth).await,
        None => {
            debug!(host = %host, token, "HTTP-01 miss");
            write_404(&mut socket).await
        }
    }
}

async fn write_challenge(socket: &mut TcpStream, key_auth: &str) -> Result<()> {
    let body = key_auth.as_bytes();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    socket.write_all(response.as_bytes()).await?;
    socket.write_all(body).await?;
    socket.shutdown().await.ok();
    Ok(())
}

async fn write_404(socket: &mut TcpStream) -> Result<()> {
    let response = b"HTTP/1.1 404 Not Found\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n";
    socket.write_all(response).await?;
    socket.shutdown().await.ok();
    Ok(())
}

/// Minimal HTTP/1.1 request-line + Host header parser. Returns `(host, path)`
/// on a GET request, or `None` on anything else (bad method, malformed, too
/// short). We deliberately don't use a full HTTP crate — this listener only
/// has to answer one extremely well-known request shape.
fn parse_request_line_and_host(buf: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let _version = parts.next()?;
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    let mut host: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let v = v.trim();
            // Strip optional :port.
            let host_only = v.split(':').next().unwrap_or(v);
            host = Some(host_only.to_ascii_lowercase());
        }
    }
    Some((host?, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_lookup_clear() {
        set("tst1.mlsh.io", "tok1", "key1");
        assert_eq!(lookup("tst1.mlsh.io", "tok1").as_deref(), Some("key1"));
        assert_eq!(lookup("TST1.MLSH.IO", "tok1").as_deref(), Some("key1"));
        clear("tst1.mlsh.io", "tok1");
        assert!(lookup("tst1.mlsh.io", "tok1").is_none());
    }

    #[test]
    fn parse_request_ok() {
        let buf = b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: app.mlsh.io\r\n\r\n";
        let (host, path) = parse_request_line_and_host(buf).unwrap();
        assert_eq!(host, "app.mlsh.io");
        assert_eq!(path, "/.well-known/acme-challenge/abc");
    }

    #[test]
    fn parse_request_strips_port() {
        let buf = b"GET / HTTP/1.1\r\nHost: app.mlsh.io:80\r\n\r\n";
        let (host, _) = parse_request_line_and_host(buf).unwrap();
        assert_eq!(host, "app.mlsh.io");
    }

    #[test]
    fn parse_request_rejects_post() {
        let buf = b"POST / HTTP/1.1\r\nHost: app.mlsh.io\r\n\r\n";
        assert!(parse_request_line_and_host(buf).is_none());
    }

    #[test]
    fn parse_request_requires_host() {
        let buf = b"GET / HTTP/1.1\r\n\r\n";
        assert!(parse_request_line_and_host(buf).is_none());
    }
}
