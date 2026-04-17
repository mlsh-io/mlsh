//! Public-ingress TCP listener with SNI-based routing.
//!
//! mlsh-signal does **not** bind public :443 itself — an outer SNI proxy
//! (host-level layer-4 splitter) forwards `*.mlsh.io` TLS connections to this
//! listener, typically on `127.0.0.1:8443`. This module:
//!
//! 1. Optionally parses a PROXY-protocol v2 header from the outer proxy to
//!    recover the real client IP.
//! 2. Peeks the TLS ClientHello, extracts the SNI hostname, and:
//!    - Routes "admin" SNIs (e.g. `signal.mlsh.io`) to the internal HTTP API.
//!    - Routes every other `*.mlsh.io` to the peer registered in
//!      `ingress_routes` via the existing QUIC relay infrastructure.
//! 3. Splices raw bytes end-to-end. Signal never terminates TLS — the peer
//!    handles it locally with its own key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mlsh_protocol::framing;
use mlsh_protocol::messages::RelayMessage;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::db;
use crate::quic::listener::QuicState;

const CLIENT_HELLO_PEEK_MAX: usize = 4096;
const CLIENT_HELLO_DEADLINE: Duration = Duration::from_secs(5);
const PROXY_V2_DEADLINE: Duration = Duration::from_secs(5);

// -------------------------------------------------------------------------
// Accept loop
// -------------------------------------------------------------------------

/// Run the public-ingress TCP accept loop until `shutdown` fires.
pub async fn run(
    bind_addr: SocketAddr,
    state: Arc<QuicState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind ingress TCP listener on {}", bind_addr))?;
    info!("Ingress TCP listener on {}", bind_addr);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((socket, remote)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, remote, state).await {
                                debug!(%remote, error = %e, "Ingress connection ended");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "Ingress accept error");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Ingress TCP listener shutting down");
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    mut socket: TcpStream,
    remote: SocketAddr,
    state: Arc<QuicState>,
) -> Result<()> {
    // 1. Optional PROXY v2 header
    let client_ip = if state.config.ingress_proxy_protocol {
        match tokio::time::timeout(PROXY_V2_DEADLINE, read_proxy_v2_header(&mut socket)).await {
            Ok(Ok(Some(addr))) => addr.ip().to_string(),
            Ok(Ok(None)) => remote.ip().to_string(),
            Ok(Err(e)) => {
                debug!(%remote, error = %e, "Invalid PROXY v2 header");
                return Ok(());
            }
            Err(_) => {
                debug!(%remote, "Timed out reading PROXY v2 header");
                return Ok(());
            }
        }
    } else {
        remote.ip().to_string()
    };

    // 2. Peek ClientHello for SNI
    let mut peek_buf = vec![0u8; CLIENT_HELLO_PEEK_MAX];
    let sni = match tokio::time::timeout(
        CLIENT_HELLO_DEADLINE,
        peek_sni(&socket, &mut peek_buf),
    )
    .await
    {
        Ok(Ok(Some(sni))) => sni,
        Ok(Ok(None)) => {
            debug!(%remote, "No SNI in ClientHello");
            return Ok(());
        }
        Ok(Err(e)) => {
            debug!(%remote, error = %e, "ClientHello parse error");
            return Ok(());
        }
        Err(_) => {
            debug!(%remote, "Timed out reading ClientHello");
            return Ok(());
        }
    };

    // 3. Admin SNI → internal HTTP API
    if state.config.admin_hosts.iter().any(|h| h.eq_ignore_ascii_case(&sni)) {
        forward_to_admin(socket, &state.config.http_bind).await?;
        return Ok(());
    }

    // 4. Ingress route lookup
    let route = match db::lookup_ingress_route_by_domain(&state.db, &sni).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            debug!(%remote, %sni, "No ingress route for SNI");
            return Ok(());
        }
        Err(e) => {
            warn!(%remote, %sni, error = %e, "DB error looking up ingress route");
            return Ok(());
        }
    };

    // 5. Target node QUIC connection
    let target_conn = match state
        .sessions
        .get_node_connection(&route.cluster_id, &route.node_id)
        .await
    {
        Some(c) => c,
        None => {
            info!(%sni, node_id = %route.node_id, "Target node offline — dropping ingress");
            return Ok(());
        }
    };

    // 6. Relay
    info!(%sni, node_id = %route.node_id, %client_ip, "Ingress relay opening");
    splice_ingress(socket, target_conn, &sni, &client_ip).await
}

async fn forward_to_admin(mut client: TcpStream, http_bind: &str) -> Result<()> {
    let upstream = match TcpStream::connect(http_bind).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target: "mlsh_signal::ingress", error = %e, "Admin backend unreachable");
            return Ok(());
        }
    };
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let (mut cr, mut cw) = client.split();
    let a = tokio::io::copy(&mut cr, &mut uw);
    let b = tokio::io::copy(&mut ur, &mut cw);
    let (_, _) = tokio::join!(a, b);
    Ok(())
}

async fn splice_ingress(
    mut client: TcpStream,
    target_conn: quinn::Connection,
    domain: &str,
    client_ip: &str,
) -> Result<()> {
    // Open bi-stream on the peer's signal connection.
    let (mut target_send, mut target_recv) = target_conn
        .open_bi()
        .await
        .context("Failed to open ingress bi-stream on target peer")?;

    // Send ingress forward header with the real client IP.
    let header = RelayMessage::IngressForward {
        domain: domain.to_string(),
        client_ip: client_ip.to_string(),
    };
    framing::write_msg(&mut target_send, &header)
        .await
        .context("Failed to write IngressForward header")?;

    // Read accepted.
    let resp: RelayMessage = framing::read_msg(&mut target_recv)
        .await
        .context("Failed to read ingress response from peer")?;

    if !matches!(resp, RelayMessage::IngressAccepted) {
        anyhow::bail!("Peer rejected ingress: {:?}", resp);
    }

    // Splice client ⇄ QUIC stream.
    let (mut cr, mut cw) = client.split();
    let c_to_p = tokio::io::copy(&mut cr, &mut target_send);
    let p_to_c = tokio::io::copy(&mut target_recv, &mut cw);
    let (r1, r2) = tokio::join!(c_to_p, p_to_c);
    debug!(
        domain,
        client_to_peer = ?r1.ok(),
        peer_to_client = ?r2.ok(),
        "Ingress splice done"
    );

    let _ = target_send.finish();
    Ok(())
}

// -------------------------------------------------------------------------
// PROXY-protocol v2 (minimal, opt-in)
// -------------------------------------------------------------------------

/// 12-byte signature that starts every PROXY v2 header.
const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Read and validate a PROXY v2 header, returning the upstream client address
/// if a TCP-over-IPv4 or TCP-over-IPv6 PROXY command is carried. Returns
/// `Ok(None)` for `LOCAL` commands (health checks).
async fn read_proxy_v2_header(
    socket: &mut TcpStream,
) -> Result<Option<SocketAddr>> {
    let mut header = [0u8; 16];
    socket
        .read_exact(&mut header)
        .await
        .context("Failed to read PROXY v2 header")?;
    if header[..12] != PROXY_V2_SIG {
        anyhow::bail!("Not a PROXY v2 header");
    }
    let ver_cmd = header[12];
    let fam_proto = header[13];
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    // Version must be 2 (high nibble), command 0 = LOCAL, 1 = PROXY.
    if (ver_cmd >> 4) != 2 {
        anyhow::bail!("Invalid PROXY v2 version");
    }
    let cmd = ver_cmd & 0x0F;

    let mut addr_buf = vec![0u8; addr_len];
    if addr_len > 0 {
        socket
            .read_exact(&mut addr_buf)
            .await
            .context("Failed to read PROXY v2 address block")?;
    }

    if cmd == 0 {
        return Ok(None); // LOCAL (health check) — fall through to peer addr.
    }

    // fam_proto: high nibble = address family (1=IPv4, 2=IPv6), low = proto (1=TCP).
    let family = fam_proto >> 4;
    let proto = fam_proto & 0x0F;
    if proto != 1 {
        return Ok(None); // ignore UDP / unspec
    }

    match family {
        1 if addr_buf.len() >= 12 => {
            let src = std::net::Ipv4Addr::new(
                addr_buf[0],
                addr_buf[1],
                addr_buf[2],
                addr_buf[3],
            );
            let src_port = u16::from_be_bytes([addr_buf[8], addr_buf[9]]);
            Ok(Some(SocketAddr::new(std::net::IpAddr::V4(src), src_port)))
        }
        2 if addr_buf.len() >= 36 => {
            let mut src = [0u8; 16];
            src.copy_from_slice(&addr_buf[0..16]);
            let src_port = u16::from_be_bytes([addr_buf[32], addr_buf[33]]);
            Ok(Some(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(src)),
                src_port,
            )))
        }
        _ => Ok(None),
    }
}

// -------------------------------------------------------------------------
// SNI extraction
// -------------------------------------------------------------------------

/// Peek bytes from the socket (without consuming) until we can extract the SNI
/// from the ClientHello, or until the buffer is full.
async fn peek_sni(socket: &TcpStream, buf: &mut [u8]) -> Result<Option<String>> {
    let mut have = 0usize;
    loop {
        let n = socket
            .peek(&mut buf[have..])
            .await
            .context("peek failed")?;
        if n == 0 {
            return Ok(None);
        }
        have = n.max(have); // peek returns TOTAL bytes currently buffered
        match extract_sni(&buf[..have]) {
            ParseResult::Sni(s) => return Ok(Some(s)),
            ParseResult::NoSni => return Ok(None),
            ParseResult::NeedMore => {
                if have >= buf.len() {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            ParseResult::Malformed(msg) => anyhow::bail!("{msg}"),
        }
    }
}

enum ParseResult {
    Sni(String),
    NoSni,
    NeedMore,
    Malformed(&'static str),
}

/// Parse the minimum necessary of a TLS ClientHello to extract the SNI.
/// Supports both TLS 1.2 and 1.3 (they share the same ClientHello format).
fn extract_sni(buf: &[u8]) -> ParseResult {
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes
    if buf.len() < 5 {
        return ParseResult::NeedMore;
    }
    if buf[0] != 0x16 {
        return ParseResult::Malformed("not a TLS handshake record");
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return ParseResult::NeedMore;
    }
    let rec = &buf[5..5 + record_len];

    // Handshake header: type(1) + length(3)
    if rec.len() < 4 {
        return ParseResult::Malformed("truncated handshake");
    }
    if rec[0] != 0x01 {
        return ParseResult::Malformed("not a ClientHello");
    }
    let hs_len =
        ((rec[1] as usize) << 16) | ((rec[2] as usize) << 8) | (rec[3] as usize);
    if rec.len() < 4 + hs_len {
        return ParseResult::NeedMore;
    }
    let body = &rec[4..4 + hs_len];
    let mut p = 0usize;

    // legacy_version(2) + random(32)
    if body.len() < p + 34 {
        return ParseResult::Malformed("truncated hello");
    }
    p += 34;

    // legacy_session_id: u8 length + bytes
    if body.len() < p + 1 {
        return ParseResult::Malformed("truncated session id");
    }
    let sid_len = body[p] as usize;
    p += 1 + sid_len;

    // cipher_suites: u16 length
    if body.len() < p + 2 {
        return ParseResult::Malformed("truncated cipher suites");
    }
    let cs_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs_len;

    // compression_methods: u8 length
    if body.len() < p + 1 {
        return ParseResult::Malformed("truncated compression");
    }
    let cm_len = body[p] as usize;
    p += 1 + cm_len;

    // extensions
    if body.len() < p + 2 {
        return ParseResult::NoSni; // no extensions
    }
    let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() < p + ext_total {
        return ParseResult::Malformed("truncated extensions");
    }
    let exts = &body[p..p + ext_total];

    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let ext_len = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        q += 4;
        if q + ext_len > exts.len() {
            return ParseResult::Malformed("bad extension length");
        }
        if ext_type == 0 {
            // server_name extension
            let ext = &exts[q..q + ext_len];
            if ext.len() < 2 {
                return ParseResult::NoSni;
            }
            let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            if list_len + 2 > ext.len() {
                return ParseResult::Malformed("bad SNI list length");
            }
            let mut r = 2usize;
            while r + 3 <= 2 + list_len {
                let name_type = ext[r];
                let name_len =
                    u16::from_be_bytes([ext[r + 1], ext[r + 2]]) as usize;
                r += 3;
                if r + name_len > ext.len() {
                    return ParseResult::Malformed("bad SNI name length");
                }
                if name_type == 0 {
                    match std::str::from_utf8(&ext[r..r + name_len]) {
                        Ok(s) => return ParseResult::Sni(s.to_ascii_lowercase()),
                        Err(_) => return ParseResult::Malformed("SNI not UTF-8"),
                    }
                }
                r += name_len;
            }
            return ParseResult::NoSni;
        }
        q += ext_len;
    }
    ParseResult::NoSni
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
        // Minimal TLS 1.2 ClientHello with only the SNI extension.
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        hello.extend_from_slice(&[0u8; 32]); // random
        hello.push(0x00); // session_id length
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite (TLS_AES_128_GCM_SHA256)
        hello.extend_from_slice(&[0x01, 0x00]); // compression: null only

        // SNI extension payload
        let mut sni_ext = Vec::new();
        let name_bytes = sni.as_bytes();
        let list_len = 3 + name_bytes.len();
        sni_ext.extend_from_slice(&(list_len as u16).to_be_bytes()); // list length
        sni_ext.push(0x00); // host_name type
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&[0x00, 0x00]); // ext type = server_name
        ext_block.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&sni_ext);

        hello.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext_block);

        // Handshake header
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hl = hello.len();
        hs.extend_from_slice(&[((hl >> 16) & 0xff) as u8, ((hl >> 8) & 0xff) as u8, (hl & 0xff) as u8]);
        hs.extend_from_slice(&hello);

        // Record header
        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x03]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extract_sni_basic() {
        let buf = build_client_hello_with_sni("myapp.mlsh.io");
        match extract_sni(&buf) {
            ParseResult::Sni(s) => assert_eq!(s, "myapp.mlsh.io"),
            _ => panic!("expected SNI"),
        }
    }

    #[test]
    fn extract_sni_lowercases() {
        let buf = build_client_hello_with_sni("MyApp.MLSH.io");
        match extract_sni(&buf) {
            ParseResult::Sni(s) => assert_eq!(s, "myapp.mlsh.io"),
            _ => panic!("expected SNI"),
        }
    }

    #[test]
    fn extract_sni_needs_more_for_truncated_record() {
        let buf = build_client_hello_with_sni("app.mlsh.io");
        match extract_sni(&buf[..4]) {
            ParseResult::NeedMore => {}
            _ => panic!("expected NeedMore"),
        }
    }

    #[test]
    fn extract_sni_rejects_non_handshake() {
        let buf = vec![0x17, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0];
        match extract_sni(&buf) {
            ParseResult::Malformed(_) => {}
            _ => panic!("expected Malformed"),
        }
    }
}
