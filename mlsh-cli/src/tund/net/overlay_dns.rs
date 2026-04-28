//! Lightweight overlay DNS resolver for mlshtund.
//!
//! Listens on UDP port 53 on the overlay IP and resolves:
//! - `<node-id>.<cluster-name>` → overlay IP (A record)
//! - `<cluster-name>` → first node's overlay IP (A record)
//!
//! Resolution uses the in-memory peer list from signal (no database).

use std::net::{Ipv4Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::tund::overlay::peer_table::PeerTable;

const RCODE_OK: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Overlay DNS configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub bind_addr: SocketAddr,
    pub zone: String,
    pub ttl: u32,
}

/// Run the overlay DNS server. Blocks until shutdown.
pub async fn run(
    config: DnsConfig,
    my_ip: Ipv4Addr,
    my_node_id: String,
    my_display_name: watch::Receiver<String>,
    peer_table: PeerTable,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    // Mark current value as seen to avoid missing a shutdown set before we start
    shutdown.borrow_and_update();

    let socket = UdpSocket::bind(config.bind_addr).await?;
    tracing::info!(
        "Overlay DNS listening on {} for zone '{}'",
        config.bind_addr,
        config.zone
    );

    let mut buf = vec![0u8; 512];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        let query = &buf[..len];
                        let display_name = my_display_name.borrow().clone();
                        let response = handle_query(query, &config, my_ip, &my_node_id, &display_name, &peer_table).await;
                        if let Ok(resp) = response {
                            let _ = socket.send_to(&resp, src).await;
                        }
                    }
                    Err(e) => {
                        tracing::error!("DNS recv error: {}", e);
                    }
                }
            }
            _ = shutdown.changed() => {
                tracing::info!("Overlay DNS shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_query(
    query: &[u8],
    config: &DnsConfig,
    my_ip: Ipv4Addr,
    my_node_id: &str,
    my_display_name: &str,
    peer_table: &PeerTable,
) -> Result<Vec<u8>, DnsError> {
    if query.len() < 12 {
        return Err(DnsError::TooShort);
    }

    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);

    let opcode = (flags >> 11) & 0xF;
    if opcode != 0 || qdcount == 0 {
        return Ok(build_response(id, RCODE_NXDOMAIN, query, None, config.ttl));
    }

    let (qname, qtype, qclass, _) = parse_question(&query[12..])?;

    if qclass != CLASS_IN {
        return Ok(build_response(id, RCODE_NXDOMAIN, query, None, config.ttl));
    }

    let ip = resolve(
        &qname,
        config,
        my_ip,
        my_node_id,
        my_display_name,
        peer_table,
    )
    .await;

    match (ip, qtype) {
        (Some(addr), TYPE_A) => Ok(build_response(id, RCODE_OK, query, Some(addr), config.ttl)),
        // Name exists in the zone but no record for this qtype → NOERROR/NODATA.
        // Returning NXDOMAIN here causes negative caching of the whole name on
        // resolvers that query A and AAAA in parallel (e.g. macOS mDNSResponder).
        (Some(_), _) => Ok(build_response(id, RCODE_OK, query, None, config.ttl)),
        (None, _) => Ok(build_response(id, RCODE_NXDOMAIN, query, None, config.ttl)),
    }
}

/// Resolve a DNS name against the peer table.
async fn resolve(
    name: &str,
    config: &DnsConfig,
    my_ip: Ipv4Addr,
    my_node_id: &str,
    my_display_name: &str,
    peer_table: &PeerTable,
) -> Option<Ipv4Addr> {
    let name = name.strip_suffix('.').unwrap_or(name).to_lowercase();
    let zone = config.zone.to_lowercase();

    // Bare zone → self
    if name == zone {
        return Some(my_ip);
    }

    let suffix = format!(".{}", zone);
    if !name.ends_with(&suffix) {
        return None;
    }

    let label = &name[..name.len() - suffix.len()];
    if label.is_empty() {
        return None;
    }

    if label == my_node_id {
        return Some(my_ip);
    }

    if !my_display_name.is_empty() && sanitize_dns_label(my_display_name) == label {
        return Some(my_ip);
    }

    let peers = peer_table.known_peers().await;

    if let Some(p) = peers.iter().find(|p| p.node_id.to_lowercase() == label) {
        return p.overlay_ip.parse().ok();
    }

    peers
        .iter()
        .find(|p| !p.display_name.is_empty() && sanitize_dns_label(&p.display_name) == label)
        .and_then(|p| p.overlay_ip.parse().ok())
}

/// Sanitize a user-entered display name into a valid DNS label per RFC 1035.
pub(crate) fn sanitize_dns_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_hyphen = false;
    for ch in input.chars() {
        let mapped = match ch {
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            'a'..='z' | '0'..='9' => Some(ch),
            ' ' | '_' | '.' | '-' => Some('-'),
            _ => None,
        };
        match mapped {
            Some('-') => {
                if !prev_hyphen && !out.is_empty() {
                    out.push('-');
                    prev_hyphen = true;
                }
            }
            Some(c) => {
                out.push(c);
                prev_hyphen = false;
            }
            None => {}
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.len() > 63 {
        out.truncate(63);
        while out.ends_with('-') {
            out.pop();
        }
    }
    out
}

fn build_response(id: u16, rcode: u8, query: &[u8], answer: Option<Ipv4Addr>, ttl: u32) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);

    // Header
    resp.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = 0x8000 | 0x0400 | (rcode as u16); // QR=1, AA=1
    resp.extend_from_slice(&flags.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount: u16 = if answer.is_some() { 1 } else { 0 };
    resp.extend_from_slice(&ancount.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Copy question section
    if query.len() > 12 {
        let mut pos = 12;
        while pos < query.len() && query[pos] != 0 {
            let label_len = query[pos] as usize;
            pos += 1 + label_len;
        }
        pos += 1 + 4; // null terminator + QTYPE + QCLASS
        if pos <= query.len() {
            resp.extend_from_slice(&query[12..pos]);
        }
    }

    // Answer
    if let Some(ip) = answer {
        resp.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to name at offset 12
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets());
    }

    resp
}

fn parse_question(data: &[u8]) -> Result<(String, u16, u16, usize), DnsError> {
    let mut pos = 0;
    let mut labels = Vec::new();

    loop {
        if pos >= data.len() {
            return Err(DnsError::Truncated);
        }
        let label_len = data[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if pos + label_len > data.len() {
            return Err(DnsError::Truncated);
        }
        let label =
            std::str::from_utf8(&data[pos..pos + label_len]).map_err(|_| DnsError::InvalidLabel)?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if pos + 4 > data.len() {
        return Err(DnsError::Truncated);
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    pos += 4;

    Ok((labels.join("."), qtype, qclass, pos))
}

#[derive(Debug)]
enum DnsError {
    TooShort,
    Truncated,
    InvalidLabel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlsh_protocol::types::PeerInfo;

    fn make_a_query(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1
        buf.extend_from_slice(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: encode name as DNS labels
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // terminator
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn parse_question_simple() {
        let mut data = Vec::new();
        data.push(3);
        data.extend_from_slice(b"nas");
        data.push(7);
        data.extend_from_slice(b"homelab");
        data.push(0);
        data.extend_from_slice(&TYPE_A.to_be_bytes());
        data.extend_from_slice(&CLASS_IN.to_be_bytes());

        let (name, qtype, qclass, _) = parse_question(&data).unwrap();
        assert_eq!(name, "nas.homelab");
        assert_eq!(qtype, TYPE_A);
        assert_eq!(qclass, CLASS_IN);
    }

    #[tokio::test]
    async fn resolve_bare_zone_returns_self() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        let my_ip = Ipv4Addr::new(100, 64, 0, 1);

        let ip = resolve("homelab", &config, my_ip, "nas", "", &table).await;
        assert_eq!(ip, Some(my_ip));
    }

    #[tokio::test]
    async fn resolve_self_node() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        let my_ip = Ipv4Addr::new(100, 64, 0, 1);

        let ip = resolve("nas.homelab", &config, my_ip, "nas", "", &table).await;
        assert_eq!(ip, Some(my_ip));
    }

    #[tokio::test]
    async fn resolve_peer_node() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        table
            .update_peers(std::sync::Arc::new(vec![PeerInfo {
                node_id: "pi".into(),
                fingerprint: "fp".into(),
                overlay_ip: "100.64.0.2".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
                role: String::new(),
            }]))
            .await;

        let ip = resolve(
            "pi.homelab",
            &config,
            Ipv4Addr::new(100, 64, 0, 1),
            "nas",
            "",
            &table,
        )
        .await;
        assert_eq!(ip, Some(Ipv4Addr::new(100, 64, 0, 2)));
    }

    #[test]
    fn sanitize_label_rules() {
        assert_eq!(sanitize_dns_label("NAS"), "nas");
        assert_eq!(sanitize_dns_label("Rack Toulouse NUC"), "rack-toulouse-nuc");
        assert_eq!(sanitize_dns_label("pi_hole.dns"), "pi-hole-dns");
        assert_eq!(sanitize_dns_label("Nico's laptop"), "nicos-laptop");
        assert_eq!(sanitize_dns_label("  --weird__.name--  "), "weird-name");
        assert_eq!(sanitize_dns_label(""), "");
        assert_eq!(sanitize_dns_label("---"), "");
        let long = "a".repeat(100);
        assert_eq!(sanitize_dns_label(&long).len(), 63);
        // truncation must not leave a trailing hyphen
        let tricky = format!("{}-tail", "a".repeat(62));
        assert!(!sanitize_dns_label(&tricky).ends_with('-'));
    }

    #[tokio::test]
    async fn resolve_by_display_name() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        table
            .update_peers(std::sync::Arc::new(vec![PeerInfo {
                node_id: "a3f8b2c1-uuid".into(),
                fingerprint: "fp".into(),
                overlay_ip: "100.64.0.5".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: "Rack Toulouse NUC".into(),
                role: String::new(),
            }]))
            .await;

        let ip = resolve(
            "rack-toulouse-nuc.homelab",
            &config,
            Ipv4Addr::new(100, 64, 0, 1),
            "nas",
            "",
            &table,
        )
        .await;
        assert_eq!(ip, Some(Ipv4Addr::new(100, 64, 0, 5)));
    }

    #[tokio::test]
    async fn node_id_takes_priority_over_display_name() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        table
            .update_peers(std::sync::Arc::new(vec![
                PeerInfo {
                    node_id: "pi".into(),
                    fingerprint: "fp1".into(),
                    overlay_ip: "100.64.0.2".into(),
                    candidates: vec![],
                    public_key: String::new(),
                    admission_cert: String::new(),
                    display_name: "Other".into(),
                    role: String::new(),
                },
                PeerInfo {
                    node_id: "xyz".into(),
                    fingerprint: "fp2".into(),
                    overlay_ip: "100.64.0.3".into(),
                    candidates: vec![],
                    public_key: String::new(),
                    admission_cert: String::new(),
                    display_name: "pi".into(),
                    role: String::new(),
                },
            ]))
            .await;

        let ip = resolve(
            "pi.homelab",
            &config,
            Ipv4Addr::new(100, 64, 0, 1),
            "nas",
            "",
            &table,
        )
        .await;
        assert_eq!(ip, Some(Ipv4Addr::new(100, 64, 0, 2)));
    }

    #[tokio::test]
    async fn resolve_unknown_returns_none() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();

        let ip = resolve(
            "unknown.homelab",
            &config,
            Ipv4Addr::new(100, 64, 0, 1),
            "nas",
            "",
            &table,
        )
        .await;
        assert!(ip.is_none());
    }

    #[tokio::test]
    async fn resolve_wrong_zone_returns_none() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();

        let ip = resolve(
            "nas.other",
            &config,
            Ipv4Addr::new(100, 64, 0, 1),
            "nas",
            "",
            &table,
        )
        .await;
        assert!(ip.is_none());
    }

    #[tokio::test]
    async fn handle_query_returns_answer() {
        let config = DnsConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            zone: "homelab".into(),
            ttl: 60,
        };
        let table = PeerTable::new();
        let my_ip = Ipv4Addr::new(100, 64, 0, 1);

        let query = make_a_query("homelab");
        let resp = handle_query(&query, &config, my_ip, "nas", "", &table)
            .await
            .unwrap();

        // Check response: QR=1, ANCOUNT=1
        assert_eq!(resp[2] & 0x80, 0x80); // QR bit
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert_eq!(ancount, 1);
    }
}
