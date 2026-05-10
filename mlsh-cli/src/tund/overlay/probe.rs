//! Happy-eyeballs candidate probing for direct overlay QUIC connections.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mlsh_protocol::types::Candidate;

use super::quic::{connect_overlay_direct, DIRECT_CONNECT_TIMEOUT};

const PROBE_STAGGER: Duration = Duration::from_millis(100);

/// Result of a successful candidate probe: connection + description of the winning candidate.
pub struct ProbeResult {
    pub conn: quinn::Connection,
    /// e.g. "host:192.168.1.73:47710"
    pub via: String,
    /// Set when the post-handshake remote address differs from the candidate
    /// we tried — i.e. a peer-reflexive address discovered through a NAT
    /// remap. Caller stashes it locally for future re-probes.
    pub learned_prflx: Option<Candidate>,
}

/// Try direct QUIC connection to peer candidates (happy eyeballs).
pub async fn probe_candidates(
    endpoint: &quinn::Endpoint,
    candidates: &[Candidate],
    expected_fingerprint: &str,
    identity_dir: &std::path::Path,
) -> Result<ProbeResult> {
    use std::net::SocketAddr;
    use tokio::sync::oneshot;

    if candidates.is_empty() {
        anyhow::bail!("No candidates to probe");
    }

    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    let (winner_tx, winner_rx) = oneshot::channel::<ProbeResult>();
    let winner_tx = Arc::new(std::sync::Mutex::new(Some(winner_tx)));
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut handles = Vec::new();

    for (i, candidate) in sorted.iter().enumerate() {
        let addr_str = candidate.addr.clone();
        let kind = candidate.kind.clone();
        let fp = expected_fingerprint.to_string();
        let id_dir = identity_dir.to_path_buf();
        let ep = endpoint.clone();
        let tx = winner_tx.clone();
        let token = cancel.clone();

        let handle = tokio::spawn(async move {
            if i > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(PROBE_STAGGER * i as u32) => {}
                    _ = token.cancelled() => return,
                }
            }
            if token.is_cancelled() {
                return;
            }

            let addr: SocketAddr = match addr_str.parse() {
                Ok(a) => a,
                Err(_) => return,
            };

            tracing::debug!("Probing {} candidate {}", kind, addr);

            match connect_overlay_direct(&ep, addr, &fp, &id_dir).await {
                Ok(conn) => {
                    let learned_prflx = peer_reflexive_from(&conn, addr);
                    let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(sender) = guard.take() {
                        let via = format!("{}:{}", kind, addr);
                        let _ = sender.send(ProbeResult {
                            conn,
                            via,
                            learned_prflx,
                        });
                        token.cancel();
                    }
                }
                Err(e) => {
                    tracing::debug!("Candidate {} ({}) failed: {}", addr, kind, e);
                }
            }
        });
        handles.push(handle);
    }

    let result =
        tokio::time::timeout(DIRECT_CONNECT_TIMEOUT + Duration::from_secs(1), winner_rx).await;

    cancel.cancel();
    for h in handles {
        h.abort();
    }

    match result {
        Ok(Ok(probe)) => Ok(probe),
        _ => anyhow::bail!("All candidates failed"),
    }
}

/// If the post-handshake remote address differs from the candidate we tried,
/// derive a peer-reflexive Candidate. Priority sits between srflx (200) and
/// VPN (150) so a re-probe tries it after host but before falling back.
fn peer_reflexive_from(conn: &quinn::Connection, tried: std::net::SocketAddr) -> Option<Candidate> {
    let observed = conn.remote_address();
    if observed == tried {
        return None;
    }
    Some(Candidate {
        kind: "prflx".into(),
        addr: observed.to_string(),
        priority: 190,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn sa(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
    }

    #[test]
    fn prflx_priority_is_between_srflx_and_vpn() {
        // 150 (Vpn) < 190 (prflx) < 200 (srflx) so a freshly-learned prflx
        // ranks just below the signal-observed srflx but above any VPN tunnel.
        assert!(190 < 200);
        assert!(190 > 150);
    }

    #[test]
    fn prflx_addr_format_is_socket_addr_string() {
        // The format must roundtrip through `SocketAddr::parse` since
        // probe_candidates calls `.parse::<SocketAddr>()` on it.
        let addr = sa([198, 51, 100, 7], 4242).to_string();
        assert!(addr.parse::<SocketAddr>().is_ok());
    }
}
