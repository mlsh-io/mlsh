//! Happy-eyeballs candidate probing for direct overlay QUIC connections.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mlsh_protocol::types::Candidate;

use super::quic_client::{connect_overlay_direct, DIRECT_CONNECT_TIMEOUT};

const PROBE_STAGGER: Duration = Duration::from_millis(100);

/// Result of a successful candidate probe: connection + description of the winning candidate.
pub struct ProbeResult {
    pub conn: quinn::Connection,
    /// e.g. "host:192.168.1.73:47710"
    pub via: String,
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
                    let mut guard = tx.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(sender) = guard.take() {
                        let via = format!("{}:{}", kind, addr);
                        let _ = sender.send(ProbeResult { conn, via });
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
