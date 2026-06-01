//! Watches the peer list from signal and supervises per-peer connection tasks.
//! For each peer: spawns the FSM driver which tries direct QUIC, falls back to relay.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use mlsh_protocol::types::{Candidate, PeerInfo};
use tokio::sync::watch;

use super::peer_table::PeerTable;
use super::{establish_peer_connection, PeerConnectionContext};

struct ActivePeer {
    handle: tokio::task::JoinHandle<()>,
    ip: Ipv4Addr,
    candidates: Vec<Candidate>,
    /// Per-peer child token. Cancelling it drives the FSM's `Cancelled`
    /// teardown (remove route) instead of `abort()`, which leaks the route.
    cancel: tokio_util::sync::CancellationToken,
}

impl ActivePeer {
    /// Cancel and await so the route is removed before the next `has_route`.
    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.handle.await;
    }
}

fn candidates_equal(a: &[Candidate], b: &[Candidate]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Order matters here: signal sorts by descending priority before sending,
    // so two semantically identical updates produce identical sequences.
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.kind == y.kind && x.addr == y.addr && x.priority == y.priority)
}

pub struct ConnectionManagerContext<'a> {
    pub cancel: &'a tokio_util::sync::CancellationToken,
    pub endpoint: &'a quinn::Endpoint,
    pub peer_table: &'a PeerTable,
    pub device: &'a Arc<tun_rs::AsyncDevice>,
    pub overlay_ip: Ipv4Addr,
    pub my_node_id: &'a str,
    pub cluster_id: &'a str,
    pub identity_dir: &'a std::path::Path,
    pub fsm_registry: &'a super::fsm::FsmRegistry,
}

pub async fn run_connection_manager(
    mut peers_rx: watch::Receiver<Arc<Vec<PeerInfo>>>,
    conn_rx: watch::Receiver<Option<quinn::Connection>>,
    ctx: &ConnectionManagerContext<'_>,
) {
    use std::collections::HashMap;

    // Track active peer tasks, their overlay IPs, and the candidate list we
    // last saw — needed to forward CandidatesUpdated events when signal pushes
    // a refreshed PeerJoined.
    let mut active_peers: HashMap<String, ActivePeer> = HashMap::new();
    let mut signal_conn_rx = conn_rx.clone();
    signal_conn_rx.borrow_and_update();

    // Process current peer list, then react to changes
    loop {
        let peers = Arc::clone(&peers_rx.borrow_and_update());

        // Find peers that left — cancel their tasks and remove routes
        let current_ids: std::collections::HashSet<&str> = peers
            .iter()
            .filter(|p| p.node_id != ctx.my_node_id)
            .map(|p| p.node_id.as_str())
            .collect();

        let removed: Vec<String> = active_peers
            .keys()
            .filter(|id| !current_ids.contains(id.as_str()))
            .cloned()
            .collect();

        for node_id in removed {
            if let Some(active) = active_peers.remove(&node_id) {
                tracing::info!("Peer {} left, tearing down connection task", node_id);
                active.shutdown().await;
            }
        }

        // Clean up finished tasks so they can be retried
        active_peers.retain(|node_id, active| {
            if active.handle.is_finished() {
                tracing::debug!("Connection task for {} finished, will retry", node_id);
                false
            } else {
                true
            }
        });

        // Forward refreshed candidate lists to FSMs of already-active peers.
        // Without this, the second `PeerJoined` (which carries host candidates
        // arriving after the initial srflx-only join) is silently dropped.
        for peer in peers.iter() {
            if peer.node_id == ctx.my_node_id {
                continue;
            }
            if let Some(active) = active_peers.get_mut(&peer.node_id) {
                if !candidates_equal(&active.candidates, &peer.candidates) {
                    active.candidates = peer.candidates.clone();
                    ctx.fsm_registry
                        .notify(
                            active.ip,
                            super::fsm::Event::__CandidatesUpdatedWith(peer.candidates.clone()),
                        )
                        .await;
                }
            }
        }

        // Find peers that need connections (new or finished tasks to retry)
        for peer in peers.iter() {
            if peer.node_id == ctx.my_node_id || active_peers.contains_key(&peer.node_id) {
                continue;
            }

            let peer_ip: Ipv4Addr = match peer.overlay_ip.parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            // Skip if we already have a working route (e.g. from relay_handler or quic_server)
            if ctx.peer_table.has_route(peer_ip).await {
                continue;
            }

            // Child token so tearing one peer down doesn't disturb the others.
            let peer_cancel = ctx.cancel.child_token();
            let peer_info = peer.clone();
            let cancel = peer_cancel.clone();
            let ep = ctx.endpoint.clone();
            let table = ctx.peer_table.clone();
            let dev = ctx.device.clone();
            let cid = ctx.cluster_id.to_string();
            let nid = ctx.my_node_id.to_string();
            let signal_conn = conn_rx.borrow().clone();
            let id_dir = ctx.identity_dir.to_path_buf();
            let overlay_ip = ctx.overlay_ip;

            let fsm_registry = ctx.fsm_registry.clone();
            let handle = tokio::spawn(async move {
                establish_peer_connection(PeerConnectionContext {
                    cancel,
                    endpoint: ep,
                    peer: peer_info,
                    peer_ip,
                    overlay_ip,
                    peer_table: table,
                    device: dev,
                    signal_conn,
                    cluster_id: cid,
                    my_node_id: nid,
                    identity_dir: id_dir,
                    fsm_registry,
                })
                .await;
            });

            active_peers.insert(
                peer.node_id.clone(),
                ActivePeer {
                    handle,
                    ip: peer_ip,
                    candidates: peer.candidates.clone(),
                    cancel: peer_cancel,
                },
            );
        }

        // Wait for peer list change OR signal reconnection (new connection available)
        tokio::select! {
            result = peers_rx.changed() => {
                if result.is_err() { break; }
            }
            _ = signal_conn_rx.changed() => {
                // Signal reconnected: tear down peer tasks (they hold the old
                // signal_conn) so the next iteration respawns them with the new one.
                tracing::debug!("Signal connection changed, tearing down peer tasks");
                let draining: Vec<(String, ActivePeer)> = active_peers.drain().collect();
                for (node_id, active) in draining {
                    active.shutdown().await;
                    tracing::debug!("Tore down peer task for {node_id}");
                }
            }
            _ = ctx.cancel.cancelled() => { break; }
            // Periodically check for finished tasks to retry
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }

    // Drain remaining peer tasks (parent cancel already fired).
    for (_, active) in active_peers {
        active.shutdown().await;
    }
}
