//! Watches the peer list from signal and supervises per-peer connection tasks.
//! For each peer: spawns the FSM driver which tries direct QUIC, falls back to relay.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use mlsh_protocol::types::PeerInfo;
use tokio::sync::watch;

use super::peer_fsm_driver::{establish_peer_connection, PeerConnectionContext};
use super::peer_table::PeerTable;

pub struct ConnectionManagerContext<'a> {
    pub cancel: &'a tokio_util::sync::CancellationToken,
    pub endpoint: &'a quinn::Endpoint,
    pub peer_table: &'a PeerTable,
    pub device: &'a Arc<tun_rs::AsyncDevice>,
    pub overlay_ip: Ipv4Addr,
    pub my_node_id: &'a str,
    pub cluster_id: &'a str,
    pub identity_dir: &'a std::path::Path,
    pub fsm_registry: &'a super::peer_fsm::FsmRegistry,
}

pub async fn run_connection_manager(
    mut peers_rx: watch::Receiver<Arc<Vec<PeerInfo>>>,
    conn_rx: watch::Receiver<Option<quinn::Connection>>,
    ctx: &ConnectionManagerContext<'_>,
) {
    use std::collections::HashMap;

    // Track active peer tasks and their overlay IPs for cleanup
    let mut active_peers: HashMap<String, (tokio::task::JoinHandle<()>, Ipv4Addr)> = HashMap::new();
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
            if let Some((handle, _ip)) = active_peers.remove(&node_id) {
                tracing::info!("Peer {} left, aborting connection task", node_id);
                handle.abort();
                // Don't remove the route here — the quic_server may have
                // inserted a newer direct route for this peer. Routes are
                // cleaned up when the actual QUIC connection closes (in
                // establish_peer_connection or quic_server::accept_loop).
            }
        }

        // Clean up finished tasks so they can be retried
        active_peers.retain(|node_id, (handle, _ip)| {
            if handle.is_finished() {
                tracing::debug!("Connection task for {} finished, will retry", node_id);
                false
            } else {
                true
            }
        });

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

            // Spawn a task to establish connection to this peer
            let peer_info = peer.clone();
            let cancel = ctx.cancel.clone();
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

            active_peers.insert(peer.node_id.clone(), (handle, peer_ip));
        }

        // Wait for peer list change OR signal reconnection (new connection available)
        tokio::select! {
            result = peers_rx.changed() => {
                if result.is_err() { break; }
            }
            _ = signal_conn_rx.changed() => {
                // Signal reconnected. Peer tasks captured the old signal_conn
                // at spawn time; abort them so the next iteration respawns
                // them with the fresh connection. Routes they installed are
                // cleaned up as part of their Cancelled transition.
                tracing::debug!("Signal connection changed, aborting peer tasks");
                for (node_id, (handle, ip)) in active_peers.drain() {
                    handle.abort();
                    ctx.peer_table.remove_route(ip).await;
                    ctx.fsm_registry.unregister(ip).await;
                    tracing::debug!("Aborted peer task for {node_id}");
                }
            }
            _ = ctx.cancel.cancelled() => { break; }
            // Periodically check for finished tasks to retry
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }

    // Clean up all active peer tasks
    for (_, (handle, _)) in active_peers {
        handle.abort();
    }
}
