//! In-memory overlay routing table for mlshtund.
//!
//! Maps overlay IPs to either direct QUIC connections or relay channels.
//! Updated reactively from signal session's peer list.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};

use mlsh_protocol::types::PeerInfo;

/// Validate an inbound IP packet before writing to the TUN device.
/// Checks: IPv4 version, minimum length, destination within overlay range.
pub fn validate_inbound_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    // Must be IPv4
    if pkt[0] >> 4 != 4 {
        return false;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    // Reject packets targeting loopback or link-local
    if dst.is_loopback() || dst.is_link_local() || dst.is_broadcast() {
        return false;
    }
    true
}

/// A route to a peer — either a direct QUIC connection or a relay channel.
pub enum PeerRoute {
    /// Direct QUIC connection to the peer.
    Direct(quinn::Connection),
    /// Relay through signal — send packets to this channel.
    Relay(mpsc::Sender<Vec<u8>>),
}

/// Cloned route handle for lock-free async I/O.
enum RouteHandle {
    Direct(quinn::Connection),
    Relay(mpsc::Sender<Vec<u8>>),
}

/// Thread-safe overlay routing table.
#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<RwLock<PeerTableInner>>,
    /// Shared RX byte counter (incremented when writing to TUN).
    pub bytes_rx: Arc<AtomicU64>,
    /// TUN device name for OS-level /32 route management.
    tun_name: Arc<String>,
}

struct PeerTableInner {
    /// Known peers from signal (for DNS and candidate probing).
    /// Arc-wrapped for cheap sharing with DNS and other readers.
    known_peers: Arc<Vec<PeerInfo>>,
    /// Active routes (established connections).
    routes: HashMap<Ipv4Addr, PeerRoute>,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    pub fn new() -> Self {
        Self::with_tun_name(String::new())
    }

    /// Create a PeerTable bound to a specific TUN device for OS route management.
    pub fn with_tun_name(tun_name: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerTableInner {
                known_peers: Arc::new(Vec::new()),
                routes: HashMap::new(),
            })),
            bytes_rx: Arc::new(AtomicU64::new(0)),
            tun_name: Arc::new(tun_name),
        }
    }

    /// Record inbound bytes (called when writing received packets to TUN).
    pub fn record_rx(&self, n: usize) {
        self.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Update the known peers list (from signal session).
    pub async fn update_peers(&self, peers: Arc<Vec<PeerInfo>>) {
        self.inner.write().await.known_peers = peers;
    }

    /// Get the known peers list (cheap Arc clone).
    pub async fn known_peers(&self) -> Arc<Vec<PeerInfo>> {
        Arc::clone(&self.inner.read().await.known_peers)
    }

    /// Look up a peer by overlay IP.
    pub async fn lookup_peer(&self, ip: Ipv4Addr) -> Option<PeerInfo> {
        let inner = self.inner.read().await;
        inner
            .known_peers
            .iter()
            .find(|p| p.overlay_ip.parse::<Ipv4Addr>().ok() == Some(ip))
            .cloned()
    }

    /// Insert a direct connection route and add OS-level /32 route.
    pub async fn insert_direct(&self, ip: Ipv4Addr, conn: quinn::Connection) {
        let is_new = !self.inner.read().await.routes.contains_key(&ip);
        self.inner
            .write()
            .await
            .routes
            .insert(ip, PeerRoute::Direct(conn));
        if is_new && !self.tun_name.is_empty() {
            super::routes::add_peer_route(ip, &self.tun_name);
        }
    }

    /// Insert a relay route and add OS-level /32 route.
    pub async fn insert_relay(&self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        let is_new = !self.inner.read().await.routes.contains_key(&ip);
        self.inner
            .write()
            .await
            .routes
            .insert(ip, PeerRoute::Relay(tx));
        if is_new && !self.tun_name.is_empty() {
            super::routes::add_peer_route(ip, &self.tun_name);
        }
    }

    /// Remove a route and the OS-level /32 route.
    pub async fn remove_route(&self, ip: Ipv4Addr) {
        let removed = self.inner.write().await.routes.remove(&ip).is_some();
        if removed && !self.tun_name.is_empty() {
            super::routes::remove_peer_route(ip);
        }
    }

    /// Remove a route only if it is still a relay (not upgraded to direct).
    /// Returns `true` if the relay was removed.
    pub async fn remove_relay_only(&self, ip: Ipv4Addr) -> bool {
        let mut inner = self.inner.write().await;
        if matches!(inner.routes.get(&ip), Some(PeerRoute::Relay(_))) {
            inner.routes.remove(&ip);
            drop(inner);
            if !self.tun_name.is_empty() {
                super::routes::remove_peer_route(ip);
            }
            true
        } else {
            false
        }
    }

    /// Check if any route (direct or relay) exists for an IP.
    pub async fn has_route(&self, ip: Ipv4Addr) -> bool {
        self.inner.read().await.routes.contains_key(&ip)
    }

    /// Get a direct connection for an IP, if available.
    pub async fn get_direct(&self, ip: Ipv4Addr) -> Option<quinn::Connection> {
        let inner = self.inner.read().await;
        match inner.routes.get(&ip) {
            Some(PeerRoute::Direct(conn)) if conn.close_reason().is_none() => Some(conn.clone()),
            _ => None,
        }
    }

    /// Get a relay sender for an IP, if available.
    pub async fn get_relay(&self, ip: Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
        let inner = self.inner.read().await;
        match inner.routes.get(&ip) {
            Some(PeerRoute::Relay(tx)) => Some(tx.clone()),
            _ => None,
        }
    }

    /// Number of active routes.
    pub async fn route_count(&self) -> usize {
        self.inner.read().await.routes.len()
    }

    /// Number of known peers.
    pub async fn peer_count(&self) -> usize {
        self.inner.read().await.known_peers.len()
    }

    /// Send a packet to a peer by overlay IP using the routing table.
    /// Returns `true` if the packet was sent (or queued), `false` if no route exists.
    pub async fn send_packet(&self, dst: Ipv4Addr, packet: &[u8]) -> bool {
        // Clone the route handle under the lock, then release the lock before any async I/O
        let route = {
            let inner = self.inner.read().await;
            match inner.routes.get(&dst) {
                Some(PeerRoute::Direct(conn)) => Some(RouteHandle::Direct(conn.clone())),
                Some(PeerRoute::Relay(tx)) => Some(RouteHandle::Relay(tx.clone())),
                None => None,
            }
        };

        match route {
            Some(RouteHandle::Direct(conn)) => {
                if let Ok(mut s) = conn.open_uni().await {
                    let len = (packet.len() as u32).to_be_bytes();
                    let _ = s.write_all(&len).await;
                    let _ = s.write_all(packet).await;
                    let _ = s.finish();
                    true
                } else {
                    false
                }
            }
            Some(RouteHandle::Relay(tx)) => tx.try_send(packet.to_vec()).is_ok(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_table_is_empty() {
        let table = PeerTable::new();
        assert_eq!(table.route_count().await, 0);
        assert_eq!(table.peer_count().await, 0);
    }

    #[tokio::test]
    async fn update_and_lookup_peers() {
        let table = PeerTable::new();
        let peers = vec![
            PeerInfo {
                node_id: "nas".into(),
                fingerprint: "fp-1".into(),
                overlay_ip: "100.64.0.1".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
            },
            PeerInfo {
                node_id: "pi".into(),
                fingerprint: "fp-2".into(),
                overlay_ip: "100.64.0.2".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
            },
        ];
        table.update_peers(Arc::new(peers)).await;
        assert_eq!(table.peer_count().await, 2);

        let found = table.lookup_peer(Ipv4Addr::new(100, 64, 0, 1)).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().node_id, "nas");

        assert!(table
            .lookup_peer(Ipv4Addr::new(100, 64, 0, 99))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn insert_and_remove_relay() {
        let table = PeerTable::new();
        let (tx, _rx) = mpsc::channel(16);
        let ip = Ipv4Addr::new(100, 64, 0, 5);

        table.insert_relay(ip, tx).await;
        assert_eq!(table.route_count().await, 1);
        assert!(table.get_relay(ip).await.is_some());
        assert!(table.get_direct(ip).await.is_none());

        table.remove_route(ip).await;
        assert_eq!(table.route_count().await, 0);
    }
}
