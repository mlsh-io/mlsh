//! In-memory store of active node sessions.
//!
//! Tracks which nodes are connected, their QUIC connections, overlay IPs,
//! candidates, and push channels for server-initiated messages.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::protocol::{Candidate, PeerInfo, ServerMessage};

/// A connected node session.
struct NodeSession {
    connection: quinn::Connection,
    /// Channel for pushing messages (PeerJoined/PeerLeft).
    push_tx: Option<tokio::sync::mpsc::UnboundedSender<Arc<ServerMessage>>>,
    node_id: String,
    fingerprint: String,
    overlay_ip: std::net::Ipv4Addr,
    host_candidates: Vec<Candidate>,
    public_key: String,
    admission_cert: String,
    session_id: u64,
}

/// Information needed to register a node session.
pub struct NodeSessionInfo {
    pub node_id: String,
    pub fingerprint: String,
    pub overlay_ip: std::net::Ipv4Addr,
    pub connection: quinn::Connection,
    pub push_tx: tokio::sync::mpsc::UnboundedSender<Arc<ServerMessage>>,
    pub public_key: String,
    pub admission_cert: String,
}

/// Thread-safe store of active node sessions, keyed by (cluster_id, node_id).
pub struct SessionStore {
    sessions: RwLock<HashMap<(String, String), NodeSession>>,
}

impl SessionStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Register a node session. Replaces any existing session for this node.
    pub async fn register(&self, cluster_id: &str, info: NodeSessionInfo, session_id: u64) {
        let key = (cluster_id.to_string(), info.node_id.clone());
        let node_id = info.node_id.clone();
        let overlay_ip = info.overlay_ip;
        let session = NodeSession {
            connection: info.connection,
            push_tx: Some(info.push_tx),
            node_id: info.node_id,
            fingerprint: info.fingerprint,
            overlay_ip: info.overlay_ip,
            host_candidates: Vec::new(),
            public_key: info.public_key,
            admission_cert: info.admission_cert,
            session_id,
        };
        self.sessions.write().await.insert(key, session);
        tracing::info!(cluster_id, %node_id, %overlay_ip, "Node session registered");
    }

    /// Remove a node session. Only removes if session_id matches.
    /// Returns true if the session was actually removed.
    pub async fn deregister(&self, cluster_id: &str, node_id: &str, session_id: u64) -> bool {
        let key = (cluster_id.to_string(), node_id.to_string());
        let mut sessions = self.sessions.write().await;
        if let Some(existing) = sessions.get(&key) {
            if existing.session_id == session_id {
                sessions.remove(&key);
                tracing::info!(cluster_id, node_id, "Node session deregistered");
                return true;
            }
        }
        false
    }

    /// Update host candidates for a node.
    pub async fn set_candidates(
        &self,
        cluster_id: &str,
        node_id: &str,
        candidates: Vec<Candidate>,
    ) {
        let key = (cluster_id.to_string(), node_id.to_string());
        if let Some(session) = self.sessions.write().await.get_mut(&key) {
            session.host_candidates = candidates;
        }
    }

    /// Get peer info for all connected nodes in a cluster (excluding a specific node).
    pub async fn get_peer_list(&self, cluster_id: &str, exclude_node: &str) -> Vec<PeerInfo> {
        let sessions = self.sessions.read().await;
        sessions
            .iter()
            .filter(|((cid, _), _)| cid == cluster_id)
            .filter(|((_, nid), _)| nid != exclude_node)
            .map(|(_, s)| {
                let mut candidates = s.host_candidates.clone();
                candidates.push(Candidate {
                    kind: "srflx".into(),
                    addr: s.connection.remote_address().to_string(),
                    priority: 200,
                });
                candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
                PeerInfo {
                    node_id: s.node_id.clone(),
                    fingerprint: s.fingerprint.clone(),
                    overlay_ip: s.overlay_ip.to_string(),
                    candidates,
                    public_key: s.public_key.clone(),
                    admission_cert: s.admission_cert.clone(),
                }
            })
            .collect()
    }

    /// Broadcast a message to all connected nodes in a cluster.
    pub async fn broadcast(&self, cluster_id: &str, msg: ServerMessage) {
        let msg = Arc::new(msg);
        let sessions = self.sessions.read().await;
        for ((cid, _), session) in sessions.iter() {
            if cid == cluster_id {
                if let Some(ref tx) = session.push_tx {
                    let _ = tx.send(Arc::clone(&msg));
                }
            }
        }
    }

    /// Notify all connected peers in a cluster that a new peer has joined.
    pub async fn notify_peer_joined(&self, cluster_id: &str, peer: PeerInfo) {
        self.broadcast(cluster_id, ServerMessage::PeerJoined { peer })
            .await;
    }

    /// Notify all connected peers in a cluster that a peer has left.
    pub async fn notify_peer_left(&self, cluster_id: &str, node_id: &str) {
        self.broadcast(
            cluster_id,
            ServerMessage::PeerLeft {
                node_id: node_id.to_string(),
                cluster_id: cluster_id.to_string(),
            },
        )
        .await;
    }

    /// Get a specific node's QUIC connection.
    pub async fn get_node_connection(
        &self,
        cluster_id: &str,
        node_id: &str,
    ) -> Option<quinn::Connection> {
        let key = (cluster_id.to_string(), node_id.to_string());
        let sessions = self.sessions.read().await;
        let session = sessions.get(&key)?;
        if session.connection.close_reason().is_some() {
            return None;
        }
        Some(session.connection.clone())
    }

    /// Get any node's connection in the cluster other than the specified one.
    pub async fn get_other_node_connection(
        &self,
        cluster_id: &str,
        exclude_node_id: &str,
    ) -> Option<(String, quinn::Connection)> {
        let sessions = self.sessions.read().await;
        for ((cid, nid), session) in sessions.iter() {
            if cid == cluster_id
                && nid != exclude_node_id
                && session.connection.close_reason().is_none()
            {
                return Some((nid.clone(), session.connection.clone()));
            }
        }
        None
    }

    /// Force-disconnect all nodes in a cluster.
    pub async fn kick_all(&self, cluster_id: &str) {
        let mut sessions = self.sessions.write().await;
        let keys: Vec<_> = sessions
            .keys()
            .filter(|(cid, _)| cid == cluster_id)
            .cloned()
            .collect();
        for key in keys {
            if let Some(session) = sessions.remove(&key) {
                session
                    .connection
                    .close(quinn::VarInt::from_u32(2), b"cluster deleted");
            }
        }
        tracing::info!(cluster_id, "All nodes kicked (cluster deleted)");
    }

    /// Force-disconnect a node: remove its session and close its QUIC connection.
    pub async fn kick_node(&self, cluster_id: &str, node_id: &str) {
        let key = (cluster_id.to_string(), node_id.to_string());
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(&key) {
            session
                .connection
                .close(quinn::VarInt::from_u32(1), b"revoked");
            tracing::info!(cluster_id, node_id, "Node kicked (revoked)");
        }
    }

    /// Return online counts for all clusters.
    pub async fn all_online_counts(&self) -> Vec<(String, usize)> {
        let sessions = self.sessions.read().await;
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (cid, _) in sessions.keys() {
            *counts.entry(cid.as_str()).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    /// Return the number of active sessions in this cluster.
    pub async fn online_count(&self, cluster_id: &str) -> usize {
        let sessions = self.sessions.read().await;
        sessions.keys().filter(|(cid, _)| cid == cluster_id).count()
    }

    /// Return the set of node_ids that have an active session in this cluster.
    pub async fn online_node_ids(&self, cluster_id: &str) -> HashSet<String> {
        let sessions = self.sessions.read().await;
        sessions
            .keys()
            .filter(|(cid, _)| cid == cluster_id)
            .map(|(_, nid)| nid.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_store_is_empty() {
        let store = SessionStore::new();
        assert!(store.online_node_ids("any").await.is_empty());
        assert!(store.get_node_connection("c", "n").await.is_none());
        assert!(store.get_other_node_connection("c", "n").await.is_none());
    }
}
