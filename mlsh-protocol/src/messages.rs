//! Wire protocol message types for QUIC signal streams.
//!
//! Session messages use a long-lived bidirectional stream.
//! The `type` field determines the message kind via serde tagging.

use serde::{Deserialize, Serialize};

use crate::types::{Candidate, NodeInfo, PeerInfo};

// --- Client → Server

/// Union of all client-to-server message types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamMessage {
    Ping,

    /// Node reports its candidate addresses (host IPs on QUIC port).
    ReportCandidates {
        candidates: Vec<Candidate>,
    },

    /// Relay stream request (opens bidirectional relay through signal).
    /// Caller is authenticated via TLS client certificate.
    RelayOpen {
        cluster_id: String,
        node_id: String,
        /// Target peer to relay to. If empty, signal picks the first available.
        #[serde(default)]
        target_node_id: String,
    },

    /// Node authentication via TLS client certificate.
    /// Signal extracts the fingerprint from the QUIC connection's client cert
    /// and looks it up in the node registry — no shared secret needed.
    NodeAuth {
        cluster_id: String,
        #[serde(default)]
        public_key: String,
    },

    /// New node onboarding: register with a pre-auth (invite) token.
    Adopt {
        cluster_id: String,
        pre_auth_token: String,
        fingerprint: String,
        node_id: String,
        /// Ed25519 public key (base64url, 32 bytes) for signature verification.
        #[serde(default)]
        public_key: String,
        #[serde(default)]
        expires_at: u64,
        /// Self-signed admission cert (JSON, for root admin setup).
        #[serde(default)]
        admission_cert: String,
    },

    /// Admin revocation: remove a node from the cluster.
    /// Caller is authenticated via TLS client certificate.
    Revoke {
        cluster_id: String,
        target_node_id: String,
    },

    /// Change a node's role (admin only). The caller signs a new admission cert.
    Promote {
        cluster_id: String,
        target_node_id: String,
        new_role: String,
        /// New admission cert signed by the caller (JSON-serialized).
        admission_cert: String,
    },

    /// List all nodes in the cluster (sent within an authenticated session).
    ListNodes,
}

// --- Server → Client

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Pong,

    /// Relay stream is ready (bidirectional splicing active).
    RelayReady,

    // Per-node keypair auth responses
    NodeAuthOk {
        cluster_id: String,
        overlay_ip: String,
        overlay_subnet: String,
        peers: Vec<PeerInfo>,
    },
    AdoptOk {
        cluster_id: String,
        node_id: String,
        overlay_ip: String,
        overlay_subnet: String,
        peers: Vec<PeerInfo>,
    },

    /// Pushed to all connected peers when a new node joins.
    PeerJoined {
        peer: PeerInfo,
    },
    /// Pushed to all connected peers when a node leaves or is revoked.
    PeerLeft {
        node_id: String,
        cluster_id: String,
    },
    RevokeOk,
    PromoteOk,

    /// Pushed to all connected peers when a node's role changes.
    PeerUpdated {
        node_id: String,
        cluster_id: String,
        new_role: String,
        admission_cert: String,
    },

    /// Response to ListNodes: all registered nodes with online/offline status.
    NodeList {
        nodes: Vec<NodeInfo>,
    },

    // Shared
    Error {
        code: String,
        message: String,
    },
}

impl ServerMessage {
    pub fn error(code: &str, message: &str) -> Self {
        Self::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

// --- Relay handshake

/// Messages exchanged on relay bi-streams between signal and peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMessage {
    /// Signal → target peer: incoming relay from another node.
    RelayIncoming { from_node_id: String },
    /// Target peer → signal: relay accepted.
    RelayAccepted,
}

// --- Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_error() {
        let msg = ServerMessage::error("E01", "bad");
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "error");
        assert_eq!(v["code"], "E01");
    }

    #[test]
    fn deserialize_report_candidates() {
        let msg: StreamMessage = serde_json::from_str(
            r#"{"type":"report_candidates","candidates":[{"kind":"host","addr":"192.168.1.10:4433","priority":100}]}"#
        ).unwrap();
        match msg {
            StreamMessage::ReportCandidates { candidates } => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].kind, "host");
            }
            _ => panic!("expected ReportCandidates"),
        }
    }

    #[test]
    fn deserialize_relay_open() {
        let msg: StreamMessage =
            serde_json::from_str(r#"{"type":"relay_open","cluster_id":"c1","node_id":"n1"}"#)
                .unwrap();
        match msg {
            StreamMessage::RelayOpen {
                cluster_id,
                node_id,
                target_node_id,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(node_id, "n1");
                assert!(target_node_id.is_empty());
            }
            _ => panic!("expected RelayOpen"),
        }
    }

    #[test]
    fn serialize_relay_ready() {
        let msg = ServerMessage::RelayReady;
        let v = serde_json::to_value(&msg).unwrap();
        assert_eq!(v["type"], "relay_ready");
    }

    #[test]
    fn relay_message_roundtrip() {
        let msg = RelayMessage::RelayIncoming {
            from_node_id: "node1".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            RelayMessage::RelayIncoming { from_node_id } => {
                assert_eq!(from_node_id, "node1");
            }
            _ => panic!("expected RelayIncoming"),
        }
    }

    #[test]
    fn server_message_deserialize_roundtrip() {
        let msg = ServerMessage::NodeAuthOk {
            cluster_id: "c1".into(),
            overlay_ip: "100.64.0.1".into(),
            overlay_subnet: "100.64.0.0/10".into(),
            peers: vec![],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::NodeAuthOk { overlay_ip, .. } => {
                assert_eq!(overlay_ip, "100.64.0.1");
            }
            _ => panic!("expected NodeAuthOk"),
        }
    }
}
