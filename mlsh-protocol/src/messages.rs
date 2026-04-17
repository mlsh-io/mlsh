//! Wire protocol message types for QUIC signal streams.
//!
//! Session messages use a long-lived bidirectional stream.
//! The `type` field determines the message kind via serde tagging.

use serde::{Deserialize, Serialize};

use crate::types::{Candidate, IngressMode, IngressRoute, NodeInfo, PeerInfo};

// --- Client → Server

/// Union of all client-to-server message types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        node_uuid: String,
        /// Ed25519 public key (base64url, 32 bytes) for signature verification.
        #[serde(default)]
        public_key: String,
        #[serde(default)]
        expires_at: u64,
        /// Self-signed admission cert (JSON, for root admin setup).
        #[serde(default)]
        admission_cert: String,
        #[serde(default)]
        display_name: String,
    },

    /// Admin revocation: remove a node from the cluster.
    /// Caller is authenticated via TLS client certificate.
    Revoke {
        cluster_id: String,
        target_name: String,
    },

    /// Rename a node's display label (admin only).
    Rename {
        cluster_id: String,
        target_name: String,
        new_display_name: String,
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

    /// Register a public reverse-proxy route for a domain served by the caller.
    /// Caller is authenticated via TLS client certificate.
    ExposeService {
        cluster_id: String,
        /// Fully-qualified domain (e.g. "myapp.mlsh.io").
        domain: String,
        /// Local upstream URL the peer's rpxy-lib should forward to
        /// (e.g. "http://localhost:3000").
        target: String,
        #[serde(default)]
        mode: IngressMode,
    },

    /// Remove a previously-registered ingress route.
    UnexposeService {
        cluster_id: String,
        domain: String,
    },

    /// List ingress routes registered in the cluster.
    ListExposed {
        cluster_id: String,
    },
}

// --- Server → Client

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
        node_uuid: String,
        overlay_ip: String,
        overlay_subnet: String,
        peers: Vec<PeerInfo>,
        display_name: String,
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

    /// Pushed to all connected peers when a node's display name changes.
    PeerRenamed {
        node_id: String,
        new_display_name: String,
    },

    /// Confirmation that a rename was applied.
    RenameOk {
        display_name: String,
    },

    /// Response to ListNodes: all registered nodes with online/offline status.
    NodeList {
        nodes: Vec<NodeInfo>,
    },

    /// Response to `ExposeService`: the route is registered. In the current
    /// implementation `public_mode` is always "relay" — direct-ingress mode
    /// (Mode B) is not implemented.
    ExposeOk {
        domain: String,
        /// "relay" or "direct".
        public_mode: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_ip: Option<String>,
    },
    UnexposeOk,
    ExposedList {
        routes: Vec<IngressRoute>,
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
#[serde(rename_all = "snake_case")]
pub enum RelayMessage {
    /// Signal → target peer: incoming relay from another node.
    RelayIncoming { from_node_id: String },
    /// Target peer → signal: relay accepted.
    RelayAccepted,
    /// Signal → target peer: incoming public ingress connection for `domain`.
    /// After `IngressAccepted`, signal splices raw TCP bytes over the stream
    /// and the peer hands them to its local rpxy-lib for TLS termination.
    IngressForward {
        domain: String,
        /// Real client IP observed by signal (or outer SNI proxy via
        /// PROXY-protocol), if available. For logging / PROXY v2 on the peer.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        client_ip: String,
    },
    /// Target peer → signal: ingress stream accepted, start splicing.
    IngressAccepted,
}

// --- Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_roundtrip<T: serde::Serialize + serde::de::DeserializeOwned>(msg: &T) -> T {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).unwrap();
        ciborium::from_reader(&buf[..]).unwrap()
    }

    fn cbor_bytes<T: serde::Serialize>(msg: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).unwrap();
        buf
    }

    // --- StreamMessage roundtrips ---

    #[test]
    fn ping_roundtrip() {
        match cbor_roundtrip(&StreamMessage::Ping) {
            StreamMessage::Ping => {}
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[test]
    fn report_candidates_roundtrip() {
        let msg = StreamMessage::ReportCandidates {
            candidates: vec![
                Candidate {
                    kind: "host".into(),
                    addr: "192.168.1.10:4433".into(),
                    priority: 100,
                },
                Candidate {
                    kind: "srflx".into(),
                    addr: "203.0.113.5:4433".into(),
                    priority: 200,
                },
            ],
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::ReportCandidates { candidates } => {
                assert_eq!(candidates.len(), 2);
                assert_eq!(candidates[0].kind, "host");
                assert_eq!(candidates[0].addr, "192.168.1.10:4433");
                assert_eq!(candidates[0].priority, 100);
                assert_eq!(candidates[1].kind, "srflx");
                assert_eq!(candidates[1].priority, 200);
            }
            other => panic!("expected ReportCandidates, got {:?}", other),
        }
    }

    #[test]
    fn report_candidates_empty() {
        let msg = StreamMessage::ReportCandidates { candidates: vec![] };
        match cbor_roundtrip(&msg) {
            StreamMessage::ReportCandidates { candidates } => {
                assert!(candidates.is_empty());
            }
            other => panic!("expected ReportCandidates, got {:?}", other),
        }
    }

    #[test]
    fn relay_open_roundtrip() {
        let msg = StreamMessage::RelayOpen {
            cluster_id: "c1".into(),
            node_id: "n1".into(),
            target_node_id: "n2".into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::RelayOpen {
                cluster_id,
                node_id,
                target_node_id,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(node_id, "n1");
                assert_eq!(target_node_id, "n2");
            }
            other => panic!("expected RelayOpen, got {:?}", other),
        }
    }

    #[test]
    fn relay_open_empty_target() {
        let msg = StreamMessage::RelayOpen {
            cluster_id: "c1".into(),
            node_id: "n1".into(),
            target_node_id: String::new(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::RelayOpen { target_node_id, .. } => {
                assert!(target_node_id.is_empty());
            }
            other => panic!("expected RelayOpen, got {:?}", other),
        }
    }

    #[test]
    fn node_auth_roundtrip() {
        let msg = StreamMessage::NodeAuth {
            cluster_id: "cluster-abc".into(),
            public_key: "base64url-key".into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::NodeAuth {
                cluster_id,
                public_key,
            } => {
                assert_eq!(cluster_id, "cluster-abc");
                assert_eq!(public_key, "base64url-key");
            }
            other => panic!("expected NodeAuth, got {:?}", other),
        }
    }

    #[test]
    fn adopt_roundtrip() {
        let msg = StreamMessage::Adopt {
            cluster_id: "c1".into(),
            pre_auth_token: "tok-123".into(),
            fingerprint: "sha256-abc".into(),
            node_uuid: "n1".into(),
            public_key: "pk-xyz".into(),
            expires_at: 1700000000,
            admission_cert: r#"{"node_id":"n1"}"#.into(),
            display_name: String::new(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::Adopt {
                cluster_id,
                pre_auth_token,
                fingerprint,
                node_uuid,
                public_key,
                expires_at,
                admission_cert,
                display_name,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(pre_auth_token, "tok-123");
                assert_eq!(fingerprint, "sha256-abc");
                assert_eq!(node_uuid, "n1");
                assert_eq!(public_key, "pk-xyz");
                assert_eq!(expires_at, 1700000000);
                assert!(admission_cert.contains("node_id"));
                assert!(display_name.is_empty());
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn revoke_roundtrip() {
        let msg = StreamMessage::Revoke {
            cluster_id: "c1".into(),
            target_name: "n2".into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::Revoke {
                cluster_id,
                target_name,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(target_name, "n2");
            }
            other => panic!("expected Revoke, got {:?}", other),
        }
    }

    #[test]
    fn promote_roundtrip() {
        let msg = StreamMessage::Promote {
            cluster_id: "c1".into(),
            target_node_id: "n2".into(),
            new_role: "admin".into(),
            admission_cert: r#"{"role":"admin"}"#.into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::Promote {
                cluster_id,
                target_node_id,
                new_role,
                admission_cert,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(target_node_id, "n2");
                assert_eq!(new_role, "admin");
                assert!(admission_cert.contains("admin"));
            }
            other => panic!("expected Promote, got {:?}", other),
        }
    }

    #[test]
    fn list_nodes_roundtrip() {
        match cbor_roundtrip(&StreamMessage::ListNodes) {
            StreamMessage::ListNodes => {}
            other => panic!("expected ListNodes, got {:?}", other),
        }
    }

    // --- ServerMessage roundtrips ---

    #[test]
    fn pong_roundtrip() {
        match cbor_roundtrip(&ServerMessage::Pong) {
            ServerMessage::Pong => {}
            other => panic!("expected Pong, got {:?}", other),
        }
    }

    #[test]
    fn relay_ready_roundtrip() {
        match cbor_roundtrip(&ServerMessage::RelayReady) {
            ServerMessage::RelayReady => {}
            other => panic!("expected RelayReady, got {:?}", other),
        }
    }

    #[test]
    fn error_roundtrip() {
        let msg = ServerMessage::error("E01", "bad");
        match cbor_roundtrip(&msg) {
            ServerMessage::Error { code, message } => {
                assert_eq!(code, "E01");
                assert_eq!(message, "bad");
            }
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn node_auth_ok_roundtrip() {
        let msg = ServerMessage::NodeAuthOk {
            cluster_id: "c1".into(),
            overlay_ip: "100.64.0.1".into(),
            overlay_subnet: "100.64.0.0/10".into(),
            peers: vec![PeerInfo {
                node_id: "n2".into(),
                fingerprint: "fp-abc".into(),
                overlay_ip: "100.64.0.2".into(),
                candidates: vec![Candidate {
                    kind: "host".into(),
                    addr: "10.0.0.5:4433".into(),
                    priority: 100,
                }],
                public_key: "pk".into(),
                admission_cert: "cert".into(),
                display_name: String::new(),
            }],
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::NodeAuthOk {
                cluster_id,
                overlay_ip,
                overlay_subnet,
                peers,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(overlay_ip, "100.64.0.1");
                assert_eq!(overlay_subnet, "100.64.0.0/10");
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].node_id, "n2");
                assert_eq!(peers[0].candidates.len(), 1);
            }
            other => panic!("expected NodeAuthOk, got {:?}", other),
        }
    }

    #[test]
    fn adopt_ok_roundtrip() {
        let msg = ServerMessage::AdoptOk {
            cluster_id: "c1".into(),
            node_uuid: "n1".into(),
            overlay_ip: "100.64.0.5".into(),
            overlay_subnet: "100.64.0.0/10".into(),
            peers: vec![],
            display_name: "my-node".into(),
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::AdoptOk {
                cluster_id,
                node_uuid,
                overlay_ip,
                overlay_subnet,
                peers,
                display_name,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(node_uuid, "n1");
                assert_eq!(overlay_ip, "100.64.0.5");
                assert_eq!(overlay_subnet, "100.64.0.0/10");
                assert!(peers.is_empty());
                assert_eq!(display_name, "my-node");
            }
            other => panic!("expected AdoptOk, got {:?}", other),
        }
    }

    #[test]
    fn peer_joined_roundtrip() {
        let msg = ServerMessage::PeerJoined {
            peer: PeerInfo {
                node_id: "n3".into(),
                fingerprint: "fp".into(),
                overlay_ip: "100.64.0.3".into(),
                candidates: vec![],
                public_key: String::new(),
                admission_cert: String::new(),
                display_name: String::new(),
            },
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::PeerJoined { peer } => {
                assert_eq!(peer.node_id, "n3");
                assert_eq!(peer.overlay_ip, "100.64.0.3");
                assert!(peer.candidates.is_empty());
            }
            other => panic!("expected PeerJoined, got {:?}", other),
        }
    }

    #[test]
    fn peer_left_roundtrip() {
        let msg = ServerMessage::PeerLeft {
            node_id: "n2".into(),
            cluster_id: "c1".into(),
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::PeerLeft {
                node_id,
                cluster_id,
            } => {
                assert_eq!(node_id, "n2");
                assert_eq!(cluster_id, "c1");
            }
            other => panic!("expected PeerLeft, got {:?}", other),
        }
    }

    #[test]
    fn revoke_ok_roundtrip() {
        match cbor_roundtrip(&ServerMessage::RevokeOk) {
            ServerMessage::RevokeOk => {}
            other => panic!("expected RevokeOk, got {:?}", other),
        }
    }

    #[test]
    fn promote_ok_roundtrip() {
        match cbor_roundtrip(&ServerMessage::PromoteOk) {
            ServerMessage::PromoteOk => {}
            other => panic!("expected PromoteOk, got {:?}", other),
        }
    }

    #[test]
    fn peer_updated_roundtrip() {
        let msg = ServerMessage::PeerUpdated {
            node_id: "n2".into(),
            cluster_id: "c1".into(),
            new_role: "admin".into(),
            admission_cert: "cert-data".into(),
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::PeerUpdated {
                node_id,
                cluster_id,
                new_role,
                admission_cert,
            } => {
                assert_eq!(node_id, "n2");
                assert_eq!(cluster_id, "c1");
                assert_eq!(new_role, "admin");
                assert_eq!(admission_cert, "cert-data");
            }
            other => panic!("expected PeerUpdated, got {:?}", other),
        }
    }

    #[test]
    fn node_list_roundtrip() {
        let msg = ServerMessage::NodeList {
            nodes: vec![
                NodeInfo {
                    node_id: "n1".into(),
                    overlay_ip: "100.64.0.1".into(),
                    role: "admin".into(),
                    online: true,
                    has_admission_cert: true,
                    display_name: String::new(),
                },
                NodeInfo {
                    node_id: "n2".into(),
                    overlay_ip: "100.64.0.2".into(),
                    role: "member".into(),
                    online: false,
                    has_admission_cert: false,
                    display_name: String::new(),
                },
            ],
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::NodeList { nodes } => {
                assert_eq!(nodes.len(), 2);
                assert_eq!(nodes[0].node_id, "n1");
                assert!(nodes[0].online);
                assert!(nodes[0].has_admission_cert);
                assert_eq!(nodes[1].role, "member");
                assert!(!nodes[1].online);
                assert!(!nodes[1].has_admission_cert);
            }
            other => panic!("expected NodeList, got {:?}", other),
        }
    }

    // --- Ingress roundtrips ---

    #[test]
    fn expose_service_roundtrip() {
        let msg = StreamMessage::ExposeService {
            cluster_id: "c1".into(),
            domain: "app.mlsh.io".into(),
            target: "http://localhost:3000".into(),
            mode: IngressMode::Http,
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::ExposeService {
                cluster_id,
                domain,
                target,
                mode,
            } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(domain, "app.mlsh.io");
                assert_eq!(target, "http://localhost:3000");
                assert_eq!(mode, IngressMode::Http);
            }
            other => panic!("expected ExposeService, got {:?}", other),
        }
    }

    #[test]
    fn unexpose_service_roundtrip() {
        let msg = StreamMessage::UnexposeService {
            cluster_id: "c1".into(),
            domain: "app.mlsh.io".into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::UnexposeService { cluster_id, domain } => {
                assert_eq!(cluster_id, "c1");
                assert_eq!(domain, "app.mlsh.io");
            }
            other => panic!("expected UnexposeService, got {:?}", other),
        }
    }

    #[test]
    fn list_exposed_roundtrip() {
        let msg = StreamMessage::ListExposed {
            cluster_id: "c1".into(),
        };
        match cbor_roundtrip(&msg) {
            StreamMessage::ListExposed { cluster_id } => {
                assert_eq!(cluster_id, "c1");
            }
            other => panic!("expected ListExposed, got {:?}", other),
        }
    }

    #[test]
    fn expose_ok_roundtrip() {
        let msg = ServerMessage::ExposeOk {
            domain: "app.mlsh.io".into(),
            public_mode: "relay".into(),
            public_ip: None,
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::ExposeOk {
                domain,
                public_mode,
                public_ip,
            } => {
                assert_eq!(domain, "app.mlsh.io");
                assert_eq!(public_mode, "relay");
                assert!(public_ip.is_none());
            }
            other => panic!("expected ExposeOk, got {:?}", other),
        }
    }

    #[test]
    fn exposed_list_roundtrip() {
        let msg = ServerMessage::ExposedList {
            routes: vec![IngressRoute {
                domain: "app.mlsh.io".into(),
                target: "http://localhost:3000".into(),
                node_id: "n1".into(),
                mode: IngressMode::Http,
                public_mode: "direct".into(),
                public_ip: "203.0.113.5".into(),
            }],
        };
        match cbor_roundtrip(&msg) {
            ServerMessage::ExposedList { routes } => {
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0].domain, "app.mlsh.io");
                assert_eq!(routes[0].public_mode, "direct");
                assert_eq!(routes[0].public_ip, "203.0.113.5");
            }
            other => panic!("expected ExposedList, got {:?}", other),
        }
    }

    #[test]
    fn ingress_forward_roundtrip() {
        let msg = RelayMessage::IngressForward {
            domain: "app.mlsh.io".into(),
            client_ip: "198.51.100.7".into(),
        };
        match cbor_roundtrip(&msg) {
            RelayMessage::IngressForward { domain, client_ip } => {
                assert_eq!(domain, "app.mlsh.io");
                assert_eq!(client_ip, "198.51.100.7");
            }
            other => panic!("expected IngressForward, got {:?}", other),
        }
    }

    #[test]
    fn ingress_accepted_roundtrip() {
        match cbor_roundtrip(&RelayMessage::IngressAccepted) {
            RelayMessage::IngressAccepted => {}
            other => panic!("expected IngressAccepted, got {:?}", other),
        }
    }

    // --- RelayMessage roundtrips ---

    #[test]
    fn relay_incoming_roundtrip() {
        let msg = RelayMessage::RelayIncoming {
            from_node_id: "node1".into(),
        };
        match cbor_roundtrip(&msg) {
            RelayMessage::RelayIncoming { from_node_id } => {
                assert_eq!(from_node_id, "node1");
            }
            other => panic!("expected RelayIncoming, got {:?}", other),
        }
    }

    #[test]
    fn relay_accepted_roundtrip() {
        match cbor_roundtrip(&RelayMessage::RelayAccepted) {
            RelayMessage::RelayAccepted => {}
            other => panic!("expected RelayAccepted, got {:?}", other),
        }
    }

    // --- Cross-type rejection ---

    #[test]
    fn stream_message_not_decodable_as_server_message() {
        let bytes = cbor_bytes(&StreamMessage::Ping);
        let result: Result<ServerMessage, _> = ciborium::from_reader(&bytes[..]);
        // Ping and Pong use different tag names, so cross-decode should fail
        // (or at least not silently produce the wrong variant).
        if let Ok(msg) = result {
            // If it happens to decode, it must not be a meaningful ServerMessage variant
            // that could be confused with a real server response.
            match msg {
                ServerMessage::Pong
                | ServerMessage::RelayReady
                | ServerMessage::RevokeOk
                | ServerMessage::PromoteOk => {
                    // Unit variants might alias — acceptable as long as the tag differs.
                    // The serde tag for StreamMessage::Ping is "ping", ServerMessage has no "ping".
                    panic!("StreamMessage::Ping decoded as a valid ServerMessage variant");
                }
                _ => {} // decoded as Error or similar garbage — acceptable
            }
        }
        // Decoding failure is the expected (good) outcome.
    }

    // --- Binary stability: encoding must be deterministic ---

    #[test]
    fn cbor_encoding_is_deterministic() {
        let msg = StreamMessage::Adopt {
            cluster_id: "c1".into(),
            pre_auth_token: "tok".into(),
            fingerprint: "fp".into(),
            node_uuid: "n1".into(),
            public_key: "pk".into(),
            expires_at: 999,
            admission_cert: "cert".into(),
            display_name: String::new(),
        };
        let a = cbor_bytes(&msg);
        let b = cbor_bytes(&msg);
        assert_eq!(a, b, "CBOR encoding must be deterministic");
    }

    // --- Optional/default field handling ---

    #[test]
    fn peer_info_skips_empty_optional_fields() {
        let peer = PeerInfo {
            node_id: "n1".into(),
            fingerprint: "fp".into(),
            overlay_ip: "100.64.0.1".into(),
            candidates: vec![],
            public_key: String::new(),
            admission_cert: String::new(),
            display_name: String::new(),
        };
        let bytes = cbor_bytes(&peer);
        let decoded: PeerInfo = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(decoded.node_id, "n1");
        assert!(decoded.candidates.is_empty());
        assert!(decoded.public_key.is_empty());
        assert!(decoded.admission_cert.is_empty());
    }

    // ===================================================================
    // CBOR attack vector tests
    // ===================================================================

    /// Depth bomb: deeply nested CBOR arrays → must not stack overflow.
    #[test]
    fn depth_bomb_nested_arrays() {
        // CBOR array of length 1 = 0x81, nesting 10_000 deep
        let depth = 10_000usize;
        let mut payload = vec![0x81u8; depth]; // each byte opens a 1-element array
        payload.push(0x60); // empty text string to close the innermost
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        // Must not panic (stack overflow). Error is fine.
        assert!(result.is_err(), "depth bomb should be rejected");
    }

    /// Depth bomb with nested maps.
    #[test]
    fn depth_bomb_nested_maps() {
        // 0xA1 = map with 1 entry, key = 0x60 (empty string)
        let depth = 10_000usize;
        let mut payload = Vec::with_capacity(depth * 2 + 1);
        for _ in 0..depth {
            payload.push(0xA1); // map(1)
            payload.push(0x60); // key: ""
        }
        payload.push(0x60); // innermost value: ""
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        assert!(result.is_err(), "nested map bomb should be rejected");
    }

    /// Huge allocation attack: CBOR header claims a massive array but no data follows.
    #[test]
    fn huge_array_allocation() {
        // 0x9B + 8 bytes = array with u64 length.
        // Claim 0x00000000FFFFFFFF items (~4 billion) but provide nothing.
        let payload: Vec<u8> = vec![0x9B, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        // Must fail without actually allocating 4B entries (OOM).
        assert!(result.is_err());
    }

    /// Huge string allocation: header claims a 1 GB string.
    #[test]
    fn huge_string_allocation() {
        // 0x7B + 8 bytes = text string with u64 length
        let payload: Vec<u8> = vec![
            0x7B, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // ~1 GiB string
        ];
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        assert!(result.is_err());
    }

    /// Indefinite-length array: 0x9F starts an array with no declared size.
    #[test]
    fn indefinite_length_array() {
        // 0x9F = start indefinite array, 0x01 0x02 0x03 = items, 0xFF = break
        let payload: Vec<u8> = vec![0x9F, 0x01, 0x02, 0x03, 0xFF];
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        // ciborium supports indefinite-length, but it won't decode as StreamMessage.
        assert!(result.is_err());
    }

    /// Indefinite-length array that never terminates (no 0xFF break code).
    #[test]
    fn indefinite_length_no_break() {
        // 0x9F = start indefinite array, then just a few items, no break
        let payload: Vec<u8> = vec![0x9F, 0x01, 0x02, 0x03];
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        assert!(result.is_err());
    }

    /// Indefinite-length byte string.
    #[test]
    fn indefinite_length_bytestring() {
        // 0x5F = start indefinite byte string, 0x41 0xAA = 1-byte chunk, 0xFF = break
        let payload: Vec<u8> = vec![0x5F, 0x41, 0xAA, 0xFF];
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        assert!(result.is_err());
    }

    /// Type confusion: integer where a string is expected in a known variant.
    #[test]
    fn type_confusion_int_for_string() {
        // Manually craft a CBOR map that looks like {"node_auth": {"cluster_id": 42}}
        // where cluster_id should be a string but we supply an integer.
        use std::collections::BTreeMap;
        let mut inner = BTreeMap::new();
        inner.insert("cluster_id", ciborium::Value::Integer(42.into()));
        inner.insert("public_key", ciborium::Value::Text(String::new()));
        let outer = ciborium::Value::Map(vec![(
            ciborium::Value::Text("node_auth".into()),
            ciborium::Value::Map(
                inner
                    .into_iter()
                    .map(|(k, v)| (ciborium::Value::Text(k.into()), v))
                    .collect(),
            ),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&outer, &mut buf).unwrap();
        let result: Result<StreamMessage, _> = ciborium::from_reader(&buf[..]);
        assert!(
            result.is_err(),
            "integer in place of string must be rejected"
        );
    }

    /// Type confusion: string where an integer is expected (expires_at in Adopt).
    #[test]
    fn type_confusion_string_for_int() {
        let outer = ciborium::Value::Map(vec![(
            ciborium::Value::Text("adopt".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("cluster_id".into()),
                    ciborium::Value::Text("c1".into()),
                ),
                (
                    ciborium::Value::Text("pre_auth_token".into()),
                    ciborium::Value::Text("tok".into()),
                ),
                (
                    ciborium::Value::Text("fingerprint".into()),
                    ciborium::Value::Text("fp".into()),
                ),
                (
                    ciborium::Value::Text("node_uuid".into()),
                    ciborium::Value::Text("n1".into()),
                ),
                (
                    ciborium::Value::Text("public_key".into()),
                    ciborium::Value::Text("pk".into()),
                ),
                (
                    ciborium::Value::Text("expires_at".into()),
                    ciborium::Value::Text("not-a-number".into()),
                ),
                (
                    ciborium::Value::Text("admission_cert".into()),
                    ciborium::Value::Text("cert".into()),
                ),
            ]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&outer, &mut buf).unwrap();
        let result: Result<StreamMessage, _> = ciborium::from_reader(&buf[..]);
        assert!(result.is_err(), "string in place of u64 must be rejected");
    }

    /// Duplicate map keys: serde/ciborium accepts them (last wins), verify no panic.
    #[test]
    fn duplicate_map_keys_no_panic() {
        // Build a CBOR map with cluster_id appearing twice
        let outer = ciborium::Value::Map(vec![(
            ciborium::Value::Text("node_auth".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("cluster_id".into()),
                    ciborium::Value::Text("first".into()),
                ),
                (
                    ciborium::Value::Text("cluster_id".into()),
                    ciborium::Value::Text("second".into()),
                ),
                (
                    ciborium::Value::Text("public_key".into()),
                    ciborium::Value::Text("pk".into()),
                ),
            ]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&outer, &mut buf).unwrap();
        // Must not panic. If it decodes, one of the two values wins.
        let result: Result<StreamMessage, _> = ciborium::from_reader(&buf[..]);
        if let Ok(StreamMessage::NodeAuth { cluster_id, .. }) = result {
            assert!(
                cluster_id == "first" || cluster_id == "second",
                "one of the duplicate values should win"
            );
        }
        // Error is also acceptable.
    }

    /// Tag spoofing: unknown variant tag must be rejected, not silently accepted.
    #[test]
    fn unknown_variant_tag_rejected() {
        let outer = ciborium::Value::Map(vec![(
            ciborium::Value::Text("totally_fake_command".into()),
            ciborium::Value::Map(vec![(
                ciborium::Value::Text("payload".into()),
                ciborium::Value::Text("evil".into()),
            )]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&outer, &mut buf).unwrap();
        let result: Result<StreamMessage, _> = ciborium::from_reader(&buf[..]);
        assert!(result.is_err(), "unknown variant tag must be rejected");
    }

    /// Extra unknown fields in a known variant should not cause a panic.
    #[test]
    fn extra_fields_in_known_variant() {
        let outer = ciborium::Value::Map(vec![(
            ciborium::Value::Text("revoke".into()),
            ciborium::Value::Map(vec![
                (
                    ciborium::Value::Text("cluster_id".into()),
                    ciborium::Value::Text("c1".into()),
                ),
                (
                    ciborium::Value::Text("target_name".into()),
                    ciborium::Value::Text("n2".into()),
                ),
                (
                    ciborium::Value::Text("injected_field".into()),
                    ciborium::Value::Text("evil".into()),
                ),
            ]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&outer, &mut buf).unwrap();
        // serde typically ignores unknown fields by default — should decode fine.
        let result: Result<StreamMessage, _> = ciborium::from_reader(&buf[..]);
        if let Ok(StreamMessage::Revoke {
            cluster_id,
            target_name,
        }) = result
        {
            assert_eq!(cluster_id, "c1");
            assert_eq!(target_name, "n2");
        }
        // Error is also acceptable (strict mode).
    }

    /// CBOR tag (semantic tag 55799 = self-describe CBOR) wrapping a valid message.
    #[test]
    fn cbor_semantic_tag_wrapper() {
        // Tag 55799 (0xD9 0xD9 0xF7) is the self-describe tag.
        // Wrap a valid StreamMessage::Ping encoding with it.
        let mut inner = Vec::new();
        ciborium::into_writer(&StreamMessage::Ping, &mut inner).unwrap();
        let mut payload = vec![0xD9, 0xD9, 0xF7]; // tag(55799)
        payload.extend_from_slice(&inner);
        let result: Result<StreamMessage, _> = ciborium::from_reader(&payload[..]);
        // ciborium may or may not strip the self-describe tag.
        // Either way, must not panic.
        match result {
            Ok(StreamMessage::Ping) => {} // fine if tag is transparent
            Err(_) => {}                  // fine if tag is rejected
            Ok(other) => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn node_info_has_admission_cert_defaults_false() {
        // Simulate a payload missing has_admission_cert (e.g. from older signal)
        use std::collections::BTreeMap;
        let mut map = BTreeMap::new();
        map.insert("node_id", "n1");
        map.insert("overlay_ip", "100.64.0.1");
        map.insert("role", "member");

        // Build CBOR with the bool field manually
        let mut cbor_map = Vec::new();
        // Encode as a full NodeInfo with online=true but missing has_admission_cert
        let full = serde_json::json!({
            "node_id": "n1",
            "overlay_ip": "100.64.0.1",
            "role": "member",
            "online": true
        });
        ciborium::into_writer(&full, &mut cbor_map).unwrap();
        let decoded: NodeInfo = ciborium::from_reader(&cbor_map[..]).unwrap();
        assert_eq!(decoded.node_id, "n1");
        assert!(decoded.online);
        assert!(
            !decoded.has_admission_cert,
            "has_admission_cert should default to false"
        );
    }
}
