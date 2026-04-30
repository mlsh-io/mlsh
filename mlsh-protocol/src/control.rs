//! Wire types for the `mlsh-control` ALPN stream.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAuthHeader {
    pub cluster_id: String,
    #[serde(default)]
    pub cluster_name: String,
    pub caller_node_uuid: String,
    pub caller_fingerprint: String,
    pub caller_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlRequest {
    AdoptConfirm {
        node_uuid: String,
        fingerprint: String,
        public_key: String,
        display_name: String,
        invite_token: String,
    },
    ListNodes,
    Rename {
        target_node_uuid: String,
        new_display_name: String,
    },
    Promote {
        target_node_uuid: String,
        new_role: String,
    },
    Revoke {
        target_node_uuid: String,
    },
    /// Open a long-lived event stream. The control server keeps the bi-stream
    /// alive and writes a sequence of `ControlEvent` records on it. The client
    /// reads them as they arrive — no per-event response is sent. Subscribers
    /// that fall behind (write blocks) are dropped server-side; the client
    /// reconnects and reseeds via `ListNodes`.
    Subscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlResponse {
    AdoptAck {
        accepted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    Nodes {
        nodes: Vec<ControlNodeInfo>,
    },
    Ok,
    Error {
        code: String,
        message: String,
    },
}

impl ControlResponse {
    pub fn error(code: &str, message: &str) -> Self {
        Self::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlNodeInfo {
    pub node_uuid: String,
    pub fingerprint: String,
    pub display_name: String,
    pub role: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
}

/// Server-pushed event on a `Subscribe` stream.
///
/// Only mutations that happen on the control node (the source of truth) are
/// surfaced here. Network-level facts (peer joined / left the overlay) keep
/// flowing over signal's existing push channel — they're not control events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlEvent {
    NodeJoined {
        node_uuid: String,
        display_name: String,
        role: String,
    },
    NodeLeft {
        node_uuid: String,
    },
    NodeRenamed {
        node_uuid: String,
        new_display_name: String,
    },
    NodePromoted {
        node_uuid: String,
        new_role: String,
    },
    NodeRevoked {
        node_uuid: String,
    },
    ExposedAdded {
        domain: String,
        node_uuid: String,
    },
    ExposedRemoved {
        domain: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        ciborium::from_reader(&buf[..]).unwrap()
    }

    #[test]
    fn auth_header_roundtrip() {
        let h = ControlAuthHeader {
            cluster_id: "c1".into(),
            cluster_name: String::new(),
            caller_node_uuid: "n1".into(),
            caller_fingerprint: "fp".into(),
            caller_role: "admin".into(),
        };
        let back: ControlAuthHeader = roundtrip(&h);
        assert_eq!(back.cluster_id, "c1");
        assert_eq!(back.caller_role, "admin");
    }

    #[test]
    fn adopt_confirm_roundtrip() {
        let req = ControlRequest::AdoptConfirm {
            node_uuid: "u".into(),
            fingerprint: "fp".into(),
            public_key: "pk".into(),
            display_name: "host".into(),
            invite_token: "tok".into(),
        };
        let back: ControlRequest = roundtrip(&req);
        match back {
            ControlRequest::AdoptConfirm {
                node_uuid,
                display_name,
                ..
            } => {
                assert_eq!(node_uuid, "u");
                assert_eq!(display_name, "host");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_error_helper() {
        match ControlResponse::error("forbidden", "not admin") {
            ControlResponse::Error { code, message } => {
                assert_eq!(code, "forbidden");
                assert_eq!(message, "not admin");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn subscribe_request_roundtrip() {
        let req = ControlRequest::Subscribe;
        let back: ControlRequest = roundtrip(&req);
        assert!(matches!(back, ControlRequest::Subscribe));
    }

    #[test]
    fn control_event_renamed_roundtrip() {
        let ev = ControlEvent::NodeRenamed {
            node_uuid: "u1".into(),
            new_display_name: "macbook".into(),
        };
        let back: ControlEvent = roundtrip(&ev);
        match back {
            ControlEvent::NodeRenamed {
                node_uuid,
                new_display_name,
            } => {
                assert_eq!(node_uuid, "u1");
                assert_eq!(new_display_name, "macbook");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn control_event_exposed_added_roundtrip() {
        let ev = ControlEvent::ExposedAdded {
            domain: "app.auriol.mlsh.io".into(),
            node_uuid: "u1".into(),
        };
        let back: ControlEvent = roundtrip(&ev);
        match back {
            ControlEvent::ExposedAdded { domain, node_uuid } => {
                assert_eq!(domain, "app.auriol.mlsh.io");
                assert_eq!(node_uuid, "u1");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn nodes_response_with_optional_last_seen() {
        let r = ControlResponse::Nodes {
            nodes: vec![
                ControlNodeInfo {
                    node_uuid: "u".into(),
                    fingerprint: "fp".into(),
                    display_name: "host".into(),
                    role: "node".into(),
                    status: "active".into(),
                    last_seen: Some("2026-04-27T00:00:00Z".into()),
                },
                ControlNodeInfo {
                    node_uuid: "u2".into(),
                    fingerprint: "fp2".into(),
                    display_name: "h2".into(),
                    role: "admin".into(),
                    status: "active".into(),
                    last_seen: None,
                },
            ],
        };
        let back: ControlResponse = roundtrip(&r);
        if let ControlResponse::Nodes { nodes } = back {
            assert_eq!(nodes.len(), 2);
            assert_eq!(nodes[0].last_seen.as_deref(), Some("2026-04-27T00:00:00Z"));
            assert!(nodes[1].last_seen.is_none());
        } else {
            panic!("wrong variant");
        }
    }
}
