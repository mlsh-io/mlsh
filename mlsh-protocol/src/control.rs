//! Wire types for the `mlsh-control` ALPN stream.
//!
//! This protocol predates the REST API. Most CLI admin calls (`Rename`,
//! `Promote`, `Revoke`) used to live here; they have moved to the REST
//! surface documented in ADR-035 Phase E. What still travels over CBOR on
//! this channel is the **bootstrap and runtime-cache** glue — operations
//! that happen on a connection to signal **before** the joining node has
//! an overlay address (so HTTP+mTLS to `control.<cluster>:8443` is not
//! reachable yet). See ADR-035 Phase G.
//!
//! Surface kept:
//!   - [`ControlRequest::AdoptConfirm`] — bootstrap registration. The
//!     joining node opens a QUIC connection on ALPN `mlsh-control` to
//!     signal, signal relays the bi-stream to the cluster's control node,
//!     the control node upserts the node row.
//!   - [`ControlRequest::Subscribe`] — long-lived event stream that pushes
//!     `ControlEvent`s to drive the UI's live updates and the daemon's
//!     `display_names_loop` cache.
//!   - [`ControlRequest::ListNodes`] — initial seed of the daemon's
//!     in-memory peer-name cache. Runs **on every tunnel daemon** at
//!     reconnect time, before the overlay is up — it cannot read the
//!     control node's SQLite directly because the daemon isn't on the
//!     control node. The Subscribe stream then incrementally maintains
//!     the cache.
//!
//! All three flows are *internal infrastructure*, not user-facing API.
//! New admin endpoints go to the REST router (`api/*`), never here.

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
    /// Internal: seed the daemon's display-name cache. Not exposed to the
    /// CLI — admin listing happens over `GET /api/v1/nodes` (ADR-035 Phase
    /// E).
    ListNodes,
    /// Open a long-lived event stream. The control server keeps the bi-stream
    /// alive and writes a sequence of `ControlEvent` records on it. The
    /// client reads them as they arrive — no per-event response is sent.
    /// Subscribers that fall behind (write blocks) are dropped server-side;
    /// the client reconnects.
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
    Error {
        code: String,
        message: String,
    },
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
    /// `true` for the row corresponding to the cluster's control node — the
    /// peer that hosts the REST admin surface (one per cluster, ADR-030 §2).
    /// Used by the daemon's overlay DNS to resolve `control.<cluster>` to
    /// the right IP without baking the role into signal.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_control_node: bool,
}

impl ControlResponse {
    pub fn error(code: &str, message: &str) -> Self {
        Self::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
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
}
