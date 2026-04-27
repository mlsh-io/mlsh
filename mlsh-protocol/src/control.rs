//! Wire types for the `mlsh-control` ALPN stream (ADR-033).
//!
//! On a stream opened by a node toward the cluster's `control` node (relayed
//! by mlsh-signal), the conversation is:
//!
//! 1. Signal writes a `ControlAuthHeader` (1 frame). It identifies the caller
//!    via the mTLS fingerprint on the incoming connection. The control plane
//!    trusts signal to have already authenticated the caller — so this header
//!    is the source of truth for the caller's identity and role.
//! 2. The caller writes a `ControlRequest` (1 frame).
//! 3. The control plane writes a `ControlResponse` (1 frame).
//! 4. Stream is closed. One request per stream — no pipelining in V1.
//!
//! Framing is the standard mlsh-protocol length-prefixed CBOR (see `framing`).

use serde::{Deserialize, Serialize};

/// Injected by mlsh-signal as the very first frame on a relayed control stream.
/// Tells the control plane who is calling. The control plane must not infer
/// identity from anything else on the stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAuthHeader {
    /// Cluster UUID — opaque identifier for the cluster.
    pub cluster_id: String,
    /// Cluster human-readable name (e.g. "auriol"). Populated by signal from
    /// its `clusters` table. The control plane uses this as the key in its
    /// own `nodes` table to stay in sync with the UI.
    #[serde(default)]
    pub cluster_name: String,
    pub caller_node_uuid: String,
    pub caller_fingerprint: String,
    /// `"admin"` or `"node"` — signal resolves this from its registry at the
    /// moment the stream is opened. Multi-role to be added later.
    pub caller_role: String,
}

/// Request sent by a node to the control plane on an authenticated stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlRequest {
    /// A new node, freshly admitted to the mesh by signal via a sponsor-signed
    /// invite, announces itself to the control plane. The control plane records
    /// it (or rejects it). Best-effort from the node's perspective in V1.
    AdoptConfirm {
        node_uuid: String,
        fingerprint: String,
        /// Ed25519 public key, base64url, 32 bytes.
        public_key: String,
        display_name: String,
        /// The full invite payload (base64) the node used to join. Recorded for
        /// audit; the control plane may also re-verify it against the sponsor's
        /// public key.
        invite_token: String,
    },

    /// List all nodes known to the control plane for this cluster.
    ListNodes,

    /// Rename a node's display label. Admin-only — the control plane checks
    /// `caller_role == "admin"` from the auth header.
    Rename {
        target_node_uuid: String,
        new_display_name: String,
    },

    /// Promote/demote a node between `"node"` and `"admin"`.
    Promote {
        target_node_uuid: String,
        new_role: String,
    },

    /// Mark a node as revoked in the control DB. V1 does not kick the live
    /// session on signal — signal will refuse the next reconnect once it
    /// learns about the revocation through a separate channel.
    Revoke {
        target_node_uuid: String,
    },
}

/// Response sent by the control plane on the same stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlResponse {
    /// Acknowledgement of `AdoptConfirm`. `accepted=false` means the control
    /// plane rejected the node — signal still has it in the mesh, the node
    /// should treat this as a soft failure and may retry or surface the error.
    AdoptAck {
        accepted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Response to `ListNodes`.
    Nodes {
        nodes: Vec<ControlNodeInfo>,
    },

    /// Generic success acknowledgement (Rename / Promote / Revoke).
    Ok,

    /// Generic error.
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

/// Node entry returned in `ControlResponse::Nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlNodeInfo {
    pub node_uuid: String,
    pub fingerprint: String,
    pub display_name: String,
    /// `"admin"` or `"node"` for now.
    pub role: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// RFC3339 last-seen timestamp; `None` if never seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
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
