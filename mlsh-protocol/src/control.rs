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
