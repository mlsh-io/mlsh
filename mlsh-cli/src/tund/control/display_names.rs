//! Authoritative `node_uuid → display_name` map maintained from mlsh-control.
//!
//! Seeded from `ControlRequest::ListNodes` on every (re)connect and kept in
//! sync via `ControlEvent` records on the subscribe stream. The overlay DNS
//! resolver consults this map to translate a DNS-sanitised label back to a
//! UUID, then crosses with the signal-owned `peer_table` to obtain the IP.

use std::collections::HashMap;
use std::sync::Arc;

use mlsh_protocol::control::{ControlEvent, ControlNodeInfo};
use tokio::sync::RwLock;

use crate::tund::net::overlay_dns::sanitize_dns_label;

#[derive(Default)]
struct Inner {
    /// node_uuid → display_name.
    by_uuid: HashMap<String, String>,
    /// sanitised label (lowercase, RFC 1035) → node_uuid. Rebuilt from
    /// `by_uuid` on every mutation so lookups stay O(1).
    by_label: HashMap<String, String>,
    /// UUID of the cluster's control node (one per cluster, ADR-030 §2).
    /// Set by `seed()` from the `is_control_node` flag in the
    /// `ControlNodeInfo` snapshot. Used by overlay DNS to resolve
    /// `control.<cluster>`.
    control_uuid: Option<String>,
}

/// Clone-cheap handle to the shared display-name map.
#[derive(Clone, Default)]
pub struct DisplayNameMap {
    inner: Arc<RwLock<Inner>>,
}

impl DisplayNameMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the entire map from a `ListNodes` response. Called on every
    /// (re)connect — the new snapshot fully supersedes the old one.
    pub async fn seed(&self, nodes: &[ControlNodeInfo]) {
        let mut inner = self.inner.write().await;
        inner.by_uuid.clear();
        inner.by_label.clear();
        inner.control_uuid = None;
        for n in nodes {
            if n.is_control_node {
                inner.control_uuid = Some(n.node_uuid.clone());
            }
            if n.display_name.is_empty() {
                continue;
            }
            insert(&mut inner, &n.node_uuid, &n.display_name);
        }
    }

    /// Pre-seed the control node UUID before the first `ListNodes` arrives.
    /// Called by mlshtund when it boots with the `control` role itself —
    /// it knows its own UUID without waiting for the network round-trip,
    /// so `control.<cluster>` resolves immediately.
    pub async fn set_local_control_uuid(&self, uuid: String) {
        let mut inner = self.inner.write().await;
        inner.control_uuid = Some(uuid);
    }

    /// UUID of the cluster's control node, when known. Returned by the
    /// overlay DNS resolver to map `control.<cluster>` to an IP.
    pub async fn control_uuid(&self) -> Option<String> {
        self.inner.read().await.control_uuid.clone()
    }

    /// Apply a single push event from the subscribe stream. Unrelated events
    /// (Exposed*, NodePromoted) are ignored — they don't affect name lookup.
    pub async fn apply(&self, event: &ControlEvent) {
        let mut inner = self.inner.write().await;
        match event {
            ControlEvent::NodeJoined {
                node_uuid,
                display_name,
                ..
            }
            | ControlEvent::NodeRenamed {
                node_uuid,
                new_display_name: display_name,
            } => {
                if display_name.is_empty() {
                    remove_uuid(&mut inner, node_uuid);
                } else {
                    insert(&mut inner, node_uuid, display_name);
                }
            }
            ControlEvent::NodeLeft { node_uuid } | ControlEvent::NodeRevoked { node_uuid } => {
                remove_uuid(&mut inner, node_uuid);
            }
            ControlEvent::NodePromoted { .. }
            | ControlEvent::ExposedAdded { .. }
            | ControlEvent::ExposedRemoved { .. } => {}
        }
    }

    /// Return the UUID owning a given DNS label, if any. The input is the
    /// label as it appears in the DNS query (already lowercased by the
    /// resolver).
    pub async fn lookup_uuid(&self, label: &str) -> Option<String> {
        self.inner.read().await.by_label.get(label).cloned()
    }
}

fn insert(inner: &mut Inner, node_uuid: &str, display_name: &str) {
    // Drop any prior label this UUID owned — names can change, and an
    // earlier mapping must not linger after a rename.
    if let Some(prev_name) = inner.by_uuid.get(node_uuid) {
        let prev_label = sanitize_dns_label(prev_name);
        if !prev_label.is_empty() {
            // Only drop if the prior label still points at *this* uuid
            // (defensive — avoid kicking out a rename collision).
            if inner.by_label.get(&prev_label).map(String::as_str) == Some(node_uuid) {
                inner.by_label.remove(&prev_label);
            }
        }
    }
    let label = sanitize_dns_label(display_name);
    inner
        .by_uuid
        .insert(node_uuid.to_string(), display_name.to_string());
    if !label.is_empty() {
        inner.by_label.insert(label, node_uuid.to_string());
    }
}

fn remove_uuid(inner: &mut Inner, node_uuid: &str) {
    if let Some(name) = inner.by_uuid.remove(node_uuid) {
        let label = sanitize_dns_label(&name);
        if !label.is_empty() && inner.by_label.get(&label).map(String::as_str) == Some(node_uuid) {
            inner.by_label.remove(&label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(uuid: &str, name: &str) -> ControlNodeInfo {
        ControlNodeInfo {
            node_uuid: uuid.into(),
            fingerprint: "fp".into(),
            display_name: name.into(),
            role: "node".into(),
            status: "active".into(),
            last_seen: None,
            is_control_node: false,
        }
    }

    fn control_node(uuid: &str, name: &str) -> ControlNodeInfo {
        ControlNodeInfo {
            is_control_node: true,
            ..node(uuid, name)
        }
    }

    #[tokio::test]
    async fn seed_then_lookup() {
        let map = DisplayNameMap::new();
        map.seed(&[
            node("u1", "Macbook Pro"),
            node("u2", "rack-toulouse"),
            node("u3", ""),
        ])
        .await;
        assert_eq!(map.lookup_uuid("macbook-pro").await.as_deref(), Some("u1"));
        assert_eq!(
            map.lookup_uuid("rack-toulouse").await.as_deref(),
            Some("u2")
        );
        // Empty display_name skipped.
        assert!(map.lookup_uuid("u3").await.is_none());
        // Unknown label.
        assert!(map.lookup_uuid("nope").await.is_none());
    }

    #[tokio::test]
    async fn rename_event_updates_label() {
        let map = DisplayNameMap::new();
        map.seed(&[node("u1", "old-name")]).await;
        assert_eq!(map.lookup_uuid("old-name").await.as_deref(), Some("u1"));

        map.apply(&ControlEvent::NodeRenamed {
            node_uuid: "u1".into(),
            new_display_name: "new-name".into(),
        })
        .await;

        assert!(map.lookup_uuid("old-name").await.is_none());
        assert_eq!(map.lookup_uuid("new-name").await.as_deref(), Some("u1"));
    }

    #[tokio::test]
    async fn revoke_event_drops_label() {
        let map = DisplayNameMap::new();
        map.seed(&[node("u1", "doomed")]).await;
        map.apply(&ControlEvent::NodeRevoked {
            node_uuid: "u1".into(),
        })
        .await;
        assert!(map.lookup_uuid("doomed").await.is_none());
    }

    #[tokio::test]
    async fn join_event_adds_label() {
        let map = DisplayNameMap::new();
        map.apply(&ControlEvent::NodeJoined {
            node_uuid: "u1".into(),
            display_name: "fresh".into(),
            role: "node".into(),
        })
        .await;
        assert_eq!(map.lookup_uuid("fresh").await.as_deref(), Some("u1"));
    }

    #[tokio::test]
    async fn reseed_replaces_state() {
        let map = DisplayNameMap::new();
        map.seed(&[node("u1", "first")]).await;
        // Reseed without u1 → label must vanish.
        map.seed(&[node("u2", "second")]).await;
        assert!(map.lookup_uuid("first").await.is_none());
        assert_eq!(map.lookup_uuid("second").await.as_deref(), Some("u2"));
    }

    #[tokio::test]
    async fn seed_picks_up_control_uuid() {
        let map = DisplayNameMap::new();
        map.seed(&[node("u1", "macbook"), control_node("u2", "homelab")])
            .await;
        assert_eq!(map.control_uuid().await.as_deref(), Some("u2"));
    }

    #[tokio::test]
    async fn reseed_replaces_control_uuid() {
        let map = DisplayNameMap::new();
        map.seed(&[control_node("u1", "old-control")]).await;
        assert_eq!(map.control_uuid().await.as_deref(), Some("u1"));
        // Reseed without u1 holding the role — control_uuid must clear.
        map.seed(&[node("u2", "successor")]).await;
        assert!(map.control_uuid().await.is_none());
    }

    #[tokio::test]
    async fn local_seed_sets_control_uuid_eagerly() {
        let map = DisplayNameMap::new();
        // Before any ListNodes arrives, the local node knows it's control.
        map.set_local_control_uuid("u1".into()).await;
        assert_eq!(map.control_uuid().await.as_deref(), Some("u1"));
    }

    #[tokio::test]
    async fn unrelated_events_ignored() {
        let map = DisplayNameMap::new();
        map.seed(&[node("u1", "kept")]).await;
        map.apply(&ControlEvent::NodePromoted {
            node_uuid: "u1".into(),
            new_role: "admin".into(),
        })
        .await;
        map.apply(&ControlEvent::ExposedAdded {
            domain: "x.y.z".into(),
            node_uuid: "u1".into(),
        })
        .await;
        assert_eq!(map.lookup_uuid("kept").await.as_deref(), Some("u1"));
    }
}
