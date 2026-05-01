//! CBOR-over-UNIX-socket listener for the mlsh-control plane.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use mlsh_protocol::control::{
    ControlAuthHeader, ControlEvent, ControlNodeInfo, ControlRequest, ControlResponse,
};
use mlsh_protocol::framing;
use sqlx::SqlitePool;
use tokio::net::{UnixListener, UnixStream};

use crate::control::events::EventHub;
use crate::control::nodes;

pub fn default_socket_path() -> PathBuf {
    crate::tund::tunnel::control_plane_socket_path()
}

#[derive(Clone)]
pub struct StreamState {
    pub pool: SqlitePool,
    pub events: EventHub,
}

pub async fn serve(socket_path: &Path, state: StreamState) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path).ok();
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(path = %socket_path.display(), "mlsh-control CBOR socket listening");

    let state = Arc::new(state);
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_one(stream, &state).await {
                        tracing::debug!(error = %e, "control CBOR session ended with error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "control socket accept failed");
                return Err(e.into());
            }
        }
    }
}

async fn handle_one(mut stream: UnixStream, state: &StreamState) -> Result<()> {
    let (mut rd, mut wr) = stream.split();

    let header: ControlAuthHeader = framing::read_msg(&mut rd).await?;
    let request: ControlRequest = framing::read_msg(&mut rd).await?;

    if matches!(request, ControlRequest::Subscribe) {
        return run_subscribe(&mut wr, &state.events, cluster_key(&header)).await;
    }

    let response = dispatch(state, &header, &request).await;
    framing::write_msg(&mut wr, &response).await?;
    Ok(())
}

/// Stream `ControlEvent` records to a subscriber until the connection drops or
/// the hub evicts us (slow consumer).
async fn run_subscribe(
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    hub: &EventHub,
    cluster_key: &str,
) -> Result<()> {
    let (_handle, mut rx) = hub.register(cluster_key).await;
    tracing::debug!(cluster = %cluster_key, "control: subscribe stream opened");
    while let Some(event) = rx.recv().await {
        if let Err(e) = framing::write_msg(wr, &*event).await {
            tracing::debug!(cluster = %cluster_key, error = %e, "control: subscribe write failed; closing");
            break;
        }
    }
    tracing::debug!(cluster = %cluster_key, "control: subscribe stream closed");
    Ok(())
}

fn cluster_key(auth: &ControlAuthHeader) -> &str {
    if !auth.cluster_name.is_empty() {
        &auth.cluster_name
    } else {
        &auth.cluster_id
    }
}

async fn dispatch(
    state: &StreamState,
    auth: &ControlAuthHeader,
    req: &ControlRequest,
) -> ControlResponse {
    let pool = &state.pool;
    let events = &state.events;
    match req {
        ControlRequest::AdoptConfirm {
            node_uuid,
            fingerprint,
            public_key,
            display_name,
            invite_token: _,
        } => match nodes::upsert(
            pool,
            cluster_key(auth),
            node_uuid,
            fingerprint,
            public_key,
            display_name,
            if node_uuid == &auth.caller_node_uuid {
                &auth.caller_role
            } else {
                "node"
            },
        )
        .await
        {
            Ok(()) => ControlResponse::AdoptAck {
                accepted: true,
                message: None,
            },
            Err(e) => ControlResponse::error("internal", &format!("upsert failed: {e:#}")),
        },

        ControlRequest::ListNodes => match nodes::list(pool, cluster_key(auth)).await {
            Ok(rows) => ControlResponse::Nodes {
                nodes: rows.into_iter().map(node_row_to_info).collect(),
            },
            Err(e) => ControlResponse::error("internal", &format!("list failed: {e:#}")),
        },

        ControlRequest::Rename {
            target_node_uuid,
            new_display_name,
        } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can rename");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            let old_name = match nodes::get_display_name(pool, key, &uuid).await {
                Ok(Some(n)) => n,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("lookup failed: {e:#}"))
                }
            };
            match nodes::set_display_name(pool, key, &uuid, new_display_name).await {
                Ok(true) => {}
                Ok(false) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("rename failed: {e:#}"))
                }
            }
            let _ = old_name;
            events
                .publish(
                    key,
                    ControlEvent::NodeRenamed {
                        node_uuid: uuid,
                        new_display_name: new_display_name.clone(),
                    },
                )
                .await;
            ControlResponse::Ok
        }

        ControlRequest::Promote {
            target_node_uuid,
            new_role,
        } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can promote");
            }
            if new_role != "admin" && new_role != "node" {
                return ControlResponse::error("bad_role", "role must be 'admin' or 'node'");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            match nodes::set_role(pool, key, &uuid, new_role).await {
                Ok(true) => {
                    events
                        .publish(
                            key,
                            ControlEvent::NodePromoted {
                                node_uuid: uuid,
                                new_role: new_role.clone(),
                            },
                        )
                        .await;
                    ControlResponse::Ok
                }
                Ok(false) => ControlResponse::error("not_found", "Node not found"),
                Err(e) => ControlResponse::error("internal", &format!("promote failed: {e:#}")),
            }
        }

        ControlRequest::Revoke { target_node_uuid } => {
            if auth.caller_role != "admin" {
                return ControlResponse::error("forbidden", "Only admin nodes can revoke");
            }
            let key = cluster_key(auth);
            let uuid = match nodes::resolve_target(pool, key, target_node_uuid).await {
                Ok(Some(u)) => u,
                Ok(None) => return ControlResponse::error("not_found", "Node not found"),
                Err(e) => {
                    return ControlResponse::error("internal", &format!("resolve failed: {e:#}"))
                }
            };
            match nodes::set_status(pool, key, &uuid, "revoked").await {
                Ok(true) => {
                    events
                        .publish(key, ControlEvent::NodeRevoked { node_uuid: uuid })
                        .await;
                    ControlResponse::Ok
                }
                Ok(false) => ControlResponse::error("not_found", "Node not found"),
                Err(e) => ControlResponse::error("internal", &format!("revoke failed: {e:#}")),
            }
        }

        ControlRequest::Subscribe => {
            // Handled in handle_one before dispatch is called.
            ControlResponse::error("internal", "Subscribe must not reach dispatch")
        }
    }
}

fn node_row_to_info(r: nodes::NodeRow) -> ControlNodeInfo {
    ControlNodeInfo {
        node_uuid: r.node_uuid,
        fingerprint: r.fingerprint,
        display_name: r.display_name,
        role: r.role,
        status: r.status,
        last_seen: r.last_seen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn test_state() -> StreamState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE nodes (
                cluster_id    TEXT NOT NULL,
                node_uuid     TEXT NOT NULL,
                fingerprint   TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                display_name  TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'node',
                status        TEXT NOT NULL DEFAULT 'active',
                last_seen     TEXT,
                created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (cluster_id, node_uuid)
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        StreamState {
            pool,
            events: EventHub::new(),
        }
    }

    fn admin_header(cluster: &str, caller_uuid: &str) -> ControlAuthHeader {
        ControlAuthHeader {
            cluster_id: cluster.into(),
            cluster_name: cluster.into(),
            caller_node_uuid: caller_uuid.into(),
            caller_fingerprint: "fp".into(),
            caller_role: "admin".into(),
        }
    }

    async fn seed_node(state: &StreamState, cluster: &str, uuid: &str, name: &str) {
        nodes::upsert(&state.pool, cluster, uuid, "fp", "pk", name, "admin")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rename_publishes_node_renamed_event() {
        let state = test_state().await;
        seed_node(&state, "auriol", "u1", "old-name").await;

        let (_h, mut rx) = state.events.register("auriol").await;
        let req = ControlRequest::Rename {
            target_node_uuid: "u1".into(),
            new_display_name: "new-name".into(),
        };
        let resp = dispatch(&state, &admin_header("auriol", "u1"), &req).await;
        assert!(matches!(resp, ControlResponse::Ok));

        let event = rx.recv().await.unwrap();
        match &*event {
            ControlEvent::NodeRenamed {
                node_uuid,
                new_display_name,
            } => {
                assert_eq!(node_uuid, "u1");
                assert_eq!(new_display_name, "new-name");
            }
            other => panic!("expected NodeRenamed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn promote_publishes_node_promoted_event() {
        let state = test_state().await;
        seed_node(&state, "auriol", "u1", "name").await;

        let (_h, mut rx) = state.events.register("auriol").await;
        let req = ControlRequest::Promote {
            target_node_uuid: "u1".into(),
            new_role: "node".into(),
        };
        let resp = dispatch(&state, &admin_header("auriol", "caller"), &req).await;
        assert!(matches!(resp, ControlResponse::Ok));

        let event = rx.recv().await.unwrap();
        match &*event {
            ControlEvent::NodePromoted {
                node_uuid,
                new_role,
            } => {
                assert_eq!(node_uuid, "u1");
                assert_eq!(new_role, "node");
            }
            other => panic!("expected NodePromoted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_publishes_node_revoked_event() {
        let state = test_state().await;
        seed_node(&state, "auriol", "u1", "doomed").await;

        let (_h, mut rx) = state.events.register("auriol").await;
        let req = ControlRequest::Revoke {
            target_node_uuid: "u1".into(),
        };
        let resp = dispatch(&state, &admin_header("auriol", "caller"), &req).await;
        assert!(matches!(resp, ControlResponse::Ok));

        let event = rx.recv().await.unwrap();
        match &*event {
            ControlEvent::NodeRevoked { node_uuid } => assert_eq!(node_uuid, "u1"),
            other => panic!("expected NodeRevoked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forbidden_rename_does_not_publish() {
        let state = test_state().await;
        seed_node(&state, "auriol", "u1", "name").await;

        let (_h, mut rx) = state.events.register("auriol").await;
        let mut header = admin_header("auriol", "u1");
        header.caller_role = "node".into();
        let req = ControlRequest::Rename {
            target_node_uuid: "u1".into(),
            new_display_name: "new".into(),
        };
        let resp = dispatch(&state, &header, &req).await;
        assert!(matches!(resp, ControlResponse::Error { .. }));

        // No event should land for a rejected mutation.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
                .await
                .is_err()
        );
    }
}
