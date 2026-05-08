//! Nodes API — the cluster's authoritative node registry.
//!
//! Path id segment `{node}` accepts either a node UUID or a display name; the
//! handler resolves to a UUID via [`super::super::nodes::resolve_target`].

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use std::collections::HashSet;

use crate::control::auth::{AuthState, Caller};
use crate::control::nodes::{self, NodeRow};
use mlsh_protocol::control::ControlEvent;

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/nodes", get(list_nodes))
        .route("/api/v1/nodes/{node}", get(get_node).delete(delete_node))
        .route("/api/v1/nodes/{node}/name", post(set_name))
        .route("/api/v1/nodes/{node}/role", post(set_role))
        .route("/api/v1/nodes/{node}/revoke", post(revoke))
        .with_state(state)
}

// ---------- response shapes ----------

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NodeResponse {
    /// Stable node UUID.
    pub id: String,
    /// Mutable, human-readable name.
    pub display_name: String,
    /// `"node"` or `"admin"` (and the implied `"control"` superset).
    pub role: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// `true` when the node is `active` AND signal currently has a live QUIC
    /// session for it. Real liveness, sourced from signal's session map —
    /// not from a heartbeat.
    pub online: bool,
    /// Cert fingerprint (cluster-CA-signed).
    pub fingerprint: String,
    /// RFC 3339 UTC, last activity stamp. `None` on a fresh registration.
    pub last_seen: Option<String>,
    /// RFC 3339 UTC.
    pub created_at: String,
}

/// Build a response row, marking online only if the node is `active` AND
/// `online_uuids` contains its UUID. The live set is fetched once per
/// request from the local tund manager (which round-trips to signal).
fn build_response(n: NodeRow, online_uuids: &HashSet<String>) -> NodeResponse {
    let online = n.status == "active" && online_uuids.contains(&n.node_uuid);
    NodeResponse {
        id: n.node_uuid,
        display_name: n.display_name,
        role: n.role,
        status: n.status,
        online,
        fingerprint: n.fingerprint,
        last_seen: n.last_seen,
        created_at: n.created_at,
    }
}

/// Ask the daemon's tunnel manager which nodes have a live signal session
/// for this cluster. Returns an empty set if the manager isn't running or
/// signal is unreachable — callers degrade to "everyone offline" rather
/// than a stale fiction.
async fn fetch_online_uuids(cluster_name: &str) -> HashSet<String> {
    let Some(manager) = crate::tund::manager_handle::get() else {
        return HashSet::new();
    };
    let mgr = manager.lock().await;
    match mgr.list_nodes(cluster_name).await {
        Ok(nodes) => nodes
            .into_iter()
            .filter(|n| n.online)
            .map(|n| n.node_id)
            .collect(),
        Err(e) => {
            tracing::debug!(error = %e, cluster = %cluster_name, "online-set fetch failed");
            HashSet::new()
        }
    }
}

// ---------- request bodies ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetNameRequest {
    pub display_name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRoleRequest {
    /// `"node"` or `"admin"`.
    pub role: String,
}

// ---------- handlers ----------

/// List every node in the cluster.
#[utoipa::path(
    get,
    path = "/api/v1/nodes",
    responses(
        (status = 200, description = "Nodes", body = [NodeResponse]),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "Nodes"
)]
pub async fn list_nodes(State(state): State<AuthState>, _caller: Caller) -> Response {
    let cluster = state.cluster.cluster_id.clone();
    match nodes::list(state.store.pool(), &cluster).await {
        Ok(rows) => {
            let online_uuids = fetch_online_uuids(&state.cluster.name).await;
            let out: Vec<NodeResponse> = rows
                .into_iter()
                .map(|r| build_response(r, &online_uuids))
                .collect();
            Json(out).into_response()
        }
        Err(e) => internal_error(e),
    }
}

/// Get a single node by id (or display name).
#[utoipa::path(
    get,
    path = "/api/v1/nodes/{node}",
    params(("node" = String, Path, description = "Node UUID or display name")),
    responses(
        (status = 200, description = "Node", body = NodeResponse),
        (status = 404, description = "Node not found"),
    ),
    tag = "Nodes"
)]
pub async fn get_node(
    State(state): State<AuthState>,
    _caller: Caller,
    Path(target): Path<String>,
) -> Response {
    let cluster = state.cluster.cluster_id.clone();
    let uuid = match nodes::resolve_target(state.store.pool(), &cluster, &target).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(e),
    };
    match nodes::find(state.store.pool(), &cluster, &uuid).await {
        Ok(Some(row)) => {
            let online_uuids = fetch_online_uuids(&state.cluster.name).await;
            Json(build_response(row, &online_uuids)).into_response()
        }
        Ok(None) => not_found(),
        Err(e) => internal_error(e),
    }
}

/// Delete (= revoke) a node. Idempotent.
#[utoipa::path(
    delete,
    path = "/api/v1/nodes/{node}",
    params(("node" = String, Path, description = "Node UUID or display name")),
    responses(
        (status = 204, description = "Node revoked"),
        (status = 404, description = "Node not found"),
    ),
    tag = "Nodes"
)]
pub async fn delete_node(
    State(state): State<AuthState>,
    caller: Caller,
    Path(target): Path<String>,
) -> Response {
    revoke_inner(state, caller, target).await
}

/// Revoke a node. Idempotent — succeeds even if the node was already revoked.
#[utoipa::path(
    post,
    path = "/api/v1/nodes/{node}/revoke",
    params(("node" = String, Path, description = "Node UUID or display name")),
    responses(
        (status = 204, description = "Node revoked"),
        (status = 404, description = "Node not found"),
    ),
    tag = "Nodes"
)]
pub async fn revoke(
    State(state): State<AuthState>,
    caller: Caller,
    Path(target): Path<String>,
) -> Response {
    revoke_inner(state, caller, target).await
}

async fn revoke_inner(state: AuthState, _caller: Caller, target: String) -> Response {
    let cluster = state.cluster.cluster_id.clone();
    let uuid = match nodes::resolve_target(state.store.pool(), &cluster, &target).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(e),
    };
    match nodes::set_status(state.store.pool(), &cluster, &uuid, "revoked").await {
        Ok(_) => {
            state
                .events
                .publish(&cluster, ControlEvent::NodeRevoked { node_uuid: uuid })
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => internal_error(e),
    }
}

/// Set the node's display name.
#[utoipa::path(
    post,
    path = "/api/v1/nodes/{node}/name",
    params(("node" = String, Path, description = "Node UUID or display name")),
    request_body = SetNameRequest,
    responses(
        (status = 204, description = "Name updated"),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Node not found"),
    ),
    tag = "Nodes"
)]
pub async fn set_name(
    State(state): State<AuthState>,
    _caller: Caller,
    Path(target): Path<String>,
    Json(body): Json<SetNameRequest>,
) -> Response {
    let new_name = body.display_name.trim();
    if new_name.is_empty() {
        return (StatusCode::BAD_REQUEST, "display_name must not be empty").into_response();
    }
    let cluster = state.cluster.cluster_id.clone();
    let uuid = match nodes::resolve_target(state.store.pool(), &cluster, &target).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(e),
    };
    match nodes::set_display_name(state.store.pool(), &cluster, &uuid, new_name).await {
        Ok(true) => {
            state
                .events
                .publish(
                    &cluster,
                    ControlEvent::NodeRenamed {
                        node_uuid: uuid,
                        new_display_name: new_name.to_string(),
                    },
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(),
        Err(e) => internal_error(e),
    }
}

/// Set the node's role (`node` or `admin`).
#[utoipa::path(
    post,
    path = "/api/v1/nodes/{node}/role",
    params(("node" = String, Path, description = "Node UUID or display name")),
    request_body = SetRoleRequest,
    responses(
        (status = 204, description = "Role updated"),
        (status = 400, description = "Invalid role"),
        (status = 404, description = "Node not found"),
    ),
    tag = "Nodes"
)]
pub async fn set_role(
    State(state): State<AuthState>,
    _caller: Caller,
    Path(target): Path<String>,
    Json(body): Json<SetRoleRequest>,
) -> Response {
    if body.role != "admin" && body.role != "node" {
        return (StatusCode::BAD_REQUEST, "role must be 'admin' or 'node'").into_response();
    }
    let cluster = state.cluster.cluster_id.clone();
    let uuid = match nodes::resolve_target(state.store.pool(), &cluster, &target).await {
        Ok(Some(u)) => u,
        Ok(None) => return not_found(),
        Err(e) => return internal_error(e),
    };
    match nodes::set_role(state.store.pool(), &cluster, &uuid, &body.role).await {
        Ok(true) => {
            state
                .events
                .publish(
                    &cluster,
                    ControlEvent::NodePromoted {
                        node_uuid: uuid,
                        new_role: body.role.clone(),
                    },
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => not_found(),
        Err(e) => internal_error(e),
    }
}

// ---------- helpers ----------

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    tracing::warn!(error = %e, "nodes handler error");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, body_string, TestApp};
    use serde_json::json;

    /// Insert a fresh node row into the test DB.
    async fn seed_node(
        app: &TestApp,
        node_uuid: &str,
        fingerprint: &str,
        display_name: &str,
        role: &str,
    ) {
        nodes::upsert(
            app.state.store.pool(),
            app.cluster_id(),
            node_uuid,
            fingerprint,
            "pubkey",
            display_name,
            role,
        )
        .await
        .unwrap();
    }

    // ---------- GET /api/v1/nodes ----------

    #[tokio::test]
    async fn list_nodes_empty() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/nodes").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let nodes: Vec<NodeResponse> = body_json(resp).await;
        assert!(nodes.is_empty());
    }

    #[tokio::test]
    async fn list_nodes_returns_seeded_nodes() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "macbook", "admin").await;
        seed_node(&app, "u2", "fp2", "homelab", "node").await;

        let resp = app.get("/api/v1/nodes").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let nodes: Vec<NodeResponse> = body_json(resp).await;
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.status == "active"));
        // No tund manager registered in the test harness → live presence
        // can't be queried → everyone is reported offline. Liveness is
        // covered directly via `build_response_marks_online_set` below.
        assert!(nodes.iter().all(|n| !n.online));
    }

    #[test]
    fn build_response_marks_online_set() {
        let row = NodeRow {
            cluster_id: "c".into(),
            node_uuid: "u1".into(),
            fingerprint: "fp".into(),
            public_key: "pk".into(),
            display_name: "macbook".into(),
            role: "admin".into(),
            status: "active".into(),
            last_seen: None,
            created_at: "2026-01-01 00:00:00".into(),
        };

        let mut live = HashSet::new();
        assert!(
            !build_response(row.clone(), &live).online,
            "absent → offline"
        );

        live.insert("u1".into());
        assert!(
            build_response(row.clone(), &live).online,
            "present → online"
        );

        let revoked = NodeRow {
            status: "revoked".into(),
            ..row
        };
        assert!(
            !build_response(revoked, &live).online,
            "revoked node is never online, even with a live session"
        );
    }

    #[tokio::test]
    async fn list_nodes_unauthenticated_returns_401() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/nodes").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------- GET /api/v1/nodes/{node} ----------

    #[tokio::test]
    async fn get_node_by_uuid() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "macbook", "node").await;

        let resp = app.get("/api/v1/nodes/u1").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: NodeResponse = body_json(resp).await;
        assert_eq!(body.id, "u1");
        assert_eq!(body.display_name, "macbook");
        assert_eq!(body.role, "node");
    }

    #[tokio::test]
    async fn get_node_by_display_name() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "macbook", "node").await;

        let resp = app.get("/api/v1/nodes/macbook").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: NodeResponse = body_json(resp).await;
        assert_eq!(body.id, "u1");
    }

    #[tokio::test]
    async fn get_node_not_found() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/nodes/ghost").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---------- POST /api/v1/nodes/{node}/name ----------

    #[tokio::test]
    async fn set_name_updates_display_name() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "old-name", "node").await;

        let resp = app
            .post(
                "/api/v1/nodes/u1/name",
                &json!({ "display_name": "new-name" }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let row = nodes::find(app.state.store.pool(), app.cluster_id(), "u1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.display_name, "new-name");
    }

    #[tokio::test]
    async fn set_name_empty_returns_400() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let resp = app
            .post("/api/v1/nodes/u1/name", &json!({ "display_name": "   " }))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_name_unknown_node_returns_404() {
        let app = TestApp::new().await;
        let resp = app
            .post("/api/v1/nodes/ghost/name", &json!({ "display_name": "x" }))
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---------- POST /api/v1/nodes/{node}/role ----------

    #[tokio::test]
    async fn set_role_promotes_to_admin() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let resp = app
            .post("/api/v1/nodes/u1/role", &json!({ "role": "admin" }))
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let row = nodes::find(app.state.store.pool(), app.cluster_id(), "u1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.role, "admin");
    }

    #[tokio::test]
    async fn set_role_demotes_to_node() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "admin").await;

        let resp = app
            .post("/api/v1/nodes/u1/role", &json!({ "role": "node" }))
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let row = nodes::find(app.state.store.pool(), app.cluster_id(), "u1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.role, "node");
    }

    #[tokio::test]
    async fn set_role_invalid_returns_400() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let resp = app
            .post("/api/v1/nodes/u1/role", &json!({ "role": "superadmin" }))
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---------- POST /api/v1/nodes/{node}/revoke ----------

    #[tokio::test]
    async fn revoke_marks_node_revoked() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let resp = app.post("/api/v1/nodes/u1/revoke", &json!({})).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let row = nodes::find(app.state.store.pool(), app.cluster_id(), "u1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "revoked");
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let r1 = app.post("/api/v1/nodes/u1/revoke", &json!({})).await;
        assert_eq!(r1.status(), StatusCode::NO_CONTENT);
        let r2 = app.post("/api/v1/nodes/u1/revoke", &json!({})).await;
        assert_eq!(r2.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revoke_unknown_returns_404() {
        let app = TestApp::new().await;
        let resp = app.post("/api/v1/nodes/ghost/revoke", &json!({})).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---------- DELETE /api/v1/nodes/{node} ----------

    #[tokio::test]
    async fn delete_node_marks_revoked() {
        let app = TestApp::new().await;
        seed_node(&app, "u1", "fp1", "name", "node").await;

        let resp = app.delete("/api/v1/nodes/u1").await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let row = nodes::find(app.state.store.pool(), app.cluster_id(), "u1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "revoked");
    }

    /// Sanity-check that the `body_string` helper is wired into this module
    /// (otherwise rust-analyzer will flag it as unused). Real tests above
    /// only use `body_json`; this exercises the string path against a route
    /// that returns a 401 plain-text body.
    #[tokio::test]
    async fn unauth_response_body_is_human_readable() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/nodes").await;
        let s = body_string(resp).await;
        assert!(s.contains("unauthenticated"), "got: {s}");
    }
}
