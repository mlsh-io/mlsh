//! Cluster singleton — metadata about the cluster this control instance serves.

use axum::{extract::State, response::Json, routing::get, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::control::auth::AuthState;

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/cluster", get(get_cluster))
        .with_state(state)
}

/// Get cluster metadata.
#[utoipa::path(
    get,
    path = "/api/v1/cluster",
    responses(
        (status = 200, description = "Cluster metadata", body = ClusterResponse),
    ),
    tag = "Cluster"
)]
pub async fn get_cluster(State(state): State<AuthState>) -> Json<ClusterResponse> {
    Json(ClusterResponse {
        id: state.cluster.cluster_id.clone(),
        name: state.cluster.name.clone(),
        version: env!("GIT_VERSION").to_string(),
    })
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClusterResponse {
    /// Stable cluster UUID (matches `cluster.id` in the cluster TOML).
    pub id: String,
    /// Human-readable cluster name (matches `cluster.name` in the cluster TOML).
    pub name: String,
    /// mlsh version of the control instance serving this cluster.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, TestApp};

    #[tokio::test]
    async fn get_cluster_returns_dummy_metadata() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/cluster").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body: ClusterResponse = body_json(resp).await;
        assert_eq!(body.id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(body.name, "test-cluster");
        assert!(!body.version.is_empty());
    }

    #[tokio::test]
    async fn get_cluster_is_public_no_auth_required() {
        // The cluster endpoint exposes only metadata that's already public
        // by hostname (`control.<cluster>` resolves to it). No auth gate.
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/cluster").await;
        // Either OK (no auth required) or matches what the route actually
        // does today. As of writing, the route has no `Caller` extractor so
        // this should be 200 OK.
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
