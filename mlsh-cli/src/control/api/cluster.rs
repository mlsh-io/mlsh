//! Cluster singleton — metadata + expose toggle for the admin UI.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::control::auth::{AuthState, HumanCaller};

const EXPOSE_ENABLED_KEY: &str = "expose_control_enabled";
const CONTROL_PORT: u16 = 8443;

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/cluster", get(get_cluster))
        .route("/api/v1/cluster/expose", get(get_expose).put(put_expose))
        .with_state(state)
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClusterResponse {
    pub id: String,
    pub name: String,
    pub version: String,
    /// Public DNS zone served by signal (`mlsh.io`, `dev.mlsh.io`, …).
    /// Empty for clusters that haven't received it yet.
    pub zone: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/cluster",
    responses((status = 200, body = ClusterResponse)),
    tag = "Cluster"
)]
pub async fn get_cluster(State(state): State<AuthState>) -> Json<ClusterResponse> {
    Json(ClusterResponse {
        id: state.cluster.cluster_id.clone(),
        name: state.cluster.name.clone(),
        version: env!("GIT_VERSION").to_string(),
        zone: state.cluster.zone(),
    })
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ClusterExposeResponse {
    /// `true` when the toggle is on.
    pub enabled: bool,
    /// Domain the cluster will be reachable at (`<name>.<zone>`). Empty
    /// when the zone is not yet known.
    pub domain: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ClusterExposeRequest {
    pub enabled: bool,
}

fn expose_domain(state: &AuthState) -> String {
    let zone = state.cluster.zone();
    if zone.is_empty() {
        String::new()
    } else {
        format!("{}.{}", state.cluster.name, zone)
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/cluster/expose",
    responses(
        (status = 200, body = ClusterExposeResponse),
        (status = 401),
    ),
    tag = "Cluster"
)]
pub async fn get_expose(State(state): State<AuthState>, _user: HumanCaller) -> Response {
    let enabled = state
        .store
        .get_config(EXPOSE_ENABLED_KEY)
        .await
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(false);
    Json(ClusterExposeResponse {
        enabled,
        domain: expose_domain(&state),
    })
    .into_response()
}

#[utoipa::path(
    put,
    path = "/api/v1/cluster/expose",
    request_body = ClusterExposeRequest,
    responses(
        (status = 200, body = ClusterExposeResponse),
        (status = 400, description = "Cluster zone unknown — reconnect once to learn it"),
        (status = 401),
        (status = 502, description = "Signal rejected the route"),
    ),
    tag = "Cluster"
)]
pub async fn put_expose(
    State(state): State<AuthState>,
    _user: HumanCaller,
    Json(body): Json<ClusterExposeRequest>,
) -> Response {
    let domain = expose_domain(&state);
    if domain.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "cluster zone unknown — reconnect to signal first",
        )
            .into_response();
    }

    let manager = match crate::tund::manager_handle::get() {
        Some(m) => m,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "tunnel manager not yet initialized",
            )
                .into_response();
        }
    };

    if body.enabled {
        let target = format!("https://127.0.0.1:{}", CONTROL_PORT);
        let signal_resp = {
            let mgr = manager.lock().await;
            mgr.expose(&state.cluster.name, &domain, &target).await
        };
        if let Err(e) = signal_resp {
            tracing::warn!(error = %e, "signal expose failed");
            return (StatusCode::BAD_GATEWAY, format!("expose failed: {e}")).into_response();
        }
        crate::tund::ingress::add(&domain, &target);
        crate::tund::acme::spawn_issuance(
            manager.clone(),
            state.cluster.name.clone(),
            domain.clone(),
            None,
            crate::tund::acme::Directory::Production,
        );
    } else {
        let mgr = manager.lock().await;
        if let Err(e) = mgr.unexpose(&state.cluster.name, &domain).await {
            tracing::warn!(error = %e, "signal unexpose failed");
        }
        crate::tund::ingress::remove(&domain);
    }

    if let Err(e) = state
        .store
        .set_config(
            EXPOSE_ENABLED_KEY,
            if body.enabled { "true" } else { "false" },
        )
        .await
    {
        tracing::warn!(error = %e, "persist expose flag failed");
    }

    Json(ClusterExposeResponse {
        enabled: body.enabled,
        domain,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, TestApp};

    #[tokio::test]
    async fn get_cluster_returns_metadata() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/cluster").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: ClusterResponse = body_json(resp).await;
        assert_eq!(body.name, "test-cluster");
        assert_eq!(body.zone, "test.local");
    }

    #[tokio::test]
    async fn get_expose_default_disabled() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/cluster/expose").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: ClusterExposeResponse = body_json(resp).await;
        assert!(!body.enabled);
        assert_eq!(body.domain, "test-cluster.test.local");
    }

    #[tokio::test]
    async fn get_expose_unauthenticated_returns_401() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/cluster/expose").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
