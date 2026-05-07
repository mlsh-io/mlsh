//! Health check endpoint.

use axum::{response::Json, routing::get, Router};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Mount the JSON health route under `/api/v1`.
pub fn router() -> Router {
    Router::new().route("/api/v1/health", get(get_status))
}

/// Get cluster status.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    responses(
        (status = 200, description = "Health status", body = HealthStatusResponse),
    ),
    tag = "Cluster"
)]
pub async fn get_status() -> Json<HealthStatusResponse> {
    Json(HealthStatusResponse {
        status: "healthy".to_string(),
        service: "mlsh-control".to_string(),
        version: env!("GIT_VERSION").to_string(),
    })
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct HealthStatusResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, TestApp};

    #[tokio::test]
    async fn health_returns_healthy() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/health").await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body: HealthStatusResponse = body_json(resp).await;
        assert_eq!(body.status, "healthy");
        assert_eq!(body.service, "mlsh-control");
        assert!(!body.version.is_empty());
    }
}
