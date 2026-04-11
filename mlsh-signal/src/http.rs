//! Internal HTTP API for cloud integration.
//!
//! Minimal axum server with a single endpoint for cluster creation.
//! Only started when `cloud_api_token` is configured.
//! Binds to `127.0.0.1:4434` (internal network only).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::cluster;

struct HttpState {
    pool: SqlitePool,
    api_token: String,
}

#[derive(Deserialize)]
struct CreateClusterRequest {
    name: String,
    #[serde(default = "default_ttl")]
    ttl_minutes: u64,
}

fn default_ttl() -> u64 {
    15
}

#[derive(Serialize)]
struct CreateClusterResponse {
    cluster_id: String,
    name: String,
    setup_token: String,
}

async fn create_cluster(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    Json(req): Json<CreateClusterRequest>,
) -> Result<Json<CreateClusterResponse>, StatusCode> {
    // Verify internal secret
    let provided = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided != state.api_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let result = cluster::create_cluster(&state.pool, &req.name, req.ttl_minutes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create cluster: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreateClusterResponse {
        cluster_id: result.cluster_id,
        name: result.name,
        setup_token: result.setup_token,
    }))
}

/// Start the internal HTTP server. Runs until the shutdown receiver fires.
pub async fn run(
    bind_addr: SocketAddr,
    pool: SqlitePool,
    api_token: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let state = Arc::new(HttpState { pool, api_token });

    let app = Router::new()
        .route("/internal/clusters", post(create_cluster))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("Internal HTTP API listening on {}", bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await?;

    Ok(())
}
