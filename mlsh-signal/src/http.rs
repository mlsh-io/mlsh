//! Internal HTTP API for cloud integration.
//!
//! Minimal axum server for cluster/node management.
//! Only started when `cloud_api_token` is configured.
//! Binds to `127.0.0.1:4434` (internal network only).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::cluster;
use crate::metrics::Metrics;
use crate::sessions::SessionStore;

struct HttpState {
    pool: SqlitePool,
    api_token: String,
    sessions: Arc<SessionStore>,
    metrics: Arc<Metrics>,
}

// -- Auth middleware ----------------------------------------------------------

fn verify_token(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let provided = headers
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != expected {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

// -- Create cluster ----------------------------------------------------------

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
    verify_token(&headers, &state.api_token)?;

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

// -- List clusters -----------------------------------------------------------

#[derive(Serialize)]
struct ClusterInfo {
    id: String,
    name: String,
    created_at: String,
    node_count: i64,
    online_count: usize,
}

async fn list_clusters(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ClusterInfo>>, StatusCode> {
    verify_token(&headers, &state.api_token)?;

    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, name, created_at FROM clusters ORDER BY created_at DESC")
            .fetch_all(&state.pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut clusters = Vec::new();
    for (id, name, created_at) in rows {
        let node_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE cluster_id = ?1")
                .bind(&id)
                .fetch_one(&state.pool)
                .await
                .unwrap_or(0);

        let online_count = state.sessions.online_count(&id).await;

        clusters.push(ClusterInfo {
            id,
            name,
            created_at,
            node_count,
            online_count,
        });
    }

    Ok(Json(clusters))
}

// -- List nodes in a cluster -------------------------------------------------

#[derive(Serialize)]
struct NodeInfo {
    node_id: String,
    display_name: String,
    fingerprint: String,
    overlay_ip: String,
    role: String,
    created_at: String,
    online: bool,
}

async fn list_nodes(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    Path(cluster_id): Path<String>,
) -> Result<Json<Vec<NodeInfo>>, StatusCode> {
    verify_token(&headers, &state.api_token)?;

    let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT node_id, display_name, fingerprint, overlay_ip, role, created_at FROM nodes WHERE cluster_id = ?1 ORDER BY created_at",
    )
    .bind(&cluster_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let online_nodes = state.sessions.online_node_ids(&cluster_id).await;

    let nodes = rows
        .into_iter()
        .map(
            |(node_id, display_name, fingerprint, overlay_ip, role, created_at)| {
                let online = online_nodes.contains(&node_id);
                NodeInfo {
                    node_id,
                    display_name,
                    fingerprint,
                    overlay_ip,
                    role,
                    created_at,
                    online,
                }
            },
        )
        .collect();

    Ok(Json(nodes))
}

// -- Delete cluster ----------------------------------------------------------

async fn delete_cluster(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    Path(cluster_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    verify_token(&headers, &state.api_token)?;

    // Kick all connected nodes in this cluster
    state.sessions.kick_all(&cluster_id).await;

    // Delete from DB
    let deleted = crate::db::delete_cluster(&state.pool, &cluster_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete cluster: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// -- Prometheus metrics -------------------------------------------------------

async fn metrics(State(state): State<Arc<HttpState>>) -> (StatusCode, String) {
    (StatusCode::OK, state.metrics.prometheus().await)
}

// -- Server ------------------------------------------------------------------

/// Start the internal HTTP server. Runs until the shutdown receiver fires.
pub async fn run(
    bind_addr: SocketAddr,
    pool: SqlitePool,
    api_token: String,
    sessions: Arc<SessionStore>,
    metrics_ref: Arc<Metrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let state = Arc::new(HttpState {
        pool,
        api_token,
        sessions,
        metrics: metrics_ref,
    });

    let app = Router::new()
        .route("/metrics", get(metrics))
        .route("/internal/clusters", post(create_cluster))
        .route("/internal/clusters", get(list_clusters))
        .route("/internal/clusters/{cluster_id}", delete(delete_cluster))
        .route("/internal/clusters/{cluster_id}/nodes", get(list_nodes))
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
