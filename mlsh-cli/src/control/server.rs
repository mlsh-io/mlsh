use anyhow::Result;
use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

pub async fn serve() -> Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/clusters/{cluster}/nodes", get(list_nodes));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
    tracing::info!("mlsh-control listening on {addr}");

    // TODO: add TLS (rcgen self-signed for dev, ACME for prod)
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn list_nodes(Path(cluster): Path<String>) -> impl IntoResponse {
    let mut client = match DaemonClient::connect_default().await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": format!("mlshtund unreachable: {:#}", e) })),
            )
                .into_response();
        }
    };

    match client.list_nodes(&cluster).await {
        Ok(DaemonResponse::NodeList { nodes }) => Json(nodes).into_response(),
        Ok(DaemonResponse::Error { code, message }) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": message, "code": code })),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "unexpected daemon response" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{:#}", e) })),
        )
            .into_response(),
    }
}
