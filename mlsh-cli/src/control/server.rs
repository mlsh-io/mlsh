use anyhow::{Context, Result};
use axum::{
    extract::Path as AxumPath,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use rust_embed::RustEmbed;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

#[derive(RustEmbed)]
#[folder = "ui/dist/"]
struct UiAssets;

pub async fn serve() -> Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/clusters/{cluster}/nodes", get(list_nodes))
        .fallback(get(serve_ui));

    // Loopback only. Remote access goes through `mlsh control open` which
    // tunnels via the overlay (mTLS-authenticated peers, role-checked by the
    // target mlshtund). No direct internet exposure for the admin UI.
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8443));
    tracing::info!("mlsh-control listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .context("mlsh-control HTTP server crashed")?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn serve_ui(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let asset = UiAssets::get(path).or_else(|| UiAssets::get("index.html"));
    match asset {
        Some(file) => {
            let mime = mime_for_path(path);
            ([(header::CONTENT_TYPE, mime)], file.data.into_owned()).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn mime_for_path(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, e)| e) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

async fn whoami() -> impl IntoResponse {
    let cluster = std::env::var("MLSH_CONTROL_CLUSTER").unwrap_or_default();
    Json(serde_json::json!({
        "cluster": cluster,
        "roles": ["node", "admin", "control"],
    }))
}

async fn list_nodes(AxumPath(cluster): AxumPath<String>) -> impl IntoResponse {
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
