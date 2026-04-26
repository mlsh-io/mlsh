use anyhow::{Context, Result};
use axum::{
    extract::Path as AxumPath,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

#[derive(RustEmbed)]
#[folder = "ui/dist/"]
struct UiAssets;

pub async fn serve() -> Result<()> {
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/clusters/{cluster}/nodes", get(list_nodes))
        .route(
            "/api/v1/clusters/{cluster}/nodes/{target}",
            delete(revoke_node).patch(rename_node),
        )
        .route(
            "/api/v1/clusters/{cluster}/nodes/{target}/promote",
            post(promote_node),
        )
        .fallback(get(serve_ui));

    // Bind on all interfaces so peers in the overlay (and only peers — the
    // public 0.0.0.0 is masked by the host firewall typically; the overlay
    // is the only path) can reach it via `http://<peer-overlay-ip>:8443`.
    // No app-level auth yet (TODO: JWT signed by an admin node, ADR-029).
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));
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

async fn list_nodes(AxumPath(cluster): AxumPath<String>) -> Response {
    daemon_call(
        |mut c| async move { c.list_nodes(&cluster).await },
        |resp| match resp {
            DaemonResponse::NodeList { nodes } => Ok(Json(nodes).into_response()),
            other => Err(other),
        },
    )
    .await
}

async fn revoke_node(AxumPath((cluster, target)): AxumPath<(String, String)>) -> Response {
    daemon_call(
        |mut c| async move { c.revoke(&cluster, &target).await },
        ok_response,
    )
    .await
}

#[derive(Deserialize)]
struct RenameBody {
    display_name: String,
}

async fn rename_node(
    AxumPath((cluster, target)): AxumPath<(String, String)>,
    Json(body): Json<RenameBody>,
) -> Response {
    daemon_call(
        |mut c| async move { c.rename(&cluster, &target, &body.display_name).await },
        ok_response,
    )
    .await
}

#[derive(Deserialize)]
struct PromoteBody {
    role: String,
}

async fn promote_node(
    AxumPath((cluster, target)): AxumPath<(String, String)>,
    Json(body): Json<PromoteBody>,
) -> Response {
    daemon_call(
        |mut c| async move { c.promote(&cluster, &target, &body.role).await },
        ok_response,
    )
    .await
}

fn ok_response(resp: DaemonResponse) -> Result<Response, DaemonResponse> {
    match resp {
        DaemonResponse::Ok { message } => {
            Ok(Json(serde_json::json!({ "ok": true, "message": message })).into_response())
        }
        other => Err(other),
    }
}

async fn daemon_call<F, Fut, M>(call: F, map: M) -> Response
where
    F: FnOnce(DaemonClient) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<DaemonResponse>>,
    M: FnOnce(DaemonResponse) -> Result<Response, DaemonResponse>,
{
    let client = match DaemonClient::connect_default().await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": format!("mlshtund unreachable: {:#}", e) })),
            )
                .into_response();
        }
    };

    match call(client).await {
        Ok(resp) => match map(resp) {
            Ok(r) => r,
            Err(DaemonResponse::Error { code, message }) => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": message, "code": code })),
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "unexpected daemon response" })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{:#}", e) })),
        )
            .into_response(),
    }
}
