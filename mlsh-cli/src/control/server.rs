use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;

use crate::control::auth::{handlers as auth_handlers, AuthState};

#[derive(RustEmbed)]
#[folder = "ui/dist/"]
struct UiAssets;

pub async fn serve(state: AuthState) -> Result<()> {
    let app = build_app(state);

    let bind = std::env::var("MLSH_CONTROL_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    tracing::info!("mlsh-control listening on http://{bind}");

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind mlsh-control on {bind}"))?;
    axum::serve(listener, app)
        .await
        .context("mlsh-control HTTP server crashed")?;
    Ok(())
}

pub fn build_app(state: AuthState) -> Router {
    let auth_routes = Router::new()
        .route("/auth/login", post(auth_handlers::login))
        .route("/auth/logout", post(auth_handlers::logout))
        .route("/auth/session", get(auth_handlers::whoami))
        .route(
            "/auth/bootstrap",
            get(auth_handlers::bootstrap_status).post(auth_handlers::bootstrap_create),
        )
        .route(
            "/auth/login/device/start",
            post(auth_handlers::device_start),
        )
        .route("/auth/login/device/poll", post(auth_handlers::device_poll))
        .route("/auth/totp/enroll", post(auth_handlers::totp_enroll))
        .route("/auth/totp/verify", post(auth_handlers::totp_verify))
        .route("/auth/totp", delete(auth_handlers::totp_delete))
        .route("/auth/sessions", get(auth_handlers::list_sessions))
        .route("/auth/sessions/{id}", delete(auth_handlers::revoke_session))
        .route(
            "/auth/webauthn/register/start",
            post(auth_handlers::webauthn_register_start),
        )
        .route(
            "/auth/webauthn/register/finish",
            post(auth_handlers::webauthn_register_finish),
        )
        .route(
            "/auth/webauthn/login/start",
            post(auth_handlers::webauthn_login_start),
        )
        .route(
            "/auth/webauthn/login/finish",
            post(auth_handlers::webauthn_login_finish),
        )
        .route(
            "/auth/webauthn/credentials",
            get(auth_handlers::webauthn_list),
        )
        .route(
            "/auth/webauthn/credentials/{id}",
            delete(auth_handlers::webauthn_delete),
        )
        .with_state(state.clone());

    let user_routes = Router::new()
        .route(
            "/api/v1/users",
            get(crate::control::users::list).post(crate::control::users::create),
        )
        .route(
            "/api/v1/users/{id}",
            axum::routing::patch(crate::control::users::update)
                .delete(crate::control::users::delete),
        )
        .route("/api/v1/whoami", get(whoami))
        .with_state(state.clone());

    // Local-only HTTP routes that read/write mlsh-control's authoritative
    // node registry (ADR-033 phase 2). These are consumed by the bundled UI.
    // Remote nodes use the CBOR-over-QUIC channel via mlshtund instead.
    let node_routes = Router::new()
        .route("/api/v1/clusters/{cluster}/nodes", get(list_nodes))
        .route(
            "/api/v1/clusters/{cluster}/nodes/{target}",
            delete(revoke_node).patch(rename_node),
        )
        .route(
            "/api/v1/clusters/{cluster}/nodes/{target}/promote",
            post(promote_node),
        )
        .with_state(state);

    Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(user_routes)
        .merge(node_routes)
        .fallback(get(serve_ui))
}

async fn health() -> &'static str {
    "ok"
}

async fn serve_ui(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let (asset, mime_path) = match UiAssets::get(path) {
        Some(file) => (Some(file), path),
        None => (UiAssets::get("index.html"), "index.html"),
    };
    match asset {
        Some(file) => {
            let mime = mime_for_path(mime_path);
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

async fn whoami(_user: crate::control::auth::session::CurrentUser) -> impl IntoResponse {
    let cluster = std::env::var("MLSH_CONTROL_CLUSTER").unwrap_or_default();
    Json(serde_json::json!({
        "cluster": cluster,
        "roles": ["node", "admin", "control"],
    }))
}

// --- Local HTTP routes consumed by the bundled UI (ADR-033 phase 2).
// They read/write mlsh-control's `nodes` table directly via the local pool.

fn node_to_ui(n: crate::control::nodes::NodeRow) -> serde_json::Value {
    serde_json::json!({
        "node_id": n.node_uuid,
        "overlay_ip": "",
        "role": n.role,
        "online": n.status == "active",
        "display_name": n.display_name,
    })
}

async fn list_nodes(
    State(state): State<AuthState>,
    _user: crate::control::auth::session::CurrentUser,
    AxumPath(cluster): AxumPath<String>,
) -> Response {
    match crate::control::nodes::list(state.store.pool(), &cluster).await {
        Ok(rows) => {
            let out: Vec<_> = rows.into_iter().map(node_to_ui).collect();
            Json(out).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e:#}") })),
        )
            .into_response(),
    }
}

async fn revoke_node(
    State(state): State<AuthState>,
    _user: crate::control::auth::session::CurrentUser,
    AxumPath((cluster, target)): AxumPath<(String, String)>,
) -> Response {
    let uuid =
        match crate::control::nodes::resolve_target(state.store.pool(), &cluster, &target).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "node not found" })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("{e:#}") })),
                )
                    .into_response();
            }
        };
    match crate::control::nodes::set_status(state.store.pool(), &cluster, &uuid, "revoked").await {
        Ok(true) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e:#}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RenameBody {
    display_name: String,
}

async fn rename_node(
    State(state): State<AuthState>,
    _user: crate::control::auth::session::CurrentUser,
    AxumPath((cluster, target)): AxumPath<(String, String)>,
    Json(body): Json<RenameBody>,
) -> Response {
    let uuid =
        match crate::control::nodes::resolve_target(state.store.pool(), &cluster, &target).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "node not found" })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("{e:#}") })),
                )
                    .into_response();
            }
        };
    match crate::control::nodes::set_display_name(
        state.store.pool(),
        &cluster,
        &uuid,
        &body.display_name,
    )
    .await
    {
        Ok(true) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e:#}") })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct PromoteBody {
    role: String,
}

async fn promote_node(
    State(state): State<AuthState>,
    _user: crate::control::auth::session::CurrentUser,
    AxumPath((cluster, target)): AxumPath<(String, String)>,
    Json(body): Json<PromoteBody>,
) -> Response {
    if body.role != "admin" && body.role != "node" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "role must be 'admin' or 'node'" })),
        )
            .into_response();
    }
    let uuid =
        match crate::control::nodes::resolve_target(state.store.pool(), &cluster, &target).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "node not found" })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": format!("{e:#}") })),
                )
                    .into_response();
            }
        };
    match crate::control::nodes::set_role(state.store.pool(), &cluster, &uuid, &body.role).await {
        Ok(true) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e:#}") })),
        )
            .into_response(),
    }
}
