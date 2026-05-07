use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rust_embed::RustEmbed;

use crate::control::api;
use crate::control::auth::{mtls_acceptor::MtlsAcceptor, AuthState};
use crate::control::tls;

#[derive(RustEmbed)]
#[folder = "ui/dist/"]
struct UiAssets;

pub async fn serve(state: AuthState) -> Result<()> {
    let cluster = state.cluster.clone();
    let app = build_app(state);

    let bind = std::env::var("MLSH_CONTROL_BIND").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let addr: std::net::SocketAddr = bind.parse().with_context(|| format!("invalid bind address {bind}"))?;

    let rustls_config = tls::build_server_config(&cluster).context("build TLS server config")?;
    let tls = RustlsConfig::from_config(Arc::new(rustls_config));
    let acceptor = MtlsAcceptor::new(tls);

    tracing::info!("mlsh-control listening on https://{addr}");

    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .context("mlsh-control HTTPS server crashed")?;
    Ok(())
}

pub fn build_app(state: AuthState) -> Router {
    Router::new()
        .merge(api::router(state))
        .fallback(get(serve_ui))
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
