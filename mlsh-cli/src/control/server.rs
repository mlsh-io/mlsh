use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use axum::{
    extract::Path as AxumPath,
    http::{header, StatusCode, Uri},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
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

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8443));

    let tls = ensure_self_signed_tls(&data_dir()).await?;
    tracing::info!("mlsh-control listening on https://{addr} (self-signed TLS)");

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .context("axum-server crashed")?;
    Ok(())
}

fn data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("mlsh")
        .join("control")
}

/// Load the TLS cert+key from `<data_dir>/tls/{cert,key}.pem`, generating
/// a fresh self-signed pair on first run. Sufficient for local browser
/// access in dev; production exposure goes through signal's SNI passthrough
/// and uses an ACME-issued cert (TODO).
async fn ensure_self_signed_tls(data_dir: &Path) -> Result<RustlsConfig> {
    let tls_dir = data_dir.join("tls");
    std::fs::create_dir_all(&tls_dir)?;

    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        let (cert_pem, key_pem) =
            crate::tund::ingress::generate_self_signed(&["mlsh-control.local", "localhost"])?;
        std::fs::write(&cert_path, &cert_pem).context("write cert.pem")?;
        std::fs::write(&key_path, &key_pem).context("write key.pem")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %cert_path.display(), "Generated self-signed TLS cert");
    }

    RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .context("load TLS cert/key")
}

async fn health() -> &'static str {
    "ok"
}

/// Serve the embedded SPA. Unknown paths fall back to `index.html` so the
/// router can handle client-side routes; `*.{js,css,…}` resolve directly
/// to their compiled asset.
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
