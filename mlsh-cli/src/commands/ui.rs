//! `mlsh ui <cluster>` — open the cluster's web UI in the default browser
//! via a localhost HTTP proxy (ADR-035 Phase F).
//!
//! The browser sees a plain `http://127.0.0.1:<random>` URL. Each request
//! is forwarded to `https://control.<cluster>:8443` over an mTLS
//! connection authenticated by the local node's identity cert. This way:
//! - the user never has to trust the cluster-CA cert in their browser,
//! - cookies set by the API stay scoped to localhost,
//! - the cluster doesn't need to be publicly exposed (no Let's Encrypt
//!   cert, no `<cluster>.mlsh.io`).
//!
//! Requires the local mlshtund to be up so the overlay DNS resolver can
//! map `control.<cluster>` to its overlay IP. If the tunnel is down the
//! first proxied request fails — we surface a hint when the upstream call
//! returns a connection error.

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use colored::Colorize;
use reqwest::Identity;

use crate::tund::cluster_config::ClusterConfig;
use crate::tund::tunnel::load_cluster_config;

/// Default port mlsh-control binds — must match `control::server::serve`.
const CONTROL_PORT: u16 = 8443;

#[derive(Clone)]
struct ProxyState {
    upstream_base: String,
    client: reqwest::Client,
}

pub async fn handle_ui(cluster_name: &str, open_browser: bool) -> Result<()> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    let state = build_proxy_state(&config)?;
    let app = Router::new().fallback(any(proxy_handler)).with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind localhost listener")?;
    let local_addr = listener.local_addr().context("query local addr")?;
    let url = format!("http://{local_addr}");

    println!(
        "{} {} {}",
        "mlsh ui:".bold(),
        url.cyan(),
        format!("→ {}:{}", config.name, CONTROL_PORT).dimmed()
    );

    if open_browser {
        open_in_browser(&url);
    } else {
        println!("Open this URL in your browser. Ctrl+C to stop.");
    }

    axum::serve(listener, app)
        .await
        .context("local proxy crashed")?;
    Ok(())
}

fn build_proxy_state(config: &ClusterConfig) -> Result<ProxyState> {
    let cert_pem =
        std::fs::read(config.identity_dir.join("cert.pem")).context("read identity cert.pem")?;
    let key_pem =
        std::fs::read(config.identity_dir.join("key.pem")).context("read identity key.pem")?;

    let mut identity_pem = cert_pem;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key_pem);
    let identity = Identity::from_pem(&identity_pem).context("build mTLS identity")?;

    let client = reqwest::Client::builder()
        .identity(identity)
        // Self-signed identity cert; pinning lands in ADR-035 Phase C.
        .danger_accept_invalid_certs(true)
        // Don't auto-redirect — the browser handles 3xx itself, we just
        // forward the response.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build reqwest client")?;

    Ok(ProxyState {
        upstream_base: format!("https://{}:{}", config.name, CONTROL_PORT),
        client,
    })
}

async fn proxy_handler(
    State(state): State<ProxyState>,
    req: Request<Body>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let upstream_url = format!("{}{}", state.upstream_base, path_and_query);

    let body_bytes = axum::body::to_bytes(body, 16 * 1024 * 1024)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("read body: {e}")))?;

    let upstream_req = state
        .client
        .request(parts.method.clone(), &upstream_url)
        .headers(filter_request_headers(&parts.headers))
        .body(body_bytes.to_vec())
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("build req: {e}")))?;

    let upstream_resp = match state.client.execute(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            let hint = if e.is_connect() {
                " (is mlshtund up and the tunnel connected?)"
            } else {
                ""
            };
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("upstream {} failed: {e}{hint}", state.upstream_base),
            ));
        }
    };

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();
    let body_bytes = upstream_resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("read upstream body: {e}")))?;

    let mut response = Response::builder().status(status);
    {
        let headers = response
            .headers_mut()
            .expect("axum::Response::Builder::headers_mut on fresh builder");
        copy_response_headers(&upstream_headers, headers);
    }
    response.body(Body::from(body_bytes)).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("build resp: {e}"),
        )
    })
}

/// Headers that must not be forwarded from the browser to the upstream.
/// `Host`, hop-by-hop, and the rewritten `connection` token list — see
/// RFC 7230 §6.1.
fn filter_request_headers(src: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(src.len());
    for (name, value) in src {
        if HOP_BY_HOP
            .iter()
            .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        if name == header::HOST {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Copy upstream response headers into the response we send to the browser,
/// stripping hop-by-hop tokens and rewriting `Set-Cookie` to drop any
/// `Domain=` attribute (the browser scopes the cookie to localhost
/// regardless; an explicit Domain mismatch makes browsers refuse the
/// cookie outright).
fn copy_response_headers(upstream: &HeaderMap, dest: &mut HeaderMap) {
    for (name, value) in upstream {
        if HOP_BY_HOP
            .iter()
            .any(|h| name.as_str().eq_ignore_ascii_case(h))
        {
            continue;
        }
        if name == header::SET_COOKIE {
            if let Ok(s) = value.to_str() {
                let rewritten = strip_cookie_domain(s);
                if let Ok(v) = axum::http::HeaderValue::from_str(&rewritten) {
                    dest.append(name.clone(), v);
                    continue;
                }
            }
        }
        dest.append(name.clone(), value.clone());
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove a `Domain=...;` segment from a Set-Cookie value. The browser
/// will scope the cookie to `localhost` automatically, which is what we
/// want.
fn strip_cookie_domain(cookie: &str) -> String {
    cookie
        .split(';')
        .map(|piece| piece.trim())
        .filter(|piece| !piece.to_ascii_lowercase().starts_with("domain="))
        .collect::<Vec<_>>()
        .join("; ")
}

fn open_in_browser(url: &str) {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).status()
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("xdg-open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
    } else {
        Ok(std::process::ExitStatus::default())
    };
    if result.is_err() {
        println!(
            "{}",
            "(could not open browser automatically — copy the URL above)".dimmed()
        );
    }
}
