//! Test harness for `api/*` integration tests. Spawns the full Axum router
//! against an in-memory SQLite, supports authenticated requests through the
//! cookie-session path (the mTLS extracted via `MtlsAcceptor` is bypassed
//! because `axum::Router::oneshot` skips the connection layer entirely).
//!
//! Pattern: each test calls [`TestApp::new`] then sends requests via
//! `app.get("/path")` / `app.post("/path", body)` etc. — these return the
//! raw `Response` and the test asserts status + body.

#![cfg(test)]
#![allow(dead_code)]

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

use crate::control::auth::store::{AuthStore, NewLocalUser, User};
use crate::control::auth::{AuthState, SessionKey};
use crate::control::events::EventHub;
use crate::control::server::build_app;
use crate::control::{auth, db};
use crate::tund::cluster_config::ClusterConfig;

/// Read response body as bytes.
pub async fn body_bytes(resp: Response) -> Vec<u8> {
    to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap()
        .to_vec()
}

/// Read response body as a UTF-8 string.
pub async fn body_string(resp: Response) -> String {
    String::from_utf8(body_bytes(resp).await).unwrap()
}

/// Read response body as a typed JSON value.
pub async fn body_json<T: DeserializeOwned>(resp: Response) -> T {
    let bytes = body_bytes(resp).await;
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        let preview = String::from_utf8_lossy(&bytes);
        panic!(
            "expected JSON {}, got: {}",
            std::any::type_name::<T>(),
            preview
                .chars()
                .take(500)
                .collect::<String>()
                .trim()
                .to_string()
                + " ("
                + &e.to_string()
                + ")"
        )
    })
}

/// A booted test app. Holds the router (cheap to clone), the auth state for
/// direct DB access in tests, and the cookie of the seed admin user so
/// authenticated requests are one-liners.
pub struct TestApp {
    pub app: Router,
    pub state: AuthState,
    /// `mlsh_control_session=<value>` — pre-computed for the seed admin so
    /// tests don't repeat the login dance every time.
    pub admin_cookie: String,
    pub admin: User,
}

impl TestApp {
    /// Boot a fresh app with one seeded admin user. The cookie is already
    /// usable — it's been issued via `auth::session::issue` and signed with
    /// the same key the router validates against.
    pub async fn new() -> Self {
        Self::with_admin("admin@example.com", "hunter2").await
    }

    /// Convenience: cluster_id of the dummy `ClusterConfig` baked into the
    /// `AuthState`. Tests that seed `nodes` rows need this to match the
    /// `WHERE cluster_id = ?` filter used by every nodes handler.
    pub fn cluster_id(&self) -> &str {
        &self.state.cluster.cluster_id
    }

    /// Boot a fresh app with a real identity certificate written to a
    /// `tempdir`, plumbed into the cluster config. Required by tests for
    /// endpoints that read `cert.pem` / `key.pem` — invite generation,
    /// future mTLS server boot, etc. Returns the app + the tempdir guard
    /// (drop it when the test ends).
    pub async fn with_identity_dir() -> (Self, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let identity = mlsh_crypto::identity::load_or_generate(dir.path(), "test-node").unwrap();
        // load_or_generate writes cert.pem + key.pem; double-check the
        // shape so tests don't fail later for opaque IO reasons.
        assert!(dir.path().join("cert.pem").exists());
        assert!(dir.path().join("key.pem").exists());
        let _ = identity; // keep the binding so `_identity` is observable

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();

        let store = AuthStore::new(pool);
        let admin = store
            .create_local_user(NewLocalUser {
                email: "admin@example.com",
                password: "hunter2",
                must_change_password: false,
            })
            .await
            .unwrap();

        let state = AuthState {
            store,
            key: SessionKey([7u8; 32]),
            oauth: auth::oauth::OAuthConfig::disabled(),
            mfa_key: Arc::new([1u8; 32]),
            webauthn: None,
            events: EventHub::new(),
            cluster: ClusterConfig::dummy_with_identity_dir(dir.path().to_path_buf()),
        };

        let cookie = auth::session::issue(&state, &admin.id).await.unwrap();
        let admin_cookie = format!("{}={}", auth::session::COOKIE_NAME, cookie);

        let app = build_app(state.clone());
        (
            Self {
                app,
                state,
                admin_cookie,
                admin,
            },
            dir,
        )
    }

    /// Boot with an admin of your choice (other email/password).
    pub async fn with_admin(email: &str, password: &str) -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();

        let store = AuthStore::new(pool);
        let admin = store
            .create_local_user(NewLocalUser {
                email,
                password,
                must_change_password: false,
            })
            .await
            .unwrap();

        let state = AuthState {
            store,
            key: SessionKey([7u8; 32]),
            oauth: auth::oauth::OAuthConfig::disabled(),
            mfa_key: Arc::new([1u8; 32]),
            webauthn: None,
            events: EventHub::new(),
            cluster: ClusterConfig::dummy(),
        };

        let cookie = auth::session::issue(&state, &admin.id).await.unwrap();
        let admin_cookie = format!("{}={}", auth::session::COOKIE_NAME, cookie);

        let app = build_app(state.clone());
        Self {
            app,
            state,
            admin_cookie,
            admin,
        }
    }

    /// Send an authenticated GET. Use `get_anonymous` to skip the cookie.
    pub async fn get(&self, path: &str) -> Response {
        self.send(Request::builder().method("GET").uri(path)).await
    }

    /// Send an authenticated GET without the admin cookie.
    pub async fn get_anonymous(&self, path: &str) -> Response {
        self.send_anonymous(Request::builder().method("GET").uri(path))
            .await
    }

    /// Send an authenticated POST with a JSON body.
    pub async fn post<B: Serialize>(&self, path: &str, body: &B) -> Response {
        self.send(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json"),
        )
        .with_body(serde_json::to_vec(body).unwrap())
        .await
    }

    /// Send an authenticated PUT with a JSON body.
    pub async fn put<B: Serialize>(&self, path: &str, body: &B) -> Response {
        self.send(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json"),
        )
        .with_body(serde_json::to_vec(body).unwrap())
        .await
    }

    /// Send an authenticated DELETE.
    pub async fn delete(&self, path: &str) -> Response {
        self.send(Request::builder().method("DELETE").uri(path))
            .await
    }

    pub fn send(&self, builder: axum::http::request::Builder) -> RequestSender<'_> {
        RequestSender {
            app: &self.app,
            builder,
            cookie: Some(&self.admin_cookie),
            body: None,
        }
    }

    pub fn send_anonymous(&self, builder: axum::http::request::Builder) -> RequestSender<'_> {
        RequestSender {
            app: &self.app,
            builder,
            cookie: None,
            body: None,
        }
    }
}

/// Mid-flight request: the harness's `get/post/put/delete` returns this so
/// callers can chain `.with_body(...)` and finally `.await`. Idiomatic Rust
/// would use a real Future, but this is internal test code — the Future
/// impl below is a thin wrapper that runs `Router::oneshot`.
pub struct RequestSender<'a> {
    app: &'a Router,
    builder: axum::http::request::Builder,
    cookie: Option<&'a str>,
    body: Option<Vec<u8>>,
}

impl<'a> RequestSender<'a> {
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

impl<'a> std::future::IntoFuture for RequestSender<'a> {
    type Output = Response;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut builder = self.builder;
            if let Some(cookie) = self.cookie {
                builder = builder.header(header::COOKIE, cookie);
            }
            let body = self.body.map(Body::from).unwrap_or_else(Body::empty);
            let req: Request<Body> = builder.body(body).unwrap();
            self.app.clone().oneshot(req).await.unwrap()
        })
    }
}

/// Assert the response status code, with a helpful body preview on failure.
pub async fn assert_status(resp: Response, expected: StatusCode) -> Response {
    let status = resp.status();
    if status == expected {
        return resp;
    }
    let body = body_string(resp).await;
    panic!(
        "expected status {}, got {} — body: {}",
        expected, status, body
    );
}

/// Convenience: build an empty JSON body (`{}`) for endpoints that take no
/// fields but still expect `application/json`.
pub fn empty_body() -> serde_json::Value {
    json!({})
}
