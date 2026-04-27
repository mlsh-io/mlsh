use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use super::session::{self, AuthState, CurrentUser};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub must_change_password: bool,
}

impl From<super::store::User> for UserView {
    fn from(u: super::store::User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            must_change_password: u.must_change_password,
        }
    }
}

/// POST /auth/login — self-hosted password login.
pub async fn login(State(state): State<AuthState>, Json(body): Json<LoginRequest>) -> Response {
    let user = match state
        .store
        .verify_password(&body.email, &body.password)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "invalid_credentials" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "verify_password failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    match super::totp::require_step_up(&state, &user.id, &user.email, body.totp_code.as_deref())
        .await
    {
        Ok(super::totp::StepUp::NotEnrolled) | Ok(super::totp::StepUp::Ok) => {}
        Ok(super::totp::StepUp::Required) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "totp_required" })),
            )
                .into_response();
        }
        Ok(super::totp::StepUp::Invalid) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "totp_invalid" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "totp step-up failed at login");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }

    let cookie = match session::issue(&state, &user.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "session issue failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session::set_cookie_header(&cookie, false));
    (StatusCode::OK, headers, Json(UserView::from(user))).into_response()
}

/// POST /auth/logout — revoke the current session, clear cookie.
pub async fn logout(State(state): State<AuthState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = current_session_id(&state, &headers) {
        if let Err(e) = session::revoke(state.store.pool(), &session_id).await {
            tracing::warn!(error = %e, "session revoke failed");
        }
    }
    let mut out = HeaderMap::new();
    out.insert(SET_COOKIE, session::set_cookie_header("", true));
    (StatusCode::OK, out).into_response()
}

/// GET /auth/session — return the current user, or 401.
pub async fn whoami(user: CurrentUser) -> Json<UserView> {
    Json(UserView::from(user.0))
}

#[derive(Serialize)]
pub struct TotpEnrollment {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

/// POST /auth/totp/enroll — generate (or replace) the caller's TOTP secret.
/// Resets `verified=0`; the user must POST /auth/totp/verify to confirm.
pub async fn totp_enroll(State(state): State<AuthState>, user: CurrentUser) -> Response {
    match super::totp::enroll(&state, &user.0.id, &user.0.email).await {
        Ok(e) => Json(TotpEnrollment {
            secret_base32: e.secret_base32,
            otpauth_uri: e.otpauth_uri,
        })
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "totp enroll failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct TotpVerifyRequest {
    pub code: String,
}

/// POST /auth/totp/verify — confirm enrollment by submitting a current code.
pub async fn totp_verify(
    State(state): State<AuthState>,
    user: CurrentUser,
    Json(body): Json<TotpVerifyRequest>,
) -> Response {
    match super::totp::verify(&state, &user.0.id, &user.0.email, &body.code).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::UNAUTHORIZED, "invalid code").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "totp verify failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
    pub current: bool,
}

/// GET /auth/sessions — list the caller's own sessions.
pub async fn list_sessions(
    State(state): State<AuthState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Response {
    let current = current_session_id(&state, &headers);
    match state.store.list_sessions(&user.0.id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|r| SessionView {
                    current: current.as_deref() == Some(&r.id),
                    id: r.id,
                    created_at: r.created_at,
                    expires_at: r.expires_at,
                    revoked: r.revoked,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "list_sessions failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// DELETE /auth/sessions/:id — revoke a single session belonging to the caller.
pub async fn revoke_session(
    State(state): State<AuthState>,
    user: CurrentUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match state.store.revoke_session_for_user(&user.0.id, &id).await {
        Ok(0) => StatusCode::NOT_FOUND.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "revoke_session failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// DELETE /auth/totp — remove the caller's TOTP credential.
pub async fn totp_delete(State(state): State<AuthState>, user: CurrentUser) -> Response {
    match super::totp::delete(&state, &user.0.id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "totp delete failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

fn webauthn_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "WebAuthn not configured (set MLSH_CONTROL_RP_ID and MLSH_CONTROL_RP_ORIGIN)",
    )
        .into_response()
}

pub async fn webauthn_register_start(
    State(state): State<AuthState>,
    user: CurrentUser,
) -> Response {
    if state.webauthn.is_none() {
        return webauthn_unavailable();
    }
    match super::webauthn::register_start(&state, &user.0.id).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn register_start failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(Serialize)]
struct WebauthnId {
    id: String,
}

pub async fn webauthn_register_finish(
    State(state): State<AuthState>,
    user: CurrentUser,
    Json(body): Json<super::webauthn::FinishRegistration>,
) -> Response {
    if state.webauthn.is_none() {
        return webauthn_unavailable();
    }
    match super::webauthn::register_finish(&state, &user.0.id, body).await {
        Ok(id) => Json(WebauthnId { id }).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn register_finish failed");
            (StatusCode::BAD_REQUEST, "registration failed").into_response()
        }
    }
}

pub async fn webauthn_login_start(State(state): State<AuthState>, user: CurrentUser) -> Response {
    if state.webauthn.is_none() {
        return webauthn_unavailable();
    }
    match super::webauthn::login_start(&state, &user.0.id).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn login_start failed");
            (StatusCode::BAD_REQUEST, "no credentials enrolled").into_response()
        }
    }
}

pub async fn webauthn_login_finish(
    State(state): State<AuthState>,
    user: CurrentUser,
    Json(body): Json<super::webauthn::FinishAuthentication>,
) -> Response {
    if state.webauthn.is_none() {
        return webauthn_unavailable();
    }
    match super::webauthn::login_finish(&state, &user.0.id, body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn login_finish failed");
            (StatusCode::UNAUTHORIZED, "authentication failed").into_response()
        }
    }
}

pub async fn webauthn_list(State(state): State<AuthState>, user: CurrentUser) -> Response {
    match super::webauthn::list(&state, &user.0.id).await {
        Ok(creds) => Json(creds).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

pub async fn webauthn_delete(
    State(state): State<AuthState>,
    user: CurrentUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match super::webauthn::delete(&state, &user.0.id, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "webauthn delete failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct BootstrapStatus {
    pub needed: bool,
    /// `"self-hosted"` or `"managed"`, or `null` if the mode hasn't been set
    /// yet (control plane started before `mlsh setup` declared a mode).
    pub mode: Option<&'static str>,
}

/// GET /auth/bootstrap — drives the first-admin path on the UI side. `needed`
/// is true while `users` is empty; `mode` tells the UI which screen to show
/// (form for self-hosted, "Login with mlsh.io" for managed).
pub async fn bootstrap_status(State(state): State<AuthState>) -> Response {
    let needed = match state.store.user_count().await {
        Ok(n) => n == 0,
        Err(e) => {
            tracing::warn!(error = %e, "user_count failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let mode = match crate::control::mode::current(&state.store).await {
        Ok(Some(m)) => Some(m.as_str()),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "mode read failed");
            None
        }
    };
    Json(BootstrapStatus { needed, mode }).into_response()
}

#[derive(Serialize)]
pub struct DeviceStartResponse {
    pub ticket: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
}

/// POST /auth/login/device/start — kick off a mlsh-cloud device-flow login.
/// mlsh-control reaches out to mlsh-cloud, gets a `(device_code, user_code,
/// verification_uri, interval)`, returns everything except `device_code` to
/// the UI (the device_code stays server-side, keyed by an opaque ticket).
pub async fn device_start(State(state): State<AuthState>) -> Response {
    if !state.oauth.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed-mode auth not configured (set MLSH_CLOUD_JWT_PUBKEY_PEM)",
        )
            .into_response();
    }
    let cloud = crate::cloud::CloudClient::new();
    let resp = match tokio::task::spawn_blocking(move || cloud.request_device_code()).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "request_device_code failed");
            return (StatusCode::BAD_GATEWAY, "mlsh-cloud unreachable").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "device-code task panicked");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let ticket = uuid::Uuid::new_v4().to_string();
    state.oauth.store_ticket(ticket.clone(), resp.device_code);
    Json(DeviceStartResponse {
        ticket,
        user_code: resp.user_code,
        verification_uri: resp.verification_uri,
        interval: resp.interval.max(2),
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct DevicePollRequest {
    pub ticket: String,
}

/// POST /auth/login/device/poll — one-shot poll. Returns 200 with a session
/// cookie when mlsh-cloud emits a token. Returns 425 (Too Early) while the
/// user hasn't authorized yet. Returns 410 (Gone) on expiry / unknown ticket.
pub async fn device_poll(
    State(state): State<AuthState>,
    Json(body): Json<DevicePollRequest>,
) -> Response {
    if !state.oauth.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed-mode auth not configured",
        )
            .into_response();
    }
    let device_code = match state.oauth.peek_device_code(&body.ticket) {
        Some(c) => c,
        None => return (StatusCode::GONE, "ticket expired or unknown").into_response(),
    };
    let cloud = crate::cloud::CloudClient::new();
    let dc = device_code.clone();
    let token_resp = tokio::task::spawn_blocking(move || cloud.poll_device_token_once(&dc)).await;
    let token = match token_resp {
        Ok(Ok(Some(t))) => t,
        Ok(Ok(None)) => return StatusCode::TOO_EARLY.into_response(),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "poll_device_token failed");
            state.oauth.remove_ticket(&body.ticket);
            return (StatusCode::GONE, "device flow failed").into_response();
        }
        Err(e) => {
            tracing::warn!(error = %e, "device-poll task panicked");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // We have a JWT — validate it, upsert the user, issue a local session.
    let claims = match state.oauth.validate_token(&token.access_token) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "cloud JWT validation failed");
            state.oauth.remove_ticket(&body.ticket);
            return (StatusCode::UNAUTHORIZED, "invalid cloud token").into_response();
        }
    };
    state.oauth.remove_ticket(&body.ticket);

    let user = match state
        .store
        .find_or_create_managed(&claims.sub, &claims.email)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "managed user upsert failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    if !user.active {
        return (StatusCode::FORBIDDEN, "account suspended").into_response();
    }
    let cookie = match session::issue(&state, &user.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "session issue failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session::set_cookie_header(&cookie, false));
    (StatusCode::OK, headers, Json(UserView::from(user))).into_response()
}

#[derive(Deserialize)]
pub struct BootstrapRequest {
    pub email: String,
    pub password: String,
}

/// POST /auth/bootstrap — create the first admin and immediately log them in.
/// Returns 409 if the bootstrap window already closed (any user exists).
pub async fn bootstrap_create(
    State(state): State<AuthState>,
    Json(body): Json<BootstrapRequest>,
) -> Response {
    if body.email.is_empty() || body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "email and password are required").into_response();
    }
    if let Ok(Some(crate::control::mode::Mode::Managed)) =
        crate::control::mode::current(&state.store).await
    {
        return (
            StatusCode::CONFLICT,
            "managed mode: log in via mlsh-cloud instead",
        )
            .into_response();
    }
    match state.store.user_count().await {
        Ok(0) => {}
        Ok(_) => return (StatusCode::CONFLICT, "bootstrap already completed").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "user_count failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    }
    let user = match state
        .store
        .create_local_user(super::store::NewLocalUser {
            email: &body.email,
            password: &body.password,
            must_change_password: false,
        })
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "first-admin creation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let cookie = match session::issue(&state, &user.id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "session issue failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session::set_cookie_header(&cookie, false));
    (StatusCode::OK, headers, Json(UserView::from(user))).into_response()
}

fn current_session_id(state: &AuthState, headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for piece in raw.split(';') {
        let piece = piece.trim();
        if let Some(value) = piece.strip_prefix(&format!("{}=", session::COOKIE_NAME)) {
            return session::verify_signed_cookie(&state.key, value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::auth::session::{AuthState, SessionKey};
    use crate::control::auth::store::{AuthStore, NewLocalUser};
    use axum::body::to_bytes;
    use axum::extract::State;
    use axum::http::header::COOKIE;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup() -> AuthState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                password_hash TEXT, cloud_user_id TEXT UNIQUE,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK ((password_hash IS NOT NULL) <> (cloud_user_id IS NOT NULL))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let store = AuthStore::new(pool);
        store
            .create_local_user(NewLocalUser {
                email: "admin@example.com",
                password: "hunter2",
                must_change_password: false,
            })
            .await
            .unwrap();
        AuthState {
            store,
            key: SessionKey([3u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([0u8; 32]),
            webauthn: None,
        }
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn login_success_sets_cookie() {
        let state = setup().await;
        let resp = login(
            State(state.clone()),
            Json(LoginRequest {
                email: "admin@example.com".into(),
                password: "hunter2".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie_header = resp
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie_header.starts_with(&format!("{}=", session::COOKIE_NAME)));
        assert!(cookie_header.contains("HttpOnly"));
        let body = body_string(resp).await;
        assert!(body.contains("admin@example.com"));
    }

    #[tokio::test]
    async fn login_wrong_password_is_unauthorized() {
        let state = setup().await;
        let resp = login(
            State(state),
            Json(LoginRequest {
                email: "admin@example.com".into(),
                password: "wrong".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    async fn empty_state() -> AuthState {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                password_hash TEXT, cloud_user_id TEXT UNIQUE,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK ((password_hash IS NOT NULL) <> (cloud_user_id IS NOT NULL))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        AuthState {
            store: AuthStore::new(pool),
            key: SessionKey([4u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([0u8; 32]),
            webauthn: None,
        }
    }

    #[tokio::test]
    async fn bootstrap_status_reports_needed_then_done() {
        let state = empty_state().await;
        let resp = bootstrap_status(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"needed\":true"));

        let resp = bootstrap_create(
            State(state.clone()),
            Json(BootstrapRequest {
                email: "first@example.com".into(),
                password: "hunter2".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(SET_COOKIE).is_some());

        let resp = bootstrap_status(State(state.clone())).await;
        assert!(body_string(resp).await.contains("\"needed\":false"));
    }

    #[tokio::test]
    async fn bootstrap_create_rejects_after_first_user() {
        let state = setup().await;
        let resp = bootstrap_create(
            State(state),
            Json(BootstrapRequest {
                email: "second@example.com".into(),
                password: "x".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn bootstrap_create_rejects_empty_input() {
        let state = empty_state().await;
        let resp = bootstrap_create(
            State(state),
            Json(BootstrapRequest {
                email: "".into(),
                password: "".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn device_endpoints_503_without_pubkey() {
        let state = empty_state().await;
        let resp = device_start(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let resp = device_poll(State(state), Json(DevicePollRequest { ticket: "x".into() })).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn logout_revokes_session_and_clears_cookie() {
        let state = setup().await;
        let user = state
            .store
            .find_by_email("admin@example.com")
            .await
            .unwrap()
            .unwrap();
        let cookie = session::issue(&state, &user.id).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={}", session::COOKIE_NAME, cookie)
                .parse()
                .unwrap(),
        );
        let resp = logout(State(state.clone()), headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cleared = resp.headers().get(SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cleared.contains("Max-Age=0"));

        // Session row should now be revoked.
        let session_id = cookie.split('.').next().unwrap();
        let revoked: i64 = sqlx::query_scalar("SELECT revoked FROM sessions WHERE id = ?")
            .bind(session_id)
            .fetch_one(state.store.pool())
            .await
            .unwrap();
        assert_eq!(revoked, 1);
    }
}
