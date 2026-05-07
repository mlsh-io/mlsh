//! Auth, Bootstrap, TOTP, WebAuthn endpoints.
//!
//! Routes live under `/auth/*` (not `/api/v1/`) because they predate the
//! session: they're consumed by clients with no cookie/no mTLS yet.
//!
//! This module owns the API *surface* (paths, OpenAPI annotations, router).
//! The actual logic (password verify, OAuth device flow, WebAuthn
//! ceremonies, TOTP step-up) lives in [`crate::control::auth::handlers`],
//! and the request/response types — annotated with `ToSchema` over there —
//! are referenced by name from each `#[utoipa::path]` in this module.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};

use crate::control::auth::{
    handlers::{
        self as imp, BootstrapRequest, BootstrapStatus, DevicePollRequest, DeviceStartResponse,
        LoginRequest, TotpEnrollment, TotpVerifyRequest, UserView, WebauthnId,
    },
    webauthn, AuthState, HumanCaller,
};

pub fn router(state: AuthState) -> Router {
    Router::new()
        // Bootstrap
        .route(
            "/auth/bootstrap",
            get(bootstrap_status).post(bootstrap_create),
        )
        // Password login + logout
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        // mlsh-cloud device flow
        .route("/auth/login/device/start", post(device_start))
        .route("/auth/login/device/poll", post(device_poll))
        // TOTP
        .route("/auth/totp/enroll", post(totp_enroll))
        .route("/auth/totp/verify", post(totp_verify))
        .route("/auth/totp", delete(totp_delete))
        // WebAuthn
        .route("/auth/webauthn/register/start", post(webauthn_register_start))
        .route(
            "/auth/webauthn/register/finish",
            post(webauthn_register_finish),
        )
        .route("/auth/webauthn/login/start", post(webauthn_login_start))
        .route("/auth/webauthn/login/finish", post(webauthn_login_finish))
        .route("/auth/webauthn/credentials", get(webauthn_list))
        .route(
            "/auth/webauthn/credentials/{credential}",
            delete(webauthn_delete),
        )
        .with_state(state)
}

// ---------- handlers (thin wrappers around `imp::*`) ----------

/// Self-hosted password login. On success returns the user object and sets
/// a session cookie. When the user has TOTP enrolled and `totp_code` is
/// missing, returns 401 with `{ "error": "totp_required" }`.
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in", body = UserView),
        (status = 401, description = "Invalid credentials or TOTP step-up failed"),
    ),
    tag = "Auth"
)]
pub async fn login(state: State<AuthState>, body: Json<LoginRequest>) -> Response {
    imp::login(state, body).await
}

/// Revoke the current session and clear the session cookie. Idempotent.
#[utoipa::path(
    post,
    path = "/auth/logout",
    responses(
        (status = 200, description = "Logged out"),
    ),
    tag = "Auth"
)]
pub async fn logout(state: State<AuthState>, headers: HeaderMap) -> Response {
    imp::logout(state, headers).await
}

/// Generate (or replace) the caller's TOTP secret. Resets `verified=0`;
/// the caller must POST /auth/totp/verify to confirm.
#[utoipa::path(
    post,
    path = "/auth/totp/enroll",
    responses(
        (status = 200, description = "TOTP enrollment material", body = TotpEnrollment),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "TOTP"
)]
pub async fn totp_enroll(state: State<AuthState>, user: HumanCaller) -> Response {
    imp::totp_enroll(state, user).await
}

/// Confirm TOTP enrollment by submitting a current code.
#[utoipa::path(
    post,
    path = "/auth/totp/verify",
    request_body = TotpVerifyRequest,
    responses(
        (status = 204, description = "TOTP verified"),
        (status = 401, description = "Invalid code"),
    ),
    tag = "TOTP"
)]
pub async fn totp_verify(
    state: State<AuthState>,
    user: HumanCaller,
    body: Json<TotpVerifyRequest>,
) -> Response {
    imp::totp_verify(state, user, body).await
}

/// Remove the caller's TOTP credential.
#[utoipa::path(
    delete,
    path = "/auth/totp",
    responses(
        (status = 204, description = "TOTP removed"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "TOTP"
)]
pub async fn totp_delete(state: State<AuthState>, user: HumanCaller) -> Response {
    imp::totp_delete(state, user).await
}

/// Begin WebAuthn registration. The response is the WebAuthn-spec
/// `PublicKeyCredentialCreationOptions` blob to feed into
/// `navigator.credentials.create()` browser-side.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/start",
    responses(
        (status = 200, description = "Registration challenge", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 503, description = "WebAuthn not configured"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_register_start(state: State<AuthState>, user: HumanCaller) -> Response {
    imp::webauthn_register_start(state, user).await
}

/// Complete WebAuthn registration with the browser's credential response.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/finish",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Credential registered", body = WebauthnId),
        (status = 400, description = "Registration failed"),
        (status = 503, description = "WebAuthn not configured"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_register_finish(
    state: State<AuthState>,
    user: HumanCaller,
    body: Json<webauthn::FinishRegistration>,
) -> Response {
    imp::webauthn_register_finish(state, user, body).await
}

/// Begin WebAuthn authentication. Returns the
/// `PublicKeyCredentialRequestOptions` blob.
#[utoipa::path(
    post,
    path = "/auth/webauthn/login/start",
    responses(
        (status = 200, description = "Authentication challenge", body = serde_json::Value),
        (status = 400, description = "No credentials enrolled"),
        (status = 503, description = "WebAuthn not configured"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_login_start(state: State<AuthState>, user: HumanCaller) -> Response {
    imp::webauthn_login_start(state, user).await
}

/// Complete WebAuthn authentication with the browser's assertion response.
#[utoipa::path(
    post,
    path = "/auth/webauthn/login/finish",
    request_body = serde_json::Value,
    responses(
        (status = 204, description = "Authentication succeeded"),
        (status = 401, description = "Authentication failed"),
        (status = 503, description = "WebAuthn not configured"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_login_finish(
    state: State<AuthState>,
    user: HumanCaller,
    body: Json<webauthn::FinishAuthentication>,
) -> Response {
    imp::webauthn_login_finish(state, user, body).await
}

/// List the caller's WebAuthn credentials.
#[utoipa::path(
    get,
    path = "/auth/webauthn/credentials",
    responses(
        (status = 200, description = "Credentials", body = [crate::control::auth::webauthn::CredentialView]),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_list(state: State<AuthState>, user: HumanCaller) -> Response {
    imp::webauthn_list(state, user).await
}

/// Delete a WebAuthn credential by id.
#[utoipa::path(
    delete,
    path = "/auth/webauthn/credentials/{credential}",
    params(("credential" = String, Path, description = "Credential id")),
    responses(
        (status = 204, description = "Credential deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Credential not found"),
    ),
    tag = "WebAuthn"
)]
pub async fn webauthn_delete(
    state: State<AuthState>,
    user: HumanCaller,
    id: Path<String>,
) -> Response {
    imp::webauthn_delete(state, user, id).await
}

/// Drives the first-admin path on the UI side. `needed` is true while
/// `users` is empty; `mode` tells the UI which screen to show (form for
/// self-hosted, "Login with mlsh.io" for managed).
#[utoipa::path(
    get,
    path = "/auth/bootstrap",
    responses(
        (status = 200, description = "Bootstrap status", body = BootstrapStatus),
    ),
    tag = "Bootstrap"
)]
pub async fn bootstrap_status(state: State<AuthState>) -> Response {
    imp::bootstrap_status(state).await
}

/// Create the first admin and immediately log them in. Returns 409 if the
/// bootstrap window already closed (any user exists, or managed mode).
#[utoipa::path(
    post,
    path = "/auth/bootstrap",
    request_body = BootstrapRequest,
    responses(
        (status = 200, description = "First admin created and logged in", body = UserView),
        (status = 400, description = "Email and password required"),
        (status = 409, description = "Bootstrap already completed or managed mode"),
    ),
    tag = "Bootstrap"
)]
pub async fn bootstrap_create(state: State<AuthState>, body: Json<BootstrapRequest>) -> Response {
    imp::bootstrap_create(state, body).await
}

/// Kick off a mlsh-cloud device-flow login. mlsh-control reaches out to
/// mlsh-cloud, gets a `(device_code, user_code, verification_uri, interval)`,
/// returns everything except `device_code` to the UI (the device_code stays
/// server-side, keyed by an opaque ticket).
#[utoipa::path(
    post,
    path = "/auth/login/device/start",
    responses(
        (status = 200, description = "Device flow started", body = DeviceStartResponse),
        (status = 502, description = "mlsh-cloud unreachable"),
        (status = 503, description = "Managed-mode auth not configured"),
    ),
    tag = "Auth"
)]
pub async fn device_start(state: State<AuthState>) -> Response {
    imp::device_start(state).await
}

/// One-shot poll. Returns 200 with a session cookie when mlsh-cloud emits a
/// token. Returns 425 (Too Early) while the user hasn't authorized yet.
/// Returns 410 (Gone) on expiry / unknown ticket.
#[utoipa::path(
    post,
    path = "/auth/login/device/poll",
    request_body = DevicePollRequest,
    responses(
        (status = 200, description = "Authorized — session cookie set", body = UserView),
        (status = 401, description = "Invalid cloud token"),
        (status = 403, description = "Account suspended"),
        (status = 410, description = "Ticket expired or device flow failed"),
        (status = 425, description = "User has not authorized yet"),
        (status = 503, description = "Managed-mode auth not configured"),
    ),
    tag = "Auth"
)]
pub async fn device_poll(state: State<AuthState>, body: Json<DevicePollRequest>) -> Response {
    imp::device_poll(state, body).await
}
