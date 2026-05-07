//! Users API.
//!
//! v1 has no role model — every authenticated user can manage every other
//! user. Two policy guards are enforced server-side:
//!   - in self-hosted mode, you can only create *local* users (managed users
//!     are provisioned from JWT)
//!   - you can't delete yourself (would lock the cluster out)
//!   - sensitive ops (PUT password, DELETE) require a TOTP step-up if the
//!     caller has TOTP enrolled (ADR-029).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::control::auth::store::{NewLocalUser, User};
use crate::control::auth::totp::{self, StepUp};
use crate::control::auth::{AuthState, Caller, HumanCaller};
use crate::control::mode::{self, Mode};

pub fn router(state: AuthState) -> Router {
    Router::new()
        .route("/api/v1/users/current", get(get_current))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route(
            "/api/v1/users/{user}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .with_state(state)
}

// ---------- response shapes ----------

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CurrentUserResponse {
    /// Stable user id (UUID).
    pub id: String,
    pub email: String,
    /// `true` when the user was provisioned with a temporary password and
    /// must rotate it before any other action.
    pub must_change_password: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    /// `"local"` (password-authenticated) or `"managed"` (mlsh-cloud OAuth).
    pub source: String,
    pub active: bool,
    pub must_change_password: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        let source = if u.cloud_user_id.is_some() {
            "managed"
        } else {
            "local"
        };
        Self {
            id: u.id,
            email: u.email,
            source: source.to_string(),
            active: u.active,
            must_change_password: u.must_change_password,
        }
    }
}

// ---------- request bodies ----------

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub must_change_password: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    /// Whether the user is active (can sign in).
    pub active: bool,
    /// New password. Omit to keep the current one.
    #[serde(default)]
    pub password: Option<String>,
}

// ---------- handlers ----------

/// Get the currently authenticated user.
#[utoipa::path(
    get,
    path = "/api/v1/users/current",
    responses(
        (status = 200, description = "Current user", body = CurrentUserResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "Users"
)]
pub async fn get_current(HumanCaller(user): HumanCaller) -> Json<CurrentUserResponse> {
    Json(CurrentUserResponse {
        id: user.id,
        email: user.email,
        must_change_password: user.must_change_password,
    })
}

/// List every user in the cluster.
#[utoipa::path(
    get,
    path = "/api/v1/users",
    responses(
        (status = 200, description = "Users", body = [UserResponse]),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "Users"
)]
pub async fn list_users(State(state): State<AuthState>, _caller: Caller) -> Response {
    match state.store.list_users().await {
        Ok(users) => {
            let out: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
            Json(out).into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "list_users failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// Get a user by id.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user}",
    params(("user" = String, Path, description = "User id (UUID)")),
    responses(
        (status = 200, description = "User", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    tag = "Users"
)]
pub async fn get_user(
    State(state): State<AuthState>,
    _caller: Caller,
    Path(id): Path<String>,
) -> Response {
    match state.store.find_by_id(&id).await {
        Ok(Some(u)) => Json(UserResponse::from(u)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "find_by_id failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// Create a local user. Rejected in managed mode (managed clusters provision
/// users from mlsh-cloud OAuth).
#[utoipa::path(
    post,
    path = "/api/v1/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 400, description = "Invalid request"),
        (status = 409, description = "Email already exists, or managed-mode cluster"),
    ),
    tag = "Users"
)]
pub async fn create_user(
    State(state): State<AuthState>,
    _caller: Caller,
    Json(body): Json<CreateUserRequest>,
) -> Response {
    if body.email.trim().is_empty() || body.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "email and password are required").into_response();
    }
    match mode::current(&state.store).await {
        Ok(Some(Mode::Managed)) => {
            return (
                StatusCode::CONFLICT,
                "managed mode: users are provisioned via mlsh-cloud",
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "mode read failed");
        }
    }
    match state
        .store
        .create_local_user(NewLocalUser {
            email: body.email.trim(),
            password: &body.password,
            must_change_password: body.must_change_password,
        })
        .await
    {
        Ok(u) => (StatusCode::CREATED, Json(UserResponse::from(u))).into_response(),
        Err(e) => {
            let msg = format!("{:#}", e);
            tracing::warn!(error = %msg, "create_local_user failed");
            if msg.contains("UNIQUE") {
                (StatusCode::CONFLICT, "email already exists").into_response()
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

/// Replace a user (active state and optionally password). Step-up required
/// when the caller has verified TOTP.
#[utoipa::path(
    put,
    path = "/api/v1/users/{user}",
    params(("user" = String, Path, description = "User id (UUID)")),
    request_body = UpdateUserRequest,
    responses(
        (status = 204, description = "User updated"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated or TOTP step-up failed"),
    ),
    tag = "Users"
)]
pub async fn update_user(
    State(state): State<AuthState>,
    caller: Caller,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateUserRequest>,
) -> Response {
    if let Caller::Human { user_id, email, .. } = &caller {
        if let Some(rej) = step_up_check(&state, user_id, email, &headers).await {
            return rej;
        }
    }
    if let Err(e) = state.store.set_active(&id, body.active).await {
        tracing::warn!(error = %e, "set_active failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }
    if let Some(pw) = body.password.as_deref() {
        if pw.is_empty() {
            return (StatusCode::BAD_REQUEST, "password must not be empty").into_response();
        }
        if let Err(e) = state.store.set_password(&id, pw).await {
            tracing::warn!(error = %e, "set_password failed");
            return (StatusCode::BAD_REQUEST, "cannot set password").into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Delete a user. Refuses self-deletion and last-user deletion. Step-up
/// required when the caller has verified TOTP.
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user}",
    params(("user" = String, Path, description = "User id (UUID)")),
    responses(
        (status = 204, description = "User deleted"),
        (status = 401, description = "Not authenticated or TOTP step-up failed"),
        (status = 403, description = "Self-delete or last-user-delete refused"),
        (status = 404, description = "User not found"),
    ),
    tag = "Users"
)]
pub async fn delete_user(
    State(state): State<AuthState>,
    caller: Caller,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Caller::Human { user_id, email, .. } = &caller {
        if id == *user_id {
            return (StatusCode::FORBIDDEN, "cannot delete yourself").into_response();
        }
        if let Some(rej) = step_up_check(&state, user_id, email, &headers).await {
            return rej;
        }
    }
    let count = match state.store.user_count().await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "user_count failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };
    if count <= 1 {
        return (
            StatusCode::FORBIDDEN,
            "cannot delete the last user in the cluster",
        )
            .into_response();
    }
    match state.store.delete_user(&id).await {
        Ok(0) => StatusCode::NOT_FOUND.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "delete_user failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

async fn step_up_check(
    state: &AuthState,
    user_id: &str,
    email: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let code = headers
        .get("X-MFA-Code")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match totp::require_step_up(state, user_id, email, code.as_deref()).await {
        Ok(StepUp::NotEnrolled) | Ok(StepUp::Ok) => None,
        Ok(StepUp::Required) => Some(
            (
                StatusCode::UNAUTHORIZED,
                "TOTP step-up required (X-MFA-Code)",
            )
                .into_response(),
        ),
        Ok(StepUp::Invalid) => {
            Some((StatusCode::UNAUTHORIZED, "invalid TOTP code").into_response())
        }
        Err(e) => {
            tracing::warn!(error = %e, "step-up check failed");
            Some((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::api::test_harness::{body_json, body_string, TestApp};
    use crate::control::auth::store::NewLocalUser;
    use serde_json::json;

    // ---------- /api/v1/users/current ----------

    #[tokio::test]
    async fn get_current_returns_admin() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/users/current").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: CurrentUserResponse = body_json(resp).await;
        assert_eq!(body.email, "admin@example.com");
        assert_eq!(body.id, app.admin.id);
        assert!(!body.must_change_password);
    }

    #[tokio::test]
    async fn get_current_unauthenticated_returns_401() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/users/current").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------- GET /api/v1/users ----------

    #[tokio::test]
    async fn list_users_returns_seed_admin() {
        let app = TestApp::new().await;
        let resp = app.get("/api/v1/users").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let users: Vec<UserResponse> = body_json(resp).await;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "admin@example.com");
        assert_eq!(users[0].source, "local");
        assert!(users[0].active);
    }

    #[tokio::test]
    async fn list_users_unauthenticated_returns_401() {
        let app = TestApp::new().await;
        let resp = app.get_anonymous("/api/v1/users").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---------- POST /api/v1/users ----------

    #[tokio::test]
    async fn create_user_local_succeeds() {
        let app = TestApp::new().await;
        let resp = app
            .post(
                "/api/v1/users",
                &json!({
                    "email": "alice@example.com",
                    "password": "alicepw",
                    "must_change_password": false,
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: UserResponse = body_json(resp).await;
        assert_eq!(body.email, "alice@example.com");
        assert_eq!(body.source, "local");
    }

    #[tokio::test]
    async fn create_user_duplicate_email_returns_409() {
        let app = TestApp::new().await;
        let resp = app
            .post(
                "/api/v1/users",
                &json!({
                    "email": "admin@example.com",
                    "password": "another",
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_user_empty_email_returns_400() {
        let app = TestApp::new().await;
        let resp = app
            .post(
                "/api/v1/users",
                &json!({
                    "email": "  ",
                    "password": "x",
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_user_rejected_in_managed_mode() {
        let app = TestApp::new().await;
        app.state
            .store
            .set_config("mode", "managed")
            .await
            .unwrap();
        let resp = app
            .post(
                "/api/v1/users",
                &json!({
                    "email": "alice@example.com",
                    "password": "alicepw",
                }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_string(resp).await;
        assert!(body.contains("managed mode"), "body was: {body}");
    }

    // ---------- GET /api/v1/users/{user} ----------

    #[tokio::test]
    async fn get_user_by_id_returns_admin() {
        let app = TestApp::new().await;
        let resp = app.get(&format!("/api/v1/users/{}", app.admin.id)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: UserResponse = body_json(resp).await;
        assert_eq!(body.id, app.admin.id);
    }

    #[tokio::test]
    async fn get_user_not_found_returns_404() {
        let app = TestApp::new().await;
        let resp = app
            .get("/api/v1/users/00000000-0000-0000-0000-000000000000")
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ---------- PUT /api/v1/users/{user} ----------

    #[tokio::test]
    async fn put_user_can_deactivate() {
        let app = TestApp::new().await;
        let alice = app
            .state
            .store
            .create_local_user(NewLocalUser {
                email: "alice@example.com",
                password: "pw",
                must_change_password: false,
            })
            .await
            .unwrap();

        let resp = app
            .put(
                &format!("/api/v1/users/{}", alice.id),
                &json!({ "active": false }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let reread = app
            .state
            .store
            .find_by_id(&alice.id)
            .await
            .unwrap()
            .unwrap();
        assert!(!reread.active);
    }

    #[tokio::test]
    async fn put_user_can_change_password() {
        let app = TestApp::new().await;
        let alice = app
            .state
            .store
            .create_local_user(NewLocalUser {
                email: "alice@example.com",
                password: "old",
                must_change_password: false,
            })
            .await
            .unwrap();

        let resp = app
            .put(
                &format!("/api/v1/users/{}", alice.id),
                &json!({ "active": true, "password": "newpw" }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify the password actually changed.
        let logged_in = app
            .state
            .store
            .verify_password("alice@example.com", "newpw")
            .await
            .unwrap();
        assert!(logged_in.is_some(), "new password should authenticate");
    }

    #[tokio::test]
    async fn put_user_empty_password_returns_400() {
        let app = TestApp::new().await;
        let alice = app
            .state
            .store
            .create_local_user(NewLocalUser {
                email: "alice@example.com",
                password: "pw",
                must_change_password: false,
            })
            .await
            .unwrap();

        let resp = app
            .put(
                &format!("/api/v1/users/{}", alice.id),
                &json!({ "active": true, "password": "" }),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---------- DELETE /api/v1/users/{user} ----------

    #[tokio::test]
    async fn delete_self_returns_403() {
        let app = TestApp::new().await;
        let resp = app
            .delete(&format!("/api/v1/users/{}", app.admin.id))
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_last_user_returns_403() {
        let app = TestApp::new().await;
        // Try to delete a phantom — `count == 1` so the guard fires before
        // the row lookup.
        let resp = app
            .delete("/api/v1/users/00000000-0000-0000-0000-000000000000")
            .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_other_user_succeeds() {
        let app = TestApp::new().await;
        let alice = app
            .state
            .store
            .create_local_user(NewLocalUser {
                email: "alice@example.com",
                password: "pw",
                must_change_password: false,
            })
            .await
            .unwrap();

        let resp = app
            .delete(&format!("/api/v1/users/{}", alice.id))
            .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let reread = app.state.store.find_by_id(&alice.id).await.unwrap();
        assert!(reread.is_none());
    }
}
