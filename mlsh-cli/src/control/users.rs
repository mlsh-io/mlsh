//! User-management API (ADR-032 §7).
//!
//! v1 has no role model — every authenticated user can manage every other
//! user. The UI may treat the first user as "owner" for display purposes, but
//! the backend imposes only two policy guards:
//!   - in self-hosted mode, you can only create *local* users (managed users
//!     are provisioned from JWT)
//!   - you can't delete yourself (would lock the cluster out)
//!   - sensitive ops (PATCH password, DELETE) require a TOTP step-up if the
//!     caller has TOTP enrolled (ADR-029, gate from totp::require_step_up).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use super::auth::session::{AuthState, CurrentUser};
use super::auth::store::{NewLocalUser, User};
use super::auth::totp::{self, StepUp};
use super::mode::{self, Mode};

#[derive(Serialize)]
pub struct UserOut {
    pub id: String,
    pub email: String,
    pub source: &'static str,
    pub active: bool,
    pub must_change_password: bool,
}

impl From<User> for UserOut {
    fn from(u: User) -> Self {
        let source = if u.cloud_user_id.is_some() {
            "managed"
        } else {
            "local"
        };
        Self {
            id: u.id,
            email: u.email,
            source,
            active: u.active,
            must_change_password: u.must_change_password,
        }
    }
}

pub async fn list(State(state): State<AuthState>, _user: CurrentUser) -> Response {
    match state.store.list_users().await {
        Ok(users) => Json(users.into_iter().map(UserOut::from).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "list_users failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub must_change_password: bool,
}

/// POST /api/v1/users — admin creates a local user. Rejected in managed mode
/// (managed clusters provision users from mlsh-cloud OAuth).
pub async fn create(
    State(state): State<AuthState>,
    _user: CurrentUser,
    Json(body): Json<CreateUser>,
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
        Ok(u) => (StatusCode::CREATED, Json(UserOut::from(u))).into_response(),
        Err(e) => {
            // UNIQUE constraint on `email` is the most common cause; treat as 409.
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

#[derive(Deserialize)]
pub struct UpdateUser {
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
}

/// PATCH /api/v1/users/:id — toggle `active` and/or change password. Step-up
/// required when the caller has verified TOTP.
pub async fn update(
    State(state): State<AuthState>,
    user: CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateUser>,
) -> Response {
    if body.active.is_none() && body.password.is_none() {
        return (StatusCode::BAD_REQUEST, "no fields to update").into_response();
    }
    if let Some(rej) = step_up_check(&state, &user.0.id, &user.0.email, &headers).await {
        return rej;
    }
    if let Some(active) = body.active {
        if let Err(e) = state.store.set_active(&id, active).await {
            tracing::warn!(error = %e, "set_active failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
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

/// DELETE /api/v1/users/:id — refuses self-deletion, refuses last-user
/// deletion (would lock the cluster). Step-up required.
pub async fn delete(
    State(state): State<AuthState>,
    user: CurrentUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if id == user.0.id {
        return (StatusCode::FORBIDDEN, "cannot delete yourself").into_response();
    }
    if let Some(rej) = step_up_check(&state, &user.0.id, &user.0.email, &headers).await {
        return rej;
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
    use crate::control::auth::oauth::OAuthConfig;
    use crate::control::auth::session::SessionKey;
    use crate::control::auth::store::AuthStore;
    use std::sync::Arc;

    async fn fresh_state() -> AuthState {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
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
            "CREATE TABLE totp_credentials (
                user_id TEXT PRIMARY KEY,
                secret_enc BLOB NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        AuthState {
            store: AuthStore::new(pool),
            key: SessionKey([0u8; 32]),
            oauth: OAuthConfig::disabled(),
            mfa_key: Arc::new([1u8; 32]),
            webauthn: None,
        }
    }

    fn current_user(u: User) -> CurrentUser {
        CurrentUser(u)
    }

    #[tokio::test]
    async fn create_local_user_succeeds_in_self_hosted_mode() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let resp = create(
            State(state.clone()),
            current_user(admin),
            Json(CreateUser {
                email: "alice@e".into(),
                password: "secret".into(),
                must_change_password: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(state.store.user_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn create_user_rejected_in_managed_mode() {
        let state = fresh_state().await;
        state.store.set_config("mode", "managed").await.unwrap();
        let admin = state
            .store
            .create_managed_user(crate::control::auth::store::NewManagedUser {
                email: "admin@e",
                cloud_user_id: "c1",
            })
            .await
            .unwrap();
        let resp = create(
            State(state),
            current_user(admin),
            Json(CreateUser {
                email: "x@y".into(),
                password: "p".into(),
                must_change_password: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn create_duplicate_email_returns_conflict() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let resp = create(
            State(state),
            current_user(admin),
            Json(CreateUser {
                email: "admin@e".into(),
                password: "p2".into(),
                must_change_password: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn delete_self_is_forbidden() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let id = admin.id.clone();
        let resp = delete(
            State(state),
            current_user(admin),
            Path(id),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_last_user_forbidden() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        // Try to delete a phantom id while only one user exists.
        let resp = delete(
            State(state),
            current_user(admin),
            Path("phantom".into()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_other_user_succeeds() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let alice = state
            .store
            .create_local_user(NewLocalUser {
                email: "alice@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let resp = delete(
            State(state.clone()),
            current_user(admin),
            Path(alice.id),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.store.user_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn update_password_rejects_empty() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let id = admin.id.clone();
        let resp = update(
            State(state),
            current_user(admin),
            Path(id),
            HeaderMap::new(),
            Json(UpdateUser {
                active: None,
                password: Some(String::new()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_no_fields_is_bad_request() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "admin@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let id = admin.id.clone();
        let resp = update(
            State(state),
            current_user(admin),
            Path(id),
            HeaderMap::new(),
            Json(UpdateUser {
                active: None,
                password: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_returns_all_users() {
        let state = fresh_state().await;
        let admin = state
            .store
            .create_local_user(NewLocalUser {
                email: "a@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        state
            .store
            .create_local_user(NewLocalUser {
                email: "b@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let resp = list(State(state), current_user(admin)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(s.contains("a@e"));
        assert!(s.contains("b@e"));
    }
}
