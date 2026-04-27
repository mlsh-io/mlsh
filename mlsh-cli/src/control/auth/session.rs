use anyhow::Result;
use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use sqlx::SqlitePool;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use uuid::Uuid;

use super::store::{user_from_row, AuthStore, User, UserRow};

pub const COOKIE_NAME: &str = "mlsh_control_session";
pub const SESSION_TTL_SECS: i64 = 86_400; // 24h

type HmacSha256 = Hmac<Sha256>;

/// Wraps the cookie-signing key. 32 bytes recommended.
#[derive(Clone)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Application state injected into the router. Cheap to clone.
#[derive(Clone)]
pub struct AuthState {
    pub store: AuthStore,
    pub key: SessionKey,
    pub oauth: super::oauth::OAuthConfig,
    /// 32-byte AES-256-GCM key used to wrap MFA secrets at rest.
    pub mfa_key: std::sync::Arc<[u8; 32]>,
    /// WebAuthn relying-party config; `None` when env is not set.
    pub webauthn: Option<super::webauthn::WebauthnConfig>,
}

/// Issue a new session row + signed cookie value.
pub async fn issue(state: &AuthState, user_id: &str) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    let expires = now + time::Duration::seconds(SESSION_TTL_SECS);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(now.format(&Iso8601::DEFAULT)?)
    .bind(expires.format(&Iso8601::DEFAULT)?)
    .execute(state.store.pool())
    .await?;
    Ok(sign_cookie(&state.key, &id))
}

/// Mark a session as revoked. Idempotent.
pub async fn revoke(pool: &SqlitePool, session_id: &str) -> Result<()> {
    sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ?")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Build a `Set-Cookie` header value. `value` is either a freshly issued signed
/// cookie or empty (with `Max-Age=0`) to clear the session.
pub fn set_cookie_header(value: &str, clear: bool) -> HeaderValue {
    let max_age = if clear { 0 } else { SESSION_TTL_SECS };
    let cookie = format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}",
        name = COOKIE_NAME,
        value = if clear { "" } else { value },
        max_age = max_age,
    );
    HeaderValue::from_str(&cookie).expect("ASCII-only cookie")
}

fn sign_cookie(key: &SessionKey, session_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("{}.{}", session_id, hex(&tag))
}

pub fn verify_signed_cookie(key: &SessionKey, raw: &str) -> Option<String> {
    verify_cookie(key, raw)
}

fn verify_cookie(key: &SessionKey, raw: &str) -> Option<String> {
    let (id, tag_hex) = raw.split_once('.')?;
    let tag = un_hex(tag_hex)?;
    let mut mac = HmacSha256::new_from_slice(&key.0).ok()?;
    mac.update(id.as_bytes());
    mac.verify_slice(&tag).ok()?;
    Some(id.to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn un_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Generate a fresh random 32-byte session key.
pub fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

/// Resolve the cookie attached to `parts` into the (active, non-revoked, non-expired)
/// user it identifies. Used by extractors below.
async fn resolve_user(state: &AuthState, parts: &Parts) -> Result<Option<User>> {
    let Some(raw) = read_cookie(parts) else {
        return Ok(None);
    };
    let Some(session_id) = verify_cookie(&state.key, &raw) else {
        return Ok(None);
    };
    let row: Option<(String, String, i64)> =
        sqlx::query_as("SELECT user_id, expires_at, revoked FROM sessions WHERE id = ?")
            .bind(&session_id)
            .fetch_optional(state.store.pool())
            .await?;
    let Some((user_id, expires_at, revoked)) = row else {
        return Ok(None);
    };
    if revoked != 0 {
        return Ok(None);
    }
    let expires = OffsetDateTime::parse(&expires_at, &Iso8601::DEFAULT)?;
    if expires < OffsetDateTime::now_utc() {
        return Ok(None);
    }
    let row: Option<UserRow> = sqlx::query_as(
        "SELECT id, email, password_hash, cloud_user_id, must_change_password, active
         FROM users WHERE id = ?",
    )
    .bind(&user_id)
    .fetch_optional(state.store.pool())
    .await?;
    Ok(row.map(user_from_row).filter(|u| u.active))
}

fn read_cookie(parts: &Parts) -> Option<String> {
    let header = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    for piece in header.split(';') {
        let piece = piece.trim();
        if let Some(value) = piece.strip_prefix(&format!("{}=", COOKIE_NAME)) {
            return Some(value.to_string());
        }
    }
    None
}

/// Required-auth extractor: rejects with 401 if no valid session.
pub struct CurrentUser(pub User);

impl FromRequestParts<AuthState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        match resolve_user(state, parts).await {
            Ok(Some(u)) => Ok(CurrentUser(u)),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, "unauthenticated").into_response()),
            Err(e) => {
                tracing::warn!(error = %e, "session resolution failed");
                Err((StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response())
            }
        }
    }
}

/// Optional-auth extractor: never rejects, returns `None` if unauthenticated.
impl OptionalFromRequestParts<AuthState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match resolve_user(state, parts).await {
            Ok(opt) => Ok(opt.map(CurrentUser)),
            Err(e) => {
                tracing::warn!(error = %e, "session resolution failed");
                Err((StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response())
            }
        }
    }
}

/// Convenience for handlers that want the AuthStore directly.
impl axum::extract::FromRef<AuthState> for AuthStore {
    fn from_ref(s: &AuthState) -> Self {
        s.store.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn cookie_round_trip() {
        let key = SessionKey([42u8; 32]);
        let signed = sign_cookie(&key, "abc-123");
        assert_eq!(verify_cookie(&key, &signed).as_deref(), Some("abc-123"));
    }

    #[test]
    fn cookie_rejects_tampered_id() {
        let key = SessionKey([42u8; 32]);
        let signed = sign_cookie(&key, "abc-123");
        let tampered = signed.replace("abc-123", "xyz-999");
        assert!(verify_cookie(&key, &tampered).is_none());
    }

    #[test]
    fn cookie_rejects_wrong_key() {
        let k1 = SessionKey([1u8; 32]);
        let k2 = SessionKey([2u8; 32]);
        let signed = sign_cookie(&k1, "abc-123");
        assert!(verify_cookie(&k2, &signed).is_none());
    }

    #[test]
    fn cookie_header_contains_required_attrs() {
        let h = set_cookie_header("v", false);
        let s = h.to_str().unwrap();
        assert!(s.starts_with(&format!("{}=v;", COOKIE_NAME)));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Strict"));
        assert!(s.contains("Path=/"));
        assert!(s.contains("Max-Age=86400"));
    }

    #[test]
    fn read_cookie_finds_named() {
        let req = Request::builder()
            .header(
                header::COOKIE,
                format!("foo=bar; {}=signed; baz=qux", COOKIE_NAME),
            )
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert_eq!(read_cookie(&parts).as_deref(), Some("signed"));
    }

    async fn setup_pool() -> SqlitePool {
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
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                cloud_user_id TEXT UNIQUE,
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
        pool
    }

    #[tokio::test]
    async fn issue_then_resolve_returns_user() {
        let pool = setup_pool().await;
        let store = AuthStore::new(pool.clone());
        let state = AuthState {
            store: store.clone(),
            key: SessionKey([9u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([0u8; 32]),
            webauthn: None,
        };
        let user = store
            .create_local_user(super::super::store::NewLocalUser {
                email: "a@b",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();

        let cookie = issue(&state, &user.id).await.unwrap();
        let req = Request::builder()
            .header(header::COOKIE, format!("{}={}", COOKIE_NAME, cookie))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let resolved = resolve_user(&state, &parts).await.unwrap();
        assert_eq!(resolved.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn revoked_session_resolves_to_none() {
        let pool = setup_pool().await;
        let store = AuthStore::new(pool.clone());
        let state = AuthState {
            store: store.clone(),
            key: SessionKey([9u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([0u8; 32]),
            webauthn: None,
        };
        let user = store
            .create_local_user(super::super::store::NewLocalUser {
                email: "a@b",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let cookie = issue(&state, &user.id).await.unwrap();
        let session_id = cookie.split('.').next().unwrap();
        revoke(&pool, session_id).await.unwrap();

        let req = Request::builder()
            .header(header::COOKIE, format!("{}={}", COOKIE_NAME, cookie))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert!(resolve_user(&state, &parts).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn inactive_user_resolves_to_none() {
        let pool = setup_pool().await;
        let store = AuthStore::new(pool.clone());
        let state = AuthState {
            store: store.clone(),
            key: SessionKey([9u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([0u8; 32]),
            webauthn: None,
        };
        let user = store
            .create_local_user(super::super::store::NewLocalUser {
                email: "a@b",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let cookie = issue(&state, &user.id).await.unwrap();
        store.set_active(&user.id, false).await.unwrap();

        let req = Request::builder()
            .header(header::COOKIE, format!("{}={}", COOKIE_NAME, cookie))
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        assert!(resolve_user(&state, &parts).await.unwrap().is_none());
    }
}
