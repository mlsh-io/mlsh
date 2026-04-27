//! TOTP (RFC 6238) for step-up MFA (ADR-029 §1, ADR-032 §5).
//!
//! Secrets are wrapped with the AES-256-GCM key managed by `crypto.rs` before
//! hitting SQLite. A user enrolls (`enroll`) → receives a fresh secret + an
//! `otpauth://` URI (used to render a QR code in the UI). Once they submit a
//! correct code (`verify`), the row is flipped to `verified=1` — only then
//! does the credential gate step-up actions.
//!
//! TOTP enforcement on a sensitive endpoint goes through `require_step_up`: if
//! the caller has a verified TOTP credential, they must include a valid code in
//! the `X-MFA-Code` header. Users with no TOTP enrolled bypass the gate (the
//! caller is responsible for higher-level admin policy elsewhere).

use anyhow::{anyhow, Result};
use totp_rs::{Algorithm, Secret, TOTP};

use super::crypto;
use super::session::AuthState;

const ISSUER: &str = "mlsh-control";
const DIGITS: usize = 6;
const STEP_SECS: u64 = 30;
/// Allow ±1 step (= ±30 s) of clock skew when verifying.
const SKEW_STEPS: u8 = 1;

/// A freshly issued (or re-issued) TOTP enrollment, returned to the UI so it
/// can render a QR code and remember the base32 fallback.
pub struct Enrollment {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

fn build_totp(secret_bytes: Vec<u8>, account: &str) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        DIGITS,
        SKEW_STEPS,
        STEP_SECS,
        secret_bytes,
        Some(ISSUER.to_string()),
        account.to_string(),
    )
    .map_err(|e| anyhow!("totp build failed: {e:?}"))
}

/// Generate a fresh TOTP secret, store it (encrypted, `verified=0`), and
/// return an enrollment payload for the UI.
pub async fn enroll(state: &AuthState, user_id: &str, account: &str) -> Result<Enrollment> {
    let secret = Secret::generate_secret();
    let bytes = secret
        .to_bytes()
        .map_err(|e| anyhow!("secret to_bytes: {e:?}"))?;
    let totp = build_totp(bytes.clone(), account)?;
    let enc = crypto::encrypt(state.mfa_key.as_ref(), &bytes)?;
    state.store.upsert_totp(user_id, &enc).await?;
    Ok(Enrollment {
        secret_base32: secret.to_encoded().to_string(),
        otpauth_uri: totp.get_url(),
    })
}

/// Verify a 6-digit code against the user's stored secret. On success, marks
/// the credential as verified (idempotent for already-verified rows).
pub async fn verify(state: &AuthState, user_id: &str, account: &str, code: &str) -> Result<bool> {
    let Some(row) = state.store.get_totp(user_id).await? else {
        return Ok(false);
    };
    let bytes = crypto::decrypt(state.mfa_key.as_ref(), &row.secret_enc)?;
    let totp = build_totp(bytes, account)?;
    if !totp
        .check_current(code)
        .map_err(|e| anyhow!("totp check: {e:?}"))?
    {
        return Ok(false);
    }
    if !row.verified {
        state.store.mark_totp_verified(user_id).await?;
    }
    Ok(true)
}

/// Delete a TOTP credential. Idempotent.
pub async fn delete(state: &AuthState, user_id: &str) -> Result<()> {
    state.store.delete_totp(user_id).await
}

/// Step-up gate. Returns `Ok(())` if the caller is allowed to proceed:
/// - user has no verified TOTP credential → bypass
/// - user has a verified credential and `code` is valid → ok
/// Returns `Err` (rejection) otherwise.
pub async fn require_step_up(
    state: &AuthState,
    user_id: &str,
    account: &str,
    code: Option<&str>,
) -> Result<StepUp> {
    let Some(row) = state.store.get_totp(user_id).await? else {
        return Ok(StepUp::NotEnrolled);
    };
    if !row.verified {
        return Ok(StepUp::NotEnrolled);
    }
    let Some(code) = code else {
        return Ok(StepUp::Required);
    };
    let bytes = crypto::decrypt(state.mfa_key.as_ref(), &row.secret_enc)?;
    let totp = build_totp(bytes, account)?;
    if totp
        .check_current(code)
        .map_err(|e| anyhow!("totp check: {e:?}"))?
    {
        Ok(StepUp::Ok)
    } else {
        Ok(StepUp::Invalid)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StepUp {
    /// User has no verified TOTP — gate is open.
    NotEnrolled,
    /// User has verified TOTP and supplied a valid code.
    Ok,
    /// User has verified TOTP but no code was supplied.
    Required,
    /// User has verified TOTP and supplied a wrong/expired code.
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::auth::session::SessionKey;
    use crate::control::auth::store::{AuthStore, NewLocalUser};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn setup() -> (AuthState, String) {
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
        let store = AuthStore::new(pool);
        let user = store
            .create_local_user(NewLocalUser {
                email: "u@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        let state = AuthState {
            store,
            key: SessionKey([1u8; 32]),
            oauth: crate::control::auth::oauth::OAuthConfig::disabled(),
            mfa_key: std::sync::Arc::new([5u8; 32]),
            webauthn: None,
        };
        (state, user.id)
    }

    fn current_code(secret_base32: &str) -> String {
        let bytes = Secret::Encoded(secret_base32.to_string())
            .to_bytes()
            .unwrap();
        let totp = build_totp(bytes, "u@e").unwrap();
        totp.generate_current().unwrap()
    }

    #[tokio::test]
    async fn enroll_then_verify_marks_credential() {
        let (state, uid) = setup().await;
        let e = enroll(&state, &uid, "u@e").await.unwrap();
        assert!(e.otpauth_uri.starts_with("otpauth://totp/"));
        assert!(e.otpauth_uri.contains("issuer=mlsh-control"));

        // Pre-verification, the row exists but verified=0.
        let row = state.store.get_totp(&uid).await.unwrap().unwrap();
        assert!(!row.verified);

        let code = current_code(&e.secret_base32);
        assert!(verify(&state, &uid, "u@e", &code).await.unwrap());
        let row = state.store.get_totp(&uid).await.unwrap().unwrap();
        assert!(row.verified);
    }

    #[tokio::test]
    async fn verify_rejects_wrong_code() {
        let (state, uid) = setup().await;
        let _ = enroll(&state, &uid, "u@e").await.unwrap();
        assert!(!verify(&state, &uid, "u@e", "000000").await.unwrap());
    }

    #[tokio::test]
    async fn step_up_open_when_no_credential() {
        let (state, uid) = setup().await;
        assert_eq!(
            require_step_up(&state, &uid, "u@e", None).await.unwrap(),
            StepUp::NotEnrolled
        );
    }

    #[tokio::test]
    async fn step_up_open_when_credential_unverified() {
        let (state, uid) = setup().await;
        let _ = enroll(&state, &uid, "u@e").await.unwrap();
        assert_eq!(
            require_step_up(&state, &uid, "u@e", None).await.unwrap(),
            StepUp::NotEnrolled
        );
    }

    #[tokio::test]
    async fn step_up_required_then_ok() {
        let (state, uid) = setup().await;
        let e = enroll(&state, &uid, "u@e").await.unwrap();
        let code = current_code(&e.secret_base32);
        verify(&state, &uid, "u@e", &code).await.unwrap();

        assert_eq!(
            require_step_up(&state, &uid, "u@e", None).await.unwrap(),
            StepUp::Required
        );
        let code = current_code(&e.secret_base32);
        assert_eq!(
            require_step_up(&state, &uid, "u@e", Some(&code))
                .await
                .unwrap(),
            StepUp::Ok
        );
        assert_eq!(
            require_step_up(&state, &uid, "u@e", Some("000000"))
                .await
                .unwrap(),
            StepUp::Invalid
        );
    }

    #[tokio::test]
    async fn delete_removes_credential() {
        let (state, uid) = setup().await;
        let _ = enroll(&state, &uid, "u@e").await.unwrap();
        delete(&state, &uid).await.unwrap();
        assert!(state.store.get_totp(&uid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn re_enroll_resets_verified_flag() {
        let (state, uid) = setup().await;
        let e1 = enroll(&state, &uid, "u@e").await.unwrap();
        let code = current_code(&e1.secret_base32);
        verify(&state, &uid, "u@e", &code).await.unwrap();
        assert!(state.store.get_totp(&uid).await.unwrap().unwrap().verified);

        let _e2 = enroll(&state, &uid, "u@e").await.unwrap();
        assert!(!state.store.get_totp(&uid).await.unwrap().unwrap().verified);
    }
}
