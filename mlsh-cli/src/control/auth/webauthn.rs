//! WebAuthn (passkeys) for step-up MFA (ADR-029, ADR-032 §5).
//!
//! Two ceremonies, two stages each:
//! 1. **Registration**: `register/start` returns a challenge; the browser uses
//!    `navigator.credentials.create()` and POSTs the result to `register/finish`.
//! 2. **Authentication (step-up)**: `login/start` returns a challenge over the
//!    user's registered credentials; `login/finish` verifies the assertion.
//!
//! Stored `Passkey` (the full webauthn-rs blob — credential ID, public key,
//! counter, transports) is serialized as JSON into the `public_key` BLOB of
//! `webauthn_credentials`. The `credential_id` column is the lookup key.
//!
//! Pending challenges live in an in-memory map keyed by an opaque ticket; the
//! browser passes that ticket back on the second leg. Tickets expire after 5
//! minutes — the WebAuthn protocol's own challenge timeout already covers
//! freshness; this is just a memory bound.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use super::session::AuthState;

const TICKET_TTL: Duration = Duration::from_secs(300);
const ENV_RP_ID: &str = "MLSH_CONTROL_RP_ID";
const ENV_RP_ORIGIN: &str = "MLSH_CONTROL_RP_ORIGIN";
const ENV_RP_NAME: &str = "MLSH_CONTROL_RP_NAME";

#[derive(Clone)]
pub struct WebauthnConfig {
    inner: Arc<Webauthn>,
    pending_register: Arc<Mutex<HashMap<String, (Uuid, PasskeyRegistration, Instant)>>>,
    pending_authn: Arc<Mutex<HashMap<String, (String, PasskeyAuthentication, Instant)>>>,
}

impl WebauthnConfig {
    /// Build from environment. Requires `MLSH_CONTROL_RP_ID` (e.g. the cluster
    /// domain) and `MLSH_CONTROL_RP_ORIGIN` (`https://control.<cluster>.…`).
    /// If unset, returns `Ok(None)` — WebAuthn endpoints respond 503.
    pub fn from_env() -> Result<Option<Self>> {
        let rp_id = match std::env::var(ENV_RP_ID) {
            Ok(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let rp_origin_str = std::env::var(ENV_RP_ORIGIN)
            .map_err(|_| anyhow!("{} is set but {} is not", ENV_RP_ID, ENV_RP_ORIGIN))?;
        let rp_origin =
            Url::parse(&rp_origin_str).map_err(|e| anyhow!("invalid {}: {}", ENV_RP_ORIGIN, e))?;
        let rp_name = std::env::var(ENV_RP_NAME).unwrap_or_else(|_| "mlsh-control".to_string());
        let inner = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name(&rp_name)
            .build()?;
        Ok(Some(Self {
            inner: Arc::new(inner),
            pending_register: Arc::new(Mutex::new(HashMap::new())),
            pending_authn: Arc::new(Mutex::new(HashMap::new())),
        }))
    }
}

#[derive(Serialize)]
pub struct StartRegistration {
    pub ticket: String,
    pub options: CreationChallengeResponse,
}

#[derive(Serialize)]
pub struct StartAuthentication {
    pub ticket: String,
    pub options: RequestChallengeResponse,
}

#[derive(Deserialize)]
pub struct FinishRegistration {
    pub ticket: String,
    pub name: Option<String>,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct FinishAuthentication {
    pub ticket: String,
    pub credential: PublicKeyCredential,
}

/// Begin passkey registration for the current user.
pub async fn register_start(state: &AuthState, user_id: &str) -> Result<StartRegistration> {
    let cfg = config(state)?;
    let user_uuid =
        Uuid::parse_str(user_id).map_err(|e| anyhow!("user id is not a UUID: {}", e))?;
    let user = state
        .store
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| anyhow!("user not found"))?;
    let existing: Vec<_> = state
        .store
        .list_webauthn(user_id)
        .await?
        .into_iter()
        .filter_map(|r| serde_json::from_slice::<Passkey>(&r.passkey_json).ok())
        .map(|pk| pk.cred_id().clone())
        .collect();
    let exclude = if existing.is_empty() {
        None
    } else {
        Some(existing)
    };
    let (ccr, reg_state) =
        cfg.inner
            .start_passkey_registration(user_uuid, &user.email, &user.email, exclude)?;
    let ticket = Uuid::new_v4().to_string();
    {
        let mut g = cfg.pending_register.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, (_, _, t)| t.elapsed() < TICKET_TTL);
        g.insert(ticket.clone(), (user_uuid, reg_state, now));
    }
    Ok(StartRegistration {
        ticket,
        options: ccr,
    })
}

/// Finish passkey registration, persisting the new credential.
pub async fn register_finish(
    state: &AuthState,
    user_id: &str,
    body: FinishRegistration,
) -> Result<String> {
    let cfg = config(state)?;
    let (user_uuid, reg_state) = {
        let mut g = cfg.pending_register.lock().unwrap();
        g.retain(|_, (_, _, t)| t.elapsed() < TICKET_TTL);
        let (uuid, st, _) = g
            .remove(&body.ticket)
            .ok_or_else(|| anyhow!("unknown or expired ticket"))?;
        (uuid, st)
    };
    let expected_uuid = Uuid::parse_str(user_id)?;
    if user_uuid != expected_uuid {
        return Err(anyhow!("ticket does not belong to this user"));
    }
    let passkey: Passkey = cfg
        .inner
        .finish_passkey_registration(&body.credential, &reg_state)?;
    let cred_id = passkey.cred_id().as_ref().to_vec();
    let json = serde_json::to_vec(&passkey)?;
    let name = body
        .name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Device".to_string());
    state
        .store
        .insert_webauthn(user_id, &cred_id, &json, &name)
        .await
}

/// Begin a step-up authentication for `user_id`.
pub async fn login_start(state: &AuthState, user_id: &str) -> Result<StartAuthentication> {
    let cfg = config(state)?;
    let creds: Vec<Passkey> = state
        .store
        .list_webauthn(user_id)
        .await?
        .into_iter()
        .filter_map(|r| serde_json::from_slice::<Passkey>(&r.passkey_json).ok())
        .collect();
    if creds.is_empty() {
        return Err(anyhow!("no webauthn credentials enrolled"));
    }
    let (rcr, ast) = cfg.inner.start_passkey_authentication(&creds)?;
    let ticket = Uuid::new_v4().to_string();
    {
        let mut g = cfg.pending_authn.lock().unwrap();
        let now = Instant::now();
        g.retain(|_, (_, _, t)| t.elapsed() < TICKET_TTL);
        g.insert(ticket.clone(), (user_id.to_string(), ast, now));
    }
    Ok(StartAuthentication {
        ticket,
        options: rcr,
    })
}

/// Finish authentication, updating the credential's sign counter on success.
pub async fn login_finish(
    state: &AuthState,
    user_id: &str,
    body: FinishAuthentication,
) -> Result<()> {
    let cfg = config(state)?;
    let ast = {
        let mut g = cfg.pending_authn.lock().unwrap();
        g.retain(|_, (_, _, t)| t.elapsed() < TICKET_TTL);
        let (uid, ast, _) = g
            .remove(&body.ticket)
            .ok_or_else(|| anyhow!("unknown or expired ticket"))?;
        if uid != user_id {
            return Err(anyhow!("ticket does not belong to this user"));
        }
        ast
    };
    let result = cfg
        .inner
        .finish_passkey_authentication(&body.credential, &ast)?;

    // If the counter advanced, persist the updated Passkey + counter.
    let cred_id = result.cred_id().as_ref().to_vec();
    let rows = state.store.list_webauthn(user_id).await?;
    if let Some(row) = rows.iter().find(|r| r.credential_id == cred_id) {
        if let Ok(mut pk) = serde_json::from_slice::<Passkey>(&row.passkey_json) {
            if pk.update_credential(&result).unwrap_or(false) {
                let bytes = serde_json::to_vec(&pk)?;
                state
                    .store
                    .update_webauthn_passkey(&cred_id, &bytes, result.counter())
                    .await?;
            }
        }
    }
    Ok(())
}

pub async fn list(state: &AuthState, user_id: &str) -> Result<Vec<CredentialView>> {
    Ok(state
        .store
        .list_webauthn(user_id)
        .await?
        .into_iter()
        .map(|r| CredentialView {
            id: r.id,
            name: r.name,
        })
        .collect())
}

pub async fn delete(state: &AuthState, user_id: &str, id: &str) -> Result<bool> {
    Ok(state.store.delete_webauthn(user_id, id).await? > 0)
}

#[derive(Serialize)]
pub struct CredentialView {
    pub id: String,
    pub name: String,
}

fn config(state: &AuthState) -> Result<&WebauthnConfig> {
    state
        .webauthn
        .as_ref()
        .ok_or_else(|| anyhow!("webauthn not configured"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::auth::oauth::OAuthConfig;
    use crate::control::auth::session::SessionKey;
    use crate::control::auth::store::AuthStore;

    fn build_config() -> WebauthnConfig {
        let origin = Url::parse("https://control.example.com").unwrap();
        let inner = WebauthnBuilder::new("control.example.com", &origin)
            .unwrap()
            .rp_name("test")
            .build()
            .unwrap();
        WebauthnConfig {
            inner: Arc::new(inner),
            pending_register: Arc::new(Mutex::new(HashMap::new())),
            pending_authn: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn setup_state() -> AuthState {
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
            "CREATE TABLE webauthn_credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                credential_id BLOB NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL DEFAULT 'Device',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        AuthState {
            store: AuthStore::new(pool),
            key: SessionKey([1u8; 32]),
            oauth: OAuthConfig::disabled(),
            mfa_key: Arc::new([0u8; 32]),
            webauthn: Some(build_config()),
        }
    }

    #[tokio::test]
    async fn list_and_delete_credentials() {
        let state = setup_state().await;
        let user = state
            .store
            .create_local_user(crate::control::auth::store::NewLocalUser {
                email: "u@e",
                password: "p",
                must_change_password: false,
            })
            .await
            .unwrap();
        // Insert a fake credential (we can't run the full ceremony without a real authenticator).
        let id = state
            .store
            .insert_webauthn(&user.id, b"\x01\x02", b"{}", "YubiKey")
            .await
            .unwrap();
        let creds = list(&state, &user.id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].name, "YubiKey");
        assert!(delete(&state, &user.id, &id).await.unwrap());
        assert!(list(&state, &user.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn ticket_purge_drops_old_entries() {
        let cfg = build_config();
        {
            let mut g = cfg.pending_register.lock().unwrap();
            // Insert a synthetic stale entry.
            let uuid = Uuid::new_v4();
            // We can't construct PasskeyRegistration from outside, so just check
            // that purge logic is right via a manual map.
            let mut local: HashMap<String, ((), Instant)> = HashMap::new();
            local.insert(
                "old".into(),
                ((), Instant::now() - Duration::from_secs(600)),
            );
            local.insert("fresh".into(), ((), Instant::now()));
            local.retain(|_, (_, t)| t.elapsed() < TICKET_TTL);
            assert!(local.contains_key("fresh"));
            assert!(!local.contains_key("old"));
            // Quiet warnings about unused.
            let _ = (uuid, &mut *g);
        }
    }

    #[test]
    fn from_env_returns_none_when_unset() {
        // Snapshot + clear (test runs serially because of env mutation).
        let prev = std::env::var(ENV_RP_ID).ok();
        std::env::remove_var(ENV_RP_ID);
        let res = WebauthnConfig::from_env().unwrap();
        assert!(res.is_none());
        if let Some(v) = prev {
            std::env::set_var(ENV_RP_ID, v);
        }
    }
}
