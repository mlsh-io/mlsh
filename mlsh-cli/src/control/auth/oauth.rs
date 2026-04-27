//! Managed-mode auth via mlsh-cloud (ADR-032 §4).
//!
//! mlsh-control authenticates the operator against mlsh-cloud using the same
//! OAuth device flow already used by `mlsh setup` (see `crate::cloud`):
//!
//! 1. UI clicks "Login with mlsh.io" → mlsh-control calls
//!    `POST /auth/device/code` on mlsh-cloud and returns the user_code +
//!    verification_uri to the browser.
//! 2. The user opens the URI on any device, enters the code, authenticates
//!    on mlsh-cloud (Google / GitHub / password).
//! 3. The UI polls mlsh-control which polls
//!    `POST /auth/device/token` until mlsh-cloud emits an access token.
//! 4. mlsh-control validates the JWT (EdDSA, signed by mlsh-cloud's Ed25519
//!    key, claims `iss="mlsh-cloud"`, `aud="mlsh-cloud-api"`, plus `sub`,
//!    `email`, `exp`), upserts a managed user keyed by `sub`, and issues a
//!    local session cookie.
//!
//! The mlsh-cloud public key is required to validate JWTs. It is loaded from
//! `MLSH_CLOUD_JWT_PUBKEY_PEM` (PEM-encoded Ed25519 public key). When unset,
//! managed-mode endpoints respond 503 — we never accept tokens against an
//! unknown signer.

use anyhow::{anyhow, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ENV_PUBKEY: &str = "MLSH_CLOUD_JWT_PUBKEY_PEM";
const ENV_CLOUD_URL: &str = "MLSH_CLOUD_URL";
const DEFAULT_CLOUD_URL: &str = "https://api.mlsh.io";
const ISSUER: &str = "mlsh-cloud";
const AUDIENCE: &str = "mlsh-cloud-api";

/// Claims emitted by mlsh-cloud (`auth/jwt.rs::Claims`). `sub` is the cloud
/// user UUID — stable across OAuth providers — and acts as our
/// `cloud_user_id` foreign key.
#[derive(Debug, Deserialize)]
pub struct CloudClaims {
    pub sub: String,
    pub email: String,
    pub exp: i64,
}

/// Pending device-flow ticket: the opaque server-side handle the UI polls. The
/// actual mlsh-cloud `device_code` never leaves mlsh-control.
#[derive(Clone)]
pub struct DeviceTicket {
    pub device_code: String,
    pub expires_at: Instant,
}

/// 30 minutes is plenty for the user to walk over to another device and
/// authenticate; mlsh-cloud's own device_code TTL is the upper bound.
const TICKET_TTL: Duration = Duration::from_secs(1800);

#[derive(Clone)]
pub struct OAuthConfig {
    pub cloud_url: String,
    decoding_key: Option<DecodingKey>,
    pub tickets: Arc<Mutex<HashMap<String, DeviceTicket>>>,
}

impl OAuthConfig {
    /// Read configuration from the environment. Returns a config with
    /// `decoding_key = None` if the public key is not provided — managed-mode
    /// endpoints then respond 503.
    pub fn from_env() -> Result<Self> {
        let cloud_url =
            std::env::var(ENV_CLOUD_URL).unwrap_or_else(|_| DEFAULT_CLOUD_URL.to_string());
        let decoding_key = match std::env::var(ENV_PUBKEY) {
            Ok(pem) if !pem.is_empty() => Some(
                DecodingKey::from_ed_pem(pem.as_bytes())
                    .map_err(|e| anyhow!("invalid {}: {}", ENV_PUBKEY, e))?,
            ),
            _ => None,
        };
        Ok(Self {
            cloud_url,
            decoding_key,
            tickets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.decoding_key.is_some()
    }

    /// A disabled config — used in tests and when no public key is configured.
    pub fn disabled() -> Self {
        Self {
            cloud_url: DEFAULT_CLOUD_URL.into(),
            decoding_key: None,
            tickets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn store_ticket(&self, ticket: String, device_code: String) {
        let mut g = self.tickets.lock().unwrap();
        g.retain(|_, v| v.expires_at > Instant::now());
        g.insert(
            ticket,
            DeviceTicket {
                device_code,
                expires_at: Instant::now() + TICKET_TTL,
            },
        );
    }

    pub fn take_device_code(&self, ticket: &str) -> Option<String> {
        self.peek_device_code(ticket)
    }

    pub fn peek_device_code(&self, ticket: &str) -> Option<String> {
        let mut g = self.tickets.lock().unwrap();
        g.retain(|_, v| v.expires_at > Instant::now());
        g.get(ticket).map(|t| t.device_code.clone())
    }

    pub fn remove_ticket(&self, ticket: &str) {
        let mut g = self.tickets.lock().unwrap();
        g.remove(ticket);
    }

    pub fn validate_token(&self, token: &str) -> Result<CloudClaims> {
        let key = self
            .decoding_key
            .as_ref()
            .ok_or_else(|| anyhow!("mlsh-cloud public key not configured"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        validation.set_required_spec_claims(&["sub", "exp", "iss", "aud"]);
        validation.validate_exp = true;
        let data = jsonwebtoken::decode::<CloudClaims>(token, key, &validation)?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand::rngs::OsRng;
    use serde::Serialize;
    use std::sync::OnceLock;
    use time::OffsetDateTime;

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        sub: &'a str,
        email: &'a str,
        plan_id: &'a str,
        iat: i64,
        exp: i64,
    }

    struct TestKeys {
        priv_pem: String,
        pub_pem: String,
    }

    /// Generate an Ed25519 keypair once for the whole test binary. Test-only.
    fn keys() -> &'static TestKeys {
        static K: OnceLock<TestKeys> = OnceLock::new();
        K.get_or_init(|| {
            let mut rng = OsRng;
            let signing = SigningKey::generate(&mut rng);
            let verifying = signing.verifying_key();
            let priv_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            let pub_pem = verifying.to_public_key_pem(LineEnding::LF).unwrap();
            TestKeys { priv_pem, pub_pem }
        })
    }

    fn cfg_with_pubkey() -> OAuthConfig {
        OAuthConfig {
            cloud_url: "https://api.example".into(),
            decoding_key: Some(DecodingKey::from_ed_pem(keys().pub_pem.as_bytes()).unwrap()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn sign_token(claims: &TestClaims) -> String {
        let key = EncodingKey::from_ed_pem(keys().priv_pem.as_bytes()).unwrap();
        encode(&Header::new(Algorithm::EdDSA), claims, &key).unwrap()
    }

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn validates_well_formed_token() {
        let cfg = cfg_with_pubkey();
        let n = now();
        let tok = sign_token(&TestClaims {
            iss: ISSUER,
            aud: AUDIENCE,
            sub: "cloud-uuid-1",
            email: "alice@example.com",
            plan_id: "free",
            iat: n,
            exp: n + 300,
        });
        let claims = cfg.validate_token(&tok).unwrap();
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.sub, "cloud-uuid-1");
    }

    #[test]
    fn rejects_expired_token() {
        let cfg = cfg_with_pubkey();
        let n = now();
        let tok = sign_token(&TestClaims {
            iss: ISSUER,
            aud: AUDIENCE,
            sub: "x",
            email: "a@b",
            plan_id: "free",
            iat: n - 600,
            exp: n - 300,
        });
        assert!(cfg.validate_token(&tok).is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let cfg = cfg_with_pubkey();
        let n = now();
        let tok = sign_token(&TestClaims {
            iss: "evil",
            aud: AUDIENCE,
            sub: "x",
            email: "a@b",
            plan_id: "free",
            iat: n,
            exp: n + 300,
        });
        assert!(cfg.validate_token(&tok).is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let cfg = cfg_with_pubkey();
        let n = now();
        let tok = sign_token(&TestClaims {
            iss: ISSUER,
            aud: "wrong",
            sub: "x",
            email: "a@b",
            plan_id: "free",
            iat: n,
            exp: n + 300,
        });
        assert!(cfg.validate_token(&tok).is_err());
    }

    #[test]
    fn validate_fails_without_pubkey() {
        let cfg = OAuthConfig::disabled();
        assert!(!cfg.is_ready());
        assert!(cfg.validate_token("any.token.value").is_err());
    }
}
