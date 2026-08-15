//! Generic OIDC login (ADR-018). Env-configured, enabled when
//! `MLSH_CONTROL_OIDC_ISSUER` is set. Design rationale lives in the ADR.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const PENDING_TTL: Duration = Duration::from_secs(600);

pub struct OidcClient {
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    scopes: String,
    groups_claim: String,
    allowed_groups: Vec<String>,
    http: reqwest::Client,
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    verifier: String,
    nonce: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// Identity extracted from a validated id_token.
pub struct OidcIdentity {
    /// `oidc:<iss>#<sub>` — stored in `users.cloud_user_id`.
    pub subject_key: String,
    pub email: String,
}

static CLIENT: OnceLock<Option<Arc<OidcClient>>> = OnceLock::new();

pub fn client() -> Option<Arc<OidcClient>> {
    CLIENT
        .get_or_init(|| OidcClient::from_env().map(Arc::new))
        .clone()
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b64url(&b)
}

impl OidcClient {
    fn from_env() -> Option<Self> {
        let issuer = std::env::var("MLSH_CONTROL_OIDC_ISSUER").ok()?;
        let client_id = std::env::var("MLSH_CONTROL_OIDC_CLIENT_ID").ok()?;
        let csv = |k: &str| -> Vec<String> {
            std::env::var(k)
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        Some(Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id,
            client_secret: std::env::var("MLSH_CONTROL_OIDC_CLIENT_SECRET").ok(),
            scopes: std::env::var("MLSH_CONTROL_OIDC_SCOPES")
                .unwrap_or_else(|_| "openid profile email".into()),
            groups_claim: std::env::var("MLSH_CONTROL_OIDC_GROUPS_CLAIM")
                .unwrap_or_else(|_| "groups".into()),
            allowed_groups: csv("MLSH_CONTROL_OIDC_ALLOWED_GROUPS"),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("build http client"),
            pending: Mutex::new(HashMap::new()),
        })
    }

    async fn discover(&self) -> Result<Discovery> {
        Ok(self
            .http
            .get(format!("{}/.well-known/openid-configuration", self.issuer))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    fn redirect_uri(host: &str) -> String {
        format!("https://{host}/auth/oidc/callback")
    }

    /// Build the IdP authorization URL and remember the PKCE/state/nonce.
    pub async fn start(&self, host: &str) -> Result<String> {
        let d = self.discover().await?;
        let (state, verifier, nonce) = (random_token(), random_token(), random_token());
        let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
        {
            let mut g = self.pending.lock().unwrap();
            g.retain(|_, p| p.expires_at > Instant::now());
            g.insert(
                state.clone(),
                Pending {
                    verifier,
                    nonce: nonce.clone(),
                    expires_at: Instant::now() + PENDING_TTL,
                },
            );
        }
        let url = url::Url::parse_with_params(
            &d.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", &self.client_id),
                ("redirect_uri", &Self::redirect_uri(host)),
                ("scope", &self.scopes),
                ("state", &state),
                ("nonce", &nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ],
        )?;
        Ok(url.into())
    }

    /// Exchange the code, validate the id_token, apply the group gate.
    pub async fn callback(&self, host: &str, code: &str, state: &str) -> Result<OidcIdentity> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .remove(state)
            .filter(|p| p.expires_at > Instant::now())
            .ok_or_else(|| anyhow!("unknown or expired state"))?;

        let d = self.discover().await?;
        let redirect_uri = Self::redirect_uri(host);
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("client_id", &self.client_id)
            .append_pair("code_verifier", &pending.verifier)
            .finish();
        let mut req = self
            .http
            .post(&d.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some(secret) = &self.client_secret {
            req = req.basic_auth(&self.client_id, Some(secret));
        }
        let tok: TokenResponse = req.send().await?.error_for_status()?.json().await?;

        let header = decode_header(&tok.id_token)?;
        let jwks: JwkSet = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let jwk = header
            .kid
            .as_ref()
            .and_then(|kid| jwks.find(kid))
            .or_else(|| jwks.keys.first())
            .ok_or_else(|| anyhow!("no usable key in JWKS"))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.client_id]);
        let claims =
            decode::<serde_json::Value>(&tok.id_token, &DecodingKey::from_jwk(jwk)?, &validation)?
                .claims;

        if claims.get("nonce").and_then(|v| v.as_str()) != Some(pending.nonce.as_str()) {
            bail!("nonce mismatch");
        }
        if !self.allowed_groups.is_empty() {
            let ok = claims
                .get(&self.groups_claim)
                .and_then(|v| v.as_array())
                .map(|gs| {
                    gs.iter()
                        .filter_map(|g| g.as_str())
                        .any(|g| self.allowed_groups.iter().any(|a| a == g))
                })
                .unwrap_or(false);
            if !ok {
                bail!("user not in an allowed group");
            }
        }
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("missing sub"))?;
        let email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or(sub)
            .to_string();
        Ok(OidcIdentity {
            subject_key: format!("oidc:{}#{}", self.issuer, sub),
            email,
        })
    }
}
