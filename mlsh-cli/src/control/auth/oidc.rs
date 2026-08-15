//! Generic OIDC login. Env-configured, enabled when
//! `MLSH_CONTROL_OIDC_ISSUER` is set.

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

        let jwks: JwkSet = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        self.verify_id_token(&tok.id_token, &jwks, &pending.nonce)
    }

    /// Verify an id_token presented as join proof. The CLI
    /// was the OAuth client, so there is no nonce to check on our side.
    pub async fn verify_join_token(&self, id_token: &str) -> Result<OidcIdentity> {
        let d = self.discover().await?;
        let jwks: JwkSet = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        self.verify(id_token, &jwks, None)
    }

    fn verify_id_token(&self, id_token: &str, jwks: &JwkSet, nonce: &str) -> Result<OidcIdentity> {
        self.verify(id_token, jwks, Some(nonce))
    }

    fn verify(&self, id_token: &str, jwks: &JwkSet, nonce: Option<&str>) -> Result<OidcIdentity> {
        let header = decode_header(id_token)?;
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
            decode::<serde_json::Value>(id_token, &DecodingKey::from_jwk(jwk)?, &validation)?
                .claims;

        if let Some(nonce) = nonce {
            if claims.get("nonce").and_then(|v| v.as_str()) != Some(nonce) {
                bail!("nonce mismatch");
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::SigningKey;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::sync::OnceLock as StdOnceLock;

    const ISS: &str = "https://id.example";
    const CLIENT_ID: &str = "mlsh";

    struct Keys {
        priv_pem: String,
        jwks: JwkSet,
    }

    fn keys() -> &'static Keys {
        static K: StdOnceLock<Keys> = StdOnceLock::new();
        K.get_or_init(|| {
            let signing = SigningKey::generate(&mut rand::rngs::OsRng);
            let priv_pem = signing.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            let x = b64url(signing.verifying_key().as_bytes());
            let jwks: JwkSet = serde_json::from_value(serde_json::json!({
                "keys": [{ "kty": "OKP", "crv": "Ed25519", "kid": "t1", "x": x }]
            }))
            .unwrap();
            Keys { priv_pem, jwks }
        })
    }

    fn client(allowed_groups: Vec<String>) -> OidcClient {
        OidcClient {
            issuer: ISS.into(),
            client_id: CLIENT_ID.into(),
            client_secret: None,
            scopes: "openid profile email".into(),
            groups_claim: "groups".into(),
            allowed_groups,
            http: reqwest::Client::new(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn sign(claims: &serde_json::Value) -> String {
        let key = EncodingKey::from_ed_pem(keys().priv_pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("t1".into());
        encode(&header, claims, &key).unwrap()
    }

    fn base_claims() -> serde_json::Value {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        serde_json::json!({
            "iss": ISS, "aud": CLIENT_ID, "sub": "u1", "email": "alice@example.com",
            "exp": now + 300, "nonce": "n1", "groups": ["mlsh", "dev"]
        })
    }

    #[test]
    fn accepts_valid_token() {
        let id = client(vec![])
            .verify_id_token(&sign(&base_claims()), &keys().jwks, "n1")
            .unwrap();
        assert_eq!(id.subject_key, format!("oidc:{ISS}#u1"));
        assert_eq!(id.email, "alice@example.com");
    }

    #[test]
    fn rejects_wrong_issuer() {
        let mut c = base_claims();
        c["iss"] = "https://evil.example".into();
        assert!(client(vec![])
            .verify_id_token(&sign(&c), &keys().jwks, "n1")
            .is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let mut c = base_claims();
        c["aud"] = "other".into();
        assert!(client(vec![])
            .verify_id_token(&sign(&c), &keys().jwks, "n1")
            .is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let mut c = base_claims();
        c["exp"] = 1000.into();
        assert!(client(vec![])
            .verify_id_token(&sign(&c), &keys().jwks, "n1")
            .is_err());
    }

    #[test]
    fn rejects_nonce_mismatch() {
        assert!(client(vec![])
            .verify_id_token(&sign(&base_claims()), &keys().jwks, "other-nonce")
            .is_err());
    }

    #[test]
    fn group_gate_allows_member_rejects_outsider() {
        let tok = sign(&base_claims());
        assert!(client(vec!["mlsh".into()])
            .verify_id_token(&tok, &keys().jwks, "n1")
            .is_ok());
        assert!(client(vec!["admins-only".into()])
            .verify_id_token(&tok, &keys().jwks, "n1")
            .is_err());
    }

    #[test]
    fn missing_email_falls_back_to_sub() {
        let mut c = base_claims();
        c.as_object_mut().unwrap().remove("email");
        let id = client(vec![])
            .verify_id_token(&sign(&c), &keys().jwks, "n1")
            .unwrap();
        assert_eq!(id.email, "u1");
    }
}
