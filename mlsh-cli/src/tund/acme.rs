//! ACME client for ingress domains — HTTP-01 flavour.
//!
//! Uses `instant-acme` to obtain a Let's Encrypt certificate via HTTP-01.
//! Signal hosts the challenge responder on `:80` (see
//! `mlsh-signal/src/acme_http.rs`), which is reachable from LE because the
//! domain already resolves to signal's public IP via the existing DNS
//! wildcard.
//!
//! Flow for one domain:
//! 1. Load or create a Let's Encrypt account, cached at
//!    `/var/lib/mlsh/ingress/acme/account.json`.
//! 2. Open a new order for the domain.
//! 3. For the HTTP-01 challenge, compute the key-authorization and push
//!    `StreamMessage::HttpChallengeSet { domain, token, key_auth }` to signal.
//! 4. Tell the ACME server the challenge is ready, poll until Ready.
//! 5. Finalize with a CSR — the private key stays on the node.
//! 6. Poll for the final certificate chain.
//! 7. Write `cert.pem` and `key.pem` under `/var/lib/mlsh/ingress/certs/`
//!    (atomic, perms 0600 on the key).
//! 8. Send `HttpChallengeClear` to signal, invalidate the TLS acceptor cache.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use tracing::{debug, info, warn};

use super::ingress;

const ACME_DIR: &str = "/var/lib/mlsh/ingress/acme";
const CERT_DIR: &str = "/var/lib/mlsh/ingress/certs";

/// Which ACME directory to use. Staging is strongly recommended for smoke
/// tests — production has hard rate limits.
pub enum Directory {
    Production,
    Staging,
}

impl Directory {
    fn url(&self) -> &'static str {
        match self {
            Directory::Production => LetsEncrypt::Production.url(),
            Directory::Staging => LetsEncrypt::Staging.url(),
        }
    }
}

/// Spawn a background task that acquires a Let's Encrypt certificate for
/// `domain` via HTTP-01. The challenge response is published via signal on
/// its :80 listener; the final cert is written locally and the TLS acceptor
/// cache is invalidated so the next inbound request picks it up.
pub fn spawn_issuance(
    domain: String,
    signal_conn: quinn::Connection,
    email: Option<String>,
    directory: Directory,
) {
    tokio::spawn(async move {
        match issue(&domain, &signal_conn, email.as_deref(), directory).await {
            Ok(()) => {
                ingress::reload_cert(&domain);
                info!(%domain, "ACME certificate installed");
            }
            Err(e) => warn!(%domain, "ACME issuance failed: {:#}", e),
        }
    });
}

pub async fn issue(
    domain: &str,
    signal_conn: &quinn::Connection,
    email: Option<&str>,
    directory: Directory,
) -> Result<()> {
    let account = load_or_create_account(email, &directory).await?;

    info!(%domain, "Starting ACME order (HTTP-01)");
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("Failed to create ACME order")?;

    // Walk authorizations (one per identifier) and publish the HTTP-01
    // challenge response via signal.
    let mut published: Vec<(String, String)> = Vec::new(); // (domain, token)
    {
        let mut auths = order.authorizations();
        while let Some(auth) = auths.next().await {
            let mut auth = auth.context("Authorization fetch failed")?;
            let mut challenge = auth
                .challenge(ChallengeType::Http01)
                .context("No HTTP-01 challenge offered for this identifier")?;
            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization().as_str().to_string();

            info!(%domain, %token, "Publishing HTTP-01 challenge via signal");
            publish_challenge(signal_conn, domain, &token, &key_auth).await?;
            published.push((domain.to_string(), token));

            challenge
                .set_ready()
                .await
                .context("Failed to mark ACME challenge ready")?;
        }
    }

    let retry = RetryPolicy::new();
    let status = order
        .poll_ready(&retry)
        .await
        .context("ACME order polling failed")?;
    if status != OrderStatus::Ready {
        // Surface the real error from LE when available so debugging doesn't
        // involve guessing.
        let mut reasons: Vec<String> = Vec::new();
        if let Some(err) = order.state().error.as_ref() {
            reasons.push(format!("order: {err:?}"));
        }
        let mut auths = order.authorizations();
        while let Some(auth) = auths.next().await {
            if let Ok(mut auth) = auth {
                if let Ok(state) = auth.refresh().await {
                    for ch in &state.challenges {
                        if ch.status == instant_acme::ChallengeStatus::Invalid {
                            if let Some(err) = ch.error.as_ref() {
                                reasons.push(format!("{:?}: {:?}", ch.r#type, err));
                            }
                        }
                    }
                }
            }
        }
        let detail = if reasons.is_empty() {
            "no detail provided by ACME server".to_string()
        } else {
            reasons.join("; ")
        };
        anyhow::bail!("ACME order not Ready ({:?}): {}", status, detail);
    }

    // Finalize: instant-acme generates a CSR and returns the PEM-encoded key.
    let key_pem = order.finalize().await.context("ACME finalize failed")?;
    let cert_pem = order
        .poll_certificate(&retry)
        .await
        .context("ACME certificate polling failed")?;

    // Persist cert + key atomically under /var/lib/mlsh/ingress/certs/.
    let dir = PathBuf::from(CERT_DIR);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create cert dir {}", dir.display()))?;
    write_restricted(&dir.join(format!("{}.crt", domain)), &cert_pem, 0o644)?;
    write_restricted(&dir.join(format!("{}.key", domain)), &key_pem, 0o600)?;

    // Clear the HTTP-01 challenge responses.
    for (d, token) in published {
        if let Err(e) = clear_challenge(signal_conn, &d, &token).await {
            debug!(%d, %token, "Failed to clear HTTP-01 (non-fatal): {}", e);
        }
    }

    Ok(())
}

async fn load_or_create_account(email: Option<&str>, directory: &Directory) -> Result<Account> {
    std::fs::create_dir_all(ACME_DIR)
        .with_context(|| format!("Failed to create ACME dir {}", ACME_DIR))?;
    let creds_path = PathBuf::from(ACME_DIR).join("account.json");

    if creds_path.exists() {
        let bytes = std::fs::read(&creds_path)
            .with_context(|| format!("Failed to read {}", creds_path.display()))?;
        let creds: AccountCredentials =
            serde_json::from_slice(&bytes).context("Invalid ACME account credentials JSON")?;
        let account = Account::builder()
            .context("Failed to init ACME account builder")?
            .from_credentials(creds)
            .await
            .context("Failed to restore ACME account from credentials")?;
        return Ok(account);
    }

    let contact = email.map(|e| format!("mailto:{}", e));
    let contacts: Vec<&str> = contact.as_deref().into_iter().collect();
    let new_account = NewAccount {
        contact: &contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, creds) = Account::builder()
        .context("Failed to init ACME account builder")?
        .create(&new_account, directory.url().to_string(), None)
        .await
        .context("Failed to create ACME account")?;

    let json = serde_json::to_vec(&creds).context("Serialize ACME credentials")?;
    write_restricted_bytes(&creds_path, &json, 0o600)?;
    info!(path = %creds_path.display(), "Created new ACME account");

    Ok(account)
}

async fn publish_challenge(
    conn: &quinn::Connection,
    domain: &str,
    token: &str,
    key_auth: &str,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::HttpChallengeSet {
        domain: domain.to_string(),
        token: token.to_string(),
        key_auth: key_auth.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;
    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    let _ = send.finish();
    match resp {
        ServerMessage::HttpChallengeOk { .. } => Ok(()),
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected signal response: {:?}", other),
    }
}

async fn clear_challenge(conn: &quinn::Connection, domain: &str, token: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::HttpChallengeClear {
        domain: domain.to_string(),
        token: token.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;
    let _resp: ServerMessage = framing::read_msg(&mut recv).await?;
    let _ = send.finish();
    Ok(())
}

fn write_restricted(path: &Path, content: &str, mode: u32) -> Result<()> {
    write_restricted_bytes(path, content.as_bytes(), mode)
}

fn write_restricted_bytes(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".tmp_{}", std::process::id()));
    let mut f = {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(mode);
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
        }
        o.open(&tmp)?
    };
    f.write_all(content)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}
