//! ACME client for ingress domains.
//!
//! Uses `instant-acme` to obtain a Let's Encrypt certificate via the DNS-01
//! challenge, with mlsh-signal acting as our authoritative DNS for `mlsh.io`.
//!
//! Flow for one domain:
//! 1. Load or create a Let's Encrypt account, cached at
//!    `/var/lib/mlsh/ingress/acme/account.json`.
//! 2. Open a new order for the domain.
//! 3. For the DNS-01 challenge, compute the TXT value and send
//!    `StreamMessage::AcmeChallenge` to signal (which writes it into the
//!    authoritative DNS zone).
//! 4. Wait briefly for propagation, tell the ACME server the challenge is
//!    ready, and poll the order until it's `Ready`.
//! 5. Finalize with a CSR — we keep the private key on the node.
//! 6. Poll for the final certificate chain.
//! 7. Write `cert.pem` and `key.pem` under `/var/lib/mlsh/ingress/certs/`
//!    (atomic, perms 0600 on the key).
//! 8. Send `AcmeChallengeClear` to signal, invalidate the TLS acceptor cache.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use super::ingress;

const ACME_DIR: &str = "/var/lib/mlsh/ingress/acme";
const CERT_DIR: &str = "/var/lib/mlsh/ingress/certs";
const PROPAGATION_WAIT: Duration = Duration::from_secs(10);

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
/// `domain`, signing DNS-01 challenges via `signal_conn` and writing the
/// cert/key to `/var/lib/mlsh/ingress/certs/`. The TLS acceptor cache is
/// invalidated on success so the next inbound stream picks up the new cert.
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

/// Perform the full ACME order for one domain. Synchronous/async wrt. caller
/// but safe to spawn via [`spawn_issuance`].
pub async fn issue(
    domain: &str,
    signal_conn: &quinn::Connection,
    email: Option<&str>,
    directory: Directory,
) -> Result<()> {
    let account = load_or_create_account(email, &directory).await?;

    info!(%domain, "Starting ACME order");
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("Failed to create ACME order")?;

    // Walk authorizations (only one for a single-domain order) and publish
    // the DNS-01 TXT record via signal.
    let mut published: Vec<String> = Vec::new();
    {
        let mut auths = order.authorizations();
        while let Some(auth) = auths.next().await {
            let mut auth = auth.context("Authorization fetch failed")?;
            let mut challenge = auth
                .challenge(ChallengeType::Dns01)
                .context("No DNS-01 challenge offered for this identifier")?;
            let dns_name = format!("_acme-challenge.{}", domain);
            let dns_value = challenge.key_authorization().dns_value();

            info!(%dns_name, "Publishing ACME DNS-01 TXT via signal");
            publish_txt(signal_conn, &dns_name, &dns_value).await?;
            published.push(dns_name.clone());

            // Give signal's in-memory map + any caches a moment to settle.
            tokio::time::sleep(PROPAGATION_WAIT).await;

            challenge
                .set_ready()
                .await
                .context("Failed to mark ACME challenge ready")?;
        }
    }

    // Poll until the order is Ready (or Invalid, which errors out).
    let retry = RetryPolicy::new();
    let status = order
        .poll_ready(&retry)
        .await
        .context("ACME order polling failed")?;
    if status != OrderStatus::Ready {
        anyhow::bail!("ACME order not Ready: {:?}", status);
    }

    // Finalize: instant-acme generates a CSR and returns the PEM-encoded key.
    let key_pem = order
        .finalize()
        .await
        .context("ACME finalize failed")?;
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

    // Clear the DNS-01 TXT records from signal.
    for name in published {
        if let Err(e) = clear_txt(signal_conn, &name).await {
            debug!(%name, "Failed to clear ACME TXT (non-fatal): {}", e);
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

async fn publish_txt(conn: &quinn::Connection, name: &str, value: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::AcmeChallenge {
        domain: name.to_string(),
        value: value.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;
    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    let _ = send.finish();
    match resp {
        ServerMessage::AcmeChallengeOk { .. } => Ok(()),
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected signal response: {:?}", other),
    }
}

async fn clear_txt(conn: &quinn::Connection, name: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::AcmeChallengeClear {
        domain: name.to_string(),
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
    std::fs::rename(&tmp, path).with_context(|| {
        format!("Failed to rename {} to {}", tmp.display(), path.display())
    })?;
    Ok(())
}

// Unused import silencer (AsyncWriteExt is pulled for parity with other modules).
#[allow(dead_code)]
async fn _unused<T: AsyncWriteExt + Unpin>(_: T) {}
