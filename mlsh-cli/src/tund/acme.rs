//! ACME client for ingress domains — TLS-ALPN-01 (RFC 8737).
//!
//! TLS-ALPN-01 beats HTTP-01 for this project: we already have a public :443
//! path (the outer SNI proxy forwards `*.mlsh.io` to signal), so no extra
//! port needs to be open. Signal's ingress listener detects the
//! `acme-tls/1` ALPN in the ClientHello and terminates TLS with the
//! challenge cert instead of relaying to the peer.
//!
//! Flow for one domain:
//! 1. Load or create a Let's Encrypt account, cached at
//!    `/var/lib/mlsh/ingress/acme/account.json`.
//! 2. Open a new order for the domain.
//! 3. Pick the TLS-ALPN-01 challenge, compute the SHA-256 of the key
//!    authorization, and generate a self-signed cert for the domain with
//!    the `id-pe-acmeIdentifier` critical X.509 extension (rcgen has a
//!    built-in helper for this).
//! 4. Send `(domain, cert_der, key_der)` to signal via
//!    `StreamMessage::TlsAlpnChallengeSet`.
//! 5. Tell the ACME server the challenge is ready, poll until Ready.
//! 6. Finalize with a CSR — the real service private key stays on the node.
//! 7. Poll for the final certificate chain.
//! 8. Write `cert.pem` and `key.pem` under `/var/lib/mlsh/ingress/certs/`
//!    (atomic, perms 0600 on the key).
//! 9. Send `TlsAlpnChallengeClear` to signal, invalidate the TLS acceptor cache.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
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
/// `domain` via TLS-ALPN-01. The challenge cert is published via signal; the
/// final cert is written locally and the TLS acceptor cache is invalidated
/// so the next inbound request picks it up.
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

    info!(%domain, "Starting ACME order (TLS-ALPN-01)");
    let identifiers = vec![Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .context("Failed to create ACME order")?;

    // Walk authorizations (one per identifier) and publish the TLS-ALPN-01
    // challenge cert via signal.
    let mut published: Vec<String> = Vec::new();
    {
        let mut auths = order.authorizations();
        while let Some(auth) = auths.next().await {
            let mut auth = auth.context("Authorization fetch failed")?;
            let mut challenge = auth
                .challenge(ChallengeType::TlsAlpn01)
                .context("No TLS-ALPN-01 challenge offered for this identifier")?;
            let digest = challenge.key_authorization().digest();
            let (cert_der, key_der) = build_challenge_cert(domain, digest.as_ref())?;

            info!(%domain, "Publishing TLS-ALPN-01 challenge via signal");
            publish_challenge(signal_conn, domain, cert_der, key_der).await?;
            published.push(domain.to_string());

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
        // Surface the real error from LE when available.
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

    // Finalize: instant-acme generates the CSR for the real service cert.
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

    // Clear the challenge certs.
    for d in published {
        if let Err(e) = clear_challenge(signal_conn, &d).await {
            debug!(%d, "Failed to clear TLS-ALPN-01 (non-fatal): {}", e);
        }
    }

    Ok(())
}

/// Build the self-signed challenge cert per RFC 8737: subject = `domain`,
/// with the critical `id-pe-acmeIdentifier` extension containing
/// SHA-256(key_authorization). Returns `(cert_der, key_der_pkcs8)`.
fn build_challenge_cert(domain: &str, sha256_digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .context("Failed to build challenge cert params")?;
    // Rcgen exposes a purpose-built helper for this exact extension —
    // marked critical, OID 1.3.6.1.5.5.7.1.31, value is a DER OCTET STRING
    // wrapping the 32-byte digest.
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(sha256_digest)];
    let key_pair = KeyPair::generate().context("Failed to generate challenge keypair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to sign challenge cert")?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
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
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::TlsAlpnChallengeSet {
        domain: domain.to_string(),
        cert_der,
        key_der,
    };
    framing::write_msg(&mut send, &msg).await?;
    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    let _ = send.finish();
    match resp {
        ServerMessage::TlsAlpnChallengeOk { .. } => Ok(()),
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected signal response: {:?}", other),
    }
}

async fn clear_challenge(conn: &quinn::Connection, domain: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    let msg = StreamMessage::TlsAlpnChallengeClear {
        domain: domain.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_challenge_cert_produces_valid_der() {
        let digest = [0x42u8; 32];
        let (cert_der, key_der) = build_challenge_cert("test.mlsh.io", &digest).unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
        // X.509 certs always start with SEQUENCE (0x30).
        assert_eq!(cert_der[0], 0x30);
        // PKCS#8 private keys start with SEQUENCE too.
        assert_eq!(key_der[0], 0x30);
    }
}
