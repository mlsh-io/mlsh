//! HMAC-based invite tokens and node authentication tokens.
//!
//! Invite tokens are generated offline by the CLI using the cluster secret.
//! They encode an expiration timestamp and can be verified by signal without
//! any stored state — signal just recomputes the HMAC.
//!
//! Node tokens are issued by signal at onboarding and used for reconnection.
//! They are derived from a signing key that is independent of the cluster secret,
//! so rotating the cluster secret does not invalidate existing node tokens.

use base64::Engine;
use ring::hmac;
use ring::signature::{self, Ed25519KeyPair};

const INVITE_DOMAIN: &[u8] = b"mlsh-invite-v1";
const NODE_TOKEN_DOMAIN: &[u8] = b"mlsh-node-token-v1";

/// Generate an invite token for a cluster.
///
/// The token is `HMAC-SHA256(cluster_secret, domain || expires_at)`, base64url-encoded.
/// `expires_at` is a Unix timestamp (seconds).
///
/// Returns `(token, expires_at)`.
pub fn generate_invite(cluster_secret: &str, ttl_seconds: u64) -> (String, u64) {
    let expires_at = now_secs() + ttl_seconds;
    let token = compute_invite_hmac(cluster_secret, expires_at);
    (token, expires_at)
}

/// Verify an invite token.
///
/// Returns `true` if the HMAC matches and the token has not expired.
pub fn verify_invite(cluster_secret: &str, token: &str, expires_at: u64) -> bool {
    if now_secs() > expires_at {
        return false;
    }
    let expected = compute_invite_hmac(cluster_secret, expires_at);
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

/// Generate a node token for reconnection.
///
/// `signing_key` is signal's internal key (independent of cluster_secret).
/// The token is `HMAC-SHA256(signing_key, domain || cluster_id || node_id)`, base64url-encoded.
pub fn generate_node_token(signing_key: &str, cluster_id: &str, node_id: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key.as_bytes());
    let mut msg =
        Vec::with_capacity(NODE_TOKEN_DOMAIN.len() + cluster_id.len() + node_id.len() + 2);
    msg.extend_from_slice(NODE_TOKEN_DOMAIN);
    msg.push(0x00); // separator
    msg.extend_from_slice(cluster_id.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(node_id.as_bytes());

    let tag = hmac::sign(&key, &msg);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag.as_ref())
}

/// Verify a node token.
pub fn verify_node_token(signing_key: &str, cluster_id: &str, node_id: &str, token: &str) -> bool {
    let expected = generate_node_token(signing_key, cluster_id, node_id);
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

fn compute_invite_hmac(cluster_secret: &str, expires_at: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, cluster_secret.as_bytes());
    let mut msg = Vec::with_capacity(INVITE_DOMAIN.len() + 9);
    msg.extend_from_slice(INVITE_DOMAIN);
    msg.push(0x00);
    msg.extend_from_slice(&expires_at.to_be_bytes());

    let tag = hmac::sign(&key, &msg);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tag.as_ref())
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

// --- Ed25519 sponsor-signed invites

/// An invite payload to be signed by the sponsor.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct InvitePayload {
    pub cluster_id: String,
    pub sponsor_node_id: String,
    pub target_role: String,
    pub expires_at: u64,
    pub nonce: String,
    /// Signal server TLS certificate fingerprint (for QUIC verification by the adopting node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_fingerprint: Option<String>,
}

/// A complete signed invite (payload + signature).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SignedInvite {
    pub payload: InvitePayload,
    pub signature: String, // base64url-encoded Ed25519 signature
}

/// Generate a sponsor-signed invite.
///
/// The sponsor signs the payload with their Ed25519 private key.
/// `key_pem` is the sponsor's private key in PEM format.
pub fn generate_signed_invite(
    key_pem: &str,
    cluster_id: &str,
    sponsor_node_id: &str,
    target_role: &str,
    ttl_seconds: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    generate_signed_invite_with_fingerprint(
        key_pem,
        cluster_id,
        sponsor_node_id,
        target_role,
        ttl_seconds,
        None,
    )
}

/// Generate a sponsor-signed invite with an optional signal fingerprint.
pub fn generate_signed_invite_with_fingerprint(
    key_pem: &str,
    cluster_id: &str,
    sponsor_node_id: &str,
    target_role: &str,
    ttl_seconds: u64,
    signal_fingerprint: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let keypair = load_ed25519_from_pem(key_pem)?;

    let expires_at = now_secs() + ttl_seconds;

    // Random nonce to prevent replay
    let mut nonce_bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce_bytes)
        .map_err(|_| "Failed to generate nonce")?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);

    let payload = InvitePayload {
        cluster_id: cluster_id.to_string(),
        sponsor_node_id: sponsor_node_id.to_string(),
        target_role: target_role.to_string(),
        expires_at,
        nonce,
        signal_fingerprint: signal_fingerprint.map(String::from),
    };

    // Serialize payload to canonical JSON for signing
    let payload_json = serde_json::to_vec(&payload)?;
    let sig = keypair.sign(&payload_json);
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref());

    let signed = SignedInvite { payload, signature };
    let signed_json = serde_json::to_vec(&signed)?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signed_json);

    Ok(encoded)
}

/// Verify a sponsor-signed invite.
///
/// `invite_b64` is the base64url-encoded signed invite.
/// `public_key_der` is the sponsor's Ed25519 public key in raw format (32 bytes).
///
/// Returns the payload if valid and not expired, or an error.
pub fn verify_signed_invite(
    invite_b64: &str,
    public_key_bytes: &[u8],
) -> Result<InvitePayload, Box<dyn std::error::Error>> {
    let invite_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(invite_b64)
        .map_err(|_| "Invalid base64 encoding")?;

    let signed: SignedInvite =
        serde_json::from_slice(&invite_json).map_err(|_| "Invalid invite JSON")?;

    // Check expiry
    if now_secs() > signed.payload.expires_at {
        return Err("Invite expired".into());
    }

    // Verify signature
    let payload_json = serde_json::to_vec(&signed.payload)?;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signed.signature)
        .map_err(|_| "Invalid signature encoding")?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    public_key
        .verify(&payload_json, &sig_bytes)
        .map_err(|_| "Invalid signature")?;

    Ok(signed.payload)
}

/// Load an Ed25519 keypair from a PEM-encoded private key.
fn load_ed25519_from_pem(pem: &str) -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    let pem = pem.trim();
    let der_b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .map_err(|_| "Invalid PEM base64")?;

    // Try PKCS8 first
    if let Ok(kp) = Ed25519KeyPair::from_pkcs8(&der) {
        return Ok(kp);
    }

    // Try raw seed (32 bytes) wrapped in PKCS8
    if der.len() == 32 {
        if let Ok(kp) = Ed25519KeyPair::from_seed_unchecked(&der) {
            return Ok(kp);
        }
    }

    Err("Failed to parse Ed25519 private key from PEM".into())
}

/// Extract the raw Ed25519 public key bytes from a PEM certificate.
///
/// This reads the DER cert, finds the Ed25519 public key (32 bytes),
/// and returns it for use with `verify_signed_invite`.
pub fn extract_public_key_from_cert_pem(
    cert_pem: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pem = cert_pem.trim();
    let der_b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .map_err(|_| "Invalid cert PEM")?;

    // Ed25519 public key in X.509 cert is at a fixed offset.
    // The OID for Ed25519 is 1.3.101.112 = 06 03 2b 65 70
    // After the OID, there's a BIT STRING containing the 32-byte key.
    let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
    if let Some(pos) = der.windows(oid.len()).position(|w| w == oid) {
        // After OID: skip to BIT STRING (03 21 00 <32 bytes>)
        let after_oid = pos + oid.len();
        for i in after_oid..der.len().saturating_sub(33) {
            if der[i] == 0x03 && der[i + 1] == 0x21 && der[i + 2] == 0x00 {
                return Ok(der[i + 3..i + 35].to_vec());
            }
        }
    }

    Err("Ed25519 public key not found in certificate".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let secret = "my-cluster-secret";
        let (token, expires_at) = generate_invite(secret, 3600);
        assert!(verify_invite(secret, &token, expires_at));
    }

    #[test]
    fn invite_wrong_secret_fails() {
        let (token, expires_at) = generate_invite("correct-secret", 3600);
        assert!(!verify_invite("wrong-secret", &token, expires_at));
    }

    #[test]
    fn invite_expired_fails() {
        let secret = "my-secret";
        let expires_at = now_secs() - 1; // already expired
        let token = compute_invite_hmac(secret, expires_at);
        assert!(!verify_invite(secret, &token, expires_at));
    }

    #[test]
    fn invite_tampered_expiry_fails() {
        let secret = "my-secret";
        let (token, expires_at) = generate_invite(secret, 3600);
        // Attacker tries to extend expiry
        assert!(!verify_invite(secret, &token, expires_at + 7200));
    }

    #[test]
    fn node_token_roundtrip() {
        let signing_key = "signal-signing-key-abc";
        let token = generate_node_token(signing_key, "cluster-1", "node-a");
        assert!(verify_node_token(
            signing_key,
            "cluster-1",
            "node-a",
            &token
        ));
    }

    #[test]
    fn node_token_wrong_key_fails() {
        let token = generate_node_token("key-a", "cluster-1", "node-a");
        assert!(!verify_node_token("key-b", "cluster-1", "node-a", &token));
    }

    #[test]
    fn node_token_wrong_node_fails() {
        let key = "signing-key";
        let token = generate_node_token(key, "cluster-1", "node-a");
        assert!(!verify_node_token(key, "cluster-1", "node-b", &token));
    }

    #[test]
    fn node_token_wrong_cluster_fails() {
        let key = "signing-key";
        let token = generate_node_token(key, "cluster-1", "node-a");
        assert!(!verify_node_token(key, "cluster-2", "node-a", &token));
    }

    #[test]
    fn different_invites_differ() {
        let (t1, _) = generate_invite("secret", 3600);
        let (t2, _) = generate_invite("secret", 7200);
        assert_ne!(t1, t2);
    }

    #[test]
    fn signed_invite_roundtrip() {
        let id = crate::identity::generate_identity("sponsor").unwrap();
        let invite =
            generate_signed_invite(&id.key_pem, "test-cluster", "sponsor", "node", 3600).unwrap();

        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();
        let payload = verify_signed_invite(&invite, &pubkey).unwrap();
        assert_eq!(payload.cluster_id, "test-cluster");
        assert_eq!(payload.sponsor_node_id, "sponsor");
        assert_eq!(payload.target_role, "node");
    }

    #[test]
    fn signed_invite_wrong_key_fails() {
        let sponsor = crate::identity::generate_identity("sponsor").unwrap();
        let other = crate::identity::generate_identity("other").unwrap();

        let invite =
            generate_signed_invite(&sponsor.key_pem, "cluster", "sponsor", "node", 3600).unwrap();

        let other_pubkey = extract_public_key_from_cert_pem(&other.cert_pem).unwrap();
        assert!(verify_signed_invite(&invite, &other_pubkey).is_err());
    }

    #[test]
    fn signed_invite_tampered_fails() {
        let id = crate::identity::generate_identity("sponsor").unwrap();
        let mut invite =
            generate_signed_invite(&id.key_pem, "cluster", "sponsor", "node", 3600).unwrap();

        // Tamper with the payload
        invite.push('X');

        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();
        assert!(verify_signed_invite(&invite, &pubkey).is_err());
    }

    #[test]
    fn extract_pubkey_from_cert() {
        let id = crate::identity::generate_identity("test").unwrap();
        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();
        assert_eq!(pubkey.len(), 32); // Ed25519 public key is 32 bytes
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
