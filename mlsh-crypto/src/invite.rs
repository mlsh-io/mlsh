//! HMAC-based invite tokens and Ed25519-signed sponsor invites.
//!
//! Invite tokens are generated offline by the CLI using the cluster secret.
//! They encode an expiration timestamp and can be verified by signal without
//! any stored state — signal just recomputes the HMAC.
//!
//! Node authentication uses mTLS — the node's Ed25519 certificate is presented
//! during the QUIC handshake and verified by fingerprint lookup. No shared
//! secret or token is needed for reconnection.

use base64::Engine;
use ring::hmac;
use ring::signature::{self, Ed25519KeyPair};

const INVITE_DOMAIN: &[u8] = b"mlsh-invite-v1";

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
    /// Root admin certificate fingerprint (for peer-side verification of admission certs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_fingerprint: Option<String>,
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
        None,
    )
}

/// Generate a sponsor-signed invite with optional signal and root fingerprints.
pub fn generate_signed_invite_with_fingerprint(
    key_pem: &str,
    cluster_id: &str,
    sponsor_node_id: &str,
    target_role: &str,
    ttl_seconds: u64,
    signal_fingerprint: Option<&str>,
    root_fingerprint: Option<&str>,
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
        root_fingerprint: root_fingerprint.map(String::from),
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

// --- Admission certificates
//
// An admission certificate is a proof of cluster membership carried by every node.
// Peers verify admission certs locally — a node injected into signal's DB without
// a valid cert is rejected by every peer.
//
// Two kinds:
// - Root admin: self-signed (sponsor_node_id == node_id), verified against
//   the root_fingerprint pinned in each node's local config.
// - Sponsored node: the original signed invite serves as proof. Peers verify
//   the invite signature against the sponsor's public key.

/// An admission certificate proving cluster membership.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdmissionCert {
    pub node_id: String,
    pub fingerprint: String,
    pub cluster_id: String,
    pub role: String,
    pub sponsor_node_id: String,
    pub issued_at: u64,
    /// Self-signed: Ed25519 signature over the cert fields (base64url).
    /// Sponsored: the original base64url signed invite token.
    pub proof: String,
}

/// Generate a self-signed admission cert for the root admin.
///
/// The root admin signs its own admission cert at setup time.
/// Peers verify it by checking that the fingerprint matches their locally
/// pinned `root_fingerprint`.
pub fn generate_self_signed_admission_cert(
    key_pem: &str,
    node_id: &str,
    fingerprint: &str,
    cluster_id: &str,
) -> Result<AdmissionCert, Box<dyn std::error::Error>> {
    let keypair = load_ed25519_from_pem(key_pem)?;
    let issued_at = now_secs();

    let cert = AdmissionCert {
        node_id: node_id.to_string(),
        fingerprint: fingerprint.to_string(),
        cluster_id: cluster_id.to_string(),
        role: "admin".to_string(),
        sponsor_node_id: node_id.to_string(), // self-signed
        issued_at,
        proof: String::new(), // placeholder, filled below
    };

    let payload = admission_cert_signing_payload(&cert);
    let sig = keypair.sign(&payload);
    let proof = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref());

    Ok(AdmissionCert { proof, ..cert })
}

/// Build an admission cert for a sponsored node.
///
/// The proof is the original signed invite token — peers can verify it
/// against the sponsor's public key to confirm an admin authorized the join.
pub fn build_sponsored_admission_cert(
    node_id: &str,
    fingerprint: &str,
    cluster_id: &str,
    role: &str,
    sponsor_node_id: &str,
    invite_token: &str,
) -> AdmissionCert {
    AdmissionCert {
        node_id: node_id.to_string(),
        fingerprint: fingerprint.to_string(),
        cluster_id: cluster_id.to_string(),
        role: role.to_string(),
        sponsor_node_id: sponsor_node_id.to_string(),
        issued_at: now_secs(),
        proof: invite_token.to_string(),
    }
}

/// Verify a self-signed admission cert (root admin).
///
/// `public_key_bytes` is the root admin's Ed25519 public key (32 bytes).
/// Also checks that the fingerprint matches the expected root fingerprint.
pub fn verify_self_signed_admission_cert(
    cert: &AdmissionCert,
    public_key_bytes: &[u8],
    expected_root_fingerprint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if cert.sponsor_node_id != cert.node_id {
        return Err("Not a self-signed cert".into());
    }
    if cert.fingerprint != expected_root_fingerprint {
        return Err("Fingerprint does not match root_fingerprint".into());
    }

    let payload = admission_cert_signing_payload(cert);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&cert.proof)
        .map_err(|_| "Invalid proof encoding")?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    public_key
        .verify(&payload, &sig_bytes)
        .map_err(|_| "Invalid self-signed admission cert signature")?;

    Ok(())
}

/// Verify a sponsored admission cert.
///
/// Decodes the invite from the proof field and verifies the Ed25519 signature
/// against the sponsor's public key. Also checks cluster_id and role match.
pub fn verify_sponsored_admission_cert(
    cert: &AdmissionCert,
    sponsor_public_key_bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if cert.sponsor_node_id == cert.node_id {
        return Err("This is a self-signed cert, use verify_self_signed_admission_cert".into());
    }

    let payload = verify_signed_invite(&cert.proof, sponsor_public_key_bytes)?;

    if payload.cluster_id != cert.cluster_id {
        return Err("Invite cluster_id does not match admission cert".into());
    }
    if payload.target_role != cert.role {
        return Err("Invite role does not match admission cert".into());
    }

    Ok(())
}

/// Canonical byte payload for self-signed admission cert signatures.
fn admission_cert_signing_payload(cert: &AdmissionCert) -> Vec<u8> {
    // domain || node_id || fingerprint || cluster_id || role || sponsor || issued_at
    let mut buf = Vec::new();
    buf.extend_from_slice(b"mlsh-admission-v1\x00");
    buf.extend_from_slice(cert.node_id.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(cert.fingerprint.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(cert.cluster_id.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(cert.role.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(cert.sponsor_node_id.as_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&cert.issued_at.to_be_bytes());
    buf
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

    #[test]
    fn self_signed_admission_cert_roundtrip() {
        let id = crate::identity::generate_identity("root-admin").unwrap();
        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();

        let cert = generate_self_signed_admission_cert(
            &id.key_pem,
            "root-admin",
            &id.fingerprint,
            "test-cluster",
        )
        .unwrap();

        assert_eq!(cert.sponsor_node_id, cert.node_id);
        assert!(verify_self_signed_admission_cert(&cert, &pubkey, &id.fingerprint).is_ok());
    }

    #[test]
    fn self_signed_admission_cert_wrong_root_fingerprint_fails() {
        let id = crate::identity::generate_identity("root-admin").unwrap();
        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();

        let cert = generate_self_signed_admission_cert(
            &id.key_pem,
            "root-admin",
            &id.fingerprint,
            "test-cluster",
        )
        .unwrap();

        assert!(verify_self_signed_admission_cert(&cert, &pubkey, "wrong-fingerprint").is_err());
    }

    #[test]
    fn self_signed_admission_cert_wrong_key_fails() {
        let admin = crate::identity::generate_identity("root-admin").unwrap();
        let other = crate::identity::generate_identity("attacker").unwrap();
        let other_pubkey = extract_public_key_from_cert_pem(&other.cert_pem).unwrap();

        let cert = generate_self_signed_admission_cert(
            &admin.key_pem,
            "root-admin",
            &admin.fingerprint,
            "test-cluster",
        )
        .unwrap();

        assert!(
            verify_self_signed_admission_cert(&cert, &other_pubkey, &admin.fingerprint).is_err()
        );
    }

    #[test]
    fn sponsored_admission_cert_roundtrip() {
        let sponsor = crate::identity::generate_identity("sponsor").unwrap();
        let sponsor_pubkey = extract_public_key_from_cert_pem(&sponsor.cert_pem).unwrap();

        let invite = generate_signed_invite(
            &sponsor.key_pem,
            "test-cluster",
            "sponsor",
            "node",
            3600,
        )
        .unwrap();

        let cert = build_sponsored_admission_cert(
            "new-node",
            "new-node-fp",
            "test-cluster",
            "node",
            "sponsor",
            &invite,
        );

        assert!(verify_sponsored_admission_cert(&cert, &sponsor_pubkey).is_ok());
    }

    #[test]
    fn sponsored_admission_cert_wrong_sponsor_key_fails() {
        let sponsor = crate::identity::generate_identity("sponsor").unwrap();
        let attacker = crate::identity::generate_identity("attacker").unwrap();
        let attacker_pubkey = extract_public_key_from_cert_pem(&attacker.cert_pem).unwrap();

        let invite = generate_signed_invite(
            &sponsor.key_pem,
            "test-cluster",
            "sponsor",
            "node",
            3600,
        )
        .unwrap();

        let cert = build_sponsored_admission_cert(
            "new-node",
            "new-node-fp",
            "test-cluster",
            "node",
            "sponsor",
            &invite,
        );

        assert!(verify_sponsored_admission_cert(&cert, &attacker_pubkey).is_err());
    }
}
