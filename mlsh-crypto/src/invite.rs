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
    pub cluster_name: String,
    pub sponsor_node_uuid: String,
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

/// Compact CBOR representation of an invite payload.
/// Fingerprints are raw 32-byte arrays instead of 64-char hex strings.
/// Nonce is raw 16 bytes instead of base64url.
/// Field names use short integer keys via tuple struct.
#[derive(serde::Serialize, serde::Deserialize)]
struct CompactPayload(
    String,                                 // 0: cluster_id
    String,                                 // 1: cluster_name
    String,                                 // 2: sponsor_node_uuid
    String,                                 // 3: target_role
    u64,                                    // 4: expires_at
    #[serde(with = "serde_bytes")] Vec<u8>, // 5: nonce (raw 16 bytes)
    #[serde(with = "serde_bytes")] Vec<u8>, // 6: signal_fingerprint (raw 32 bytes, empty if absent)
    #[serde(with = "serde_bytes")] Vec<u8>, // 7: root_fingerprint (raw 32 bytes, empty if absent)
);

impl CompactPayload {
    fn from_invite(p: &InvitePayload) -> Result<Self, Box<dyn std::error::Error>> {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&p.nonce)
            .unwrap_or_else(|_| p.nonce.as_bytes().to_vec());
        let sig_fp = p
            .signal_fingerprint
            .as_deref()
            .map(|h| hex::decode(h).unwrap_or_default())
            .unwrap_or_default();
        let root_fp = p
            .root_fingerprint
            .as_deref()
            .map(|h| hex::decode(h).unwrap_or_default())
            .unwrap_or_default();
        Ok(Self(
            p.cluster_id.clone(),
            p.cluster_name.clone(),
            p.sponsor_node_uuid.clone(),
            p.target_role.clone(),
            p.expires_at,
            nonce,
            sig_fp,
            root_fp,
        ))
    }

    fn to_invite(&self) -> InvitePayload {
        InvitePayload {
            cluster_id: self.0.clone(),
            cluster_name: self.1.clone(),
            sponsor_node_uuid: self.2.clone(),
            target_role: self.3.clone(),
            expires_at: self.4,
            nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.5),
            signal_fingerprint: if self.6.is_empty() {
                None
            } else {
                Some(hex::encode(&self.6))
            },
            root_fingerprint: if self.7.is_empty() {
                None
            } else {
                Some(hex::encode(&self.7))
            },
        }
    }
}

/// Parameters for generating a signed invite.
pub struct InviteParams<'a> {
    pub key_pem: &'a str,
    pub cluster_id: &'a str,
    pub cluster_name: &'a str,
    pub sponsor_node_uuid: &'a str,
    pub target_role: &'a str,
    pub ttl_seconds: u64,
    pub signal_fingerprint: Option<&'a str>,
    pub root_fingerprint: Option<&'a str>,
}

/// Generate a sponsor-signed invite.
///
/// The sponsor signs the payload with their Ed25519 private key.
pub fn generate_signed_invite(
    key_pem: &str,
    cluster_id: &str,
    cluster_name: &str,
    sponsor_node_uuid: &str,
    target_role: &str,
    ttl_seconds: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    generate_signed_invite_full(&InviteParams {
        key_pem,
        cluster_id,
        cluster_name,
        sponsor_node_uuid,
        target_role,
        ttl_seconds,
        signal_fingerprint: None,
        root_fingerprint: None,
    })
}

/// Generate a sponsor-signed invite with full parameters.
pub fn generate_signed_invite_full(
    params: &InviteParams<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let keypair = load_ed25519_from_pem(params.key_pem)?;

    let expires_at = now_secs() + params.ttl_seconds;

    // Random nonce to prevent replay
    let mut nonce_bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce_bytes)
        .map_err(|_| "Failed to generate nonce")?;

    let payload = InvitePayload {
        cluster_id: params.cluster_id.to_string(),
        cluster_name: params.cluster_name.to_string(),
        sponsor_node_uuid: params.sponsor_node_uuid.to_string(),
        target_role: params.target_role.to_string(),
        expires_at,
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes),
        signal_fingerprint: params.signal_fingerprint.map(String::from),
        root_fingerprint: params.root_fingerprint.map(String::from),
    };

    // Encode compact CBOR (raw bytes for fingerprints and nonce)
    let compact = CompactPayload::from_invite(&payload)?;
    let payload_cbor = {
        let mut buf = Vec::new();
        ciborium::into_writer(&compact, &mut buf)
            .map_err(|e| format!("CBOR encode failed: {}", e))?;
        buf
    };

    let sig = keypair.sign(&payload_cbor);

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(
        &ciborium::value::Value::Array(vec![
            ciborium::value::Value::Bytes(payload_cbor),
            ciborium::value::Value::Bytes(sig.as_ref().to_vec()),
        ]),
        &mut cbor_buf,
    )
    .map_err(|e| format!("CBOR encode failed: {}", e))?;

    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor_buf);

    Ok(encoded)
}

/// Verify a sponsor-signed invite (checks expiry).
///
/// `invite_b64` is the base64url-encoded signed invite.
/// `public_key_der` is the sponsor's Ed25519 public key in raw format (32 bytes).
///
/// Returns the payload if valid and not expired, or an error.
pub fn verify_signed_invite(
    invite_b64: &str,
    public_key_bytes: &[u8],
) -> Result<InvitePayload, Box<dyn std::error::Error>> {
    let payload = verify_signed_invite_signature(invite_b64, public_key_bytes)?;

    if now_secs() > payload.expires_at {
        return Err("Invite expired".into());
    }

    Ok(payload)
}

/// Decode an invite payload without verifying the signature.
///
/// Used when you need to extract fields (e.g., sponsor_node_uuid) before you have
/// the public key to verify. Always call verify after obtaining the key.
pub fn decode_invite_payload(
    invite_b64: &str,
) -> Result<InvitePayload, Box<dyn std::error::Error>> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(invite_b64)
        .map_err(|_| "Invalid base64 encoding")?;

    let value: ciborium::value::Value =
        ciborium::from_reader(&raw[..]).map_err(|_| "Invalid CBOR encoding")?;
    let arr = value.as_array().ok_or("Expected CBOR array")?;
    let payload_cbor = arr
        .first()
        .and_then(|v| v.as_bytes())
        .ok_or("Expected payload bytes")?;

    let compact: CompactPayload =
        ciborium::from_reader(&payload_cbor[..]).map_err(|_| "Invalid payload CBOR")?;
    let payload = compact.to_invite();

    Ok(payload)
}

/// Verify a sponsor-signed invite signature only (no expiry check).
///
/// Used for admission cert verification — the invite was valid at admission time,
/// so expiry is irrelevant for ongoing membership proof.
pub fn verify_signed_invite_signature(
    invite_b64: &str,
    public_key_bytes: &[u8],
) -> Result<InvitePayload, Box<dyn std::error::Error>> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(invite_b64)
        .map_err(|_| "Invalid base64 encoding")?;

    // CBOR format: [payload_cbor_bytes, signature_bytes]
    let value: ciborium::value::Value =
        ciborium::from_reader(&raw[..]).map_err(|_| "Invalid CBOR encoding")?;
    let arr = value.as_array().ok_or("Expected CBOR array")?;
    if arr.len() < 2 {
        return Err("CBOR array too short".into());
    }
    let payload_cbor = arr[0].as_bytes().ok_or("Expected bytes for payload")?;
    let sig_bytes = arr[1].as_bytes().ok_or("Expected bytes for signature")?;

    let compact: CompactPayload =
        ciborium::from_reader(&payload_cbor[..]).map_err(|_| "Invalid payload CBOR")?;

    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    public_key
        .verify(payload_cbor, sig_bytes)
        .map_err(|_| "Invalid signature")?;

    Ok(compact.to_invite())
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
// - Root admin: self-signed (sponsor_node_uuid == node_id), verified against
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
    pub sponsor_node_uuid: String,
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
        sponsor_node_uuid: node_id.to_string(), // self-signed
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
    sponsor_node_uuid: &str,
    invite_token: &str,
) -> AdmissionCert {
    AdmissionCert {
        node_id: node_id.to_string(),
        fingerprint: fingerprint.to_string(),
        cluster_id: cluster_id.to_string(),
        role: role.to_string(),
        sponsor_node_uuid: sponsor_node_uuid.to_string(),
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
    if cert.sponsor_node_uuid != cert.node_id {
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
    if cert.sponsor_node_uuid == cert.node_id {
        return Err("This is a self-signed cert, use verify_self_signed_admission_cert".into());
    }

    let payload = verify_signed_invite_signature(&cert.proof, sponsor_public_key_bytes)?;

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
    // domain || node_id || fingerprint || cluster_id || role || sponsor_node_uuid || issued_at
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
    buf.extend_from_slice(cert.sponsor_node_uuid.as_bytes());
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
            generate_signed_invite(&id.key_pem, "test-cluster", "test", "sponsor", "node", 3600)
                .unwrap();

        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();
        let payload = verify_signed_invite(&invite, &pubkey).unwrap();
        assert_eq!(payload.cluster_id, "test-cluster");
        assert_eq!(payload.sponsor_node_uuid, "sponsor");
        assert_eq!(payload.target_role, "node");
    }

    #[test]
    fn signed_invite_size_with_fingerprints() {
        let id = crate::identity::generate_identity("sponsor").unwrap();
        let invite = generate_signed_invite_full(&InviteParams {
            key_pem: &id.key_pem,
            cluster_id: "550e8400-e29b-41d4-a716-446655440000",
            cluster_name: "homelab",
            sponsor_node_uuid: "nicolas-macbook",
            target_role: "node",
            ttl_seconds: 3600,
            signal_fingerprint: Some(
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            ),
            root_fingerprint: Some(
                "f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5",
            ),
        })
        .unwrap();

        let url = format!("mlsh://signal.mlsh.io/adopt/{}", invite);
        eprintln!("CBOR invite base64url: {} chars", invite.len());
        eprintln!("Full URL: {} chars", url.len());

        // Verify it still works
        let pubkey = extract_public_key_from_cert_pem(&id.cert_pem).unwrap();
        let payload = verify_signed_invite(&invite, &pubkey).unwrap();
        assert_eq!(payload.cluster_name, "homelab");
    }

    #[test]
    fn signed_invite_wrong_key_fails() {
        let sponsor = crate::identity::generate_identity("sponsor").unwrap();
        let other = crate::identity::generate_identity("other").unwrap();

        let invite =
            generate_signed_invite(&sponsor.key_pem, "cluster", "test", "sponsor", "node", 3600)
                .unwrap();

        let other_pubkey = extract_public_key_from_cert_pem(&other.cert_pem).unwrap();
        assert!(verify_signed_invite(&invite, &other_pubkey).is_err());
    }

    #[test]
    fn signed_invite_tampered_fails() {
        let id = crate::identity::generate_identity("sponsor").unwrap();
        let mut invite =
            generate_signed_invite(&id.key_pem, "cluster", "test", "sponsor", "node", 3600)
                .unwrap();

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

        assert_eq!(cert.sponsor_node_uuid, cert.node_id);
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
            "test",
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
            "test",
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
