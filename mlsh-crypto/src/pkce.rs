//! PKCE material for the OIDC join flow.

use base64::Engine;
use sha2::{Digest, Sha256};

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 32 random bytes, base64url. Used for state, nonce and verifiers.
pub fn random_urlsafe() -> String {
    let mut b = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
    b64url(&b)
}

/// Returns `(code_verifier, code_challenge)` for S256.
pub fn pair() -> (String, String) {
    let verifier = random_urlsafe();
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// OIDC `nonce` bound to a node's certificate fingerprint. The joining node
/// sets it in the authorization request; the control node recomputes it from
/// the fingerprint it received over the (cert-verified) adopt path and
/// requires the id_token to carry the same value. Both sides must derive it
/// identically, so it lives here.
pub fn nonce_for_fingerprint(fingerprint: &str) -> String {
    b64url(&Sha256::digest(fingerprint.as_bytes()))
}
