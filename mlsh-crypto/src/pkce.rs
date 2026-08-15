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
