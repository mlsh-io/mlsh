//! Deterministic keypair derivation from the setup code.
//!
//! The setup code (displayed on the physical console) is used as the input keying
//! material for HKDF-SHA256. The derived Ed25519 seed produces a deterministic keypair
//! that both the server and CLI can independently compute.
//!
//! The HKDF salt is fixed (`b"mlsh-setup-v1"`) by design — both sides must derive the
//! same keypair without prior communication. The setup code itself provides the entropy
//! (~61 bits). The `info` field provides domain separation.

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose,
    PKCS_ED25519,
};
use ring::hkdf;
use ring::signature::{self, Ed25519KeyPair};
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};

const HKDF_SALT: &[u8] = b"mlsh-setup-v1";
const HKDF_INFO: &[u8] = b"ed25519-seed";
const ED25519_SEED_LEN: usize = 32;

/// Output length wrapper for HKDF expand — extracts exactly 32 bytes for the Ed25519 seed.
struct SeedLen;

impl hkdf::KeyType for SeedLen {
    fn len(&self) -> usize {
        ED25519_SEED_LEN
    }
}

/// Derive a 32-byte Ed25519 seed from a setup code via HKDF-SHA256.
fn derive_seed(setup_code: &str) -> [u8; ED25519_SEED_LEN] {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(setup_code.as_bytes());
    let okm = prk
        .expand(&[HKDF_INFO], SeedLen)
        .expect("HKDF expand failed — this should never happen with valid parameters");

    let mut seed = [0u8; ED25519_SEED_LEN];
    okm.fill(&mut seed)
        .expect("HKDF fill failed — output length mismatch");
    seed
}

/// Derive the Ed25519 public key bytes (32 bytes) from a setup code.
///
/// Used by the CLI to build a custom TLS verifier that checks the server's
/// certificate public key matches the expected value derived from the code.
pub fn derive_setup_public_key(setup_code: &str) -> Vec<u8> {
    let seed = derive_seed(setup_code);
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .expect("Ed25519 keypair from seed failed — seed is always 32 bytes");
    signature::KeyPair::public_key(&keypair).as_ref().to_vec()
}

/// Derive a deterministic Ed25519 keypair and self-signed certificate from a setup code.
///
/// Returns `(keypair, cert)` where:
/// - `keypair` is the rcgen `KeyPair` (for use with quinn/rustls server config)
/// - `cert` is the self-signed `Certificate` (call `.der()` for DER, `.pem()` for PEM)
///
/// The certificate has CN=mlsh-setup, 1-day validity, ServerAuth extended key usage.
pub fn derive_setup_keypair(setup_code: &str) -> (KeyPair, Certificate) {
    let seed = derive_seed(setup_code);

    // Build Ed25519 keypair via ring to verify, then build PKCS8 DER for rcgen
    let ring_keypair =
        Ed25519KeyPair::from_seed_unchecked(&seed).expect("Ed25519 keypair from seed failed");

    // Build the PKCS8 v1 DER from the seed (ring doesn't expose PKCS8 serialization from seed)
    let pkcs8_der = build_ed25519_pkcs8_der(&seed);
    let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8_der.as_slice());

    let keypair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
        .expect("rcgen KeyPair::from_pkcs8_der_and_sign_algo failed for Ed25519");

    // Verify consistency: the rcgen keypair must produce the same public key
    debug_assert_eq!(
        keypair.public_key_raw(),
        signature::KeyPair::public_key(&ring_keypair).as_ref(),
        "rcgen and ring disagree on the public key — critical bug"
    );

    // Build self-signed certificate
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "mlsh-setup");
    dn.push(DnType::OrganizationName, "MLSH");
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);

    let cert = params
        .self_signed(&keypair)
        .expect("self-signed cert generation failed");

    (keypair, cert)
}

/// SHA-256 hex digest of a setup code — used for storage in SQLite.
pub fn hash_setup_code(setup_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(setup_code.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Build an Ed25519 PKCS8 v1 DER structure from a 32-byte seed.
///
/// RFC 8410: Algorithm Identifiers for Ed25519.
fn build_ed25519_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    // Pre-computed DER prefix for Ed25519 PKCS8 v1:
    //   SEQUENCE (46 bytes) {
    //     INTEGER 0 (version)
    //     SEQUENCE { OID 1.3.101.112 (Ed25519) }
    //     OCTET STRING { OCTET STRING { 32-byte seed } }
    //   }
    let prefix: &[u8] = &[
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE (5 bytes, AlgorithmIdentifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING (34 bytes, wrapping)
        0x04, 0x20, // OCTET STRING (32 bytes, the seed)
    ];

    let mut der = Vec::with_capacity(prefix.len() + seed.len());
    der.extend_from_slice(prefix);
    der.extend_from_slice(seed);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_derivation() {
        let code = "A3K7-Z9QX-5T2M";
        let pk1 = derive_setup_public_key(code);
        let pk2 = derive_setup_public_key(code);
        assert_eq!(pk1, pk2, "same code must produce same public key");
        assert_eq!(pk1.len(), 32, "Ed25519 public key must be 32 bytes");
    }

    #[test]
    fn different_codes_produce_different_keys() {
        let pk1 = derive_setup_public_key("A3K7-Z9QX-5T2M");
        let pk2 = derive_setup_public_key("B4L8-W0RY-6U3N");
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn keypair_and_public_key_match() {
        let code = "TEST-CODE-ABCD";
        let (keypair, _cert) = derive_setup_keypair(code);
        let expected_pk = derive_setup_public_key(code);
        assert_eq!(keypair.public_key_raw(), expected_pk.as_slice());
    }

    #[test]
    fn cert_is_valid_der() {
        let code = "CERT-TEST-1234";
        let (_keypair, cert) = derive_setup_keypair(code);
        assert!(!cert.der().is_empty());
    }

    #[test]
    fn cert_pem_is_valid() {
        let code = "PEM-TEST-5678";
        let (_keypair, cert) = derive_setup_keypair(code);
        let pem = cert.pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn hash_is_consistent() {
        let code = "A3K7-Z9QX-5T2M";
        let h1 = hash_setup_code(code);
        let h2 = hash_setup_code(code);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn hash_differs_for_different_codes() {
        let h1 = hash_setup_code("CODE-AAAA-BBBB");
        let h2 = hash_setup_code("CODE-CCCC-DDDD");
        assert_ne!(h1, h2);
    }

    #[test]
    fn pkcs8_der_is_valid() {
        let seed = derive_seed("PKCS-TEST-1234");
        let der = build_ed25519_pkcs8_der(&seed);
        // Verify rcgen can parse it with the Ed25519 algo
        let pkcs8 = PrivatePkcs8KeyDer::from(der.as_slice());
        let _kp = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519).unwrap();
    }
}
