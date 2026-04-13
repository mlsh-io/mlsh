//! Node identity: self-signed TLS certificate + SHA-256 fingerprint.
//!
//! Each MLSH node generates a random Ed25519 keypair and self-signed certificate
//! at first run. The SHA-256 fingerprint of the DER-encoded certificate becomes
//! the node's identity — used for authentication and certificate pinning.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A node's TLS identity: certificate (DER + PEM), private key (PEM), and fingerprint.
pub struct NodeIdentity {
    /// DER-encoded self-signed certificate.
    pub cert_der: Vec<u8>,
    /// PEM-encoded self-signed certificate.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// SHA-256 hex fingerprint of the DER certificate.
    pub fingerprint: String,
}

/// Generate a self-signed Ed25519 certificate for a node.
///
/// The certificate has:
/// - CN=`node_uuid`, O=MLSH
/// - 10-year validity (identity certs are long-lived; auth is via fingerprint registry)
/// - ServerAuth + ClientAuth extended key usage (node acts as both)
pub fn generate_identity(node_uuid: &str) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        DnValue::Utf8String(node_uuid.to_string()),
    );
    dn.push(
        DnType::OrganizationName,
        DnValue::Utf8String("MLSH".to_string()),
    );
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().to_vec();
    let fingerprint = compute_fingerprint(&cert_der);

    Ok(NodeIdentity {
        cert_der,
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        fingerprint,
    })
}

/// Compute the SHA-256 hex fingerprint of a DER-encoded certificate.
pub fn compute_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hex::encode(hash)
}

/// Load an existing identity from disk, or generate and save a new one.
///
/// Looks for `cert.pem` and `key.pem` in `dir`. If both exist, loads them.
/// Otherwise generates a new identity, writes both files, and returns it.
///
/// File permissions: the key file is created with mode 0600 on Unix.
pub fn load_or_generate(
    dir: &Path,
    node_uuid: &str,
) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        let cert_der = pem_to_der(&cert_pem)?;
        let fingerprint = compute_fingerprint(&cert_der);

        return Ok(NodeIdentity {
            cert_der,
            cert_pem,
            key_pem,
            fingerprint,
        });
    }

    let identity = generate_identity(node_uuid)?;

    std::fs::create_dir_all(dir)?;
    std::fs::write(&cert_path, &identity.cert_pem)?;

    // Write key with restricted permissions
    std::fs::write(&key_path, &identity.key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(identity)
}

/// Extract DER bytes from a PEM-encoded certificate.
pub fn pem_to_der_pub(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pem_to_der(pem)
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let pem = pem.trim();
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)?;
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_identity() {
        let id = generate_identity("test-node").unwrap();
        assert!(!id.cert_der.is_empty());
        assert!(id.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(id.key_pem.contains("PRIVATE KEY"));
        assert_eq!(id.fingerprint.len(), 64); // SHA-256 hex
        assert!(id.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_cert() {
        let id = generate_identity("node-a").unwrap();
        let fp2 = compute_fingerprint(&id.cert_der);
        assert_eq!(id.fingerprint, fp2);
    }

    #[test]
    fn different_nodes_have_different_fingerprints() {
        let id1 = generate_identity("node-a").unwrap();
        let id2 = generate_identity("node-b").unwrap();
        assert_ne!(id1.fingerprint, id2.fingerprint);
    }

    #[test]
    fn pem_to_der_roundtrip() {
        let id = generate_identity("roundtrip").unwrap();
        let der = pem_to_der(&id.cert_pem).unwrap();
        assert_eq!(der, id.cert_der);
    }

    #[test]
    fn load_or_generate_creates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let id1 = load_or_generate(dir.path(), "test-node").unwrap();
        let id2 = load_or_generate(dir.path(), "test-node").unwrap();
        // Same fingerprint on reload
        assert_eq!(id1.fingerprint, id2.fingerprint);
        assert_eq!(id1.cert_pem, id2.cert_pem);
    }

    #[test]
    fn load_or_generate_sets_key_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let _id = load_or_generate(dir.path(), "perm-test").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key_path = dir.path().join("key.pem");
            let perms = std::fs::metadata(&key_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }
}
