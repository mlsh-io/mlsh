//! Custom TLS certificate verifier for the QUIC setup flow.
//!
//! The CLI derives the expected Ed25519 public key from the setup code (via `mlsh_crypto`),
//! then verifies that the QUIC server's self-signed certificate uses the same key.
//! This is not TOFU — both sides independently derive the same keypair.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

/// Verifies the QUIC server's certificate matches the expected setup-code-derived public key.
#[derive(Debug)]
pub struct SetupCodeVerifier {
    /// Expected Ed25519 public key bytes (32 bytes), derived from the setup code.
    expected_public_key: Vec<u8>,
}

impl SetupCodeVerifier {
    pub fn new(setup_code: &str) -> Self {
        Self {
            expected_public_key: mlsh_crypto::setup::derive_setup_public_key(setup_code),
        }
    }
}

impl ServerCertVerifier for SetupCodeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Parse the DER certificate to extract the public key
        // Ed25519 public keys in X.509 certs are in the SubjectPublicKeyInfo field.
        // The raw public key is the last 32 bytes of the SPKI bitstring.
        let cert_der = end_entity.as_ref();

        // Find the Ed25519 OID (1.3.101.112) in the cert to locate the public key
        // OID encoding: 06 03 2b 65 70
        let ed25519_oid = &[0x06, 0x03, 0x2b, 0x65, 0x70];

        let oid_pos = cert_der
            .windows(ed25519_oid.len())
            .position(|w| w == ed25519_oid)
            .ok_or_else(|| {
                rustls::Error::General("Server cert does not contain an Ed25519 key".to_string())
            })?;

        // After the OID, there's a NULL params (optional) then BIT STRING with the key.
        // The BIT STRING is: 03 21 00 <32 bytes of public key>
        // Search for this pattern after the OID
        let after_oid = &cert_der[oid_pos + ed25519_oid.len()..];

        // Find the BIT STRING tag (0x03) followed by length 33 (0x21) and unused bits 0 (0x00)
        let bitstring_header = &[0x03, 0x21, 0x00];
        let key_pos = after_oid
            .windows(bitstring_header.len())
            .position(|w| w == bitstring_header)
            .ok_or_else(|| {
                rustls::Error::General(
                    "Could not locate Ed25519 public key in server cert".to_string(),
                )
            })?;

        let key_start = key_pos + bitstring_header.len();
        if after_oid.len() < key_start + 32 {
            return Err(rustls::Error::General(
                "Certificate too short to contain Ed25519 key".to_string(),
            ));
        }

        let server_public_key = &after_oid[key_start..key_start + 32];

        if server_public_key == self.expected_public_key.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "Server public key does not match expected setup-code-derived key".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is not used with QUIC
        Err(rustls::Error::General(
            "TLS 1.2 not supported for QUIC setup".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Delegate to the default rustls verification for the TLS 1.3 signature
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Verify the server's certificate fingerprint matches the expected value.
/// Used for direct peer-to-peer overlay connections where we know the peer's
/// fingerprint from signal's peer list.
#[derive(Debug)]
pub struct FingerprintVerifier {
    /// Expected SHA-256 hex fingerprint of the peer's DER-encoded certificate.
    expected_fingerprint: String,
}

impl FingerprintVerifier {
    pub fn new(expected_fingerprint: &str) -> Self {
        Self {
            expected_fingerprint: expected_fingerprint.to_string(),
        }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.expected_fingerprint.is_empty() {
            return Err(rustls::Error::General(
                "No signal_fingerprint in cluster config. Re-run 'mlsh adopt' to fix.".to_string(),
            ));
        }

        let fingerprint = mlsh_crypto::identity::compute_fingerprint(end_entity.as_ref());
        if fingerprint == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}..., got {}...",
                &self.expected_fingerprint[..self.expected_fingerprint.len().min(16)],
                &fingerprint[..fingerprint.len().min(16)]
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".to_string()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
