//! Custom TLS certificate verifiers for QUIC connections.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

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
