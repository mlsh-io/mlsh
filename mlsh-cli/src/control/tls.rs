//! TLS configuration for the control HTTP listener.
//!
//! The server presents the node's self-signed identity cert (same one used
//! for QUIC towards signal). It also requests — but does not require —
//! a client certificate; identity is verified post-handshake by hashing the
//! peer cert and looking the fingerprint up in the `nodes` table
//! (ADR-023, ADR-035 Phase D). Human callers without a client cert fall
//! through to the cookie-session middleware.
//!
//! When the listener serves both `control.<cluster>` (cluster-CA-signed)
//! and `<cluster>.mlsh.io` (Let's Encrypt) per ADR-035 Phase C, the SNI
//! resolver replaces `with_single_cert` here.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

use crate::tund::cluster_config::ClusterConfig;

/// Build a rustls `ServerConfig` for the control HTTP listener.
///
/// The cert/key come from the node's identity dir (`cert.pem`, `key.pem`).
/// `WebPkiClientVerifier::optional` is replaced with [`AcceptAnyCert`] —
/// rustls hands every presented client cert to the application without
/// validating against a CA chain (we hash + look up by fingerprint
/// instead).
pub fn build_server_config(cluster: &ClusterConfig) -> Result<rustls::ServerConfig> {
    let cert_path = cluster.identity_dir.join("cert.pem");
    let key_path = cluster.identity_dir.join("key.pem");

    let cert_pem = std::fs::read(&cert_path)
        .with_context(|| format!("read identity cert at {}", cert_path.display()))?;
    let key_pem = std::fs::read(&key_path)
        .with_context(|| format!("read identity key at {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse cert.pem")?;
    if certs.is_empty() {
        anyhow::bail!("cert.pem contains no certificates");
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse key.pem")?
        .ok_or_else(|| anyhow::anyhow!("key.pem contains no private key"))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyCert))
        .with_single_cert(certs, key)
        .context("rustls server config")?;

    Ok(config)
}

/// Client cert verifier that accepts every presented certificate without
/// PKI validation. The application authenticates the caller by hashing the
/// presented cert and looking the SHA-256 fingerprint up in the cluster's
/// `nodes` registry. Modeled on `mlsh-signal/src/quic/tls.rs`.
#[derive(Debug)]
struct AcceptAnyCert;

impl ClientCertVerifier for AcceptAnyCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
