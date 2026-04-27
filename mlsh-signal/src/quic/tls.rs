//! TLS configuration for the mlsh-signal QUIC server.
//!
//! The QUIC certificate is persisted in the signal DB so it survives restarts.
//! Clients verify this certificate's fingerprint (obtained during setup/adopt
//! via HTTPS).

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

use crate::config::QuicConfig;

/// Accept any client certificate — we verify identity by fingerprint after
/// handshake, not during TLS negotiation. The purpose is to make the client
/// SEND its cert so we can extract the fingerprint from the QUIC connection.
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 not supported for QUIC".to_string(),
        ))
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

/// Build a quinn::ServerConfig and return the certificate's SHA-256 fingerprint.
///
/// If cert_path/key_path are configured, uses those. Otherwise loads from DB
/// or generates a new cert and persists it.
pub async fn build_server_config(
    config: &QuicConfig,
    db: &sqlx::SqlitePool,
) -> Result<(quinn::ServerConfig, String), anyhow::Error> {
    let (cert_chain, private_key, fingerprint) = match (&config.cert_path, &config.key_path) {
        (Some(cert_path), Some(key_path)) => {
            let (certs, key) = load_pem_files(cert_path, key_path)?;
            let fp = mlsh_crypto::identity::compute_fingerprint(certs[0].as_ref());
            (certs, key, fp)
        }
        _ => load_or_generate_cert(db).await?,
    };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyCert))
        .with_single_cert(cert_chain, private_key)?;

    tls_config.alpn_protocols = vec![
        super::alpn::ALPN_SIGNAL.to_vec(),
        super::alpn::ALPN_CONTROL.to_vec(),
    ];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30 * 60)).unwrap(),
    ));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    server_config.transport_config(Arc::new(transport));

    Ok((server_config, fingerprint))
}

fn load_pem_files(
    cert_path: &str,
    key_path: &str,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    anyhow::Error,
> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    Ok((certs, key))
}

/// Load cert from DB, or generate and persist.
async fn load_or_generate_cert(
    db: &sqlx::SqlitePool,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
        String,
    ),
    anyhow::Error,
> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Try to load from DB
    if let (Ok(Some(cert_b64)), Ok(Some(key_b64))) = (
        crate::db::get_config(db, "quic_cert_der").await,
        crate::db::get_config(db, "quic_key_der").await,
    ) {
        let cert_der = b64.decode(&cert_b64)?;
        let key_der = b64.decode(&key_b64)?;
        let fp = mlsh_crypto::identity::compute_fingerprint(&cert_der);

        let cert = rustls::pki_types::CertificateDer::from(cert_der);
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse persisted key: {}", e))?;

        tracing::info!(fingerprint = &fp[..16], "Loaded QUIC certificate from DB");
        return Ok((vec![cert], key, fp));
    }

    // Generate new cert
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec!["mlsh-signal.local".to_string()])?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("mlsh-signal".to_string()),
    );
    // 10-year validity
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let cert = params.self_signed(&key_pair)?;

    let cert_der_bytes = cert.der().to_vec();
    let key_der_bytes = key_pair.serialize_der();
    let fp = mlsh_crypto::identity::compute_fingerprint(&cert_der_bytes);

    // Persist in DB
    crate::db::set_config(db, "quic_cert_der", &b64.encode(&cert_der_bytes))
        .await
        .ok();
    crate::db::set_config(db, "quic_key_der", &b64.encode(&key_der_bytes))
        .await
        .ok();

    tracing::info!(
        fingerprint = &fp[..16],
        "Generated and persisted QUIC certificate"
    );

    let cert_der = rustls::pki_types::CertificateDer::from(cert_der_bytes);
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to convert private key: {}", e))?;

    Ok((vec![cert_der], key_der, fp))
}
