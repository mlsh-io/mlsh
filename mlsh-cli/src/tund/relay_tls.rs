//! E2E TLS encryption for relay streams.
//!
//! Wraps a relay bidirectional stream (SendStream + RecvStream) in a TLS
//! session, using the same mTLS configuration as direct peer connections.
//! Signal sees only TLS ciphertext in the relay splice.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bidirectional stream adapter: combines Quinn's SendStream + RecvStream into
/// a single AsyncRead + AsyncWrite, suitable for wrapping with tokio-rustls.
pub struct DuplexStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl DuplexStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for DuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }
}

/// Wrap a relay stream as TLS client (initiator side).
///
/// Uses the same FingerprintVerifier + client cert as direct QUIC connections.
/// The peer's certificate fingerprint is verified during the TLS handshake.
pub async fn wrap_initiator(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    identity: &mlsh_crypto::identity::NodeIdentity,
    peer_fingerprint: &str,
) -> Result<tokio_rustls::client::TlsStream<DuplexStream>> {
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(peer_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_OVERLAY.to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("mlsh-relay")
        .map_err(|_| anyhow::anyhow!("Invalid server name"))?;

    let duplex = DuplexStream::new(send, recv);
    let tls_stream = connector
        .connect(server_name, duplex)
        .await
        .context("TLS handshake failed on relay (initiator)")?;

    Ok(tls_stream)
}

/// Wrap a relay stream as TLS server (responder side).
///
/// Accepts the peer's client certificate and verifies via the TLS handshake.
pub async fn wrap_responder(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    identity: &mlsh_crypto::identity::NodeIdentity,
) -> Result<tokio_rustls::server::TlsStream<DuplexStream>> {
    use rustls::pki_types::CertificateDer;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

    /// Accept any client certificate — we verify by fingerprint after handshake.
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
            true
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
            Err(rustls::Error::General("TLS 1.2 not supported".into()))
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

    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(AcceptAnyCert))
        .with_single_cert(vec![cert], key)
        .context("Failed to set server cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_OVERLAY.to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let duplex = DuplexStream::new(send, recv);
    let tls_stream = acceptor
        .accept(duplex)
        .await
        .context("TLS handshake failed on relay (responder)")?;

    Ok(tls_stream)
}

/// Extract the peer's certificate fingerprint from a TLS server stream.
pub fn extract_peer_fingerprint_server(
    tls: &tokio_rustls::server::TlsStream<DuplexStream>,
) -> Option<String> {
    let (_, server_conn) = tls.get_ref();
    let certs = server_conn.peer_certificates()?;
    let cert = certs.first()?;
    Some(mlsh_crypto::identity::compute_fingerprint(cert.as_ref()))
}
