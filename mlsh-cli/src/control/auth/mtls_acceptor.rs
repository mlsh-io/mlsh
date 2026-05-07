//! Custom axum-server acceptor that wraps `RustlsAcceptor` and injects the
//! client peer certificate (when present) into each request as a
//! [`PeerCert`] extension.
//!
//! Without this layer the peer cert is captured by rustls during the
//! handshake but never makes it past axum-server into the Axum router. The
//! [`super::caller::Caller`] extractor reads the extension to authenticate
//! a node by SHA-256 fingerprint (ADR-035 Phase D).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::Request;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};

/// Extension attached to every request whose connection presented a client
/// certificate. Wrapped in `Arc` so cloning per-request is cheap.
#[derive(Clone)]
pub struct PeerCert(pub Arc<CertificateDer<'static>>);

#[derive(Clone)]
pub struct MtlsAcceptor {
    inner: RustlsAcceptor,
}

impl MtlsAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

type IoResult<T> = std::io::Result<T>;

impl<I, S> Accept<I, S> for MtlsAcceptor
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = InjectPeerCert<S>;
    type Future = Pin<Box<dyn Future<Output = IoResult<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = Accept::<I, S>::accept(&self.inner, stream, service);
        Box::pin(async move {
            let (tls_stream, service) = inner.await?;
            let peer_cert = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|c| Arc::new(c.clone().into_owned()));
            let injected = InjectPeerCert {
                inner: service,
                peer_cert,
            };
            Ok((tls_stream, injected))
        })
    }
}

/// Tower service wrapper that clones a captured peer cert into each
/// request's extensions.
#[derive(Clone)]
pub struct InjectPeerCert<S> {
    inner: S,
    peer_cert: Option<Arc<CertificateDer<'static>>>,
}

impl<S, B> tower::Service<Request<B>> for InjectPeerCert<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(cert) = &self.peer_cert {
            req.extensions_mut().insert(PeerCert(cert.clone()));
        }
        self.inner.call(req)
    }
}
