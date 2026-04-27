//! Persistent QUIC connection from mlshtund to mlsh-signal on ALPN
//! `mlsh-control` (ADR-033 phase 2).
//!
//! Two roles share this single connection:
//!
//! - Outbound: when the local CLI runs `mlsh nodes/promote/revoke/rename` it
//!   reaches mlshtund over the local UNIX socket. mlshtund opens a bi-stream
//!   on the existing `mlsh-control` connection toward signal, sends a CBOR
//!   `ControlRequest`, reads the `ControlResponse`, and returns it to the CLI.
//!   Signal relays the stream to the cluster's control node.
//!
//! - Inbound (control node only): signal opens bi-streams toward mlshtund on
//!   the same connection. Each carries a CBOR `ControlAuthHeader` + a
//!   `ControlRequest` (already authenticated by signal). mlshtund forwards it
//!   over the local UNIX socket of mlsh-control's CBOR listener and pipes the
//!   reply back.
//!
//! Non-control nodes silently close any incoming bi-stream — signal should
//! never relay to them, but we ignore stragglers safely.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use mlsh_protocol::framing;
use tokio::sync::Mutex;

use super::signal_session::SignalCredentials;

/// Handle on the control session shared by the daemon's tunnel task.
///
/// Cheap to clone: holds the live `quinn::Connection` behind an `Arc<Mutex>`.
/// V1 reopens on demand if the connection died — no background reconnect FSM.
#[derive(Clone)]
pub struct ControlSession {
    inner: Arc<Mutex<Inner>>,
    creds: Arc<SignalCredentials>,
    /// Local socket where mlsh-control listens for relayed inbound CBOR
    /// streams (only used on the control node).
    control_socket: PathBuf,
}

struct Inner {
    conn: Option<quinn::Connection>,
    endpoint: quinn::Endpoint,
    /// Set once the very first AdoptConfirm best-effort attempt has fired.
    adopt_confirm_done: bool,
}

impl ControlSession {
    pub fn new(creds: SignalCredentials, control_socket: PathBuf) -> Result<Self> {
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .context("Failed to create QUIC client endpoint for control session")?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                conn: None,
                endpoint,
                adopt_confirm_done: false,
            })),
            creds: Arc::new(creds),
            control_socket,
        })
    }

    /// Connect (or reconnect) and spawn the inbound accept loop. Idempotent.
    pub async fn ensure_connected(&self) -> Result<quinn::Connection> {
        // Fast path: already-live connection. Drop the lock before any await.
        let endpoint = {
            let g = self.inner.lock().await;
            if let Some(c) = &g.conn {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
            g.endpoint.clone()
        };

        let client_config = build_client_config(&self.creds)?;
        let addr = resolve_addr(&self.creds.signal_endpoint).await?;
        let sni = self
            .creds
            .signal_endpoint
            .split(':')
            .next()
            .unwrap_or(&self.creds.signal_endpoint);
        let connecting = endpoint.connect_with(client_config, addr, sni)?;
        let conn = tokio::time::timeout(std::time::Duration::from_secs(10), connecting)
            .await
            .map_err(|_| anyhow::anyhow!("Timed out connecting mlsh-control"))?
            .context("Failed to connect mlsh-control")?;
        tracing::info!(endpoint = %self.creds.signal_endpoint, "mlsh-control session connected");

        let should_adopt_confirm;
        {
            let mut g = self.inner.lock().await;
            g.conn = Some(conn.clone());
            should_adopt_confirm = !g.adopt_confirm_done;
            if should_adopt_confirm {
                g.adopt_confirm_done = true;
            }
        }

        // Spawn inbound relay task.
        let socket = self.control_socket.clone();
        let conn_for_inbound = conn.clone();
        tokio::spawn(async move {
            inbound_loop(conn_for_inbound, socket).await;
        });

        if should_adopt_confirm {
            // Synchronous best-effort — keeps the future Send. Adds a tiny bit
            // of latency to the first call but the whole thing is bounded by
            // a short timeout in `call`.
            if let Err(e) = best_effort_adopt_confirm_on(&conn, &self.creds).await {
                tracing::debug!(error = %e, "AdoptConfirm best-effort failed");
            }
        }

        Ok(conn)
    }

    /// Outbound CBOR request: open a bi-stream, send `request_cbor` (already a
    /// `ControlRequest` encoded by the caller), read the reply, return it.
    /// Used by the daemon when handling `DaemonRequest::ControlCall`.
    pub async fn call(&self, request_cbor: Vec<u8>) -> Result<Vec<u8>> {
        let conn = self.ensure_connected().await?;
        call_on(&conn, request_cbor).await
    }
}

/// Accept incoming bi-streams (control-node role). Each stream carries a
/// `ControlAuthHeader` + `ControlRequest`, forwarded verbatim to mlsh-control's
/// local UNIX socket; the reply is piped back.
async fn inbound_loop(conn: quinn::Connection, control_socket: PathBuf) {
    loop {
        let stream = tokio::select! {
            s = conn.accept_bi() => s,
            _ = conn.closed() => return,
        };
        let (send, recv) = match stream {
            Ok(s) => s,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return,
            Err(e) => {
                tracing::debug!(error = %e, "control inbound accept ended");
                return;
            }
        };
        let socket = control_socket.clone();
        tokio::spawn(async move {
            if let Err(e) = forward_to_control(send, recv, &socket).await {
                tracing::debug!(error = %e, "control inbound forward failed");
            }
        });
    }
}

async fn forward_to_control(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    socket: &std::path::Path,
) -> Result<()> {
    if !socket.exists() {
        // Not the control node — close politely.
        let resp = mlsh_protocol::control::ControlResponse::error(
            "not_control",
            "This node is not running mlsh-control",
        );
        framing::write_msg(&mut send, &resp).await?;
        return Ok(());
    }

    let mut local = tokio::net::UnixStream::connect(socket)
        .await
        .context("Failed to connect mlsh-control socket")?;
    let (mut local_rd, mut local_wr) = local.split();

    let to_local = tokio::io::copy(&mut recv, &mut local_wr);
    let to_remote = tokio::io::copy(&mut local_rd, &mut send);
    let (r1, r2) = tokio::join!(to_local, to_remote);
    tracing::debug!(
        to_local = ?r1.ok(),
        to_remote = ?r2.ok(),
        "control inbound splice finished"
    );
    Ok(())
}

fn build_client_config(creds: &SignalCredentials) -> Result<quinn::ClientConfig> {
    let cert_der = {
        let b64: String = creds
            .cert_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
            .context("Invalid identity cert PEM")?
    };
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut creds.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(&creds.signal_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![mlsh_protocol::alpn::ALPN_CONTROL.to_vec()];

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(
        std::time::Duration::from_secs(30 * 60),
    )?));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

async fn best_effort_adopt_confirm_on(
    conn: &quinn::Connection,
    creds: &SignalCredentials,
) -> Result<()> {
    use mlsh_protocol::control::{ControlRequest, ControlResponse};
    let req = ControlRequest::AdoptConfirm {
        node_uuid: creds.node_id.clone(),
        fingerprint: creds.fingerprint.clone(),
        public_key: creds.public_key.clone(),
        display_name: creds.display_name.clone(),
        invite_token: String::new(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&req, &mut buf)
        .map_err(|e| anyhow::anyhow!("encode AdoptConfirm: {e}"))?;

    let reply_bytes = call_on(conn, buf).await?;
    let reply: ControlResponse = ciborium::from_reader(&reply_bytes[..])
        .map_err(|e| anyhow::anyhow!("decode AdoptConfirm reply: {e}"))?;
    match reply {
        ControlResponse::AdoptAck { accepted, message } => {
            tracing::info!(accepted, ?message, "mlsh-control AdoptConfirm");
        }
        ControlResponse::Error { code, message } => {
            tracing::warn!(code, message, "mlsh-control AdoptConfirm rejected");
        }
        other => {
            tracing::warn!(?other, "AdoptConfirm: unexpected response");
        }
    }
    Ok(())
}

/// Open a bi-stream on `conn`, send the framed CBOR `payload`, read the framed
/// reply. Shared helper so both `ensure_connected` (for AdoptConfirm) and
/// `call` use the same wire logic.
async fn call_on(conn: &quinn::Connection, payload: Vec<u8>) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open bi-stream on mlsh-control")?;
    let len = (payload.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&payload).await?;
    send.finish().ok();

    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 1_048_576 {
        anyhow::bail!("control reply too large: {n} bytes");
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    let mut iter = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("Failed to resolve {endpoint}"))?;
    iter.next()
        .ok_or_else(|| anyhow::anyhow!("No address resolved for {endpoint}"))
}
