//! Persistent QUIC connection from mlshtund to mlsh-signal on ALPN `mlsh-control`.
//!
//! ADR-035 Phase G — bootstrap-and-runtime-cache channel, not admin API.
//! All steady-state admin operations (rename, promote, revoke, list…) live
//! on the REST API at `https://control.<cluster>:8443` reached over the
//! overlay (Phase E). What still goes through this CBOR-over-QUIC channel:
//!   - `AdoptConfirm` once per session (registers the local node in the
//!     control plane's `nodes` table — required before this daemon can
//!     get an overlay address).
//!   - `ListNodes` as the initial seed of the local peer-name cache, then
//!     `Subscribe` to keep it in sync via `ControlEvent`s.
//!
//! Signal relays the bi-streams to the cluster's control node; this
//! daemon never touches the control node's SQLite directly.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mlsh_protocol::control::ControlEvent;
use mlsh_protocol::framing;
use tokio::sync::{broadcast, watch, Mutex};

use crate::tund::control::display_names::DisplayNameMap;
use crate::tund::signal_session::SignalCredentials;

/// Capacity of the per-session ControlEvent broadcast channel. Keep this
/// small: subscribers that fall behind are signalled via `RecvError::Lagged`
/// and expected to reseed via `ListNodes`.
const EVENT_BROADCAST_CAPACITY: usize = 256;

/// Reconnect backoff for the mlsh-control supervisor. Mirrors the values in
/// `signal_session.rs` so both long-lived QUIC sessions behave alike.
const RECONNECT_INITIAL: Duration = Duration::from_millis(200);
const RECONNECT_MAX: Duration = Duration::from_secs(10);
const RECONNECT_JITTER: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct ControlSession {
    inner: Arc<Mutex<Inner>>,
    creds: Arc<SignalCredentials>,
    /// Local human-facing label written to mlsh-control on first AdoptConfirm.
    /// Held here rather than in `SignalCredentials` because signal no longer
    /// stores display names (ADR 018).
    display_name: Arc<String>,
    control_socket: PathBuf,
    events_tx: broadcast::Sender<Arc<ControlEvent>>,
    display_names: DisplayNameMap,
}

struct Inner {
    conn: Option<quinn::Connection>,
    endpoint: quinn::Endpoint,
    adopt_confirm_done: bool,
    subscribe_running: bool,
    seed_running: bool,
}

impl ControlSession {
    pub fn new(
        creds: SignalCredentials,
        display_name: String,
        control_socket: PathBuf,
    ) -> Result<Self> {
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .context("Failed to create QUIC client endpoint for control session")?;
        let (events_tx, _) = broadcast::channel(EVENT_BROADCAST_CAPACITY);
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                conn: None,
                endpoint,
                adopt_confirm_done: false,
                subscribe_running: false,
                seed_running: false,
            })),
            creds: Arc::new(creds),
            display_name: Arc::new(display_name),
            control_socket,
            events_tx,
            display_names: DisplayNameMap::new(),
        })
    }

    /// Shared display-name map kept in sync with mlsh-control. Consumers (the
    /// overlay DNS resolver in particular) clone this handle and read from it.
    pub fn display_names(&self) -> DisplayNameMap {
        self.display_names.clone()
    }

    /// Subscribe to server-pushed `ControlEvent`s for this session. New
    /// receivers see only events arriving after subscription. If the inner
    /// subscriber falls behind, `RecvError::Lagged` is surfaced and the caller
    /// is expected to reseed (e.g. via `ListNodes`).
    pub fn subscribe_events(&self) -> broadcast::Receiver<Arc<ControlEvent>> {
        self.events_tx.subscribe()
    }

    pub async fn ensure_connected(&self) -> Result<quinn::Connection> {
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
        let should_start_subscribe;
        let should_start_seed;
        {
            let mut g = self.inner.lock().await;
            g.conn = Some(conn.clone());
            should_adopt_confirm = !g.adopt_confirm_done;
            if should_adopt_confirm {
                g.adopt_confirm_done = true;
            }
            should_start_subscribe = !g.subscribe_running;
            if should_start_subscribe {
                g.subscribe_running = true;
            }
            // The seed task always reseeds on reconnect — start it whenever
            // there isn't already one in flight.
            should_start_seed = !g.seed_running;
            if should_start_seed {
                g.seed_running = true;
            }
        }

        let socket = self.control_socket.clone();
        let conn_for_inbound = conn.clone();
        tokio::spawn(async move {
            inbound_loop(conn_for_inbound, socket).await;
        });

        if should_adopt_confirm {
            best_effort_adopt_confirm_with_retry(&conn, &self.creds, &self.display_name).await;
        }

        if should_start_subscribe {
            let conn_for_subscribe = conn.clone();
            let events_tx = self.events_tx.clone();
            let inner = self.inner.clone();
            tokio::spawn(async move {
                subscribe_loop(conn_for_subscribe, events_tx).await;
                inner.lock().await.subscribe_running = false;
            });
        }

        if should_start_seed {
            // Subscribe to the broadcast *before* issuing ListNodes so any
            // event landing during the seed is buffered, not lost.
            let rx = self.events_tx.subscribe();
            let conn_for_seed = conn.clone();
            let map = self.display_names.clone();
            let inner = self.inner.clone();
            tokio::spawn(async move {
                display_names_loop(conn_for_seed, map, rx).await;
                inner.lock().await.seed_running = false;
            });
        }

        Ok(conn)
    }

    pub async fn call(&self, request_cbor: Vec<u8>) -> Result<Vec<u8>> {
        let conn = self.ensure_connected().await?;
        call_on(&conn, request_cbor).await
    }

    /// Long-running task that keeps the ALPN `mlsh-control` QUIC session to
    /// signal alive for the entire tunnel lifetime. Without this a control
    /// node never re-initiates the connection after it dies — `ensure_connected`
    /// is only triggered by outbound traffic, and a control node is a receiver
    /// in steady state. Signal would end up with an empty `control_conns` map
    /// and reject every relayed `AdoptConfirm` with `control_offline`. See #88.
    pub async fn supervise(self, mut shutdown_rx: watch::Receiver<bool>) {
        shutdown_rx.borrow_and_update();
        let mut error_backoff = RECONNECT_INITIAL;

        loop {
            let conn = match self.ensure_connected().await {
                Ok(c) => {
                    error_backoff = RECONNECT_INITIAL;
                    c
                }
                Err(e) => {
                    let d = error_backoff;
                    tracing::warn!(
                        error = %e,
                        delay = ?d,
                        "mlsh-control session connect failed, retrying"
                    );
                    error_backoff = error_backoff.saturating_mul(2).min(RECONNECT_MAX);
                    tokio::select! {
                        _ = tokio::time::sleep(d) => continue,
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { return; }
                            continue;
                        }
                    }
                }
            };

            let reason = tokio::select! {
                r = conn.closed() => r,
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        conn.close(quinn::VarInt::from_u32(0), b"shutdown");
                        return;
                    }
                    continue;
                }
            };

            tracing::info!(%reason, "mlsh-control connection lost, reconnecting");
            // Drop the dead handle so the next ensure_connected dials anew
            // instead of returning the closed connection.
            self.inner.lock().await.conn = None;

            let jitter = rand_jitter(RECONNECT_JITTER);
            tokio::select! {
                _ = tokio::time::sleep(jitter) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { return; }
                }
            }
        }
    }
}

fn rand_jitter(max: Duration) -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let factor = 0.5 + (nanos as f64 / u32::MAX as f64) * 0.5;
    Duration::from_secs_f64(max.as_secs_f64() * factor)
}

/// Open a `Subscribe` stream on this control connection and forward every
/// inbound `ControlEvent` to the broadcast channel. Returns when the stream
/// closes (connection lost, server-side eviction, or local error). The caller
/// is responsible for resetting the `subscribe_running` flag on return.
async fn subscribe_loop(conn: quinn::Connection, events_tx: broadcast::Sender<Arc<ControlEvent>>) {
    use mlsh_protocol::control::ControlRequest;

    let (mut send, mut recv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, "control: failed to open Subscribe stream");
            return;
        }
    };

    if let Err(e) = framing::write_msg(&mut send, &ControlRequest::Subscribe).await {
        tracing::debug!(error = %e, "control: failed to send Subscribe");
        return;
    }
    // We only read from this stream from now on; let the server know we're
    // done writing.
    let _ = send.finish();

    tracing::info!("control: subscribed to event stream");

    loop {
        match framing::read_msg_opt::<ControlEvent>(&mut recv).await {
            Ok(Some(event)) => {
                tracing::debug!(?event, "control: event received");
                // Best-effort fanout — if no one is listening, drop silently.
                let _ = events_tx.send(Arc::new(event));
            }
            Ok(None) => {
                tracing::info!("control: subscribe stream closed by server");
                return;
            }
            Err(e) => {
                tracing::debug!(error = %e, "control: subscribe read error; closing");
                return;
            }
        }
    }
}

/// Seed the `DisplayNameMap` from `ListNodes`, then keep it in sync by
/// applying every `ControlEvent` arriving on the broadcast. Returns when the
/// broadcast is closed (session torn down) — the caller resets the
/// `seed_running` flag so the next reconnect spawns a fresh task that reseeds.
async fn display_names_loop(
    conn: quinn::Connection,
    map: DisplayNameMap,
    mut rx: broadcast::Receiver<Arc<ControlEvent>>,
) {
    use mlsh_protocol::control::{ControlRequest, ControlResponse};

    // --- Initial seed via ListNodes on the live connection ---
    let req = ControlRequest::ListNodes;
    let mut buf = Vec::new();
    if let Err(e) = ciborium::into_writer(&req, &mut buf) {
        tracing::warn!(error = %e, "display_names: failed to encode ListNodes; skipping seed");
    } else {
        match call_on(&conn, buf).await {
            Ok(reply_bytes) => {
                match ciborium::from_reader::<ControlResponse, _>(&reply_bytes[..]) {
                    Ok(ControlResponse::Nodes { nodes }) => {
                        let count = nodes.len();
                        map.seed(&nodes).await;
                        tracing::info!(count, "display_names: seeded from ListNodes");
                    }
                    Ok(ControlResponse::Error { code, message }) => {
                        tracing::warn!(code, message, "display_names: ListNodes returned error");
                    }
                    Ok(other) => {
                        tracing::warn!(?other, "display_names: unexpected ListNodes response");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "display_names: failed to decode ListNodes reply");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "display_names: ListNodes call failed");
            }
        }
    }

    // --- Apply incremental updates ---
    loop {
        match rx.recv().await {
            Ok(event) => map.apply(&event).await,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    skipped = n,
                    "display_names: broadcast lagged; map may drift until next reconnect"
                );
                // Best-effort: keep going. A reconnect will reseed; live drift
                // is bounded by the next mutation we observe.
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::debug!("display_names: broadcast closed, exiting loop");
                return;
            }
        }
    }
}

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
        let resp = mlsh_protocol::control::ControlResponse::error(
            "not_control",
            "This node is not running mlsh-control",
        );
        framing::write_msg(&mut send, &resp).await?;
        return Ok(());
    }

    #[cfg(unix)]
    {
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
    #[cfg(not(unix))]
    {
        let _ = &mut recv;
        let resp = mlsh_protocol::control::ControlResponse::error(
            "not_control",
            "mlsh-control forwarding is not supported on this platform",
        );
        framing::write_msg(&mut send, &resp).await?;
        Ok(())
    }
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

/// Retries to absorb the boot race with the mlsh-control sub-process socket.
async fn best_effort_adopt_confirm_with_retry(
    conn: &quinn::Connection,
    creds: &SignalCredentials,
    display_name: &str,
) {
    use mlsh_protocol::control::ControlResponse;
    let attempts = 8u32;
    let backoff = std::time::Duration::from_millis(250);
    for i in 0..attempts {
        if conn.close_reason().is_some() {
            tracing::debug!("AdoptConfirm: connection closed, abort");
            return;
        }
        match adopt_confirm_once(conn, creds, display_name).await {
            Ok(ControlResponse::AdoptAck { accepted, message }) => {
                tracing::info!(accepted, ?message, "mlsh-control AdoptConfirm");
                return;
            }
            Ok(ControlResponse::Error { code, message: _ }) if code == "not_control" => {
                tracing::debug!(
                    attempt = i + 1,
                    "AdoptConfirm: control plane not ready yet, retrying"
                );
                tokio::time::sleep(backoff).await;
                continue;
            }
            Ok(ControlResponse::Error { code, message }) => {
                tracing::warn!(code, message, "mlsh-control AdoptConfirm rejected");
                return;
            }
            Ok(other) => {
                tracing::warn!(?other, "AdoptConfirm: unexpected response");
                return;
            }
            Err(e) => {
                tracing::debug!(attempt = i + 1, error = %e, "AdoptConfirm attempt failed");
                tokio::time::sleep(backoff).await;
                continue;
            }
        }
    }
    tracing::warn!("AdoptConfirm gave up after {attempts} attempts");
}

async fn adopt_confirm_once(
    conn: &quinn::Connection,
    creds: &SignalCredentials,
    display_name: &str,
) -> Result<mlsh_protocol::control::ControlResponse> {
    use mlsh_protocol::control::{ControlRequest, ControlResponse};
    let req = ControlRequest::AdoptConfirm {
        node_uuid: creds.node_id.clone(),
        fingerprint: creds.fingerprint.clone(),
        public_key: creds.public_key.clone(),
        display_name: display_name.to_string(),
        invite_token: String::new(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&req, &mut buf)
        .map_err(|e| anyhow::anyhow!("encode AdoptConfirm: {e}"))?;
    let reply_bytes = call_on(conn, buf).await?;
    let reply: ControlResponse = ciborium::from_reader(&reply_bytes[..])
        .map_err(|e| anyhow::anyhow!("decode AdoptConfirm reply: {e}"))?;
    Ok(reply)
}

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
