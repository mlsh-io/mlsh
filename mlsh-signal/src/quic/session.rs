//! QUIC stream handler for the `mlsh-signal` ALPN.
//!
//! Each connection may open multiple bidirectional streams. The first message
//! on each stream determines its type:
//! - `NodeAuth` → long-lived session (peer updates, candidates)
//! - `Adopt` → one-shot: register a new node
//! - `RelayOpen` → relay bi-stream splice to target peer
//!
//! Display-name renames, role transitions and node revocations are owned by
//! mlsh-control (ADR 018) — signal does not handle them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tracing::{debug, info, warn};

use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use mlsh_protocol::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};

use crate::db;

use super::listener::QuicState;

static NEXT_ID: AtomicU64 = AtomicU64::new(1_000_000);

const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_DEADLINE: Duration = Duration::from_secs(60);

/// Accept streams from a signal connection and dispatch by message type.
pub async fn handle_signal_connection(conn: quinn::Connection, state: Arc<QuicState>) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => break,
        };

        let state = state.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, &conn, &state).await {
                debug!(error = %e, "Stream handler error");
            }
        });
    }
}

/// Read the first message and dispatch accordingly.
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conn: &quinn::Connection,
    state: &QuicState,
) -> anyhow::Result<()> {
    let msg: StreamMessage = match framing::read_msg_opt(&mut recv).await? {
        Some(m) => m,
        None => return Ok(()),
    };

    match msg {
        StreamMessage::NodeAuth {
            cluster_id,
            public_key,
            protocol_version,
            client_version,
        } => {
            if let Some(resp) = check_protocol_version(protocol_version, &client_version) {
                log_protocol_reject("NodeAuth", &cluster_id, &client_version, protocol_version);
                framing::write_msg(&mut send, &resp).await.ok();
                send.finish().ok();
                return Ok(());
            }
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            run_node_session(
                id,
                &cluster_id,
                &public_key,
                &client_version,
                send,
                recv,
                conn,
                state,
            )
            .await?;
        }
        StreamMessage::Adopt {
            cluster_id,
            pre_auth_token,
            fingerprint,
            node_uuid,
            public_key: _,
            expires_at: _,
            admission_cert: _,
            protocol_version,
            client_version,
        } => {
            if let Some(resp) = check_protocol_version(protocol_version, &client_version) {
                log_protocol_reject("Adopt", &cluster_id, &client_version, protocol_version);
                framing::write_msg(&mut send, &resp).await.ok();
                send.finish().ok();
                return Ok(());
            }
            let resp = handle_adopt(
                state,
                &AdoptRequest {
                    cluster_id,
                    pre_auth_token,
                    fingerprint,
                    node_uuid,
                    client_version,
                },
            )
            .await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::RelayOpen {
            cluster_id,
            node_id,
            target_node_id,
        } => {
            super::relay::handle_relay(
                send,
                recv,
                conn,
                state,
                &cluster_id,
                &node_id,
                &target_node_id,
            )
            .await?;
            return Ok(());
        }
        StreamMessage::ExposeService {
            cluster_id,
            domain,
            target,
            mode,
        } => {
            let resp = handle_expose(state, conn, &cluster_id, &domain, &target, mode).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::UnexposeService { cluster_id, domain } => {
            let resp = handle_unexpose(state, conn, &cluster_id, &domain).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::ListExposed { cluster_id } => {
            let resp = handle_list_exposed(state, conn, &cluster_id).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::TlsAlpnChallengeSet {
            domain,
            cert_der,
            key_der,
        } => {
            let resp =
                handle_tls_alpn(state, conn, &domain, TlsAlpnOp::Set { cert_der, key_der }).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::TlsAlpnChallengeClear { domain } => {
            let resp = handle_tls_alpn(state, conn, &domain, TlsAlpnOp::Clear).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::ListNodes => {
            let resp = handle_list_nodes(state, conn).await;
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
        _ => {
            let resp = ServerMessage::error(
                "auth_required",
                "First message must be NodeAuth, Adopt, RelayOpen, ExposeService, UnexposeService, ListExposed, ListNodes, or TlsAlpnChallenge*",
            );
            framing::write_msg(&mut send, &resp).await?;
            send.finish()?;
        }
    }

    Ok(())
}

/// Reject clients that don't speak at least `MIN_PROTOCOL_VERSION`.
/// Returns `Some(ServerMessage::Error)` to send back when the client is
/// too old (caller logs and finishes the stream), or `None` to proceed.
fn check_protocol_version(client_proto: u32, client_version: &str) -> Option<ServerMessage> {
    if client_proto >= MIN_PROTOCOL_VERSION {
        return None;
    }
    let shown = if client_version.is_empty() {
        "unknown"
    } else {
        client_version
    };
    let msg = format!(
        "version too old, please update mlsh (client {shown} speaks protocol {client_proto}, signal requires >= {MIN_PROTOCOL_VERSION})"
    );
    Some(ServerMessage::error("version_too_old", &msg))
}

// --- Per-node mTLS auth

/// Long-lived session for a node authenticated via TLS client certificate.
///
/// The node's identity is its Ed25519 certificate fingerprint, extracted from
/// the QUIC connection. No shared secret (node_token) is needed — the TLS
/// handshake proves the node holds the private key.
#[allow(clippy::too_many_arguments)]
async fn run_node_session(
    id: u64,
    cluster_id: &str,
    public_key: &str,
    client_version: &str,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conn: &quinn::Connection,
    state: &QuicState,
) -> anyhow::Result<()> {
    // Extract fingerprint from the TLS client certificate.
    let fingerprint = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => {
            warn!(
                id,
                cluster_id, "No client certificate presented for NodeAuth"
            );
            let resp = ServerMessage::error("auth_failed", "Client certificate required");
            framing::write_msg(&mut send, &resp).await.ok();
            return Ok(());
        }
    };

    let node = match db::lookup_node_by_fingerprint(&state.db, cluster_id, &fingerprint).await? {
        Some(n) => n,
        None => {
            let resp = ServerMessage::error("auth_failed", "Unknown fingerprint");
            framing::write_msg(&mut send, &resp).await.ok();
            return Ok(());
        }
    };
    // The overlay IP is assigned once at adoption and persisted; NodeAuth
    // only reads it. The `nodes` row is the single source of truth.
    let overlay_ip = node.overlay_ip;
    let node_id = node.node_id;

    // Build peer list (excluding self)
    let peers = state.sessions.get_peer_list(cluster_id, &node_id).await;

    // Send auth success
    let reply = ServerMessage::NodeAuthOk {
        cluster_id: cluster_id.to_string(),
        overlay_ip: overlay_ip.to_string(),
        overlay_subnet: state.overlay_subnet.cidr.clone(),
        peers,
        zone: state.config.zone.clone(),
    };
    framing::write_msg(&mut send, &reply).await?;
    info!(
        id,
        cluster_id,
        node_id = %node_id,
        %overlay_ip,
        client_version = %client_version,
        "Node session authenticated"
    );

    // Register session + push channel
    let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<ServerMessage>>();
    state
        .sessions
        .register(
            cluster_id,
            crate::sessions::NodeSessionInfo {
                node_id: node_id.clone(),
                fingerprint: fingerprint.clone(),
                overlay_ip,
                connection: conn.clone(),
                push_tx,
                client_version: client_version.to_string(),
            },
            id,
        )
        .await;

    // Store the public key in the session so sponsor-invite verification can access it.
    if !public_key.is_empty() {
        state
            .sessions
            .set_public_key(cluster_id, &node_id, public_key)
            .await;
    }

    // Notify other peers. Build the PeerInfo from the registered session so
    // the srflx (derived from the quinn connection's remote address) is
    // included — host_candidates fill in later via ReportCandidates, which
    // triggers a re-broadcast below.
    if let Some(peer_info) = state.sessions.peer_info_for(cluster_id, &node_id).await {
        state
            .sessions
            .notify_peer_joined(cluster_id, peer_info)
            .await;
    }

    // Message loop
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut last_activity = std::time::Instant::now();

    loop {
        tokio::select! {
            msg = framing::read_msg_opt::<StreamMessage>(&mut recv) => {
                match msg {
                    Ok(Some(client_msg)) => {
                        last_activity = std::time::Instant::now();
                        match client_msg {
                            StreamMessage::Ping => {
                                let _ = framing::write_msg(&mut send, &ServerMessage::Pong).await;
                            }
                            StreamMessage::ReportCandidates { candidates } => {
                                state.sessions.set_candidates(cluster_id, &node_id, candidates).await;
                                if let Some(peer_info) = state
                                    .sessions
                                    .peer_info_for(cluster_id, &node_id)
                                    .await
                                {
                                    state.sessions.notify_peer_joined(cluster_id, peer_info).await;
                                }
                            }
                            StreamMessage::ListNodes => {
                                let online = state.sessions.online_node_ids(cluster_id).await;
                                let all_nodes = db::list_nodes(&state.db, cluster_id).await.unwrap_or_default();
                                let nodes = build_node_list(all_nodes, &online);
                                let _ = framing::write_msg(&mut send, &ServerMessage::NodeList { nodes }).await;
                            }
                            _ => {
                                debug!(id, "Ignoring message in node session");
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!(id, error = %e, "Node session read error");
                        break;
                    }
                }
            }
            push_msg = push_rx.recv() => {
                match push_msg {
                    Some(msg) => {
                        if framing::write_msg(&mut send, &msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = ping_interval.tick() => {
                if last_activity.elapsed() > PING_DEADLINE {
                    warn!(id, cluster_id, "Node timed out");
                    break;
                }
                if framing::write_msg(&mut send, &ServerMessage::Pong).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup — only notify peer_left if this session was the active one.
    // When a node reconnects, the new session replaces the old one.
    // The old session's deregister is a no-op (session_id mismatch), so we must NOT
    // broadcast peer_left or it would cancel the new session's peer_joined.
    let was_active = state.sessions.deregister(cluster_id, &node_id, id).await;

    if was_active {
        state.sessions.notify_peer_left(cluster_id, &node_id).await;
    }

    info!(id, cluster_id, node_id = %node_id, was_active, "Node session closed");
    Ok(())
}

// --- Adopt handler

struct AdoptRequest {
    cluster_id: String,
    pre_auth_token: String,
    fingerprint: String,
    node_uuid: String,
    client_version: String,
}

async fn handle_adopt(state: &QuicState, req: &AdoptRequest) -> ServerMessage {
    let cluster_id = &req.cluster_id;
    let pre_auth_token = &req.pre_auth_token;
    let fingerprint = &req.fingerprint;
    let node_uuid = &req.node_uuid;
    let client_version = &req.client_version;
    // Two adoption paths:
    // 1. One-time setup code → first node (role: admin), code is burned after use.
    // 2. Sponsor-signed invite → subsequent nodes (role from invite).

    let is_setup_code = {
        use sha2::{Digest, Sha256};
        let code_hash = format!("{:x}", Sha256::digest(pre_auth_token.as_bytes()));
        db::verify_and_burn_setup_code(&state.db, cluster_id, &code_hash)
            .await
            .unwrap_or(false)
    };

    let role = if is_setup_code {
        "admin".to_string()
    } else {
        match verify_sponsor_invite(state, cluster_id, pre_auth_token).await {
            Ok(target_role) => target_role,
            Err(e) => return ServerMessage::error("unauthorized", &e),
        }
    };

    if let Err(reason) = check_quota_with_cloud(state, cluster_id).await {
        return ServerMessage::error("quota_exceeded", &reason);
    }
    // TODO(quota-race): two concurrent adoptions can both pass; atomic increment in DB needed.

    let overlay_ip = match db::register_node_full(
        &state.db,
        &db::NodeRegistration {
            cluster_id,
            node_id: node_uuid,
            fingerprint,
            role: &role,
        },
        &state.overlay_subnet,
    )
    .await
    {
        Ok(ip) => ip,
        Err(e) => {
            warn!(error = %e, "Failed to register node");
            return ServerMessage::error("internal", &format!("Registration failed: {}", e));
        }
    };

    let peers = state.sessions.get_peer_list(cluster_id, node_uuid).await;

    info!(
        cluster_id,
        node_uuid,
        %overlay_ip,
        role,
        client_version = %client_version,
        "Node adopted"
    );

    ServerMessage::AdoptOk {
        cluster_id: cluster_id.to_string(),
        node_uuid: node_uuid.to_string(),
        overlay_ip: overlay_ip.to_string(),
        overlay_subnet: state.overlay_subnet.cidr.clone(),
        peers,
        zone: state.config.zone.clone(),
    }
}

/// Ask cloud whether this cluster can adopt one more node. Fail-closed: any
/// HTTP error or `allowed: false` short-circuits the adoption.
async fn check_quota_with_cloud(state: &QuicState, cluster_id: &str) -> Result<(), String> {
    let cloud_url = state
        .config
        .cloud_url
        .as_deref()
        .ok_or_else(|| "cloud_url not configured".to_string())?;
    let secret = state.config.cloud_api_token.as_deref().unwrap_or("");
    let url = format!(
        "{}/internal/clusters/{}/check-adoption",
        cloud_url, cluster_id
    );

    #[derive(serde::Deserialize)]
    struct Resp {
        allowed: bool,
        reason: Option<String>,
    }

    let resp = state
        .http_client
        .post(&url)
        .header("X-Internal-Secret", secret)
        .send()
        .await
        .map_err(|e| format!("cloud unreachable: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("cloud returned {}", resp.status()));
    }

    let body: Resp = resp
        .json()
        .await
        .map_err(|e| format!("invalid cloud response: {}", e))?;
    if !body.allowed {
        return Err(body.reason.unwrap_or_else(|| "quota exceeded".into()));
    }
    Ok(())
}

/// Verify a sponsor-signed invite token.
///
/// The sponsor's public key is obtained from the active session (TLS
/// connection carries the node's Ed25519 cert). This avoids storing public
/// keys in signal's DB — identity is the cert fingerprint alone.
///
/// Returns target_role on success, or error message.
async fn verify_sponsor_invite(
    state: &QuicState,
    cluster_id: &str,
    invite_token: &str,
) -> Result<String, String> {
    let invite_payload = mlsh_crypto::invite::decode_invite_payload(invite_token)
        .map_err(|e| format!("Invalid invite: {}", e))?;

    if invite_payload.cluster_id != cluster_id {
        return Err("Invite is for a different cluster".to_string());
    }

    // Verify sponsor exists and has admin role
    let sponsor = db::list_nodes(&state.db, cluster_id)
        .await
        .map_err(|_| "Database error".to_string())?
        .into_iter()
        .find(|n| n.node_id == invite_payload.sponsor_node_uuid);

    let sponsor = match sponsor {
        Some(s) => s,
        None => return Err("Sponsor node not found".to_string()),
    };

    if sponsor.role != "admin" {
        return Err("Sponsor does not have admin role".to_string());
    }

    // Get the sponsor's public key from its active session (TLS connection)
    let sponsor_public_key = state
        .sessions
        .get_public_key(cluster_id, &sponsor.node_id)
        .await
        .ok_or("Sponsor is not currently connected — cannot verify invite")?;

    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&sponsor_public_key)
        .map_err(|_| "Invalid sponsor public key encoding".to_string())?;

    mlsh_crypto::invite::verify_signed_invite(invite_token, &pubkey_bytes)
        .map_err(|e| format!("Invite signature verification failed: {}", e))?;

    Ok(invite_payload.target_role)
}

// -------------------------------------------------------------------------
// Ingress handlers
// -------------------------------------------------------------------------

/// Validate a DNS label (single `[a-z0-9][a-z0-9-]*[a-z0-9]?`, ≤63 chars).
fn is_dns_label(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Validate a domain being exposed.
///
/// Two valid shapes:
///   - `<cluster>.<zone>` exactly — reserved for the cluster's admin UI.
///   - `<label>.<cluster>.<zone>` — services hosted in the cluster.
fn validate_ingress_domain(
    cfg_zone: &str,
    cluster_name: &str,
    domain: &str,
) -> Result<(), &'static str> {
    let zone = cfg_zone.trim_end_matches('.').to_ascii_lowercase();
    let cluster = cluster_name.trim().to_ascii_lowercase();
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();

    if d.is_empty() {
        return Err("Domain must not be empty");
    }
    if cluster.is_empty() || !is_dns_label(&cluster) {
        return Err(
            "Cluster name must be DNS-safe (a-z, 0-9, '-'; no underscores) before a service can be exposed",
        );
    }

    // Bare cluster domain → admin UI.
    if d == format!("{}.{}", cluster, zone) {
        return Ok(());
    }

    let suffix = format!(".{}.{}", cluster, zone);
    if !d.ends_with(&suffix) {
        return Err("Domain must be <cluster>.<zone> or <label>.<cluster>.<zone>");
    }
    let label = &d[..d.len() - suffix.len()];
    if label.is_empty() {
        return Err("Subdomain label cannot be empty");
    }
    // Reject ACME-challenge spoofing and admin-reserved names in the leaf.
    const RESERVED: &[&str] = &["signal", "api", "www", "ns1", "ns2", "ingress"];
    if RESERVED.contains(&label) || label.starts_with("_acme-challenge") {
        return Err("Domain is reserved");
    }
    for part in label.split('.') {
        if !is_dns_label(part) {
            return Err("Subdomain label must be DNS-safe");
        }
    }
    Ok(())
}

async fn resolve_caller(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
) -> Result<db::NodeRecord, ServerMessage> {
    let caller_fp = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => {
            return Err(ServerMessage::error(
                "auth_failed",
                "Client certificate required",
            ))
        }
    };
    match db::lookup_node_by_fingerprint(&state.db, cluster_id, &caller_fp).await {
        Ok(Some(n)) => Ok(n),
        Ok(None) => Err(ServerMessage::error("auth_failed", "Unknown fingerprint")),
        Err(e) => {
            warn!(error = %e, "DB error looking up caller");
            Err(ServerMessage::error("internal", "Database error"))
        }
    }
}

async fn handle_expose(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    domain: &str,
    target: &str,
    mode: mlsh_protocol::types::IngressMode,
) -> ServerMessage {
    // L4 ingress mode is not implemented yet; reject explicitly.
    if matches!(mode, mlsh_protocol::types::IngressMode::L4) {
        return ServerMessage::error("unsupported", "L4 ingress mode is not implemented yet");
    }

    let caller = match resolve_caller(state, conn, cluster_id).await {
        Ok(n) => n,
        Err(e) => return e,
    };

    let cluster_name = match db::get_cluster_name_by_id(&state.db, cluster_id).await {
        Ok(Some(n)) => n,
        Ok(None) => return ServerMessage::error("not_found", "Cluster not found"),
        Err(e) => return db_err(e, "Failed to look up cluster name"),
    };

    if let Err(reason) = validate_ingress_domain(&state.config.zone, &cluster_name, domain) {
        return ServerMessage::error("invalid_request", reason);
    }

    // Sanity-check the target URL (http://host:port form; the peer will parse
    // further). We just want to reject obvious garbage here.
    if target.is_empty() || !(target.starts_with("http://") || target.starts_with("https://")) {
        return ServerMessage::error("invalid_request", "target must be http:// or https:// URL");
    }

    let mode_str = "http";
    let ok = match db::insert_ingress_route(
        &state.db,
        &domain.to_ascii_lowercase(),
        cluster_id,
        &caller.node_id,
        target,
        mode_str,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return db_err(e, "Failed to insert ingress route"),
    };
    if !ok {
        return ServerMessage::error(
            "conflict",
            "Domain is already registered by another cluster or node",
        );
    }

    info!(
        cluster_id,
        node_id = %caller.node_id,
        domain,
        target,
        "Ingress route registered"
    );

    ServerMessage::ExposeOk {
        domain: domain.to_ascii_lowercase(),
        public_mode: "relay".into(),
        public_ip: None,
    }
}

async fn handle_unexpose(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    domain: &str,
) -> ServerMessage {
    let caller = match resolve_caller(state, conn, cluster_id).await {
        Ok(n) => n,
        Err(e) => return e,
    };

    let d = domain.to_ascii_lowercase();

    let route = match db::lookup_ingress_route_by_domain(&state.db, &d).await {
        Ok(Some(r)) => r,
        Ok(None) => return ServerMessage::error("not_found", "Domain not found"),
        Err(e) => return db_err(e, "DB error looking up ingress route"),
    };
    if route.cluster_id != cluster_id {
        return ServerMessage::error("not_found", "Domain not found");
    }
    if route.node_id != caller.node_id {
        return ServerMessage::error("forbidden", "Only the owning node may unexpose");
    }

    let removed = match db::delete_ingress_route(&state.db, cluster_id, &d).await {
        Ok(b) => b,
        Err(e) => return db_err(e, "Failed to delete ingress route"),
    };
    if !removed {
        return ServerMessage::error("not_found", "Domain not found");
    }

    info!(cluster_id, domain = %d, caller = %caller.node_id, "Ingress route removed");
    ServerMessage::UnexposeOk
}

/// Handler for `ListNodes` as a one-shot first-stream message (used by
/// `mlsh-control` via mlshtund's Unix socket — no long-lived session).
/// Authentication is by TLS client certificate; cluster is derived from the
/// caller's fingerprint.
async fn handle_list_nodes(state: &QuicState, conn: &quinn::Connection) -> ServerMessage {
    let caller_fp = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => return ServerMessage::error("auth_failed", "Client certificate required"),
    };

    let caller = match db::lookup_node_by_fingerprint_any_cluster(&state.db, &caller_fp).await {
        Ok(Some(n)) => n,
        Ok(None) => return ServerMessage::error("auth_failed", "Unknown fingerprint"),
        Err(e) => return db_err(e, "Failed to look up caller for list_nodes"),
    };

    let online = state.sessions.online_node_ids(&caller.cluster_id).await;
    let all_nodes = match db::list_nodes(&state.db, &caller.cluster_id).await {
        Ok(rows) => rows,
        Err(e) => return db_err(e, "Failed to list nodes"),
    };

    ServerMessage::NodeList {
        nodes: build_node_list(all_nodes, &online),
    }
}

async fn handle_list_exposed(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
) -> ServerMessage {
    // Authenticate the caller; any node in the cluster can list.
    if let Err(e) = resolve_caller(state, conn, cluster_id).await {
        return e;
    }

    match db::list_ingress_routes(&state.db, cluster_id).await {
        Ok(rows) => {
            let routes = rows
                .into_iter()
                .map(|r| mlsh_protocol::types::IngressRoute {
                    domain: r.domain,
                    target: r.target,
                    node_id: r.node_id,
                    mode: match r.mode.as_str() {
                        "l4" => mlsh_protocol::types::IngressMode::L4,
                        _ => mlsh_protocol::types::IngressMode::Http,
                    },
                    public_mode: r.public_mode,
                    public_ip: r.public_ip,
                })
                .collect();
            ServerMessage::ExposedList { routes }
        }
        Err(e) => db_err(e, "Failed to list ingress routes"),
    }
}

enum TlsAlpnOp {
    Set { cert_der: Vec<u8>, key_der: Vec<u8> },
    Clear,
}

async fn handle_tls_alpn(
    state: &QuicState,
    conn: &quinn::Connection,
    domain: &str,
    op: TlsAlpnOp,
) -> ServerMessage {
    let d = domain.to_ascii_lowercase();
    let route = match db::lookup_ingress_route_by_domain(&state.db, &d).await {
        Ok(Some(r)) => r,
        Ok(None) => return ServerMessage::error("not_found", "No ingress route for this domain"),
        Err(e) => return db_err(e, "DB error on TLS-ALPN-01 op"),
    };
    let caller = match resolve_caller(state, conn, &route.cluster_id).await {
        Ok(n) => n,
        Err(e) => return e,
    };
    if caller.node_id != route.node_id {
        let msg = match op {
            TlsAlpnOp::Set { .. } => "Only the domain owner may publish TLS-ALPN-01 challenges",
            TlsAlpnOp::Clear => "Only the domain owner may clear TLS-ALPN-01 challenges",
        };
        return ServerMessage::error("forbidden", msg);
    }

    match op {
        TlsAlpnOp::Set { cert_der, key_der } => {
            if cert_der.is_empty() || key_der.is_empty() {
                return ServerMessage::error("invalid_request", "cert and key must be non-empty");
            }
            crate::acme_tls::set(&d, cert_der, key_der);
        }
        TlsAlpnOp::Clear => crate::acme_tls::clear(&d),
    }
    ServerMessage::TlsAlpnChallengeOk { domain: d }
}

/// Convert a DB error into a generic `ServerMessage::error("internal", ...)` after logging it.
fn db_err(e: anyhow::Error, ctx: &str) -> ServerMessage {
    warn!(error = %e, "{}", ctx);
    ServerMessage::error("internal", "Database error")
}

fn build_node_list(
    rows: Vec<db::NodeRecord>,
    online: &std::collections::HashSet<String>,
) -> Vec<mlsh_protocol::types::NodeInfo> {
    rows.into_iter()
        .map(|n| mlsh_protocol::types::NodeInfo {
            online: online.contains(&n.node_id),
            node_id: n.node_id,
            overlay_ip: n.overlay_ip.to_string(),
            has_admission_cert: false,
        })
        .collect()
}

fn log_protocol_reject(
    op: &'static str,
    cluster_id: &str,
    client_version: &str,
    client_protocol: u32,
) {
    warn!(
        cluster_id,
        client_version,
        client_protocol,
        server_protocol = PROTOCOL_VERSION,
        "Rejecting {}: client protocol too old",
        op
    );
}

/// Extract the SHA-256 fingerprint from the peer's TLS client certificate.
pub fn extract_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let peer_certs = conn.peer_identity()?;
    let certs = peer_certs
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let cert = certs.first()?;
    Some(mlsh_crypto::identity::compute_fingerprint(cert.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::validate_ingress_domain;

    #[test]
    fn accepts_cluster_scoped_subdomain() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "app.homelab.mlsh.io").is_ok());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "APP.homelab.mlsh.io").is_ok());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "foo-bar.homelab.mlsh.io").is_ok());
    }

    #[test]
    fn accepts_deep_subdomain() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "a.b.homelab.mlsh.io").is_ok());
    }

    #[test]
    fn rejects_cross_cluster_attempt() {
        // Caller is in "homelab" but tries to register under another cluster.
        assert!(validate_ingress_domain("mlsh.io", "homelab", "app.work.mlsh.io").is_err());
    }

    #[test]
    fn rejects_unscoped_domain() {
        // Under the new scheme, a flat `app.mlsh.io` with no cluster label is invalid.
        assert!(validate_ingress_domain("mlsh.io", "homelab", "app.mlsh.io").is_err());
    }

    #[test]
    fn rejects_apex_but_accepts_bare_cluster() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "mlsh.io").is_err());
        // Bare <cluster>.<zone> is the admin-UI domain.
        assert!(validate_ingress_domain("mlsh.io", "homelab", "homelab.mlsh.io").is_ok());
    }

    #[test]
    fn rejects_non_zone() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "app.homelab.example.com").is_err());
    }

    #[test]
    fn rejects_reserved_leaf_names() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "signal.homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "api.homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "www.homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "ns1.homelab.mlsh.io").is_err());
    }

    #[test]
    fn rejects_acme_challenge_spoofing() {
        assert!(
            validate_ingress_domain("mlsh.io", "homelab", "_acme-challenge.homelab.mlsh.io")
                .is_err()
        );
    }

    #[test]
    fn rejects_bad_characters() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", "-bad.homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "bad-.homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "bad_.homelab.mlsh.io").is_err());
    }

    #[test]
    fn rejects_empty_label() {
        assert!(validate_ingress_domain("mlsh.io", "homelab", ".homelab.mlsh.io").is_err());
        assert!(validate_ingress_domain("mlsh.io", "homelab", "").is_err());
    }

    #[test]
    fn rejects_cluster_with_invalid_dns_chars() {
        // Underscores are not DNS-safe — expose must fail rather than produce
        // a broken domain.
        assert!(
            validate_ingress_domain("mlsh.io", "my_cluster", "app.my_cluster.mlsh.io").is_err()
        );
        assert!(validate_ingress_domain("mlsh.io", "", "app.mlsh.io").is_err());
    }
}
