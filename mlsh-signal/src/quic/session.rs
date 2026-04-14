//! QUIC stream handler for the `mlsh-signal` ALPN.
//!
//! Each connection may open multiple bidirectional streams. The first message
//! on each stream determines its type:
//! - `NodeAuth` → long-lived session (peer updates, candidates)
//! - `Adopt` → one-shot: register a new node
//! - `Revoke` → one-shot: remove a node
//! - `RelayOpen` → relay bi-stream splice to target peer

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tracing::{debug, info, warn};

use crate::db;
use crate::protocol::{self, ServerMessage, StreamMessage};

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
    let msg: StreamMessage = match protocol::read_message(&mut recv).await? {
        Some(m) => m,
        None => return Ok(()),
    };

    match msg {
        StreamMessage::NodeAuth {
            cluster_id,
            public_key,
        } => {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            run_node_session(id, &cluster_id, &public_key, send, recv, conn, state).await?;
        }
        StreamMessage::Adopt {
            cluster_id,
            pre_auth_token,
            fingerprint,
            node_uuid,
            display_name,
            public_key,
            expires_at: _,
            admission_cert,
        } => {
            let resp = handle_adopt(
                state,
                &AdoptRequest {
                    cluster_id,
                    pre_auth_token,
                    fingerprint,
                    node_uuid,
                    display_name,
                    public_key,
                    admission_cert,
                },
            )
            .await;
            protocol::write_message(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::Revoke {
            cluster_id,
            target_name,
        } => {
            let resp = handle_revoke(state, conn, &cluster_id, &target_name).await;
            protocol::write_message(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::Rename {
            cluster_id,
            target_name,
            new_display_name,
        } => {
            let resp =
                handle_rename(state, conn, &cluster_id, &target_name, &new_display_name).await;
            protocol::write_message(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::Promote {
            cluster_id,
            target_node_id,
            new_role,
            admission_cert,
        } => {
            let resp = handle_promote(
                state,
                conn,
                &cluster_id,
                &target_node_id,
                &new_role,
                &admission_cert,
            )
            .await;
            protocol::write_message(&mut send, &resp).await?;
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
        _ => {
            let resp = ServerMessage::error(
                "auth_required",
                "First message must be NodeAuth, Adopt, Revoke, Rename, or RelayOpen",
            );
            protocol::write_message(&mut send, &resp).await?;
            send.finish()?;
        }
    }

    Ok(())
}

// --- Per-node mTLS auth

/// Long-lived session for a node authenticated via TLS client certificate.
///
/// The node's identity is its Ed25519 certificate fingerprint, extracted from
/// the QUIC connection. No shared secret (node_token) is needed — the TLS
/// handshake proves the node holds the private key.
async fn run_node_session(
    id: u64,
    cluster_id: &str,
    public_key: &str,
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
            protocol::write_message(&mut send, &resp).await.ok();
            return Ok(());
        }
    };

    // Verify the node exists in the registry
    let node = match db::lookup_node_by_fingerprint(&state.db, cluster_id, &fingerprint).await? {
        Some(n) => n,
        None => {
            let resp = ServerMessage::error("auth_failed", "Unknown fingerprint");
            protocol::write_message(&mut send, &resp).await.ok();
            return Ok(());
        }
    };

    // Update public_key if the node sent one and it was previously empty
    if !public_key.is_empty() && node.public_key.is_empty() {
        db::update_node_public_key(&state.db, cluster_id, &node.node_id, public_key)
            .await
            .ok();
    }

    // Allocate a fresh overlay IP from the current subnet (no persistent leases)
    let overlay_ip =
        db::allocate_ip(&state.db, cluster_id, &node.node_id, &state.overlay_subnet).await?;

    // Build peer list (excluding self)
    let peers = state
        .sessions
        .get_peer_list(cluster_id, &node.node_id)
        .await;

    // Send auth success
    let reply = ServerMessage::NodeAuthOk {
        cluster_id: cluster_id.to_string(),
        overlay_ip: overlay_ip.to_string(),
        overlay_subnet: state.overlay_subnet.cidr.clone(),
        peers,
    };
    protocol::write_message(&mut send, &reply).await?;
    info!(id, cluster_id, node_id = %node.node_id, %overlay_ip, "Node session authenticated");
    db::audit(
        &state.db,
        cluster_id,
        "auth",
        &node.node_id,
        "session started",
    )
    .await;

    // Register session + push channel
    let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<ServerMessage>>();
    state
        .sessions
        .register(
            cluster_id,
            crate::sessions::NodeSessionInfo {
                node_id: node.node_id.clone(),
                fingerprint: fingerprint.clone(),
                overlay_ip,
                display_name: node.display_name.clone(),
                connection: conn.clone(),
                push_tx,
                public_key: node.public_key.clone(),
                admission_cert: node.admission_cert.clone(),
            },
            id,
        )
        .await;

    // Notify other peers
    let peer_info = crate::protocol::PeerInfo {
        node_id: node.node_id.clone(),
        fingerprint: fingerprint.clone(),
        overlay_ip: overlay_ip.to_string(),
        candidates: Vec::new(),
        public_key: node.public_key.clone(),
        admission_cert: node.admission_cert.clone(),
        display_name: node.display_name.clone(),
    };
    state
        .sessions
        .notify_peer_joined(cluster_id, peer_info)
        .await;

    // Message loop
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut last_activity = std::time::Instant::now();

    loop {
        tokio::select! {
            msg = protocol::read_message::<StreamMessage>(&mut recv) => {
                match msg {
                    Ok(Some(client_msg)) => {
                        last_activity = std::time::Instant::now();
                        match client_msg {
                            StreamMessage::Ping => {
                                let _ = protocol::write_message(&mut send, &ServerMessage::Pong).await;
                            }
                            StreamMessage::ReportCandidates { candidates } => {
                                state.sessions.set_candidates(cluster_id, &node.node_id, candidates).await;
                            }
                            StreamMessage::ListNodes => {
                                let online = state.sessions.online_node_ids(cluster_id).await;
                                let all_nodes = db::list_nodes(&state.db, cluster_id).await.unwrap_or_default();
                                let nodes: Vec<protocol::NodeInfo> = all_nodes.into_iter().map(|n| {
                                    protocol::NodeInfo {
                                        node_id: n.node_id.clone(),
                                        overlay_ip: n.overlay_ip.to_string(),
                                        role: n.role,
                                        online: online.contains(&n.node_id),
                                        has_admission_cert: !n.admission_cert.is_empty(),
                                        display_name: n.display_name,
                                    }
                                }).collect();
                                let _ = protocol::write_message(&mut send, &ServerMessage::NodeList { nodes }).await;
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
                        if protocol::write_message(&mut send, &msg).await.is_err() {
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
                if protocol::write_message(&mut send, &ServerMessage::Pong).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup — only notify peer_left if this session was the active one.
    // When a node reconnects, the new session replaces the old one.
    // The old session's deregister is a no-op (session_id mismatch), so we must NOT
    // broadcast peer_left or it would cancel the new session's peer_joined.
    let was_active = state
        .sessions
        .deregister(cluster_id, &node.node_id, id)
        .await;

    if was_active {
        state
            .sessions
            .notify_peer_left(cluster_id, &node.node_id)
            .await;
    }

    info!(id, cluster_id, node_id = %node.node_id, was_active, "Node session closed");
    Ok(())
}

// --- Adopt handler

struct AdoptRequest {
    cluster_id: String,
    pre_auth_token: String,
    fingerprint: String,
    node_uuid: String,
    display_name: String,
    public_key: String,
    admission_cert: String,
}

async fn handle_adopt(state: &QuicState, req: &AdoptRequest) -> ServerMessage {
    let cluster_id = &req.cluster_id;
    let pre_auth_token = &req.pre_auth_token;
    let fingerprint = &req.fingerprint;
    let node_uuid = &req.node_uuid;
    let display_name = &req.display_name;
    let public_key = &req.public_key;
    let client_admission_cert = &req.admission_cert;
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

    let (role, sponsored_by, admission_cert_json) = if is_setup_code {
        // First node — becomes admin via one-time setup code (now burned).
        // The client sends a self-signed admission cert.
        (
            "admin".to_string(),
            String::new(),
            client_admission_cert.to_string(),
        )
    } else {
        // Sponsor-signed Ed25519 invite — build admission cert from it
        match verify_sponsor_invite(state, cluster_id, pre_auth_token).await {
            Ok((target_role, sponsor_uuid)) => {
                let cert = mlsh_crypto::invite::build_sponsored_admission_cert(
                    node_uuid,
                    fingerprint,
                    cluster_id,
                    &target_role,
                    &sponsor_uuid,
                    pre_auth_token,
                );
                let cert_json = serde_json::to_string(&cert).unwrap_or_default();
                (target_role, sponsor_uuid, cert_json)
            }
            Err(e) => {
                return ServerMessage::error("unauthorized", &e);
            }
        }
    };

    // Register the node with role, sponsor, admission cert, and display name
    let overlay_ip = match db::register_node_full(
        &state.db,
        &db::NodeRegistration {
            cluster_id,
            node_id: node_uuid,
            fingerprint,
            public_key,
            role: &role,
            sponsored_by: &sponsored_by,
            admission_cert: &admission_cert_json,
            display_name,
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

    info!(cluster_id, node_uuid, %overlay_ip, role, "Node adopted");
    db::audit(
        &state.db,
        cluster_id,
        "adopt",
        node_uuid,
        &format!("role={}, sponsor={}", role, sponsored_by),
    )
    .await;

    ServerMessage::AdoptOk {
        cluster_id: cluster_id.to_string(),
        node_uuid: node_uuid.to_string(),
        display_name: display_name.to_string(),
        overlay_ip: overlay_ip.to_string(),
        overlay_subnet: state.overlay_subnet.cidr.clone(),
        peers,
    }
}

/// Verify a sponsor-signed invite token.
/// Returns (target_role, sponsor_node_id) on success, or error message.
async fn verify_sponsor_invite(
    state: &QuicState,
    cluster_id: &str,
    invite_token: &str,
) -> Result<(String, String), String> {
    // Decode the invite payload to extract sponsor_node_id (before signature verification)
    let invite_payload = mlsh_crypto::invite::decode_invite_payload(invite_token)
        .map_err(|e| format!("Invalid invite: {}", e))?;

    // Verify cluster_id matches
    if invite_payload.cluster_id != cluster_id {
        return Err("Invite is for a different cluster".to_string());
    }

    // Look up the sponsor in the DB
    let sponsor = db::list_nodes(&state.db, cluster_id)
        .await
        .map_err(|_| "Database error".to_string())?
        .into_iter()
        .find(|n| n.node_id == invite_payload.sponsor_node_uuid);

    let sponsor = match sponsor {
        Some(s) => s,
        None => return Err("Sponsor node not found".to_string()),
    };

    // Verify sponsor has admin role
    if sponsor.role != "admin" {
        return Err("Sponsor does not have admin role".to_string());
    }

    // Verify the signature using the sponsor's public key
    if sponsor.public_key.is_empty() {
        return Err("Sponsor has no public key — cannot verify invite signature".to_string());
    }

    // Decode the public key
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&sponsor.public_key)
        .map_err(|_| "Invalid sponsor public key encoding".to_string())?;

    // Verify the full signed invite
    mlsh_crypto::invite::verify_signed_invite(invite_token, &pubkey_bytes)
        .map_err(|e| format!("Invite signature verification failed: {}", e))?;

    Ok((invite_payload.target_role, invite_payload.sponsor_node_uuid))
}

// --- Revoke handler

/// `target_name` is the display name of the node to revoke.
/// It is resolved to the internal UUID via `lookup_node_by_display_name`.
async fn handle_revoke(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    target_name: &str,
) -> ServerMessage {
    // Authenticate the caller via TLS client certificate
    let caller_fp = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => return ServerMessage::error("auth_failed", "Client certificate required"),
    };

    let caller = match db::lookup_node_by_fingerprint(&state.db, cluster_id, &caller_fp).await {
        Ok(Some(n)) => n,
        Ok(None) => return ServerMessage::error("auth_failed", "Unknown fingerprint"),
        Err(e) => {
            warn!(error = %e, "Failed to look up caller for revoke");
            return ServerMessage::error("internal", "Database error");
        }
    };

    if caller.role != "admin" {
        return ServerMessage::error("forbidden", "Only admin nodes can revoke");
    }

    // Resolve display name → node UUID
    let target_uuid =
        match db::lookup_node_by_display_name(&state.db, cluster_id, target_name).await {
            Ok(Some(n)) => n.node_id,
            Ok(None) => return ServerMessage::error("not_found", "Node not found"),
            Err(e) => {
                warn!(error = %e, "Failed to look up target node for revoke");
                return ServerMessage::error("internal", "Database error");
            }
        };

    match db::remove_node(&state.db, cluster_id, &target_uuid).await {
        Ok(true) => {
            // Kick the node's active session (closes QUIC connection)
            state.sessions.kick_node(cluster_id, &target_uuid).await;
            state
                .sessions
                .notify_peer_left(cluster_id, &target_uuid)
                .await;
            info!(cluster_id, target_name, target_uuid, "Node revoked");
            db::audit(
                &state.db,
                cluster_id,
                "revoke",
                &target_uuid,
                &format!("target_name={}, by={}", target_name, caller.node_id),
            )
            .await;
            ServerMessage::RevokeOk
        }
        Ok(false) => ServerMessage::error("not_found", "Node not found"),
        Err(e) => {
            warn!(error = %e, "Failed to remove node");
            ServerMessage::error("internal", "Database error")
        }
    }
}

// --- Rename handler

/// Rename a node's display name.
///
/// `target_name` is the current display name used to locate the node.
/// `new_display_name` must be 1–64 characters matching `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`.
///
/// Admin nodes may rename peers or peers themselves. On success, the in-memory session and all
/// connected peers are updated via a `PeerRenamed` broadcast.
async fn handle_rename(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    target_name: &str,
    new_display_name: &str,
) -> ServerMessage {
    // Authenticate caller via TLS client certificate
    let caller_fp = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => return ServerMessage::error("auth_failed", "Client certificate required"),
    };

    let caller = match db::lookup_node_by_fingerprint(&state.db, cluster_id, &caller_fp).await {
        Ok(Some(n)) => n,
        Ok(None) => return ServerMessage::error("auth_failed", "Unknown fingerprint"),
        Err(e) => {
            warn!(error = %e, "Failed to look up caller for rename");
            return ServerMessage::error("internal", "Database error");
        }
    };

    // Validate new_display_name: 1–64 chars, starts with alnum, rest alnum/._-
    if new_display_name.is_empty() || new_display_name.len() > 64 {
        return ServerMessage::error("invalid_request", "Display name must be 1–64 characters");
    }
    let valid = {
        let mut chars = new_display_name.chars();
        chars
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    };
    if !valid {
        return ServerMessage::error(
            "invalid_request",
            "Display name must match ^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
        );
    }

    // Resolve target_name → node UUID
    let target_uuid =
        match db::lookup_node_by_display_name(&state.db, cluster_id, target_name).await {
            Ok(Some(n)) => n.node_id,
            Ok(None) => return ServerMessage::error("not_found", "Target node not found"),
            Err(e) => {
                warn!(error = %e, "Failed to look up target node for rename");
                return ServerMessage::error("internal", "Database error");
            }
        };

    // Only admins or the node itself can rename
    if caller.role != "admin" && caller.node_id != target_uuid {
        return ServerMessage::error("forbidden", "Only admin nodes can rename others; non-admin nodes can only rename themselves");
    }

    // Persist the rename (unique constraint enforced by DB)
    match db::rename_node(&state.db, cluster_id, &target_uuid, new_display_name).await {
        Ok(true) => {}
        Ok(false) => {
            return ServerMessage::error(
                "conflict",
                "Display name already in use or node not found",
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to rename node");
            return ServerMessage::error("internal", "Database error");
        }
    }

    // Update in-memory session
    state
        .sessions
        .update_node_display_name(cluster_id, &target_uuid, new_display_name)
        .await;

    // Broadcast to all connected peers
    state
        .sessions
        .notify_peer_renamed(cluster_id, &target_uuid, new_display_name)
        .await;

    info!(
        cluster_id,
        target_name,
        target_uuid,
        new_display_name,
        caller = %caller.node_id,
        "Node renamed"
    );
    db::audit(
        &state.db,
        cluster_id,
        "rename",
        &target_uuid,
        &format!(
            "from={}, to={}, by={}",
            target_name, new_display_name, caller.node_id
        ),
    )
    .await;

    ServerMessage::RenameOk {
        display_name: new_display_name.to_string(),
    }
}

// --- Promote handler

async fn handle_promote(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    target_node_id: &str,
    new_role: &str,
    admission_cert: &str,
) -> ServerMessage {
    // Validate role
    if new_role != "admin" && new_role != "node" {
        return ServerMessage::error("invalid_request", "Role must be 'admin' or 'node'");
    }

    // Authenticate the caller via TLS client certificate
    let caller_fp = match extract_peer_fingerprint(conn) {
        Some(fp) => fp,
        None => return ServerMessage::error("auth_failed", "Client certificate required"),
    };

    let caller = match db::lookup_node_by_fingerprint(&state.db, cluster_id, &caller_fp).await {
        Ok(Some(n)) => n,
        Ok(None) => return ServerMessage::error("auth_failed", "Unknown fingerprint"),
        Err(e) => {
            warn!(error = %e, "Failed to look up caller for promote");
            return ServerMessage::error("internal", "Database error");
        }
    };

    if caller.role != "admin" {
        return ServerMessage::error("forbidden", "Only admin nodes can change roles");
    }

    // Prevent demoting the last admin
    if new_role == "node" {
        match db::count_admins(&state.db, cluster_id).await {
            Ok(count) if count <= 1 => {
                return ServerMessage::error(
                    "forbidden",
                    "Cannot demote the last admin — cluster would be locked",
                );
            }
            Err(e) => {
                warn!(error = %e, "Failed to count admins");
                return ServerMessage::error("internal", "Database error");
            }
            _ => {}
        }
    }

    // Update the node's role and admission cert
    match db::update_node_role(
        &state.db,
        cluster_id,
        target_node_id,
        new_role,
        admission_cert,
    )
    .await
    {
        Ok(true) => {
            info!(cluster_id, target_node_id, new_role, caller = %caller.node_id, "Node role updated");
            db::audit(
                &state.db,
                cluster_id,
                "promote",
                target_node_id,
                &format!("role={}, by={}", new_role, caller.node_id),
            )
            .await;

            // Broadcast PeerUpdated to all connected peers
            let msg = ServerMessage::PeerUpdated {
                node_id: target_node_id.to_string(),
                cluster_id: cluster_id.to_string(),
                new_role: new_role.to_string(),
                admission_cert: admission_cert.to_string(),
            };
            state.sessions.broadcast(cluster_id, msg).await;

            ServerMessage::PromoteOk
        }
        Ok(false) => ServerMessage::error("not_found", "Node not found"),
        Err(e) => {
            warn!(error = %e, "Failed to update node role");
            ServerMessage::error("internal", "Database error")
        }
    }
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
