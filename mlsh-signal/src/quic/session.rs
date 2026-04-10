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
            node_id,
            public_key,
            expires_at,
        } => {
            let resp = handle_adopt(
                state,
                &cluster_id,
                &pre_auth_token,
                &fingerprint,
                &node_id,
                &public_key,
                expires_at,
            )
            .await;
            protocol::write_message(&mut send, &resp).await?;
            send.finish()?;
        }
        StreamMessage::Revoke {
            cluster_id,
            target_node_id,
        } => {
            let resp = handle_revoke(state, conn, &cluster_id, &target_node_id).await;
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
                "First message must be NodeAuth, Adopt, Revoke, or RelayOpen",
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
            warn!(id, cluster_id, "No client certificate presented for NodeAuth");
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
        db::update_node_public_key(&state.db, &cluster_id, &node.node_id, &public_key)
            .await
            .ok();
    }

    // Allocate a fresh overlay IP from the current subnet (no persistent leases)
    let overlay_ip =
        db::allocate_ip(&state.db, &cluster_id, &node.node_id, &state.overlay_subnet).await?;

    // Build peer list (excluding self)
    let peers = state
        .sessions
        .get_peer_list(&cluster_id, &node.node_id)
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

    // Register session + push channel
    let (push_tx, mut push_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<ServerMessage>>();
    state
        .sessions
        .register(
            &cluster_id,
            crate::sessions::NodeSessionInfo {
                node_id: node.node_id.clone(),
                fingerprint: fingerprint.clone(),
                overlay_ip,
                connection: conn.clone(),
                push_tx,
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
        admission_cert: node.admission_cert.clone(),
    };
    state
        .sessions
        .notify_peer_joined(&cluster_id, peer_info)
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
                                state.sessions.set_candidates(&cluster_id, &node.node_id, candidates).await;
                            }
                            StreamMessage::ListNodes => {
                                let online = state.sessions.online_node_ids(&cluster_id).await;
                                let all_nodes = db::list_nodes(&state.db, &cluster_id).await.unwrap_or_default();
                                let nodes: Vec<protocol::NodeInfo> = all_nodes.into_iter().map(|n| {
                                    protocol::NodeInfo {
                                        node_id: n.node_id.clone(),
                                        overlay_ip: n.overlay_ip.to_string(),
                                        role: n.role,
                                        online: online.contains(&n.node_id),
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
        .deregister(&cluster_id, &node.node_id, id)
        .await;

    if was_active {
        state
            .sessions
            .notify_peer_left(&cluster_id, &node.node_id)
            .await;
    }

    info!(id, cluster_id, node_id = %node.node_id, was_active, "Node session closed");
    Ok(())
}

// --- Adopt handler

async fn handle_adopt(
    state: &QuicState,
    cluster_id: &str,
    pre_auth_token: &str,
    fingerprint: &str,
    node_id: &str,
    public_key: &str,
    _expires_at: u64,
) -> ServerMessage {
    // Two adoption paths:
    // 1. cluster_secret → first node setup (role: admin)
    // 2. sponsor-signed invite → subsequent nodes (role from invite)

    let is_cluster_secret = state
        .config
        .cluster_secret
        .as_deref()
        .is_some_and(|secret| pre_auth_token == secret);

    let (role, sponsored_by, admission_cert_json) = if is_cluster_secret {
        // First node — becomes admin, self-signed admission cert.
        // The node's key_pem isn't available on signal, so we generate
        // a placeholder. The real self-signed cert is created client-side
        // and stored in the AdoptOk response flow.
        // For now, signal stores the fact that this is a root admin.
        ("admin".to_string(), String::new(), String::new())
    } else {
        // Sponsor-signed Ed25519 invite — build admission cert from it
        match verify_sponsor_invite(state, cluster_id, pre_auth_token).await {
            Ok((target_role, sponsor_id)) => {
                let cert = mlsh_crypto::invite::build_sponsored_admission_cert(
                    node_id,
                    fingerprint,
                    cluster_id,
                    &target_role,
                    &sponsor_id,
                    pre_auth_token,
                );
                let cert_json = serde_json::to_string(&cert).unwrap_or_default();
                (target_role, sponsor_id, cert_json)
            }
            Err(e) => {
                return ServerMessage::error("unauthorized", &e);
            }
        }
    };

    // Register the node with role, sponsor, and admission cert
    let overlay_ip = match db::register_node_full(
        &state.db,
        cluster_id,
        node_id,
        fingerprint,
        public_key,
        &role,
        &sponsored_by,
        &admission_cert_json,
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

    let peers = state.sessions.get_peer_list(cluster_id, node_id).await;

    info!(cluster_id, node_id, %overlay_ip, role, "Node adopted");

    ServerMessage::AdoptOk {
        cluster_id: cluster_id.to_string(),
        node_id: node_id.to_string(),
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
    // Try to decode and verify the signed invite
    // First, we need to extract the sponsor_node_id to look up their public key
    let invite_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(invite_token)
        .map_err(|_| "Invalid invite encoding".to_string())?;

    let signed: mlsh_crypto::invite::SignedInvite =
        serde_json::from_slice(&invite_json).map_err(|_| "Invalid invite format".to_string())?;

    // Verify cluster_id matches
    if signed.payload.cluster_id != cluster_id {
        return Err("Invite is for a different cluster".to_string());
    }

    // Look up the sponsor in the DB
    let sponsor = db::list_nodes(&state.db, cluster_id)
        .await
        .map_err(|_| "Database error".to_string())?
        .into_iter()
        .find(|n| n.node_id == signed.payload.sponsor_node_id);

    let sponsor = match sponsor {
        Some(s) => s,
        None => return Err("Sponsor node not found".to_string()),
    };

    // Verify sponsor has admin role
    if sponsor.role != "admin" {
        return Err("Sponsor does not have admin role".to_string());
    }

    // Verify the signature using the sponsor's public key
    // For now, we use the stored public_key field. If empty (migration), fall back to
    // HMAC verification for backward compat.
    if sponsor.public_key.is_empty() {
        // Fallback: try HMAC verification with cluster_secret
        if let Some(secret) = state.config.cluster_secret.as_deref() {
            if mlsh_crypto::invite::verify_invite(secret, invite_token, signed.payload.expires_at) {
                return Ok((signed.payload.target_role, signed.payload.sponsor_node_id));
            }
        }
        return Err("Sponsor has no public key and HMAC verification failed".to_string());
    }

    // Decode the public key
    let pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&sponsor.public_key)
        .map_err(|_| "Invalid sponsor public key encoding".to_string())?;

    // Verify the full signed invite
    mlsh_crypto::invite::verify_signed_invite(invite_token, &pubkey_bytes)
        .map_err(|e| format!("Invite signature verification failed: {}", e))?;

    Ok((signed.payload.target_role, signed.payload.sponsor_node_id))
}

// --- Revoke handler

async fn handle_revoke(
    state: &QuicState,
    conn: &quinn::Connection,
    cluster_id: &str,
    target_node_id: &str,
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

    match db::remove_node(&state.db, cluster_id, target_node_id).await {
        Ok(true) => {
            // Kick the node's active session (closes QUIC connection)
            state.sessions.kick_node(cluster_id, target_node_id).await;
            state
                .sessions
                .notify_peer_left(cluster_id, target_node_id)
                .await;
            info!(cluster_id, target_node_id, "Node revoked");
            ServerMessage::RevokeOk
        }
        Ok(false) => ServerMessage::error("not_found", "Node not found"),
        Err(e) => {
            warn!(error = %e, "Failed to remove node");
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
