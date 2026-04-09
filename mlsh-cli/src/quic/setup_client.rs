//! QUIC setup client for connecting to an unconfigured MLSH node.
//!
//! Derives the expected server public key from the setup code, connects via QUIC
//! with a custom TLS verifier, and exchanges the bootstrap or join payload.

use super::verifier::SetupCodeVerifier;
use anyhow::{Context, Result};
use mlsh_protocol::framing;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

const ALPN_SETUP: &[u8] = b"mlsh-setup";

/// Setup payload sent from CLI to backend (mirrors backend's SetupPayload).
#[derive(Debug, Serialize)]
#[serde(tag = "mode")]
pub enum SetupPayload {
    #[serde(rename = "bootstrap")]
    Bootstrap {
        cluster_name: String,
        hostname: String,
        admin_username: String,
        admin_password: String,
    },
    #[serde(rename = "join")]
    Join {
        hostname: String,
        join_token: String,
        leader_url: String,
    },
}

/// Response from the backend after setup.
#[derive(Debug, Deserialize)]
pub struct QuicSetupResponse {
    pub success: bool,
    pub message: String,
    pub cluster_id: Option<String>,
    pub cluster_name: Option<String>,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    /// For join mode: the node's CSR PEM.
    pub csr_pem: Option<String>,
    /// For join mode: the node's identifier.
    pub node_id: Option<String>,
    /// Overlay IP assigned to this peer.
    pub overlay_ip: Option<String>,
}

/// Message sent to the joiner after the leader signs its CSR.
#[derive(Debug, Serialize)]
pub struct JoinCompleteMessage {
    pub ca_cert: String,
    pub signed_cert: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_ip: Option<String>,
}

/// Connect to a QUIC setup endpoint using the setup code for server verification.
pub async fn connect_setup(addr: SocketAddr, setup_code: &str) -> Result<quinn::Connection> {
    let verifier = SetupCodeVerifier::new(setup_code);

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    tls_config.alpn_protocols = vec![ALPN_SETUP.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC client TLS config")?,
    ));

    let bind_addr: std::net::SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr, "mlsh-setup")
        .context("Failed to initiate QUIC connection")?
        .await
        .context("QUIC handshake failed (wrong setup code?)")?;

    Ok(connection)
}

/// Perform the bootstrap setup over an established QUIC connection.
pub async fn do_bootstrap_setup(
    conn: &quinn::Connection,
    payload: SetupPayload,
) -> Result<QuicSetupResponse> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open bidirectional stream")?;

    framing::write_msg(&mut send, &payload)
        .await
        .context("Failed to send setup payload")?;

    send.finish().context("Failed to finish send stream")?;

    let response: QuicSetupResponse = framing::read_msg(&mut recv)
        .await
        .context("Failed to read setup response")?;

    Ok(response)
}

/// Perform the join flow over an established QUIC connection.
///
/// Two-phase exchange:
/// 1. Send `SetupPayload::Join` → receive CSR from joiner
/// 2. Send `JoinCompleteMessage` (signed cert from leader) → receive ack
///
/// Between phases 1 and 2, the caller must get the CSR signed by the leader.
pub async fn do_join_phase1(
    conn: &quinn::Connection,
    hostname: &str,
) -> Result<(QuicSetupResponse, quinn::SendStream, quinn::RecvStream)> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open bidirectional stream")?;

    let payload = SetupPayload::Join {
        hostname: hostname.to_string(),
        // These fields are not used by the joiner (ADR-011: token never sent to joiner)
        join_token: String::new(),
        leader_url: String::new(),
    };

    framing::write_msg(&mut send, &payload)
        .await
        .context("Failed to send join request")?;

    let response: QuicSetupResponse = framing::read_msg(&mut recv)
        .await
        .context("Failed to read join response (CSR)")?;

    Ok((response, send, recv))
}

/// Complete the join by sending the signed cert to the joiner.
pub async fn do_join_phase2(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    complete: JoinCompleteMessage,
) -> Result<QuicSetupResponse> {
    framing::write_msg(send, &complete)
        .await
        .context("Failed to send signed certificate to joiner")?;

    let ack: QuicSetupResponse = framing::read_msg(recv)
        .await
        .context("Failed to read join completion ack")?;

    send.finish().context("Failed to finish send stream")?;

    Ok(ack)
}

/// Response from the leader's POST /api/v1/cluster/invite endpoint.
#[derive(Debug, Deserialize)]
pub struct InviteResponse {
    pub join_token: String,
    pub expires_in: u64,
}

/// Response from the leader's POST /api/v1/cluster/join endpoint.
#[derive(Debug, Deserialize)]
pub struct JoinClusterResponse {
    pub success: bool,
    pub ca_cert: String,
    pub signed_cert: String,
    pub cluster_id: Option<String>,
    pub cluster_name: Option<String>,
    pub overlay_ip: Option<String>,
}
