//! `mlsh revoke <cluster> <node>` — remove a node from the cluster (admin only).

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::tunnel::load_cluster_config;

pub async fn handle_revoke(cluster_name: &str, target_node: &str) -> Result<()> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    println!(
        "Revoking node {} from cluster {}...",
        target_node.bold(),
        config.name.bold()
    );

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&config.signal_endpoint)?;
    let conn = connect_to_signal(
        addr,
        &config.signal_endpoint,
        &config.signal_fingerprint,
        &identity,
    )
    .await?;

    // Revoke is a one-shot message (no session needed)
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    let msg = serde_json::json!({
        "type": "revoke",
        "cluster_id": config.cluster_id,
        "target_node_id": target_node,
    });
    write_msg(&mut send, &msg).await?;

    let resp: serde_json::Value = read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    let msg_type = resp.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match msg_type {
        "revoke_ok" => {
            println!(
                "{}",
                format!("Node '{}' revoked.", target_node).green().bold()
            );
            Ok(())
        }
        "error" => {
            let code = resp.get("code").and_then(|c| c.as_str()).unwrap_or("");
            let message = resp
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            anyhow::bail!("{} ({})", message, code)
        }
        _ => anyhow::bail!("Unexpected response: {}", msg_type),
    }
}

// --- QUIC helpers

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Serialize;

async fn connect_to_signal(
    addr: SocketAddr,
    endpoint_str: &str,
    signal_fingerprint: &str,
    identity: &mlsh_crypto::identity::NodeIdentity,
) -> Result<quinn::Connection> {
    let cert_der = mlsh_crypto::identity::pem_to_der_pub(&identity.cert_pem)
        .map_err(|e| anyhow::anyhow!("Invalid cert PEM: {}", e))?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls_pemfile::private_key(&mut identity.key_pem.as_bytes())
        .context("Failed to parse identity key")?
        .context("No private key in PEM")?;

    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            crate::quic::verifier::FingerprintVerifier::new(signal_fingerprint),
        ))
        .with_client_auth_cert(vec![cert], key)
        .context("Failed to set client auth cert")?;
    tls_config.alpn_protocols = vec![b"mlsh-signal".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .context("Failed to create QUIC TLS config")?,
    ));

    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let sni_host = endpoint_str.split(':').next().unwrap_or(endpoint_str);

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect(addr, sni_host)?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timed out connecting to signal"))?
    .context("Failed to connect to signal")?;

    Ok(conn)
}

fn resolve_addr(endpoint: &str) -> Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = endpoint.rsplit_once(':').unwrap_or((endpoint, "4433"));
    let port: u16 = port.parse().unwrap_or(4433);
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .or_else(|| {
            (host, port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
        })
        .context(format!("Failed to resolve: {}", endpoint))
}

async fn write_msg<T: Serialize>(send: &mut quinn::SendStream, msg: &T) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&json).await?;
    Ok(())
}

async fn read_msg<T: serde::de::DeserializeOwned>(recv: &mut quinn::RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1_048_576 {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
