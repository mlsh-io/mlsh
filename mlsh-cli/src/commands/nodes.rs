//! `mlsh nodes <cluster>` — list all nodes in a cluster with online/offline status.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

use crate::tund::tunnel::load_cluster_config;

pub async fn handle_nodes(cluster_name: &str) -> Result<()> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;
    let creds = config.signal_credentials()?;

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&creds.signal_endpoint)?;
    let conn = connect_to_signal(
        addr,
        &creds.signal_endpoint,
        &creds.signal_fingerprint,
        &identity,
    )
    .await?;

    // Open a bidirectional stream
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    // Authenticate
    let auth_msg = serde_json::json!({
        "type": "node_auth",
        "cluster_id": creds.cluster_id,
        "public_key": creds.public_key,
    });
    write_msg(&mut send, &auth_msg).await?;

    // Read auth response
    let resp: serde_json::Value = read_msg(&mut recv).await?;
    let msg_type = resp.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if msg_type == "error" {
        let msg = resp
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        anyhow::bail!("Signal auth failed: {}", msg);
    }
    if msg_type != "node_auth_ok" {
        anyhow::bail!("Unexpected signal response: {}", msg_type);
    }

    // Send list_nodes request
    write_msg(&mut send, &serde_json::json!({"type": "list_nodes"})).await?;

    // Read response — skip push messages (peer_joined, peer_left, pong) that
    // signal sends on the session stream before our node_list reply arrives.
    let resp = loop {
        let msg: serde_json::Value = read_msg(&mut recv).await?;
        let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match msg_type {
            "node_list" => break msg,
            "error" => {
                let err = msg
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                anyhow::bail!("Failed to list nodes: {}", err);
            }
            // Ignore push messages (peer_joined, peer_left, pong, etc.)
            _ => continue,
        }
    };

    #[derive(Deserialize)]
    struct NodeInfo {
        node_id: String,
        overlay_ip: String,
        role: String,
        online: bool,
        #[serde(default)]
        has_admission_cert: bool,
    }

    let nodes: Vec<NodeInfo> = serde_json::from_value(
        resp.get("nodes")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![])),
    )?;

    conn.close(quinn::VarInt::from_u32(0), b"done");

    // Display
    if nodes.is_empty() {
        println!("{}", "No nodes in this cluster.".dimmed());
        return Ok(());
    }

    println!(
        "{:<20} {:<18} {:<8} {:<8} STATUS",
        "NODE", "OVERLAY IP", "ROLE", "CERT"
    );

    for node in &nodes {
        let status = if node.online {
            "online".green().to_string()
        } else {
            "offline".red().to_string()
        };
        let cert = if node.has_admission_cert {
            "ok".green().to_string()
        } else {
            "none".yellow().to_string()
        };
        println!(
            "{:<20} {:<18} {:<8} {:<8} {}",
            node.node_id, node.overlay_ip, node.role, cert, status
        );
    }

    let online = nodes.iter().filter(|n| n.online).count();
    println!(
        "\n{} node(s), {} online",
        nodes.len(),
        online.to_string().bold()
    );

    Ok(())
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
