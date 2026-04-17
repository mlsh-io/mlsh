//! `mlsh nodes <cluster>` — list all nodes in a cluster with online/offline status.

use anyhow::{Context, Result};
use colored::Colorize;

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

    use mlsh_protocol::framing;
    use mlsh_protocol::messages::{ServerMessage, StreamMessage};

    // Authenticate
    let auth_msg = StreamMessage::NodeAuth {
        cluster_id: creds.cluster_id.clone(),
        public_key: creds.public_key.clone(),
    };
    framing::write_msg(&mut send, &auth_msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    match &resp {
        ServerMessage::NodeAuthOk { .. } => {}
        ServerMessage::Error { code, message } => {
            anyhow::bail!("Signal auth failed: {} ({})", message, code);
        }
        other => anyhow::bail!("Unexpected signal response: {:?}", other),
    }

    // Send list_nodes request
    framing::write_msg(&mut send, &StreamMessage::ListNodes).await?;

    // Read response — skip push messages (peer_joined, peer_left, pong)
    let nodes = loop {
        let msg: ServerMessage = framing::read_msg(&mut recv).await?;
        match msg {
            ServerMessage::NodeList { nodes } => break nodes,
            ServerMessage::Error { code, message } => {
                anyhow::bail!("Failed to list nodes: {} ({})", message, code);
            }
            // Ignore push messages
            _ => continue,
        }
    };

    conn.close(quinn::VarInt::from_u32(0), b"done");

    // Display
    if nodes.is_empty() {
        println!("{}", "No nodes in this cluster.".dimmed());
        return Ok(());
    }

    println!(
        "{:<24} {:<18} {:<8} {:<8} STATUS",
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
        // Show display_name when set, fall back to node_id.
        let label = if node.display_name.is_empty() {
            node.node_id.as_str()
        } else {
            node.display_name.as_str()
        };
        println!(
            "{:<24} {:<18} {:<8} {:<8} {}",
            label, node.overlay_ip, node.role, cert, status
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

use crate::quic::client::{connect_to_signal, resolve_addr};
