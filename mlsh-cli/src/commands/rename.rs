//! `mlsh rename <cluster> <node> <name>` — change a node's display name (admin only).

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::tunnel::load_cluster_config;

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    println!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
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

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    use mlsh_protocol::framing;
    use mlsh_protocol::messages::{ServerMessage, StreamMessage};

    let msg = StreamMessage::Rename {
        cluster_id: config.cluster_id.clone(),
        target_name: target_node.to_string(),
        new_display_name: new_name.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::RenameOk { display_name } => {
            println!(
                "{}",
                format!("Node '{}' renamed to '{}'.", target_node, display_name)
                    .green()
                    .bold()
            );
            Ok(())
        }
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

use crate::quic::client::{connect_to_signal, resolve_addr};
