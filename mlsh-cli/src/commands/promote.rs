//! `mlsh promote <cluster> <node> --role <admin|node>` — change a node's role (admin only).

use anyhow::{Context, Result};
use colored::Colorize;

use crate::quic::client::{connect_to_signal, resolve_addr};
use crate::tund::tunnel::load_cluster_config;

pub async fn handle_promote(cluster_name: &str, target_node: &str, role: &str) -> Result<()> {
    if role != "admin" && role != "node" {
        anyhow::bail!("Invalid role '{}'. Must be 'admin' or 'node'.", role);
    }

    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let action = if role == "admin" {
        "Promoting"
    } else {
        "Demoting"
    };
    println!("{} node {} to {}...", action, target_node.bold(), role);

    // Build admission cert for the new role (signed by us as sponsor)
    let admission_cert = mlsh_crypto::invite::build_sponsored_admission_cert(
        target_node,
        "",
        &config.cluster_id,
        role,
        &config.node_id,
        "",
    );
    let admission_cert_json = serde_json::to_string(&admission_cert)?;

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

    let msg = StreamMessage::Promote {
        cluster_id: config.cluster_id.clone(),
        target_node_id: target_node.to_string(),
        new_role: role.to_string(),
        admission_cert: admission_cert_json,
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::PromoteOk => {
            let done = if role == "admin" {
                "promoted to admin"
            } else {
                "demoted to node"
            };
            println!(
                "{}",
                format!("Node '{}' {}.", target_node, done).green().bold()
            );
            Ok(())
        }
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

