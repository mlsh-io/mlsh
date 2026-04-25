//! `mlsh nodes <cluster>` — list all nodes in a cluster.
//!
//! Routed through mlshtund's Unix socket so the CLI doesn't open its own
//! QUIC connection (ADR-030: single QUIC peer per node).

use anyhow::Result;
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

pub async fn handle_nodes(cluster_name: &str) -> Result<()> {
    let mut client = DaemonClient::connect_default().await?;
    let resp = client.list_nodes(cluster_name).await?;

    let nodes = match resp {
        DaemonResponse::NodeList { nodes } => nodes,
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    };

    if nodes.is_empty() {
        println!("{}", "No nodes in this cluster.".dimmed());
        return Ok(());
    }

    println!("{:<24} {:<18} {:<8} STATUS", "NODE", "OVERLAY IP", "ROLE");

    for node in &nodes {
        let status = if node.online {
            "online".green().to_string()
        } else {
            "offline".red().to_string()
        };
        let label = if node.display_name.is_empty() {
            node.node_id.as_str()
        } else {
            node.display_name.as_str()
        };
        println!(
            "{:<24} {:<18} {:<8} {}",
            label, node.overlay_ip, node.role, status
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
