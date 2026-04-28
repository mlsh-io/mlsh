//! `mlsh nodes <cluster>` — list all nodes in a cluster.

use anyhow::Result;
use colored::Colorize;
use mlsh_protocol::control::{ControlRequest, ControlResponse};

use crate::tund::control::client::DaemonClient;

pub async fn handle_nodes(cluster_name: &str) -> Result<()> {
    let mut client = DaemonClient::connect_default().await?;
    let resp = client
        .control_call(cluster_name, &ControlRequest::ListNodes)
        .await?;

    let nodes = match resp {
        ControlResponse::Nodes { nodes } => nodes,
        ControlResponse::Error { code, message } => {
            anyhow::bail!("control error: {message} ({code})");
        }
        other => anyhow::bail!("unexpected control response: {other:?}"),
    };

    if nodes.is_empty() {
        println!("{}", "No nodes in this cluster.".dimmed());
        return Ok(());
    }

    println!(
        "{:<36} {:<8} {:<8} DISPLAY NAME",
        "NODE UUID", "ROLE", "STATUS"
    );

    for node in &nodes {
        let status_str = if node.status == "active" {
            node.status.green().to_string()
        } else {
            node.status.red().to_string()
        };
        let label = if node.display_name.is_empty() {
            &node.node_uuid[..node.node_uuid.len().min(36)]
        } else {
            &node.display_name
        };
        println!(
            "{:<36} {:<8} {:<8} {}",
            &node.node_uuid[..node.node_uuid.len().min(36)],
            node.role,
            status_str,
            label,
        );
    }

    let active = nodes.iter().filter(|n| n.status == "active").count();
    println!(
        "\n{} node(s), {} active",
        nodes.len(),
        active.to_string().bold()
    );

    Ok(())
}
