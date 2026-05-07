//! `mlsh nodes <cluster>` — list all nodes in a cluster.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::commands::control_client;

pub async fn handle_nodes(cluster_name: &str) -> Result<()> {
    let (client, _config) = control_client::for_cluster(cluster_name)?;

    let nodes = client
        .list_nodes()
        .await
        .context("GET /api/v1/nodes failed")?
        .into_inner();

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
            &node.id[..node.id.len().min(36)]
        } else {
            &node.display_name
        };
        println!(
            "{:<36} {:<8} {:<8} {}",
            &node.id[..node.id.len().min(36)],
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
