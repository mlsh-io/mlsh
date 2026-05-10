//! `mlsh nodes <cluster>` — list all nodes in a cluster.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

use crate::commands::control_client;

#[derive(Deserialize)]
struct NodeResponse {
    id: String,
    display_name: String,
    role: String,
    status: String,
}

pub async fn handle_nodes(cluster_name: &str) -> Result<()> {
    let (http, base_url, _config) = control_client::for_cluster(cluster_name)?;

    let nodes: Vec<NodeResponse> = http
        .get(format!("{}/api/v1/nodes", base_url))
        .send()
        .await
        .context("GET /api/v1/nodes failed")?
        .error_for_status()
        .context("GET /api/v1/nodes returned error")?
        .json()
        .await
        .context("decode /api/v1/nodes response")?;

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
