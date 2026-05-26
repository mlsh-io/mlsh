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
    #[serde(default)]
    online: bool,
    #[serde(default)]
    overlay_ip: String,
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
        "{:<36} {:<8} {:<12} {:<14} DISPLAY NAME",
        "NODE UUID", "ROLE", "STATUS", "OVERLAY IP",
    );

    for node in &nodes {
        let status_str = if node.status != "active" {
            node.status.red().to_string()
        } else if node.online {
            "online".green().to_string()
        } else {
            "offline".dimmed().to_string()
        };
        let overlay_ip = if node.overlay_ip.is_empty() {
            "-".dimmed().to_string()
        } else {
            node.overlay_ip.clone()
        };
        let label = if node.display_name.is_empty() {
            &node.id[..node.id.len().min(36)]
        } else {
            &node.display_name
        };
        println!(
            "{:<36} {:<8} {:<21} {:<23} {}",
            &node.id[..node.id.len().min(36)],
            node.role,
            status_str,
            overlay_ip,
            label,
        );
    }

    let online = nodes
        .iter()
        .filter(|n| n.status == "active" && n.online)
        .count();
    let offline = nodes
        .iter()
        .filter(|n| n.status == "active" && !n.online)
        .count();
    println!(
        "\n{} node(s), {} online, {} offline",
        nodes.len(),
        online.to_string().bold(),
        offline.to_string().bold(),
    );

    Ok(())
}
