//! `mlsh revoke <cluster> <node>` — admin only.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::commands::control_client;

pub async fn handle_revoke(cluster_name: &str, target_node: &str) -> Result<()> {
    println!(
        "Revoking node {} from cluster {}...",
        target_node.bold(),
        cluster_name.bold()
    );

    let (client, _config) = control_client::for_cluster(cluster_name)?;
    client
        .revoke(target_node)
        .await
        .context("POST /api/v1/nodes/{node}/revoke failed")?;

    println!(
        "{}",
        format!("Node '{}' revoked.", target_node).green().bold()
    );
    Ok(())
}
