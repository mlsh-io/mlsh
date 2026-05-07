//! `mlsh rename <cluster> <node> <name>`.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::commands::control_client;
use crate::generated::types::SetNameRequest;

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    println!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
        cluster_name.bold()
    );

    let (client, _config) = control_client::for_cluster(cluster_name)?;
    client
        .set_name(
            target_node,
            &SetNameRequest {
                display_name: new_name.to_string(),
            },
        )
        .await
        .context("POST /api/v1/nodes/{node}/name failed")?;

    println!(
        "{}",
        format!("Node '{}' renamed to '{}'.", target_node, new_name)
            .green()
            .bold()
    );
    Ok(())
}
