//! `mlsh promote <cluster> <node> --role <admin|node>`.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::commands::control_client;
use crate::generated::types::SetRoleRequest;

pub async fn handle_promote(cluster_name: &str, target_node: &str, role: &str) -> Result<()> {
    if role != "admin" && role != "node" {
        anyhow::bail!("Invalid role '{}'. Must be 'admin' or 'node'.", role);
    }

    let action = if role == "admin" {
        "Promoting"
    } else {
        "Demoting"
    };
    println!("{} node {} to {}...", action, target_node.bold(), role);

    let (client, _config) = control_client::for_cluster(cluster_name)?;
    client
        .set_role(
            target_node,
            &SetRoleRequest {
                role: role.to_string(),
            },
        )
        .await
        .context("POST /api/v1/nodes/{node}/role failed")?;

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
