//! `mlsh promote <cluster> <node> --role <admin|node>`.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use crate::commands::control_client;
use crate::output;

#[derive(Serialize)]
struct SetRoleBody<'a> {
    role: &'a str,
}

pub async fn handle_promote(cluster_name: &str, target_node: &str, role: &str) -> Result<()> {
    if role != "admin" && role != "node" {
        anyhow::bail!("Invalid role '{}'. Must be 'admin' or 'node'.", role);
    }

    let action = if role == "admin" {
        "Promoting"
    } else {
        "Demoting"
    };
    crate::step!("{} node {} to {}...", action, target_node.bold(), role);

    let (http, base_url, _config) = control_client::for_cluster(cluster_name)?;
    http.post(format!("{}/api/v1/nodes/{}/role", base_url, target_node))
        .json(&SetRoleBody { role })
        .send()
        .await
        .context("POST /api/v1/nodes/{node}/role failed")?
        .error_for_status()
        .context("POST /api/v1/nodes/{node}/role returned error")?;

    let done = if role == "admin" {
        "promoted to admin"
    } else {
        "demoted to node"
    };
    output::emit(
        &serde_json::json!({ "cluster": cluster_name, "node": target_node, "role": role }),
        || {
            println!(
                "{}",
                format!("Node '{}' {}.", target_node, done).green().bold()
            )
        },
    );
    Ok(())
}
