//! `mlsh rename <cluster> <node> <name>`.

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Serialize;

use crate::commands::control_client;
use crate::output;

#[derive(Serialize)]
struct SetNameBody<'a> {
    display_name: &'a str,
}

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    crate::step!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
        cluster_name.bold()
    );

    let (http, base_url, _config) = control_client::for_cluster(cluster_name)?;
    http.post(format!("{}/api/v1/nodes/{}/name", base_url, target_node))
        .json(&SetNameBody {
            display_name: new_name,
        })
        .send()
        .await
        .context("POST /api/v1/nodes/{node}/name failed")?
        .error_for_status()
        .context("POST /api/v1/nodes/{node}/name returned error")?;

    output::emit(
        &serde_json::json!({ "cluster": cluster_name, "node": target_node, "name": new_name }),
        || {
            println!(
                "{}",
                format!("Node '{}' renamed to '{}'.", target_node, new_name)
                    .green()
                    .bold()
            )
        },
    );
    Ok(())
}
