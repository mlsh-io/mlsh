//! `mlsh revoke <cluster> <node>` — admin only.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::commands::control_client;
use crate::output;

pub async fn handle_revoke(cluster_name: &str, target_node: &str) -> Result<()> {
    crate::step!(
        "Revoking node {} from cluster {}...",
        target_node.bold(),
        cluster_name.bold()
    );

    let (http, base_url, _config) = control_client::for_cluster(cluster_name)?;
    http.post(format!("{}/api/v1/nodes/{}/revoke", base_url, target_node))
        .send()
        .await
        .context("POST /api/v1/nodes/{node}/revoke failed")?
        .error_for_status()
        .context("POST /api/v1/nodes/{node}/revoke returned error")?;

    output::emit(
        &serde_json::json!({ "cluster": cluster_name, "node": target_node }),
        || {
            println!(
                "{}",
                format!("Node '{}' revoked.", target_node).green().bold()
            )
        },
    );
    Ok(())
}
