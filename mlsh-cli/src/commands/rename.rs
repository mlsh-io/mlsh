//! `mlsh rename <cluster> <node> <name>` — change a node's display name (admin only).
//!
//! Routed through mlshtund's Unix socket (ADR-030).

use anyhow::Result;
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    println!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
        cluster_name.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.rename(cluster_name, target_node, new_name).await?;

    match resp {
        DaemonResponse::Ok { .. } => {
            println!(
                "{}",
                format!("Node '{}' renamed to '{}'.", target_node, new_name)
                    .green()
                    .bold()
            );
            Ok(())
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    }
}
