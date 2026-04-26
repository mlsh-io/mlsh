//! `mlsh revoke <cluster> <node>` — remove a node from the cluster (admin only).
//!
//! Routed through mlshtund's Unix socket (ADR-030).

use anyhow::Result;
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

pub async fn handle_revoke(cluster_name: &str, target_node: &str) -> Result<()> {
    println!(
        "Revoking node {} from cluster {}...",
        target_node.bold(),
        cluster_name.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.revoke(cluster_name, target_node).await?;

    match resp {
        DaemonResponse::Ok { .. } => {
            println!(
                "{}",
                format!("Node '{}' revoked.", target_node).green().bold()
            );
            Ok(())
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    }
}
