//! `mlsh promote <cluster> <node> --role <admin|node>` — change a node's role (admin only).
//!
//! Routed through mlshtund's Unix socket (ADR-030). The legacy local
//! admission-cert generation has been dropped: signal no longer stores
//! admission certs, and peer-side cert verification will be reintroduced
//! through a daemon-mediated path in a future iteration.

use anyhow::Result;
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

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

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.promote(cluster_name, target_node, role).await?;

    match resp {
        DaemonResponse::Ok { .. } => {
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
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    }
}
