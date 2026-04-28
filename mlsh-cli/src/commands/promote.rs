//! `mlsh promote <cluster> <node> --role <admin|node>`.

use anyhow::Result;
use colored::Colorize;
use mlsh_protocol::control::{ControlRequest, ControlResponse};

use crate::tund::control::client::DaemonClient;

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
    let resp = client
        .control_call(
            cluster_name,
            &ControlRequest::Promote {
                target_node_uuid: target_node.to_string(),
                new_role: role.to_string(),
            },
        )
        .await?;

    match resp {
        ControlResponse::Ok => {
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
        ControlResponse::Error { code, message } => anyhow::bail!("{message} ({code})"),
        other => anyhow::bail!("unexpected control response: {other:?}"),
    }
}
