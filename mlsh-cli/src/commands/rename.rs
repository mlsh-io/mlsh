//! `mlsh rename <cluster> <node> <name>`.

use anyhow::Result;
use colored::Colorize;
use mlsh_protocol::control::{ControlRequest, ControlResponse};

use crate::tund::control::client::DaemonClient;

pub async fn handle_rename(cluster_name: &str, target_node: &str, new_name: &str) -> Result<()> {
    println!(
        "Renaming node {} to {} in cluster {}...",
        target_node.bold(),
        new_name.bold(),
        cluster_name.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client
        .control_call(
            cluster_name,
            &ControlRequest::Rename {
                target_node_uuid: target_node.to_string(),
                new_display_name: new_name.to_string(),
            },
        )
        .await?;

    match resp {
        ControlResponse::Ok => {
            println!(
                "{}",
                format!("Node '{}' renamed to '{}'.", target_node, new_name)
                    .green()
                    .bold()
            );
            Ok(())
        }
        ControlResponse::Error { code, message } => anyhow::bail!("{message} ({code})"),
        other => anyhow::bail!("unexpected control response: {other:?}"),
    }
}
