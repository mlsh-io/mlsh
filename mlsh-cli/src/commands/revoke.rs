//! `mlsh revoke <cluster> <node>` — admin only.

use anyhow::Result;
use colored::Colorize;
use mlsh_protocol::control::{ControlRequest, ControlResponse};

use crate::tund::control::client::DaemonClient;

pub async fn handle_revoke(cluster_name: &str, target_node: &str) -> Result<()> {
    println!(
        "Revoking node {} from cluster {}...",
        target_node.bold(),
        cluster_name.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client
        .control_call(
            cluster_name,
            &ControlRequest::Revoke {
                target_node_uuid: target_node.to_string(),
            },
        )
        .await?;

    match resp {
        ControlResponse::Ok => {
            println!(
                "{}",
                format!("Node '{}' revoked.", target_node).green().bold()
            );
            Ok(())
        }
        ControlResponse::Error { code, message } => anyhow::bail!("{message} ({code})"),
        other => anyhow::bail!("unexpected control response: {other:?}"),
    }
}
