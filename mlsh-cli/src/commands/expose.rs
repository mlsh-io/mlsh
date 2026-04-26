//! `mlsh expose` / `mlsh unexpose` / `mlsh exposed`.
//!
//! Routed through mlshtund's Unix socket (ADR-030). The daemon performs the
//! expose end-to-end: signal-side route registration plus the local ingress
//! mapping and ACME issuance, atomically per request.

use anyhow::Result;
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

pub async fn handle_expose(
    cluster: &str,
    target: &str,
    domain: &str,
    email: Option<&str>,
    acme_staging: bool,
) -> Result<()> {
    println!(
        "Exposing {} as {} in cluster {}...",
        target.bold(),
        domain.bold(),
        cluster.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client
        .expose(cluster, domain, target, email, acme_staging)
        .await?;

    match resp {
        DaemonResponse::ExposeOk {
            domain,
            public_mode,
            public_ip,
        } => {
            let ip_line = public_ip
                .as_deref()
                .map(|ip| format!(" (via {})", ip))
                .unwrap_or_default();
            println!(
                "{}",
                format!(
                    "Exposed: https://{}  [mode: {}]{}",
                    domain, public_mode, ip_line
                )
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

pub async fn handle_unexpose(cluster: &str, domain: &str) -> Result<()> {
    println!(
        "Removing {} from cluster {}...",
        domain.bold(),
        cluster.bold()
    );

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.unexpose(cluster, domain).await?;

    match resp {
        DaemonResponse::Ok { .. } => {
            println!("{}", format!("Unexposed {}.", domain).green().bold());
            Ok(())
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    }
}

pub async fn handle_list_exposed(cluster: &str) -> Result<()> {
    let mut client = DaemonClient::connect_default().await?;
    let resp = client.list_exposed(cluster).await?;

    let routes = match resp {
        DaemonResponse::ExposedList { routes } => routes,
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    };

    if routes.is_empty() {
        println!("No services exposed in cluster {}.", cluster.bold());
        return Ok(());
    }
    println!(
        "{:<32}  {:<10}  {:<28}  {:<16}",
        "DOMAIN".bold(),
        "MODE".bold(),
        "TARGET".bold(),
        "NODE".bold()
    );
    for r in &routes {
        let mode_colored = if r.public_mode == "direct" {
            r.public_mode.green()
        } else {
            r.public_mode.yellow()
        };
        println!(
            "{:<32}  {:<10}  {:<28}  {:<16}",
            r.domain,
            mode_colored,
            r.target,
            short_id(&r.node_id)
        );
    }
    Ok(())
}

fn short_id(id: &str) -> &str {
    let cut = 8.min(id.len());
    &id[..cut]
}
