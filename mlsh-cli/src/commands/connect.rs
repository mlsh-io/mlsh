//! `mlsh connect <cluster>` — connect to a cluster's overlay network.
//!
//! Default: thin client that sends a `Connect` request to the `mlshtund` daemon.
//! With `--foreground`: runs the tunnel directly in this process (bypass daemon).

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::client::DaemonClient;
use crate::tund::protocol::{DaemonResponse, TunnelState};

pub async fn handle_connect(name: &str, foreground: bool) -> Result<()> {
    let cluster_name = resolve_cluster_name(name)?;

    if foreground {
        return handle_connect_foreground(&cluster_name).await;
    }

    // Load cluster config and identity from user's config dir
    let config_dir = crate::config::config_dir()?;
    let cluster_file = config_dir
        .join("clusters")
        .join(format!("{}.toml", cluster_name));
    let config_toml = std::fs::read_to_string(&cluster_file).with_context(|| {
        format!(
            "Cluster '{}' not found. Run 'mlsh setup' or 'mlsh adopt' first.",
            cluster_name
        )
    })?;

    let identity_dir = config_dir.join("identity");
    let cert_pem = std::fs::read_to_string(identity_dir.join("cert.pem"))
        .context("Missing identity certificate. Run 'mlsh setup' or 'mlsh adopt' first.")?;
    let key_pem = std::fs::read_to_string(identity_dir.join("key.pem"))
        .context("Missing identity key. Run 'mlsh setup' or 'mlsh adopt' first.")?;

    // Send config + identity to daemon
    let mut client = DaemonClient::connect_default().await?;
    let resp = client
        .connect_cluster(&cluster_name, &config_toml, &cert_pem, &key_pem)
        .await?;

    match resp {
        DaemonResponse::Ok { message } => {
            let msg = message.unwrap_or_else(|| "Connected".into());
            println!("{}", msg.green().bold());
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        DaemonResponse::Status { .. } | DaemonResponse::NodeList { .. } => {
            anyhow::bail!("Unexpected daemon response");
        }
    }

    Ok(())
}

pub async fn handle_disconnect(name: &str) -> Result<()> {
    let cluster_name = resolve_cluster_name(name)?;

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.disconnect_cluster(&cluster_name).await?;

    match resp {
        DaemonResponse::Ok { message } => {
            let msg = message.unwrap_or_else(|| "Disconnected".into());
            println!("{}", msg.green().bold());
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        DaemonResponse::Status { .. } | DaemonResponse::NodeList { .. } => {
            anyhow::bail!("Unexpected daemon response");
        }
    }

    Ok(())
}

pub async fn handle_status() -> Result<()> {
    let mut client = DaemonClient::connect_default().await?;
    let resp = client.status().await?;

    match resp {
        DaemonResponse::Status { tunnels } => {
            if tunnels.is_empty() {
                println!("{}", "No active tunnels.".dimmed());
                return Ok(());
            }

            println!(
                "{:<12} {:<14} {:<10} {:<16} {:<10} TX/RX",
                "CLUSTER", "STATE", "TRANSPORT", "OVERLAY IP", "UPTIME"
            );

            for t in &tunnels {
                let state_str = match t.state {
                    TunnelState::Connected => t.state.to_string().green().to_string(),
                    TunnelState::Connecting | TunnelState::Reconnecting => {
                        t.state.to_string().yellow().to_string()
                    }
                    TunnelState::Disconnected => t.state.to_string().red().to_string(),
                };

                let transport = t.transport.as_deref().unwrap_or("-");
                let ip = t.overlay_ip.as_deref().unwrap_or("-");
                let uptime = t
                    .uptime_secs
                    .map(format_uptime)
                    .unwrap_or_else(|| "-".into());
                let traffic = format_bytes(t.bytes_tx, t.bytes_rx);

                println!(
                    "{:<12} {:<14} {:<10} {:<16} {:<10} {}",
                    t.cluster, state_str, transport, ip, uptime, traffic
                );

                if let Some(ref err) = t.last_error {
                    println!("  {}", format!("Error: {}", err).red());
                }
            }
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        DaemonResponse::Ok { .. } | DaemonResponse::NodeList { .. } => {
            anyhow::bail!("Unexpected daemon response");
        }
    }

    Ok(())
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn format_bytes(tx: u64, rx: u64) -> String {
    fn human(b: u64) -> String {
        if b < 1024 {
            format!("{} B", b)
        } else if b < 1024 * 1024 {
            format!("{:.1} KB", b as f64 / 1024.0)
        } else if b < 1024 * 1024 * 1024 {
            format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.1} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
    format!("{} / {}", human(tx), human(rx))
}

// --- Foreground mode

async fn handle_connect_foreground(cluster_name: &str) -> Result<()> {
    use crate::tund::tunnel::{load_cluster_config, ManagedTunnel};

    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    println!(
        "{}",
        format!(
            "Connecting to cluster \"{}\" (foreground mode)...",
            config.name
        )
        .cyan()
        .bold()
    );
    println!("  Cluster:    {} ({})", config.name, config.cluster_id);
    println!(
        "  Overlay IP: {}/10",
        config.overlay_ip.as_deref().unwrap_or("pending")
    );
    println!("  Signal:     {}", config.signal_endpoint.dimmed());
    println!("  Node:       {}", config.node_id);

    let cluster_name_for_dns = config.name.clone();
    let mut tunnel = ManagedTunnel::start(config)?;

    // Wait for Ctrl+C
    println!(
        "{}",
        "Tunnel starting... Press Ctrl+C to disconnect."
            .green()
            .bold()
    );

    tokio::signal::ctrl_c().await.ok();

    println!();
    println!("{}", "Shutting down...".yellow());
    tunnel.stop().await;
    crate::tund::dns::remove_resolver(&cluster_name_for_dns);
    println!("{}", "Disconnected.".yellow());

    Ok(())
}

// --- Helpers

fn resolve_cluster_name(name: &str) -> Result<String> {
    Ok(if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name).to_string()
    } else {
        name.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cluster_name_simple() {
        assert_eq!(resolve_cluster_name("homelab").unwrap(), "homelab");
    }

    #[test]
    fn resolve_cluster_name_dotted() {
        assert_eq!(resolve_cluster_name("nas.homelab").unwrap(), "homelab");
    }

    #[test]
    fn format_uptime_seconds() {
        assert_eq!(format_uptime(45), "45s");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(125), "2m 5s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3842), "1h 4m");
    }
}
