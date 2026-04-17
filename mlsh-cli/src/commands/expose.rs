//! `mlsh expose` / `mlsh unexpose` / `mlsh exposed`.
//!
//! These commands register/remove public reverse-proxy routes with
//! mlsh-signal.

use anyhow::{Context, Result};
use colored::Colorize;

use mlsh_protocol::framing;
use mlsh_protocol::messages::{ServerMessage, StreamMessage};
use mlsh_protocol::types::IngressMode;

use crate::quic::client::{connect_to_signal, resolve_addr};
use crate::tund::client::DaemonClient;
use crate::tund::tunnel::load_cluster_config;

pub async fn handle_expose(
    cluster: &str,
    target: &str,
    domain: &str,
    email: Option<&str>,
    acme_staging: bool,
) -> Result<()> {
    let base = crate::config::config_dir()?;
    let config = load_cluster_config(cluster, &base)?;

    println!(
        "Exposing {} as {} in cluster {}...",
        target.bold(),
        domain.bold(),
        config.name.bold()
    );

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&config.signal_endpoint)?;
    let conn = connect_to_signal(addr, &config.signal_endpoint, &config.signal_fingerprint, &identity).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    let msg = StreamMessage::ExposeService {
        cluster_id: config.cluster_id.clone(),
        domain: domain.to_string(),
        target: target.to_string(),
        mode: IngressMode::Http,
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::ExposeOk {
            domain,
            public_mode,
            public_ip,
        } => {
            // Also push the target to the local daemon so its ingress handler
            // knows where to splice incoming streams. Non-fatal if the daemon
            // isn't running — signal has the authoritative record.
            match DaemonClient::connect_default().await {
                Ok(mut c) => {
                    if let Err(e) = c
                        .ingress_add(&config.name, &domain, target, email, acme_staging)
                        .await
                    {
                        eprintln!(
                            "{} {}",
                            "warning:".yellow(),
                            format!("Failed to register target with local daemon: {}", e)
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} {}",
                        "warning:".yellow(),
                        format!(
                            "mlshtund is not running — signal knows the route but no local forwarder: {}",
                            e
                        )
                    );
                }
            }

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
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

pub async fn handle_unexpose(cluster: &str, domain: &str) -> Result<()> {
    let base = crate::config::config_dir()?;
    let config = load_cluster_config(cluster, &base)?;

    println!(
        "Removing {} from cluster {}...",
        domain.bold(),
        config.name.bold()
    );

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&config.signal_endpoint)?;
    let conn = connect_to_signal(addr, &config.signal_endpoint, &config.signal_fingerprint, &identity).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    let msg = StreamMessage::UnexposeService {
        cluster_id: config.cluster_id.clone(),
        domain: domain.to_string(),
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::UnexposeOk => {
            if let Ok(mut c) = DaemonClient::connect_default().await {
                let _ = c.ingress_remove(domain).await;
            }
            println!("{}", format!("Unexposed {}.", domain).green().bold());
            Ok(())
        }
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

pub async fn handle_list_exposed(cluster: &str) -> Result<()> {
    let base = crate::config::config_dir()?;
    let config = load_cluster_config(cluster, &base)?;

    let identity = mlsh_crypto::identity::load_or_generate(&config.identity_dir, &config.node_id)
        .map_err(|e| anyhow::anyhow!("Failed to load identity: {}", e))?;

    let addr = resolve_addr(&config.signal_endpoint)?;
    let conn = connect_to_signal(addr, &config.signal_endpoint, &config.signal_fingerprint, &identity).await?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("Failed to open signal stream")?;

    let msg = StreamMessage::ListExposed {
        cluster_id: config.cluster_id.clone(),
    };
    framing::write_msg(&mut send, &msg).await?;

    let resp: ServerMessage = framing::read_msg(&mut recv).await?;
    conn.close(quinn::VarInt::from_u32(0), b"done");

    match resp {
        ServerMessage::ExposedList { routes } => {
            if routes.is_empty() {
                println!("No services exposed in cluster {}.", config.name.bold());
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
        ServerMessage::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code)
        }
        other => anyhow::bail!("Unexpected response: {:?}", other),
    }
}

fn short_id(id: &str) -> &str {
    let cut = 8.min(id.len());
    &id[..cut]
}

