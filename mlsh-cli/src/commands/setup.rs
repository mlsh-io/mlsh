//! `mlsh setup <cluster> --signal-host <host> --token <CODE@CLUSTER_ID@FP>`
//! bootstraps the first node of a cluster against an existing signal.
//!
//! After setup, `mlsh invite` adds more nodes.

use anyhow::{Context, Result};
use colored::Colorize;

use super::bootstrap::{self, BootstrapInput};
#[cfg(feature = "control-plane")]
use crate::control::{write_first_admin, write_mode_init, FirstAdmin, Mode};

const DEFAULT_SIGNAL_PORT: u16 = 4433;

pub async fn handle_setup(
    cluster_name: &str,
    signal_host: &str,
    token: &str,
    name_override: Option<&str>,
) -> Result<()> {
    handle_setup_inner(cluster_name, signal_host, token, name_override, false).await
}

async fn handle_setup_inner(
    cluster_name: &str,
    signal_host: &str,
    token: &str,
    name_override: Option<&str>,
    managed: bool,
) -> Result<()> {
    let (setup_code, cluster_id, signal_fingerprint) = parse_setup_token(token)?;

    println!("{}", "MLSH Cluster Setup".cyan().bold());
    println!("  Cluster: {}", cluster_name);
    println!("  Signal:  {}", signal_host);

    // ADR-032 §2: declare the cluster mode so the control plane and UI render
    // the right login flow. ADR-032 §3: self-hosted prompts for an admin
    // password; managed delegates auth to mlsh-cloud (no password here).
    #[cfg(feature = "control-plane")]
    {
        let mode = if managed {
            Mode::Managed
        } else {
            Mode::SelfHosted
        };
        write_mode_init(mode).context("writing mode-init file")?;
        if !managed {
            if let Some(record) = prompt_first_admin()? {
                write_first_admin(&record).context("writing first-admin bootstrap file")?;
            }
        }
    }
    #[cfg(not(feature = "control-plane"))]
    let _ = managed;

    let node_id = bootstrap::generate_node_id();
    let display_name = bootstrap::default_display_name(name_override);
    let signal_endpoint = bootstrap::ensure_port(signal_host, DEFAULT_SIGNAL_PORT);

    let out = bootstrap::run(BootstrapInput {
        cluster_name,
        cluster_id: &cluster_id,
        signal_endpoint: &signal_endpoint,
        signal_fingerprint: &signal_fingerprint,
        // Setup creates the cluster — this node IS the root admin.
        root_fingerprint: "",
        node_id: &node_id,
        display_name: &display_name,
        pre_auth_token: &setup_code,
        // First node holds all three roles (ADR-030 §2). The control role
        // can be migrated later via `mlsh control migrate <node>`.
        roles: &["node", "admin", "control"],
    })
    .await?;

    println!();
    println!("{}", "Setup completed!".green().bold());
    println!("  Cluster:    {}", cluster_name);
    println!("  Node:       {} (node + admin + control)", display_name);
    println!("  Node ID:    {}", node_id);
    println!("  Overlay IP: {}", out.overlay_ip);
    println!();
    println!("{}", "Next steps:".cyan().bold());
    println!(
        "  1. Connect: {}",
        format!("mlsh connect {}", cluster_name).bold()
    );
    println!("     Starts the tunnel and the admin UI on https://localhost:8443.");
    println!(
        "  2. Invite:  {}",
        format!("mlsh invite {} --ttl 3600", cluster_name).bold()
    );
    println!();
    println!(
        "{}",
        format!(
            "Warning: \"{}\" has only 1 admin. If you lose this machine, you lose \
             admin access forever. Run `mlsh invite {} --role admin` to add a backup admin.",
            cluster_name, cluster_name
        )
        .yellow()
    );
    Ok(())
}

/// Managed mode: authenticate via mlsh.io device flow, create cluster, then
/// delegate to the existing self-hosted setup flow with the token from cloud.
pub async fn handle_managed_setup(cluster_name: &str, name_override: Option<&str>) -> Result<()> {
    use crate::cloud::CloudClient;

    println!("{}", "MLSH Managed Setup".cyan().bold());
    println!("  Cluster: {}", cluster_name);

    let cloud = CloudClient::new();

    println!("{}", "Authenticating with mlsh.io...".cyan());
    let device = cloud.request_device_code()?;
    println!();
    println!(
        "  Open {} and enter code: {}",
        device.verification_uri,
        device.user_code.bold()
    );
    println!();
    println!("{}", "Waiting for authorization...".dimmed());

    let tokens = cloud.poll_device_token(&device.device_code, device.interval)?;
    println!("{}", "Authenticated!".green());

    println!("{}", "Creating cluster...".cyan());
    let cluster = cloud.create_cluster(&tokens.access_token, cluster_name)?;
    let setup_token = cluster
        .setup_token
        .context("Cloud did not return a setup token")?;

    handle_setup_inner(
        cluster_name,
        &cluster.signal_endpoint,
        &setup_token,
        name_override,
        true,
    )
    .await
}

/// Prompt for the first admin's email + password. Returns `None` if the
/// operator declines (empty email) — the UI bootstrap path will handle it.
#[cfg(feature = "control-plane")]
fn prompt_first_admin() -> Result<Option<FirstAdmin>> {
    println!();
    println!("{}", "Create the first admin user".cyan().bold());
    println!("  Leave email blank to skip and use the web bootstrap instead.");
    let email = read_line("  Email: ")?;
    if email.is_empty() {
        return Ok(None);
    }
    let password = rpassword::prompt_password("  Password: ")?;
    if password.is_empty() {
        anyhow::bail!("Password must not be empty");
    }
    let confirm = rpassword::prompt_password("  Confirm:  ")?;
    if confirm != password {
        anyhow::bail!("Passwords do not match");
    }
    Ok(Some(FirstAdmin { email, password }))
}

#[cfg(feature = "control-plane")]
fn read_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Parse a setup token: `CODE@CLUSTER_ID@FINGERPRINT`.
fn parse_setup_token(token: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = token.splitn(3, '@').collect();
    match parts.as_slice() {
        [code, cluster_id, fingerprint]
            if !code.is_empty() && !cluster_id.is_empty() && !fingerprint.is_empty() =>
        {
            Ok((
                code.to_string(),
                cluster_id.to_string(),
                fingerprint.to_string(),
            ))
        }
        _ => anyhow::bail!("Invalid setup token format. Expected: CODE@CLUSTER_ID@FINGERPRINT"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_valid() {
        let (code, cid, fp) =
            parse_setup_token("ABCD-EFGH-IJKL@550e8400-e29b@deadbeef1234").unwrap();
        assert_eq!(code, "ABCD-EFGH-IJKL");
        assert_eq!(cid, "550e8400-e29b");
        assert_eq!(fp, "deadbeef1234");
    }

    #[test]
    fn parse_token_missing_parts() {
        assert!(parse_setup_token("ABCDEFGH").is_err());
        assert!(parse_setup_token("code@cluster").is_err());
    }

    #[test]
    fn parse_token_empty_parts() {
        assert!(parse_setup_token("@@fingerprint").is_err());
        assert!(parse_setup_token("code@@fp").is_err());
    }
}
