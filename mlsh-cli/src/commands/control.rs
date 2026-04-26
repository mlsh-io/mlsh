//! `mlsh control` — manage the control-plane role on this node.
//!
//! `demote` strips the local node of the `control` role, stops the running
//! `mlsh-control` child, and updates the cluster TOML.
//!
//! `promote` adds the `control` role to the local config and tells mlshtund
//! to fork `mlsh-control`. The caller is responsible for placing the
//! control SQLite (and any cert/key) in the data dir before running this.
//!
//! `migrate <node>` is convenience: demote locally and print the steps for
//! the operator to copy state and run `mlsh control promote` on the target.
//! End-to-end peer-to-peer migration (over the overlay) is a future
//! enhancement (ADR-030 — out of scope for v1).
//!
//! All three commands talk to mlshtund via its Unix socket.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::{client::DaemonClient, protocol::DaemonResponse};

const CONTROL_ROLE: &str = "control";

pub async fn handle_demote(cluster_name: &str) -> Result<()> {
    let cluster_file = cluster_config_path(cluster_name)?;
    let mut roles = read_roles(&cluster_file)?;

    if !roles.iter().any(|r| r == CONTROL_ROLE) {
        println!(
            "{}",
            format!(
                "'{}' does not hold the control role; nothing to do.",
                cluster_name
            )
            .yellow()
        );
        return Ok(());
    }

    // Stop the running child first so the port is freed before we mutate
    // the on-disk config.
    let mut client = DaemonClient::connect_default().await?;
    let resp = client.control_stop(cluster_name).await?;
    log_daemon_response(&resp)?;

    roles.retain(|r| r != CONTROL_ROLE);
    write_roles(&cluster_file, &roles)?;

    println!(
        "{}",
        format!("Control role removed from '{}'.", cluster_name).green()
    );
    Ok(())
}

pub async fn handle_promote(cluster_name: &str) -> Result<()> {
    let cluster_file = cluster_config_path(cluster_name)?;
    let mut roles = read_roles(&cluster_file)?;

    if !roles.iter().any(|r| r == CONTROL_ROLE) {
        // control implies admin (ADR-030 §2)
        if !roles.iter().any(|r| r == "admin") {
            roles.push("admin".to_string());
        }
        roles.push(CONTROL_ROLE.to_string());
        write_roles(&cluster_file, &roles)?;
    }

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.control_start(cluster_name).await?;
    log_daemon_response(&resp)?;

    println!(
        "{}",
        format!("'{}' now holds the control role.", cluster_name).green()
    );
    Ok(())
}

/// Open a local TCP tunnel to the admin UI of a remote control node and
/// hold it open until Ctrl+C. Fails fast if this node isn't admin in the
/// cluster — the target's mlshtund would reject the connection anyway,
/// but the local check gives a useful error before any round-trip.
pub async fn handle_open(cluster_name: &str, target: &str) -> Result<()> {
    let cluster_file = cluster_config_path(cluster_name)?;
    let roles = read_roles(&cluster_file)?;
    if !roles.iter().any(|r| r == "admin") {
        anyhow::bail!(
            "This node does not hold the 'admin' role in cluster '{}'. \
             Ask an admin to promote it (mlsh promote {} <this-node> --role admin).",
            cluster_name,
            cluster_name
        );
    }

    let mut client = DaemonClient::connect_default().await?;
    let resp = client.open_admin_tunnel(cluster_name, target).await?;
    let port = match resp {
        DaemonResponse::AdminTunnelOpened { local_port } => local_port,
        DaemonResponse::Error { code, message } => anyhow::bail!("{} ({})", message, code),
        _ => anyhow::bail!("Unexpected daemon response"),
    };

    println!(
        "{}",
        format!("Admin UI for '{}' available at:", target)
            .green()
            .bold()
    );
    println!("  {}", format!("http://127.0.0.1:{}", port).bold());
    println!();
    println!("{}", "Press Ctrl+C to close the tunnel.".dimmed());
    tokio::signal::ctrl_c().await?;
    println!();
    println!("{}", "Tunnel closed.".yellow());
    Ok(())
}

pub async fn handle_migrate(cluster_name: &str, target: &str) -> Result<()> {
    handle_demote(cluster_name).await?;

    let src = dirs::data_local_dir()
        .map(|d| d.join("mlsh").join("control"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<data-local-dir>/mlsh/control".to_string());

    println!();
    println!("{}", "Next steps on the target node:".cyan().bold());
    println!(
        "  1. {}",
        format!("scp -r \"{}\" {}:<target-data-dir>/mlsh/", src, target).bold()
    );
    println!(
        "  2. {}",
        format!("mlsh control promote {}", cluster_name).bold()
    );

    Ok(())
}

// --- helpers

fn cluster_config_path(cluster_name: &str) -> Result<std::path::PathBuf> {
    let base = crate::config::config_dir()?;
    Ok(base.join("clusters").join(format!("{}.toml", cluster_name)))
}

fn read_roles(cluster_file: &std::path::Path) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(cluster_file)
        .with_context(|| format!("Cluster config not found: {}", cluster_file.display()))?;
    let doc: toml::Value = toml::from_str(&contents).context("Invalid cluster TOML")?;
    let roles = doc
        .get("node_auth")
        .and_then(|v| v.get("roles"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["node".to_string()]);
    Ok(roles)
}

/// Rewrite the `roles` array in `[node_auth]` in-place. Preserves the rest
/// of the file. Uses a simple line-based approach because `toml::to_string`
/// would lose comments and reorder sections.
fn write_roles(cluster_file: &std::path::Path, roles: &[String]) -> Result<()> {
    let contents = std::fs::read_to_string(cluster_file)?;
    let new_line = format!(
        "roles = [{}]",
        roles
            .iter()
            .map(|r| format!("\"{}\"", r))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut out = String::with_capacity(contents.len() + new_line.len());
    let mut in_node_auth = false;
    let mut wrote_roles = false;
    let mut roles_replaced = false;

    for line in contents.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            // Section change. If we entered/left [node_auth] without seeing
            // an existing roles= line, append it before the next section.
            if in_node_auth && !roles_replaced && !wrote_roles {
                out.push_str(&new_line);
                out.push('\n');
                wrote_roles = true;
            }
            in_node_auth = trimmed.starts_with("[node_auth]");
            out.push_str(line);
            out.push('\n');
            continue;
        }

        if in_node_auth && trimmed.starts_with("roles") && trimmed.contains('=') {
            out.push_str(&new_line);
            out.push('\n');
            roles_replaced = true;
            wrote_roles = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }

    // File ended while still inside [node_auth] without a roles line.
    if in_node_auth && !wrote_roles {
        out.push_str(&new_line);
        out.push('\n');
    }

    let tmp = cluster_file.with_extension("toml.tmp");
    std::fs::write(&tmp, out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, cluster_file)?;
    Ok(())
}

fn log_daemon_response(resp: &DaemonResponse) -> Result<()> {
    match resp {
        DaemonResponse::Ok { message } => {
            if let Some(m) = message {
                println!("  {}", m.dimmed());
            }
            Ok(())
        }
        DaemonResponse::Error { code, message } => {
            anyhow::bail!("{} ({})", message, code);
        }
        _ => anyhow::bail!("Unexpected daemon response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp_toml(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::io::Write::write_all(&mut f, contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn read_roles_with_array() {
        let f = write_tmp_toml(
            r#"
[node_auth]
node_id = "x"
fingerprint = "fp"
roles = ["node", "admin", "control"]
"#,
        );
        let roles = read_roles(f.path()).unwrap();
        assert_eq!(roles, vec!["node", "admin", "control"]);
    }

    #[test]
    fn read_roles_default_when_absent() {
        let f = write_tmp_toml(
            r#"
[node_auth]
node_id = "x"
fingerprint = "fp"
"#,
        );
        let roles = read_roles(f.path()).unwrap();
        assert_eq!(roles, vec!["node"]);
    }

    #[test]
    fn write_roles_replaces_existing() {
        let f = write_tmp_toml(
            r#"[cluster]
name = "demo"

[node_auth]
node_id = "x"
fingerprint = "fp"
roles = ["node", "admin", "control"]

[overlay]
ip = "100.64.0.1"
"#,
        );
        write_roles(f.path(), &["node".to_string(), "admin".to_string()]).unwrap();
        let after = std::fs::read_to_string(f.path()).unwrap();
        assert!(after.contains("roles = [\"node\", \"admin\"]"));
        assert!(!after.contains("control"));
        // Other sections preserved
        assert!(after.contains("[cluster]"));
        assert!(after.contains("[overlay]"));
    }

    #[test]
    fn write_roles_appends_when_missing() {
        let f = write_tmp_toml(
            r#"[cluster]
name = "demo"

[node_auth]
node_id = "x"
fingerprint = "fp"

[overlay]
ip = "100.64.0.1"
"#,
        );
        write_roles(
            f.path(),
            &[
                "node".to_string(),
                "admin".to_string(),
                "control".to_string(),
            ],
        )
        .unwrap();
        let after = std::fs::read_to_string(f.path()).unwrap();
        assert!(after.contains("roles = [\"node\", \"admin\", \"control\"]"));
    }
}
