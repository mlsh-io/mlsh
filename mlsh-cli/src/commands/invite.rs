//! `mlsh invite <cluster> --ttl <seconds> --role <admin|node>` — generate a signed invite URL.
//!
//! The inviting node signs the invite with its Ed25519 private key.
//! Signal verifies the signature using the sponsor's public key from the registry.
//! No shared secret needed — the trust comes from the sponsor's identity.

use anyhow::{Context, Result};
use colored::Colorize;

/// Handle `mlsh invite <cluster> --ttl <seconds> --role <role>`.
pub async fn handle_invite(cluster_name: &str, ttl: u64, role: &str) -> Result<()> {
    // Validate role
    if role != "admin" && role != "node" {
        anyhow::bail!("Invalid role '{}'. Must be 'admin' or 'node'.", role);
    }

    let config_dir = crate::config::config_dir()?;
    let cluster_file = config_dir
        .join("clusters")
        .join(format!("{}.toml", cluster_name));

    if !cluster_file.exists() {
        anyhow::bail!(
            "Cluster '{}' not found. Run 'mlsh setup' first.",
            cluster_name
        );
    }

    let contents = std::fs::read_to_string(&cluster_file)?;
    let table: toml::Value = toml::from_str(&contents)?;

    let cluster = table.get("cluster").context("Missing [cluster] section")?;

    let signal_endpoint = cluster
        .get("signal_endpoint")
        .and_then(|v| v.as_str())
        .context("Missing cluster.signal_endpoint")?;

    let cluster_id = cluster
        .get("id")
        .and_then(|v| v.as_str())
        .context("Missing cluster.id")?;

    let node_auth = table
        .get("node_auth")
        .context("Missing [node_auth] section")?;

    let node_id = node_auth
        .get("node_id")
        .and_then(|v| v.as_str())
        .context("Missing node_auth.node_id")?;

    let signal_fingerprint = cluster
        .get("signal_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Load the node's private key for signing
    let identity_dir = config_dir.join("identity");
    let key_path = identity_dir.join("key.pem");
    let key_pem = std::fs::read_to_string(&key_path).context(
        "Missing identity key (~/.config/mlsh/identity/key.pem). Run 'mlsh setup' first.",
    )?;

    let root_fingerprint = cluster
        .get("root_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Generate the signed invite (includes signal + root fingerprints)
    let fp = if signal_fingerprint.is_empty() {
        None
    } else {
        Some(signal_fingerprint)
    };
    let rfp = if root_fingerprint.is_empty() {
        None
    } else {
        Some(root_fingerprint)
    };
    let invite_token =
        mlsh_crypto::invite::generate_signed_invite_full(&mlsh_crypto::invite::InviteParams {
            key_pem: &key_pem,
            cluster_id,
            cluster_name,
            sponsor_node_uuid: node_id,
            target_role: role,
            ttl_seconds: ttl,
            signal_fingerprint: fp,
            root_fingerprint: rfp,
        })
        .map_err(|e| anyhow::anyhow!("Failed to generate invite: {}", e))?;

    // Build the URL
    let host = signal_endpoint.split(':').next().unwrap_or(signal_endpoint);
    let url = format!("mlsh://{}/adopt/{}", host, invite_token);

    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + ttl;
    let expires_dt = time::OffsetDateTime::from_unix_timestamp(expires_at as i64)
        .map(|dt| {
            dt.format(
                &time::format_description::parse(
                    "[year]-[month]-[day] [hour]:[minute]:[second] UTC",
                )
                .unwrap(),
            )
            .unwrap_or_else(|_| format!("{}s from now", ttl))
        })
        .unwrap_or_else(|_| format!("{}s from now", ttl));

    println!("{}", "Invite created!".green().bold());
    println!();
    println!("  URL:     {}", url);
    println!("  Role:    {}", role);
    println!("  Sponsor: {}", node_id);
    println!("  Expires: {}", expires_dt);
    println!();
    println!("On the new machine, run:");
    println!("  {} \"{}\"", "mlsh adopt".bold(), url);

    Ok(())
}
