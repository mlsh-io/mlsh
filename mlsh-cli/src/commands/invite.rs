//! `mlsh invite <cluster> --ttl <seconds> --role <admin|node>` — generate an
//! Ed25519-signed invite payload for a new node (ADR-033).
//!
//! The token is signed locally with this admin's identity key. mlsh-signal
//! validates the signature against the sponsor's public key (which it learned
//! when the sponsor joined the mesh). No DB write is needed at issue time.

use anyhow::{Context, Result};
use colored::Colorize;

use crate::tund::tunnel::load_cluster_config;

pub async fn handle_invite(cluster_name: &str, ttl: u64, role: &str) -> Result<()> {
    if role != "admin" && role != "node" {
        anyhow::bail!("Invalid role '{}'. Must be 'admin' or 'node'.", role);
    }

    let base_dir = crate::config::config_dir()?;
    let config = load_cluster_config(cluster_name, &base_dir)?;

    let key_pem = std::fs::read_to_string(config.identity_dir.join("key.pem"))
        .context("Missing identity key.pem (re-run mlsh setup)")?;

    let token =
        mlsh_crypto::invite::generate_signed_invite_full(&mlsh_crypto::invite::InviteParams {
            key_pem: &key_pem,
            cluster_id: &config.cluster_id,
            cluster_name: &config.name,
            sponsor_node_uuid: &config.node_uuid,
            target_role: role,
            ttl_seconds: ttl,
            signal_fingerprint: Some(&config.signal_fingerprint),
            root_fingerprint: if config.root_fingerprint.is_empty() {
                None
            } else {
                Some(&config.root_fingerprint)
            },
        })
        .map_err(|e| anyhow::anyhow!("Failed to sign invite: {e}"))?;

    let url = format!("mlsh://{}/adopt/{}", config.signal_endpoint, token);

    println!("{}", "Invite created!".green().bold());
    println!();
    println!("  Cluster: {}", config.name);
    println!("  Role:    {}", role);
    println!("  Expires: {}s from now", ttl);
    println!();
    println!("On the new machine, run:");
    println!("  {} {}", "mlsh adopt".bold(), url);

    Ok(())
}
