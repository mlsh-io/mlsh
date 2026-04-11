//! Cluster creation logic shared between the CLI command and the internal HTTP API.

use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use crate::db;

/// Result of creating a cluster.
pub struct ClusterCreated {
    pub cluster_id: String,
    pub name: String,
    pub setup_token: String, // CODE@UUID@FINGERPRINT
}

/// Create a cluster, generate a one-time setup code, and return the full token.
///
/// Used by both `mlsh-signal cluster create` (CLI) and `POST /internal/clusters` (HTTP).
pub async fn create_cluster(
    pool: &SqlitePool,
    name: &str,
    ttl_minutes: u64,
) -> Result<ClusterCreated> {
    let cluster_id = db::create_cluster(pool, name).await?;

    let code = generate_human_code(12);
    let code_formatted = format!("{}-{}-{}", &code[..4], &code[4..8], &code[8..12]);

    let code_hash = format!("{:x}", Sha256::digest(code_formatted.as_bytes()));
    let expires_at = (time::OffsetDateTime::now_utc()
        + time::Duration::minutes(ttl_minutes as i64))
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();

    db::store_setup_code(pool, &cluster_id, &code_hash, &expires_at).await?;

    let signal_fingerprint = db::get_config(pool, "signal_fingerprint")
        .await?
        .unwrap_or_else(|| "<unknown>".to_string());

    let setup_token = format!("{}@{}@{}", code_formatted, cluster_id, signal_fingerprint);

    Ok(ClusterCreated {
        cluster_id,
        name: name.to_string(),
        setup_token,
    })
}

/// Generate a human-readable code of the given length.
///
/// Charset: `0123456789ABCDEFGHJKLMNPQRSTUVWXYZ` (34 chars, no I/O).
/// 12 chars ~ 61 bits of entropy.
fn generate_human_code(len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut raw = vec![0u8; len];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
        .expect("Failed to generate random bytes");
    raw.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}
