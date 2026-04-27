//! mlsh-control authoritative registry of cluster nodes (ADR-033).
//!
//! Nodes are inserted/updated by the control plane in response to
//! `ControlRequest::AdoptConfirm` and mutated by `Rename`/`Promote`/`Revoke`.

use anyhow::{Context, Result};
use sqlx::SqlitePool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NodeRow {
    pub cluster_id: String,
    pub node_uuid: String,
    pub fingerprint: String,
    pub public_key: String,
    pub display_name: String,
    pub role: String,
    pub status: String,
    pub last_seen: Option<String>,
    pub created_at: String,
}

const SELECT_COLS: &str =
    "cluster_id, node_uuid, fingerprint, public_key, display_name, role, status, last_seen, created_at";

/// Insert a node, or update non-key fields if it already exists.
pub async fn upsert(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
    fingerprint: &str,
    public_key: &str,
    display_name: &str,
    role: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO nodes (cluster_id, node_uuid, fingerprint, public_key, display_name, role, status)
         VALUES (?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT(cluster_id, node_uuid) DO UPDATE SET
             fingerprint = excluded.fingerprint,
             public_key = excluded.public_key,
             display_name = excluded.display_name,
             role = excluded.role,
             status = 'active'",
    )
    .bind(cluster_id)
    .bind(node_uuid)
    .bind(fingerprint)
    .bind(public_key)
    .bind(display_name)
    .bind(role)
    .execute(pool)
    .await
    .context("nodes upsert")?;
    Ok(())
}

pub async fn list(pool: &SqlitePool, cluster_id: &str) -> Result<Vec<NodeRow>> {
    let q = format!("SELECT {SELECT_COLS} FROM nodes WHERE cluster_id = ? ORDER BY created_at ASC");
    let rows: Vec<NodeRow> = sqlx::query_as::<_, NodeRow>(&q)
        .bind(cluster_id)
        .fetch_all(pool)
        .await
        .context("nodes list")?;
    Ok(rows)
}

pub async fn set_display_name(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
    new_name: &str,
) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE nodes SET display_name = ? WHERE cluster_id = ? AND node_uuid = ?",
    )
    .bind(new_name)
    .bind(cluster_id)
    .bind(node_uuid)
    .execute(pool)
    .await
    .context("nodes set_display_name")?;
    Ok(r.rows_affected() > 0)
}

pub async fn set_role(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
    new_role: &str,
) -> Result<bool> {
    let r = sqlx::query("UPDATE nodes SET role = ? WHERE cluster_id = ? AND node_uuid = ?")
        .bind(new_role)
        .bind(cluster_id)
        .bind(node_uuid)
        .execute(pool)
        .await
        .context("nodes set_role")?;
    Ok(r.rows_affected() > 0)
}

pub async fn set_status(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
    new_status: &str,
) -> Result<bool> {
    let r = sqlx::query("UPDATE nodes SET status = ? WHERE cluster_id = ? AND node_uuid = ?")
        .bind(new_status)
        .bind(cluster_id)
        .bind(node_uuid)
        .execute(pool)
        .await
        .context("nodes set_status")?;
    Ok(r.rows_affected() > 0)
}

/// Resolve a target to its `node_uuid` — accepts either the UUID itself
/// (returned as-is if it matches a row) or the `display_name`.
pub async fn resolve_target(
    pool: &SqlitePool,
    cluster_id: &str,
    target: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT node_uuid FROM nodes
         WHERE cluster_id = ? AND (node_uuid = ? OR display_name = ?)
         LIMIT 1",
    )
    .bind(cluster_id)
    .bind(target)
    .bind(target)
    .fetch_optional(pool)
    .await
    .context("nodes resolve_target")?;
    Ok(row.map(|(u,)| u))
}

pub async fn touch_last_seen(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE nodes SET last_seen = datetime('now') WHERE cluster_id = ? AND node_uuid = ?",
    )
    .bind(cluster_id)
    .bind(node_uuid)
    .execute(pool)
    .await
    .context("nodes touch_last_seen")?;
    Ok(())
}
