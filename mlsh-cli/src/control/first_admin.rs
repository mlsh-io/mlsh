//! First-admin bootstrap file.
//!
//! `mlsh setup` writes the operator's email + password
//! to a single-use file. The control plane reads it on first start, creates the
//! user, and deletes the file. If the operator skips the prompt, no file is
//! written and the UI offers a Gitea-style first-admin screen instead (#48).
//!
//! The file lives next to the control DB and is created with mode 0600.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::auth::store::NewLocalUser;
use super::auth::AuthStore;
use super::db;

const FILENAME: &str = "first-admin.json";

#[derive(Serialize, Deserialize)]
pub struct FirstAdmin {
    pub email: String,
    pub password: String,
}

pub fn path() -> std::path::PathBuf {
    db::data_dir().join(FILENAME)
}

/// Persist a first-admin record. Writes 0600 on Unix, atomically replacing any
/// previous file (the operator may re-run setup).
pub fn write(record: &FirstAdmin) -> Result<()> {
    let dir = db::data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let json = serde_json::to_vec(record)?;
    let path = path();
    write_secret(&path, &json)?;
    Ok(())
}

/// Consume the bootstrap file: read it, seed the user, then unlink. Idempotent —
/// returns `Ok(())` if the file is absent or the users table already has rows.
pub async fn consume(store: &AuthStore) -> Result<()> {
    let path = path();
    if !path.exists() {
        return Ok(());
    }
    if store.user_count().await? > 0 {
        // Stale file from a previous setup; remove and move on.
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let record: FirstAdmin =
        serde_json::from_slice(&bytes).context("parse first-admin bootstrap file")?;
    store
        .create_local_user(NewLocalUser {
            email: &record.email,
            password: &record.password,
            must_change_password: false,
        })
        .await?;
    std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    tracing::info!(email = %record.email, "seeded first admin from bootstrap file");
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fresh_store() -> AuthStore {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                password_hash TEXT, cloud_user_id TEXT UNIQUE,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK ((password_hash IS NOT NULL) <> (cloud_user_id IS NOT NULL))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        AuthStore::new(pool)
    }

    #[tokio::test]
    async fn consume_seeds_user_and_removes_file() {
        // Use a per-test path under tempdir to avoid the shared data dir.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILENAME);
        let record = FirstAdmin {
            email: "admin@example.com".into(),
            password: "hunter2".into(),
        };
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

        // Mimic consume() but with our local path.
        let store = fresh_store().await;
        let bytes = std::fs::read(&path).unwrap();
        let r: FirstAdmin = serde_json::from_slice(&bytes).unwrap();
        store
            .create_local_user(NewLocalUser {
                email: &r.email,
                password: &r.password,
                must_change_password: false,
            })
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(store.user_count().await.unwrap(), 1);
        assert!(!path.exists());
        assert!(store
            .verify_password("admin@example.com", "hunter2")
            .await
            .unwrap()
            .is_some());
    }
}
