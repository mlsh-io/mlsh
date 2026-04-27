//! Cluster mode marker (ADR-032 §2).
//!
//! `mlsh setup` writes `mode-init.json` next to the control DB to declare
//! whether this cluster is `self-hosted` or `managed`. The control plane
//! consumes the file on first start and persists the value in `config.mode`.
//! After consumption the file is removed; the mode is then read from DB.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use super::auth::AuthStore;
use super::db;

const FILENAME: &str = "mode-init.json";
const CONFIG_KEY: &str = "mode";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    SelfHosted,
    Managed,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::SelfHosted => "self-hosted",
            Mode::Managed => "managed",
        }
    }
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "self-hosted" => Ok(Mode::SelfHosted),
            "managed" => Ok(Mode::Managed),
            other => Err(anyhow!("unknown cluster mode: {}", other)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ModeInit {
    mode: Mode,
}

fn path() -> std::path::PathBuf {
    db::data_dir().join(FILENAME)
}

/// Persist a one-shot mode declaration. Called from `mlsh setup`. Idempotent;
/// the file is overwritten if setup is re-run.
pub fn write(mode: Mode) -> Result<()> {
    let dir = db::data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let json = serde_json::to_vec(&ModeInit { mode })?;
    let p = path();
    write_secret(&p, &json)?;
    Ok(())
}

/// On control-plane start: if `mode-init.json` exists, persist the mode in DB
/// (only when not already set — first-write wins) and remove the file.
pub async fn consume(store: &AuthStore) -> Result<()> {
    let p = path();
    if !p.exists() {
        return Ok(());
    }
    let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    let init: ModeInit =
        serde_json::from_slice(&bytes).context("parse mode-init bootstrap file")?;
    if store.get_config(CONFIG_KEY).await?.is_none() {
        store.set_config(CONFIG_KEY, init.mode.as_str()).await?;
        tracing::info!(mode = init.mode.as_str(), "cluster mode initialized");
    }
    std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
    Ok(())
}

/// Read the persisted mode from `config.mode`, or `None` if not yet set.
pub async fn current(store: &AuthStore) -> Result<Option<Mode>> {
    match store.get_config(CONFIG_KEY).await? {
        Some(s) => Ok(Some(Mode::from_str(&s)?)),
        None => Ok(None),
    }
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
        AuthStore::new(pool)
    }

    #[tokio::test]
    async fn current_returns_none_when_unset() {
        let store = fresh_store().await;
        assert!(current(&store).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn current_round_trips_each_variant() {
        let store = fresh_store().await;
        store.set_config(CONFIG_KEY, "self-hosted").await.unwrap();
        assert_eq!(current(&store).await.unwrap(), Some(Mode::SelfHosted));
        store.set_config(CONFIG_KEY, "managed").await.unwrap();
        assert_eq!(current(&store).await.unwrap(), Some(Mode::Managed));
    }

    #[tokio::test]
    async fn current_rejects_unknown_value() {
        let store = fresh_store().await;
        store.set_config(CONFIG_KEY, "garbage").await.unwrap();
        assert!(current(&store).await.is_err());
    }

    #[test]
    fn mode_serde_uses_kebab() {
        assert_eq!(
            serde_json::to_string(&Mode::SelfHosted).unwrap(),
            "\"self-hosted\""
        );
        assert_eq!(
            serde_json::to_string(&Mode::Managed).unwrap(),
            "\"managed\""
        );
    }
}
