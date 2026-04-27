use anyhow::Result;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::str::FromStr;

pub async fn init() -> Result<SqlitePool> {
    let db_path = data_dir().join("control.db");
    std::fs::create_dir_all(db_path.parent().unwrap())?;

    let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", db_path.display()))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let pool = SqlitePool::connect_with(opts).await?;
    migrate(&pool).await?;
    Ok(pool)
}

async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version  INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    let version: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(pool)
        .await?;

    if version < 1 {
        apply_v1(pool).await?;
        sqlx::query("INSERT INTO schema_version (version) VALUES (1)")
            .execute(pool)
            .await?;
    }

    Ok(())
}

async fn apply_v1(pool: &SqlitePool) -> Result<()> {
    // Cluster-wide configuration (mode, etc.). See ADR-032 §2.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS config (
            key    TEXT PRIMARY KEY,
            value  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Human users (ADR-032 §6). password_hash for self-hosted, cloud_user_id for managed.
    // The XOR CHECK enforces exactly one identity source per user in v1.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id                    TEXT PRIMARY KEY,
            email                 TEXT NOT NULL UNIQUE,
            password_hash         TEXT,
            cloud_user_id         TEXT UNIQUE,
            must_change_password  INTEGER NOT NULL DEFAULT 0,
            active                INTEGER NOT NULL DEFAULT 1,
            created_at            TEXT NOT NULL DEFAULT (datetime('now')),
            CHECK ((password_hash IS NOT NULL) <> (cloud_user_id IS NOT NULL))
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // TOTP secret stored AES-GCM-encrypted as a blob (ADR-032 §6).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS totp_credentials (
            user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            secret_enc  BLOB NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            credential_id   BLOB NOT NULL UNIQUE,
            public_key      BLOB NOT NULL,
            sign_count      INTEGER NOT NULL DEFAULT 0,
            name            TEXT NOT NULL DEFAULT 'Device',
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    // License JWT cache (ADR-030 §10).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS license (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            jwt         TEXT NOT NULL,
            fetched_at  TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nodes (
            cluster_id    TEXT NOT NULL,
            node_uuid     TEXT NOT NULL,
            fingerprint   TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            display_name  TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'node' CHECK (role IN ('node', 'admin')),
            status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
            last_seen     TEXT,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (cluster_id, node_uuid)
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub fn data_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mlsh")
        .join("control")
}
