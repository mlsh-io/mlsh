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
    // Admin users (human operators who log into the UI)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            username    TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            active      INTEGER NOT NULL DEFAULT 1
        )",
    )
    .execute(pool)
    .await?;

    // WebAuthn credentials per user
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

    // TOTP credentials per user
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS totp_credentials (
            user_id     TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            secret      TEXT NOT NULL,
            verified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    // Sessions
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

    // Node groups (for ACLs)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS groups (
            name        TEXT PRIMARY KEY,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(pool)
    .await?;

    // Node → group assignments
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS node_groups (
            node_id     TEXT NOT NULL,
            group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
            PRIMARY KEY (node_id, group_name)
        )",
    )
    .execute(pool)
    .await?;

    // ACL rules between groups
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS acl_rules (
            source_group  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
            target_group  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
            action        TEXT NOT NULL DEFAULT 'allow',
            PRIMARY KEY (source_group, target_group)
        )",
    )
    .execute(pool)
    .await?;

    // Activity / audit log
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS activity_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
            event_type  TEXT NOT NULL,
            node_id     TEXT NOT NULL DEFAULT '',
            peer_id     TEXT NOT NULL DEFAULT '',
            ip_address  TEXT NOT NULL DEFAULT '',
            details     TEXT NOT NULL DEFAULT '{}'
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_activity_log_event_type ON activity_log (event_type)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_activity_log_node_id ON activity_log (node_id)")
        .execute(pool)
        .await?;

    // License JWT cache
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

    Ok(())
}

fn data_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("mlsh")
        .join("control")
}
