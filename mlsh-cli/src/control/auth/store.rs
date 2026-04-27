use anyhow::{anyhow, Result};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::crypto;

pub(super) type UserRow = (String, String, Option<String>, Option<String>, i64, i64);

pub(super) fn user_from_row(r: UserRow) -> User {
    User {
        id: r.0,
        email: r.1,
        password_hash: r.2,
        cloud_user_id: r.3,
        must_change_password: r.4 != 0,
        active: r.5 != 0,
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub cloud_user_id: Option<String>,
    pub must_change_password: bool,
    pub active: bool,
}

pub struct NewLocalUser<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub must_change_password: bool,
}

pub struct NewManagedUser<'a> {
    pub email: &'a str,
    pub cloud_user_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct TotpRow {
    pub secret_enc: Vec<u8>,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct WebauthnRow {
    pub id: String,
    pub credential_id: Vec<u8>,
    pub passkey_json: Vec<u8>,
    pub sign_count: u32,
    pub name: String,
}

#[derive(Clone)]
pub struct AuthStore {
    pool: SqlitePool,
}

impl AuthStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn user_count(&self) -> Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    pub async fn create_local_user(&self, new: NewLocalUser<'_>) -> Result<User> {
        let id = Uuid::new_v4().to_string();
        let hash = crypto::hash_password(new.password)?;
        let must_change = if new.must_change_password { 1 } else { 0 };
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, must_change_password)
             VALUES (?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(new.email)
        .bind(&hash)
        .bind(must_change)
        .execute(&self.pool)
        .await?;
        Ok(User {
            id,
            email: new.email.to_string(),
            password_hash: Some(hash),
            cloud_user_id: None,
            must_change_password: new.must_change_password,
            active: true,
        })
    }

    pub async fn create_managed_user(&self, new: NewManagedUser<'_>) -> Result<User> {
        let id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users (id, email, cloud_user_id) VALUES (?, ?, ?)")
            .bind(&id)
            .bind(new.email)
            .bind(new.cloud_user_id)
            .execute(&self.pool)
            .await?;
        Ok(User {
            id,
            email: new.email.to_string(),
            password_hash: None,
            cloud_user_id: Some(new.cloud_user_id.to_string()),
            must_change_password: false,
            active: true,
        })
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, cloud_user_id, must_change_password, active
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(user_from_row))
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, cloud_user_id, must_change_password, active
             FROM users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(user_from_row))
    }

    /// Look up a managed user by `cloud_user_id`, creating one on first sight.
    /// First-ever user is auto-admin (ADR-032 §4): no other users exist yet, so
    /// the JWT-bearing operator is the cluster owner.
    pub async fn find_or_create_managed(&self, cloud_user_id: &str, email: &str) -> Result<User> {
        if let Some(u) = self.find_by_cloud_user_id(cloud_user_id).await? {
            return Ok(u);
        }
        self.create_managed_user(NewManagedUser {
            email,
            cloud_user_id,
        })
        .await
    }

    pub async fn find_by_cloud_user_id(&self, cloud_user_id: &str) -> Result<Option<User>> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, cloud_user_id, must_change_password, active
             FROM users WHERE cloud_user_id = ?",
        )
        .bind(cloud_user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(user_from_row))
    }

    /// Verify `password` against the stored hash. Returns `Ok(true)` only if the user
    /// is local (has a password_hash), active, and the password matches.
    pub async fn verify_password(&self, email: &str, password: &str) -> Result<Option<User>> {
        let Some(user) = self.find_by_email(email).await? else {
            return Ok(None);
        };
        if !user.active {
            return Ok(None);
        }
        let Some(hash) = user.password_hash.as_deref() else {
            return Ok(None);
        };
        if crypto::verify_password(password, hash)? {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn set_password(&self, user_id: &str, new_password: &str) -> Result<()> {
        let hash = crypto::hash_password(new_password)?;
        let n = sqlx::query(
            "UPDATE users SET password_hash = ?, must_change_password = 0
             WHERE id = ? AND password_hash IS NOT NULL",
        )
        .bind(&hash)
        .bind(user_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(anyhow!(
                "cannot set password: user not found or not a local user"
            ));
        }
        Ok(())
    }

    pub async fn set_active(&self, user_id: &str, active: bool) -> Result<()> {
        sqlx::query("UPDATE users SET active = ? WHERE id = ?")
            .bind(if active { 1 } else { 0 })
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_totp(&self, user_id: &str, secret_enc: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT INTO totp_credentials (user_id, secret_enc, verified)
             VALUES (?, ?, 0)
             ON CONFLICT(user_id) DO UPDATE SET
                 secret_enc = excluded.secret_enc,
                 verified = 0,
                 created_at = datetime('now')",
        )
        .bind(user_id)
        .bind(secret_enc)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_totp_verified(&self, user_id: &str) -> Result<()> {
        sqlx::query("UPDATE totp_credentials SET verified = 1 WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_totp(&self, user_id: &str) -> Result<Option<TotpRow>> {
        let row: Option<(Vec<u8>, i64)> =
            sqlx::query_as("SELECT secret_enc, verified FROM totp_credentials WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(secret_enc, verified)| TotpRow {
            secret_enc,
            verified: verified != 0,
        }))
    }

    pub async fn list_webauthn(&self, user_id: &str) -> Result<Vec<WebauthnRow>> {
        let rows: Vec<(String, Vec<u8>, Vec<u8>, i64, String)> = sqlx::query_as(
            "SELECT id, credential_id, public_key, sign_count, name
             FROM webauthn_credentials WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| WebauthnRow {
                id: r.0,
                credential_id: r.1,
                passkey_json: r.2,
                sign_count: r.3 as u32,
                name: r.4,
            })
            .collect())
    }

    pub async fn insert_webauthn(
        &self,
        user_id: &str,
        credential_id: &[u8],
        passkey_json: &[u8],
        name: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, name)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(credential_id)
        .bind(passkey_json)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update_webauthn_passkey(
        &self,
        credential_id: &[u8],
        passkey_json: &[u8],
        sign_count: u32,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE webauthn_credentials
             SET public_key = ?, sign_count = ?
             WHERE credential_id = ?",
        )
        .bind(passkey_json)
        .bind(sign_count as i64)
        .bind(credential_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_webauthn(&self, user_id: &str, id: &str) -> Result<u64> {
        let n = sqlx::query("DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionRow>> {
        let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
            "SELECT id, created_at, expires_at, revoked
             FROM sessions WHERE user_id = ? ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SessionRow {
                id: r.0,
                created_at: r.1,
                expires_at: r.2,
                revoked: r.3 != 0,
            })
            .collect())
    }

    pub async fn revoke_session_for_user(&self, user_id: &str, session_id: &str) -> Result<u64> {
        let n = sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ? AND user_id = ?")
            .bind(session_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    pub async fn list_users(&self) -> Result<Vec<User>> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, cloud_user_id, must_change_password, active
             FROM users ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(user_from_row).collect())
    }

    pub async fn delete_user(&self, id: &str) -> Result<u64> {
        let n = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    pub async fn delete_totp(&self, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM totp_credentials WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_config(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM config WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn set_config(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO config (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn fresh_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        // Inline the v1 schema (subset relevant to tests).
        sqlx::query("CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                cloud_user_id TEXT UNIQUE,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                CHECK ((password_hash IS NOT NULL) <> (cloud_user_id IS NOT NULL))
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn local_user_lifecycle() {
        let pool = fresh_pool().await;
        let store = AuthStore::new(pool);

        assert_eq!(store.user_count().await.unwrap(), 0);

        let u = store
            .create_local_user(NewLocalUser {
                email: "admin@example.com",
                password: "hunter2",
                must_change_password: false,
            })
            .await
            .unwrap();
        assert_eq!(u.email, "admin@example.com");

        assert!(store
            .verify_password("admin@example.com", "hunter2")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .verify_password("admin@example.com", "wrong")
            .await
            .unwrap()
            .is_none());

        store.set_password(&u.id, "newpass").await.unwrap();
        assert!(store
            .verify_password("admin@example.com", "newpass")
            .await
            .unwrap()
            .is_some());

        store.set_active(&u.id, false).await.unwrap();
        assert!(store
            .verify_password("admin@example.com", "newpass")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn managed_user_has_no_password() {
        let pool = fresh_pool().await;
        let store = AuthStore::new(pool);
        let u = store
            .create_managed_user(NewManagedUser {
                email: "alice@mlsh.io",
                cloud_user_id: "cloud-123",
            })
            .await
            .unwrap();
        assert!(u.password_hash.is_none());
        assert_eq!(u.cloud_user_id.as_deref(), Some("cloud-123"));

        // set_password on a managed user must fail (CHECK constraint guard).
        assert!(store.set_password(&u.id, "anything").await.is_err());

        let found = store.find_by_cloud_user_id("cloud-123").await.unwrap();
        assert_eq!(found.unwrap().email, "alice@mlsh.io");
    }

    #[tokio::test]
    async fn xor_constraint_rejects_dual_identity() {
        let pool = fresh_pool().await;
        // Insert with both password_hash and cloud_user_id → CHECK should reject.
        let res = sqlx::query(
            "INSERT INTO users (id, email, password_hash, cloud_user_id)
             VALUES ('x', 'x@y', 'h', 'c')",
        )
        .execute(&pool)
        .await;
        assert!(res.is_err());

        // Insert with neither → also rejected.
        let res = sqlx::query("INSERT INTO users (id, email) VALUES ('x', 'x@y')")
            .execute(&pool)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn config_round_trip() {
        let pool = fresh_pool().await;
        let store = AuthStore::new(pool);
        assert!(store.get_config("mode").await.unwrap().is_none());
        store.set_config("mode", "self-hosted").await.unwrap();
        assert_eq!(
            store.get_config("mode").await.unwrap().as_deref(),
            Some("self-hosted")
        );
        store.set_config("mode", "managed").await.unwrap();
        assert_eq!(
            store.get_config("mode").await.unwrap().as_deref(),
            Some("managed")
        );
    }
}
