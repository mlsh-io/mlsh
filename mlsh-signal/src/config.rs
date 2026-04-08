use anyhow::{Context, Result};
use serde::Deserialize;
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Path to the SQLite database file
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// QUIC server configuration
    #[serde(default)]
    pub quic: QuicConfig,

    /// mlsh-cloud API base URL (e.g. "https://api.mlsh.io").
    /// If set, signal validates node adoption against cloud (billing/quotas).
    /// If absent, signal runs in self-hosted mode (no external auth).
    #[serde(default)]
    pub cloud_url: Option<String>,

    /// API token for authenticating signal → mlsh-cloud requests.
    /// Sent as `Authorization: Bearer <token>` header.
    #[serde(default)]
    pub cloud_api_token: Option<String>,

    /// Cluster secret for HMAC-based invite verification (self-hosted mode).
    /// If absent, invites cannot be verified locally (managed mode uses cloud).
    #[serde(default)]
    pub cluster_secret: Option<String>,

    /// Signing key for generating node tokens (reconnection auth).
    /// Auto-generated at first startup if absent, then persisted.
    #[serde(default)]
    pub signing_key: Option<String>,

    /// Overlay network subnet in CIDR notation (e.g. "10.0.10.0/24").
    /// Nodes are allocated sequential IPs from this range.
    #[serde(default = "default_overlay_subnet")]
    pub overlay_subnet: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QuicConfig {
    /// UDP address to bind for QUIC, e.g. "0.0.0.0:4433"
    #[serde(default = "default_quic_bind")]
    pub bind: String,

    /// Path to the TLS certificate PEM file (for production).
    /// If absent, a self-signed cert is generated at startup.
    pub cert_path: Option<String>,

    /// Path to the TLS private key PEM file (for production).
    pub key_path: Option<String>,
}

fn default_db_path() -> String {
    "/var/lib/mlsh-signal/signal.db".to_string()
}

fn default_quic_bind() -> String {
    "0.0.0.0:4433".to_string()
}

fn default_overlay_subnet() -> String {
    "100.64.0.0/10".to_string()
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind: default_quic_bind(),
            cert_path: None,
            key_path: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            quic: QuicConfig::default(),
            cloud_url: None,
            cloud_api_token: None,
            cluster_secret: None,
            signing_key: None,
            overlay_subnet: default_overlay_subnet(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut cfg = Self::load_file().unwrap_or_default();

        if let Ok(d) = std::env::var("MLSH_SIGNAL_DB") {
            cfg.db_path = d;
        }
        if let Ok(url) = std::env::var("MLSH_CLOUD_URL") {
            cfg.cloud_url = Some(url);
        }
        if let Ok(s) = std::env::var("MLSH_CLOUD_API_TOKEN") {
            cfg.cloud_api_token = Some(s);
        }
        if let Ok(s) = std::env::var("MLSH_CLUSTER_SECRET") {
            cfg.cluster_secret = Some(s);
        }
        if let Ok(s) = std::env::var("MLSH_SIGNING_KEY") {
            cfg.signing_key = Some(s);
        }
        if let Ok(s) = std::env::var("MLSH_OVERLAY_SUBNET") {
            cfg.overlay_subnet = s;
        }

        // cluster_secret and signing_key are persisted in the DB.
        // Auto-generation happens in main.rs after DB init.

        Ok(cfg)
    }

    fn load_file() -> Result<Self> {
        let path = config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("Failed to parse {}", path.display()))
    }
}

fn config_path() -> PathBuf {
    std::env::var("MLSH_SIGNAL_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/mlsh-signal/config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_values() {
        let cfg = Config::default();
        assert_eq!(cfg.db_path, "/var/lib/mlsh-signal/signal.db");
        assert_eq!(cfg.quic.bind, "0.0.0.0:4433");
    }

    #[test]
    fn parse_minimal_toml() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.db_path, "/var/lib/mlsh-signal/signal.db");
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
db_path = "/tmp/test.db"

[quic]
bind = "0.0.0.0:5555"
cert_path = "/etc/certs/cert.pem"
key_path = "/etc/certs/key.pem"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.db_path, "/tmp/test.db");
        assert_eq!(cfg.quic.bind, "0.0.0.0:5555");
    }

    #[test]
    fn env_db_overrides_default() {
        std::env::set_var("MLSH_SIGNAL_CONFIG", "/tmp/__mlsh_test_nonexistent_db.toml");
        std::env::set_var("MLSH_SIGNAL_DB", "/tmp/custom.db");
        let cfg = Config::load().unwrap();
        std::env::remove_var("MLSH_SIGNAL_DB");
        std::env::remove_var("MLSH_SIGNAL_CONFIG");
        assert_eq!(cfg.db_path, "/tmp/custom.db");
    }
}
