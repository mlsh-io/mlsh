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

    /// API token for authenticating signal ↔ mlsh-cloud requests.
    /// Used as `X-Internal-Secret` for the internal HTTP API.
    #[serde(default)]
    pub cloud_api_token: Option<String>,

    /// Bind address for the internal HTTP API (cluster provisioning).
    /// Only started if `cloud_api_token` is set.
    #[serde(default = "default_http_bind")]
    pub http_bind: String,

    /// Overlay network subnet in CIDR notation (e.g. "10.0.10.0/24").
    /// Nodes are allocated sequential IPs from this range.
    #[serde(default = "default_overlay_subnet")]
    pub overlay_subnet: String,

    /// TCP bind address for the public-ingress listener.
    /// An outer SNI proxy terminates public :443 and forwards `*.mlsh.io`
    /// connections to this port. Default is loopback so signal is never
    /// directly internet-facing unless explicitly configured.
    #[serde(default = "default_ingress_bind")]
    pub ingress_bind: String,

    /// When true, read a PROXY-protocol v2 header from the outer SNI proxy on
    /// every inbound ingress TCP connection. Use this to preserve the real
    /// client IP in logs and in the `IngressForward` header sent to peers.
    #[serde(default)]
    pub ingress_proxy_protocol: bool,

    /// SNI hostnames routed to the internal HTTP API instead of a peer
    /// (e.g. the signal web UI / admin endpoints).
    #[serde(default = "default_admin_hosts")]
    pub admin_hosts: Vec<String>,

    /// DNS zone served by this signal. Exposed services must live under
    /// `<label>.<cluster>.<zone>`. Default `"mlsh.io"` for the production
    /// instance; dev/staging instances should override (e.g. `"dev.mlsh.io"`).
    #[serde(default = "default_zone")]
    pub zone: String,
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

fn default_http_bind() -> String {
    "127.0.0.1:4434".to_string()
}

fn default_overlay_subnet() -> String {
    "100.64.0.0/10".to_string()
}

fn default_ingress_bind() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_admin_hosts() -> Vec<String> {
    vec!["signal.mlsh.io".to_string()]
}

fn default_zone() -> String {
    "mlsh.io".to_string()
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
            http_bind: default_http_bind(),
            overlay_subnet: default_overlay_subnet(),
            ingress_bind: default_ingress_bind(),
            ingress_proxy_protocol: false,
            admin_hosts: default_admin_hosts(),
            zone: default_zone(),
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
        if let Ok(s) = std::env::var("MLSH_OVERLAY_SUBNET") {
            cfg.overlay_subnet = s;
        }

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
