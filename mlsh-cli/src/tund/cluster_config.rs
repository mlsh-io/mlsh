//! Cluster configuration: TOML schema, on-disk loading, and signal credential derivation.

use anyhow::{Context, Result};
use base64::Engine;

use super::signal_session::SignalCredentials;

/// Cluster configuration loaded from a cluster TOML + identity directory.
pub struct ClusterConfig {
    pub name: String,
    pub signal_endpoint: String,
    pub signal_fingerprint: String,
    pub overlay_ip: Option<String>,
    /// Overlay subnet in CIDR notation (e.g. "100.64.0.0/10" or "10.0.10.0/24").
    pub overlay_subnet: Option<String>,
    pub cluster_id: String,
    /// UUID assigned by signal at adopt/setup time.
    pub node_uuid: String,
    /// Human-readable display name for this node (defaults to node_uuid when absent).
    pub display_name: String,
    /// Legacy field kept for backward compatibility with existing TOML files.
    /// New files store `node_uuid` instead.
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    /// Root admin fingerprint for peer-side admission cert verification.
    pub root_fingerprint: String,
    /// Roles this node holds: `node` (always), optionally `admin` and `control`
    /// (ADR-030). When `control` is present, mlshtund forks `mlsh-control`.
    pub roles: Vec<String>,
    /// Path to the identity directory containing cert.pem and key.pem.
    pub identity_dir: std::path::PathBuf,
}

impl ClusterConfig {
    /// Build signal session credentials from this config.
    pub fn signal_credentials(&self) -> Result<SignalCredentials> {
        let cert_pem = std::fs::read_to_string(self.identity_dir.join("cert.pem"))
            .context("Missing identity cert.pem")?;
        let key_pem = std::fs::read_to_string(self.identity_dir.join("key.pem"))
            .context("Missing identity key.pem")?;

        Ok(SignalCredentials {
            signal_endpoint: self.signal_endpoint.clone(),
            signal_fingerprint: self.signal_fingerprint.clone(),
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            display_name: self.display_name.clone(),
            fingerprint: self.fingerprint.clone(),
            public_key: self.public_key.clone(),
            cert_pem,
            key_pem,
            root_fingerprint: self.root_fingerprint.clone(),
        })
    }
}

/// Parse a ClusterConfig from TOML contents and an identity directory.
/// Used by the daemon when receiving config from the CLI via Connect message.
pub fn parse_cluster_config(
    toml_contents: &str,
    identity_dir: &std::path::Path,
) -> Result<ClusterConfig> {
    let table: toml::Value = toml::from_str(toml_contents)?;
    parse_cluster_config_from_toml(&table, identity_dir)
}

/// Load cluster config from disk under the given base directory.
/// The base directory should contain `clusters/` and `identity/` subdirs.
pub fn load_cluster_config(name: &str, base_dir: &std::path::Path) -> Result<ClusterConfig> {
    let cluster_name = if name.contains('.') {
        name.rsplit('.').next().unwrap_or(name).to_string()
    } else {
        name.to_string()
    };

    let cluster_file = base_dir
        .join("clusters")
        .join(format!("{}.toml", cluster_name));

    if !cluster_file.exists() {
        let clusters_dir = base_dir.join("clusters");
        let available = if clusters_dir.exists() {
            std::fs::read_dir(&clusters_dir)
                .ok()
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter_map(|e| {
                            e.path()
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        if available.is_empty() {
            anyhow::bail!(
                "Cluster '{}' not found. No clusters configured.\n\
                 Run 'mlsh setup' to bootstrap or 'mlsh adopt <url>' to join.",
                cluster_name
            );
        } else {
            anyhow::bail!(
                "Cluster '{}' not found. Available clusters: {}",
                cluster_name,
                available
            );
        }
    }

    let contents = std::fs::read_to_string(&cluster_file)?;
    let identity_dir = base_dir.join("identity");
    parse_cluster_config(&contents, &identity_dir)
}

fn parse_cluster_config_from_toml(
    table: &toml::Value,
    identity_dir: &std::path::Path,
) -> Result<ClusterConfig> {
    let cluster = table.get("cluster").context("Missing [cluster] section")?;

    let name = cluster
        .get("name")
        .and_then(|v| v.as_str())
        .context("Missing cluster.name")?
        .to_string();

    let signal_endpoint = cluster
        .get("signal_endpoint")
        .and_then(|v| v.as_str())
        .context("Missing cluster.signal_endpoint")?
        .to_string();

    let signal_fingerprint = cluster
        .get("signal_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let root_fingerprint = cluster
        .get("root_fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let cluster_id = cluster
        .get("id")
        .and_then(|v| v.as_str())
        .context("Missing cluster.id")?
        .to_string();

    let node_auth = table
        .get("node_auth")
        .context("Missing [node_auth] section. Is this cluster configured with 'mlsh setup' (mode 2) or 'mlsh adopt'?")?;

    // Accept both `node_uuid` (new) and `node_id` (legacy) for backward compatibility.
    let node_uuid = node_auth
        .get("node_uuid")
        .and_then(|v| v.as_str())
        .or_else(|| node_auth.get("node_id").and_then(|v| v.as_str()))
        .context("Missing node_auth.node_uuid (or legacy node_auth.node_id)")?
        .to_string();

    // display_name falls back to node_uuid when absent (pre-rename TOML files).
    let display_name = node_auth
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&node_uuid)
        .to_string();

    // Keep node_id as an alias pointing at node_uuid for code that hasn't migrated yet.
    let node_id = node_uuid.clone();

    let fingerprint = node_auth
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .context("Missing node_auth.fingerprint")?
        .to_string();

    let overlay_ip = table
        .get("overlay")
        .and_then(|o| o.get("ip"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let overlay_subnet = table
        .get("overlay")
        .and_then(|o| o.get("subnet"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Roles default to ["node"] when absent (legacy configs).
    let roles: Vec<String> = node_auth
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["node".to_string()]);

    // Derive public_key from the node's identity certificate
    let public_key =
        if let Ok(identity) = mlsh_crypto::identity::load_or_generate(identity_dir, &node_id) {
            mlsh_crypto::invite::extract_public_key_from_cert_pem(&identity.cert_pem)
                .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
                .unwrap_or_default()
        } else {
            String::new()
        };

    Ok(ClusterConfig {
        name,
        signal_endpoint,
        signal_fingerprint,
        overlay_ip,
        overlay_subnet,
        cluster_id,
        node_uuid,
        display_name,
        node_id,
        fingerprint,
        public_key,
        root_fingerprint,
        roles,
        identity_dir: identity_dir.to_path_buf(),
    })
}
