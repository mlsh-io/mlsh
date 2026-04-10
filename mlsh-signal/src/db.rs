use anyhow::{Context, Result};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub async fn init(db_path: &str) -> Result<SqlitePool> {
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create db directory: {}", parent.display()))?;
    }

    let url = format!("sqlite://{}?mode=rwc", db_path);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .with_context(|| format!("Failed to open SQLite database: {}", db_path))?;

    // --- Key-value config store
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create config table")?;

    // --- Node registry
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nodes (
            cluster_id     TEXT NOT NULL,
            node_id        TEXT NOT NULL,
            fingerprint    TEXT NOT NULL,
            public_key     TEXT NOT NULL DEFAULT '',
            overlay_ip     TEXT NOT NULL,
            role           TEXT NOT NULL DEFAULT 'node',
            sponsored_by   TEXT NOT NULL DEFAULT '',
            admission_cert TEXT NOT NULL DEFAULT '',
            created_at     TEXT NOT NULL,
            PRIMARY KEY (cluster_id, node_id)
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create nodes table")?;

    let _ = sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_fingerprint ON nodes (cluster_id, fingerprint)",
    )
    .execute(&pool)
    .await;
    let _ = sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_overlay_ip ON nodes (cluster_id, overlay_ip)",
    )
    .execute(&pool)
    .await;

    // Migrations for existing databases
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN public_key TEXT NOT NULL DEFAULT ''")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'node'")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN sponsored_by TEXT NOT NULL DEFAULT ''")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN admission_cert TEXT NOT NULL DEFAULT ''")
        .execute(&pool)
        .await;

    Ok(pool)
}

// --- Config key-value store

pub async fn get_config(pool: &SqlitePool, key: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM config WHERE key = ?1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .context("Failed to read config")?;
    Ok(row.map(|(v,)| v))
}

pub async fn set_config(pool: &SqlitePool, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO config (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = ?2",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .context("Failed to write config")?;
    Ok(())
}

// --- Node registry

/// Parsed overlay subnet — defines the IP allocation range for a cluster.
#[derive(Debug, Clone)]
pub struct OverlaySubnet {
    /// Network address (e.g. 100.64.0.0 for "100.64.0.0/10")
    pub network: u32,
    /// First usable host IP (network + 1)
    pub first: u32,
    /// Last usable host IP (broadcast - 1)
    pub last: u32,
    /// CIDR prefix length
    pub prefix_len: u8,
    /// Original CIDR string for display/serialization
    pub cidr: String,
}

impl OverlaySubnet {
    /// Parse a CIDR string like "100.64.0.0/10" or "10.0.10.0/24".
    pub fn parse(cidr: &str) -> anyhow::Result<Self> {
        let (ip_str, len_str) = cidr.split_once('/').context("Invalid CIDR: missing '/'")?;
        let ip: std::net::Ipv4Addr = ip_str.parse().context("Invalid CIDR IP")?;
        let prefix_len: u8 = len_str.parse().context("Invalid CIDR prefix length")?;
        anyhow::ensure!(prefix_len <= 30, "Prefix length must be <= 30");

        let mask = if prefix_len == 0 {
            0u32
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let network = u32::from(ip) & mask;
        let broadcast = network | !mask;
        let first = network + 1;
        let last = broadcast - 1;

        anyhow::ensure!(first <= last, "Subnet too small for any hosts");

        Ok(Self {
            network,
            first,
            last,
            prefix_len,
            cidr: cidr.to_string(),
        })
    }

    /// Check whether an IP falls within this subnet.
    pub fn contains(&self, ip: std::net::Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let mask = if self.prefix_len == 0 {
            0u32
        } else {
            !((1u32 << (32 - self.prefix_len)) - 1)
        };
        ip_u32 & mask == self.network
    }
}

/// A registered node in the overlay network.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeRecord {
    pub cluster_id: String,
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub overlay_ip: std::net::Ipv4Addr,
    pub role: String,
    pub sponsored_by: String,
    pub admission_cert: String,
    pub created_at: String,
}

/// Register a node and allocate an overlay IP. Idempotent: if the node already
/// exists (by `cluster_id + node_id`), returns the existing IP and updates the
/// fingerprint if it changed (cert rotation).
pub async fn register_node(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
    fingerprint: &str,
    subnet: &OverlaySubnet,
) -> Result<std::net::Ipv4Addr> {
    register_node_full(
        pool,
        cluster_id,
        node_id,
        fingerprint,
        "",
        "node",
        "",
        "",
        subnet,
    )
    .await
}

/// Register a node with full details (public key, role, sponsor, admission cert).
#[allow(clippy::too_many_arguments)]
pub async fn register_node_full(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
    fingerprint: &str,
    public_key: &str,
    role: &str,
    sponsored_by: &str,
    admission_cert: &str,
    subnet: &OverlaySubnet,
) -> Result<std::net::Ipv4Addr> {
    // Check if this node already exists
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT overlay_ip, fingerprint FROM nodes WHERE cluster_id = ?1 AND node_id = ?2",
    )
    .bind(cluster_id)
    .bind(node_id)
    .fetch_optional(pool)
    .await
    .context("Failed to lookup existing node")?;

    if let Some((ip_str, stored_fp)) = existing {
        let ip: std::net::Ipv4Addr = ip_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Bad IP in DB: {}", e))?;

        // Update fingerprint, public_key, role if changed (cert rotation or re-setup)
        sqlx::query(
            "UPDATE nodes SET fingerprint = ?1, public_key = ?2, role = ?3, sponsored_by = ?4, admission_cert = ?5
             WHERE cluster_id = ?6 AND node_id = ?7",
        )
        .bind(fingerprint)
        .bind(public_key)
        .bind(role)
        .bind(sponsored_by)
        .bind(admission_cert)
        .bind(cluster_id)
        .bind(node_id)
        .execute(pool)
        .await
        .context("Failed to update node")?;

        if stored_fp != fingerprint {
            tracing::info!(
                cluster_id,
                node_id,
                "Node fingerprint updated (cert rotation)"
            );
        }

        return Ok(ip);
    }

    // Allocate the next available IP
    let max_ip_row: Option<(String,)> = sqlx::query_as(
        "SELECT overlay_ip FROM nodes WHERE cluster_id = ?1 ORDER BY rowid DESC LIMIT 1",
    )
    .bind(cluster_id)
    .fetch_optional(pool)
    .await
    .context("Failed to query max overlay IP")?;

    let next_ip_u32 = match max_ip_row {
        Some((ip_str,)) => {
            let ip: std::net::Ipv4Addr = ip_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Bad IP in DB: {}", e))?;
            u32::from(ip) + 1
        }
        None => subnet.first,
    };

    if next_ip_u32 > subnet.last {
        anyhow::bail!("Overlay IP space exhausted ({})", subnet.cidr);
    }

    let overlay_ip = std::net::Ipv4Addr::from(next_ip_u32);
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    sqlx::query(
        "INSERT INTO nodes (cluster_id, node_id, fingerprint, public_key, overlay_ip, role, sponsored_by, admission_cert, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(cluster_id)
    .bind(node_id)
    .bind(fingerprint)
    .bind(public_key)
    .bind(overlay_ip.to_string())
    .bind(role)
    .bind(sponsored_by)
    .bind(admission_cert)
    .bind(&now)
    .execute(pool)
    .await
    .context("Failed to register node")?;

    tracing::info!(cluster_id, node_id, %overlay_ip, role, "Node registered");
    Ok(overlay_ip)
}

/// Allocate the next available IP in the subnet for a node, updating the DB.
/// Used on every NodeAuth to dynamically assign IPs from the current subnet.
pub async fn allocate_ip(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
    subnet: &OverlaySubnet,
) -> Result<std::net::Ipv4Addr> {
    // Collect all IPs currently in use by other nodes in this cluster
    let used: Vec<(String,)> =
        sqlx::query_as("SELECT overlay_ip FROM nodes WHERE cluster_id = ?1 AND node_id != ?2")
            .bind(cluster_id)
            .bind(node_id)
            .fetch_all(pool)
            .await
            .context("Failed to query used IPs")?;

    let used_ips: std::collections::HashSet<u32> = used
        .iter()
        .filter_map(|(ip_str,)| ip_str.parse::<std::net::Ipv4Addr>().ok())
        .map(u32::from)
        .collect();

    // Find the first available IP in the subnet
    let mut candidate = subnet.first;
    while candidate <= subnet.last {
        if !used_ips.contains(&candidate) {
            break;
        }
        candidate += 1;
    }

    if candidate > subnet.last {
        anyhow::bail!("Overlay IP space exhausted ({})", subnet.cidr);
    }

    let overlay_ip = std::net::Ipv4Addr::from(candidate);

    // Update the node's IP in the DB
    sqlx::query("UPDATE nodes SET overlay_ip = ?1 WHERE cluster_id = ?2 AND node_id = ?3")
        .bind(overlay_ip.to_string())
        .bind(cluster_id)
        .bind(node_id)
        .execute(pool)
        .await
        .context("Failed to update node overlay IP")?;

    tracing::debug!(cluster_id, node_id, %overlay_ip, "Allocated overlay IP");
    Ok(overlay_ip)
}

/// Look up a node by its certificate fingerprint.
#[allow(clippy::type_complexity)]
pub async fn lookup_node_by_fingerprint(
    pool: &SqlitePool,
    cluster_id: &str,
    fingerprint: &str,
) -> Result<Option<NodeRecord>> {
    let row: Option<(String, String, String, String, String, String, String, String, String)> =
        sqlx::query_as(
            "SELECT cluster_id, node_id, fingerprint, public_key, overlay_ip, role, sponsored_by, admission_cert, created_at
             FROM nodes WHERE cluster_id = ?1 AND fingerprint = ?2",
        )
        .bind(cluster_id)
        .bind(fingerprint)
        .fetch_optional(pool)
        .await
        .context("Failed to lookup node by fingerprint")?;

    Ok(row.map(|(cid, nid, fp, pk, ip, role, sb, ac, ca)| NodeRecord {
        cluster_id: cid,
        node_id: nid,
        fingerprint: fp,
        public_key: pk,
        overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        role,
        sponsored_by: sb,
        admission_cert: ac,
        created_at: ca,
    }))
}

/// Update a node's public key (backfill for nodes registered before public_key existed).
pub async fn update_node_public_key(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
    public_key: &str,
) -> Result<()> {
    sqlx::query("UPDATE nodes SET public_key = ?1 WHERE cluster_id = ?2 AND node_id = ?3")
        .bind(public_key)
        .bind(cluster_id)
        .bind(node_id)
        .execute(pool)
        .await
        .context("Failed to update node public_key")?;
    Ok(())
}

/// List all nodes in a cluster.
#[allow(clippy::type_complexity)]
pub async fn list_nodes(pool: &SqlitePool, cluster_id: &str) -> Result<Vec<NodeRecord>> {
    let rows: Vec<(String, String, String, String, String, String, String, String, String)> =
        sqlx::query_as(
            "SELECT cluster_id, node_id, fingerprint, public_key, overlay_ip, role, sponsored_by, admission_cert, created_at
             FROM nodes WHERE cluster_id = ?1 ORDER BY overlay_ip",
        )
        .bind(cluster_id)
        .fetch_all(pool)
        .await
        .context("Failed to list nodes")?;

    Ok(rows
        .into_iter()
        .map(|(cid, nid, fp, pk, ip, role, sb, ac, ca)| NodeRecord {
            cluster_id: cid,
            node_id: nid,
            fingerprint: fp,
            public_key: pk,
            overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            role,
            sponsored_by: sb,
            admission_cert: ac,
            created_at: ca,
        })
        .collect())
}

/// Remove a node from a cluster. Returns true if a row was deleted.
pub async fn remove_node(pool: &SqlitePool, cluster_id: &str, node_id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM nodes WHERE cluster_id = ?1 AND node_id = ?2")
        .bind(cluster_id)
        .bind(node_id)
        .execute(pool)
        .await
        .context("Failed to remove node")?;

    if result.rows_affected() > 0 {
        tracing::info!(cluster_id, node_id, "Node removed");
    }
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS nodes (
                cluster_id TEXT NOT NULL, node_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, public_key TEXT NOT NULL DEFAULT '',
                overlay_ip TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'node',
                sponsored_by TEXT NOT NULL DEFAULT '', admission_cert TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL, PRIMARY KEY (cluster_id, node_id))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_fingerprint ON nodes (cluster_id, fingerprint)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_overlay_ip ON nodes (cluster_id, overlay_ip)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    fn default_subnet() -> OverlaySubnet {
        OverlaySubnet::parse("100.64.0.0/10").unwrap()
    }

    #[test]
    fn parse_default_subnet() {
        let s = OverlaySubnet::parse("100.64.0.0/10").unwrap();
        assert_eq!(s.network, u32::from(std::net::Ipv4Addr::new(100, 64, 0, 0)));
        assert_eq!(s.first, u32::from(std::net::Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(
            s.last,
            u32::from(std::net::Ipv4Addr::new(100, 127, 255, 254))
        );
        assert_eq!(s.prefix_len, 10);
    }

    #[test]
    fn parse_small_subnet() {
        let s = OverlaySubnet::parse("10.0.10.0/24").unwrap();
        assert_eq!(s.first, u32::from(std::net::Ipv4Addr::new(10, 0, 10, 1)));
        assert_eq!(s.last, u32::from(std::net::Ipv4Addr::new(10, 0, 10, 254)));
        assert_eq!(s.prefix_len, 24);
    }

    #[test]
    fn subnet_contains() {
        let s = OverlaySubnet::parse("10.0.10.0/24").unwrap();
        assert!(s.contains(std::net::Ipv4Addr::new(10, 0, 10, 1)));
        assert!(s.contains(std::net::Ipv4Addr::new(10, 0, 10, 254)));
        assert!(!s.contains(std::net::Ipv4Addr::new(10, 0, 11, 1)));
        assert!(!s.contains(std::net::Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[tokio::test]
    async fn register_first_node() {
        let pool = test_pool().await;
        let s = default_subnet();
        let ip = register_node(&pool, "c1", "nas", "fp-aaa", &s)
            .await
            .unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(100, 64, 0, 1));
    }

    #[tokio::test]
    async fn register_sequential_ips() {
        let pool = test_pool().await;
        let s = default_subnet();
        let ip1 = register_node(&pool, "c1", "node-1", "fp-1", &s)
            .await
            .unwrap();
        let ip2 = register_node(&pool, "c1", "node-2", "fp-2", &s)
            .await
            .unwrap();
        let ip3 = register_node(&pool, "c1", "node-3", "fp-3", &s)
            .await
            .unwrap();
        assert_eq!(ip1, std::net::Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(ip2, std::net::Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(ip3, std::net::Ipv4Addr::new(100, 64, 0, 3));
    }

    #[tokio::test]
    async fn register_idempotent() {
        let pool = test_pool().await;
        let s = default_subnet();
        let ip1 = register_node(&pool, "c1", "nas", "fp-1", &s).await.unwrap();
        let ip2 = register_node(&pool, "c1", "nas", "fp-1", &s).await.unwrap();
        assert_eq!(ip1, ip2);
    }

    #[tokio::test]
    async fn register_updates_fingerprint() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "nas", "fp-old", &s)
            .await
            .unwrap();
        register_node(&pool, "c1", "nas", "fp-new", &s)
            .await
            .unwrap();
        let node = lookup_node_by_fingerprint(&pool, "c1", "fp-new")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.node_id, "nas");
    }

    #[tokio::test]
    async fn register_with_role_and_sponsor() {
        let pool = test_pool().await;
        let s = default_subnet();
        let ip = register_node_full(&pool, "c1", "nas", "fp-1", "pk-1", "admin", "", "", &s)
            .await
            .unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(100, 64, 0, 1));

        let ip2 = register_node_full(&pool, "c1", "rack", "fp-2", "pk-2", "node", "nas", "", &s)
            .await
            .unwrap();
        assert_eq!(ip2, std::net::Ipv4Addr::new(100, 64, 0, 2));

        let nodes = list_nodes(&pool, "c1").await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].role, "admin");
        assert_eq!(nodes[0].sponsored_by, "");
        assert_eq!(nodes[1].role, "node");
        assert_eq!(nodes[1].sponsored_by, "nas");
    }

    #[tokio::test]
    async fn lookup_by_fingerprint() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "nas", "fp-abc", &s)
            .await
            .unwrap();
        let node = lookup_node_by_fingerprint(&pool, "c1", "fp-abc")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.node_id, "nas");
        assert!(lookup_node_by_fingerprint(&pool, "c1", "fp-nonexistent")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_and_remove_nodes() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "a", "fp-a", &s).await.unwrap();
        register_node(&pool, "c1", "b", "fp-b", &s).await.unwrap();
        register_node(&pool, "c1", "c", "fp-c", &s).await.unwrap();

        let nodes = list_nodes(&pool, "c1").await.unwrap();
        assert_eq!(nodes.len(), 3);

        assert!(remove_node(&pool, "c1", "b").await.unwrap());
        assert!(!remove_node(&pool, "c1", "b").await.unwrap());

        let nodes = list_nodes(&pool, "c1").await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.node_id != "b"));
    }

    #[tokio::test]
    async fn clusters_are_isolated() {
        let pool = test_pool().await;
        let s = default_subnet();
        let ip1 = register_node(&pool, "c1", "nas", "fp-1", &s).await.unwrap();
        let ip2 = register_node(&pool, "c2", "nas", "fp-2", &s).await.unwrap();
        assert_eq!(ip1, std::net::Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(ip2, std::net::Ipv4Addr::new(100, 64, 0, 1));
        assert!(lookup_node_by_fingerprint(&pool, "c1", "fp-2")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn custom_subnet_allocation() {
        let pool = test_pool().await;
        let s = OverlaySubnet::parse("10.0.10.0/24").unwrap();
        let ip1 = register_node(&pool, "c1", "a", "fp-a", &s).await.unwrap();
        let ip2 = register_node(&pool, "c1", "b", "fp-b", &s).await.unwrap();
        assert_eq!(ip1, std::net::Ipv4Addr::new(10, 0, 10, 1));
        assert_eq!(ip2, std::net::Ipv4Addr::new(10, 0, 10, 2));
    }

    #[tokio::test]
    async fn config_get_set() {
        let pool = test_pool().await;
        assert!(get_config(&pool, "key1").await.unwrap().is_none());
        set_config(&pool, "key1", "value1").await.unwrap();
        assert_eq!(get_config(&pool, "key1").await.unwrap().unwrap(), "value1");
        set_config(&pool, "key1", "value2").await.unwrap();
        assert_eq!(get_config(&pool, "key1").await.unwrap().unwrap(), "value2");
    }
}
