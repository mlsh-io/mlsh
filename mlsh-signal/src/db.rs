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
            cluster_id   TEXT NOT NULL,
            node_id      TEXT NOT NULL,
            fingerprint  TEXT NOT NULL,
            overlay_ip   TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'node',
            display_name TEXT NOT NULL DEFAULT '',
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
    let _ = sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_display_name ON nodes (cluster_id, display_name) WHERE display_name != ''",
    )
    .execute(&pool)
    .await;

    // Migrations for existing databases
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN role TEXT NOT NULL DEFAULT 'node'")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        .execute(&pool)
        .await;

    // --- Cluster registry
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS clusters (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create clusters table")?;

    let _ = sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_name ON clusters (name)")
        .execute(&pool)
        .await;

    // --- One-time setup codes (per-cluster, burned after first use)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS setup_codes (
            cluster_id TEXT NOT NULL REFERENCES clusters(id),
            code_hash  TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (cluster_id)
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create setup_codes table")?;

    // --- Ingress routes (public reverse-proxy registrations)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ingress_routes (
            domain      TEXT PRIMARY KEY,
            cluster_id  TEXT NOT NULL,
            node_id     TEXT NOT NULL,
            target      TEXT NOT NULL,
            mode        TEXT NOT NULL DEFAULT 'http',
            public_mode TEXT NOT NULL DEFAULT 'relay',
            public_ip   TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await
    .context("Failed to create ingress_routes table")?;
    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ingress_routes_node ON ingress_routes (cluster_id, node_id)",
    )
    .execute(&pool)
    .await;

    Ok(pool)
}

// --- Cluster management

/// Create a new cluster. Returns the generated UUID.
pub async fn create_cluster(pool: &SqlitePool, name: &str) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    sqlx::query("INSERT INTO clusters (id, name, created_at) VALUES (?1, ?2, ?3)")
        .bind(&id)
        .bind(name)
        .bind(&now)
        .execute(pool)
        .await
        .context("Failed to create cluster (name may already exist)")?;

    Ok(id)
}

/// Delete a cluster and all associated data.
pub async fn delete_cluster(pool: &SqlitePool, cluster_id: &str) -> Result<bool> {
    // Delete nodes first (no FK cascade in SQLite by default)
    sqlx::query("DELETE FROM nodes WHERE cluster_id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await
        .context("Failed to delete cluster nodes")?;

    sqlx::query("DELETE FROM setup_codes WHERE cluster_id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await
        .context("Failed to delete cluster setup codes")?;

    let result = sqlx::query("DELETE FROM clusters WHERE id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await
        .context("Failed to delete cluster")?;

    Ok(result.rows_affected() > 0)
}

/// Look up a cluster by name.
pub async fn get_cluster_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<(String, String)>> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT id, name FROM clusters WHERE name = ?1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .context("Failed to lookup cluster")?;
    Ok(row)
}

/// Check whether a cluster_id exists in the clusters table.
pub async fn cluster_exists(pool: &SqlitePool, cluster_id: &str) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as("SELECT id FROM clusters WHERE id = ?1")
        .bind(cluster_id)
        .fetch_optional(pool)
        .await
        .context("Failed to check cluster")?;
    Ok(row.is_some())
}

/// Look up a cluster's display name by UUID.
pub async fn get_cluster_name_by_id(pool: &SqlitePool, cluster_id: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT name FROM clusters WHERE id = ?1")
        .bind(cluster_id)
        .fetch_optional(pool)
        .await
        .context("Failed to look up cluster name")?;
    Ok(row.map(|(n,)| n))
}

// --- Setup codes (one-time, per-cluster)

/// Store a hashed setup code for a cluster. Replaces any existing code.
pub async fn store_setup_code(
    pool: &SqlitePool,
    cluster_id: &str,
    code_hash: &str,
    expires_at: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO setup_codes (cluster_id, code_hash, expires_at) VALUES (?1, ?2, ?3)",
    )
    .bind(cluster_id)
    .bind(code_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .context("Failed to store setup code")?;
    Ok(())
}

/// Verify a setup code and burn it (delete) on success.
///
/// Returns the cluster_id if valid, or None if the code doesn't match or expired.
pub async fn verify_and_burn_setup_code(
    pool: &SqlitePool,
    cluster_id: &str,
    code_hash: &str,
) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT expires_at FROM setup_codes WHERE cluster_id = ?1 AND code_hash = ?2",
    )
    .bind(cluster_id)
    .bind(code_hash)
    .fetch_optional(pool)
    .await
    .context("Failed to verify setup code")?;

    let expires_at = match row {
        Some((ea,)) => ea,
        None => return Ok(false),
    };

    // Check expiry
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    if now > expires_at {
        // Expired — burn it anyway
        sqlx::query("DELETE FROM setup_codes WHERE cluster_id = ?1")
            .bind(cluster_id)
            .execute(pool)
            .await
            .ok();
        return Ok(false);
    }

    // Valid — burn it
    sqlx::query("DELETE FROM setup_codes WHERE cluster_id = ?1")
        .bind(cluster_id)
        .execute(pool)
        .await
        .context("Failed to burn setup code")?;

    Ok(true)
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
    pub overlay_ip: std::net::Ipv4Addr,
    pub role: String,
    pub display_name: String,
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
        &NodeRegistration {
            cluster_id,
            node_id,
            fingerprint,
            role: "node",
            display_name: "",
        },
        subnet,
    )
    .await
}

/// Fields for registering a new node.
pub struct NodeRegistration<'a> {
    pub cluster_id: &'a str,
    pub node_id: &'a str,
    pub fingerprint: &'a str,
    pub role: &'a str,
    pub display_name: &'a str,
}

/// Register a node with full details. Idempotent: updates fingerprint/role on conflict.
pub async fn register_node_full(
    pool: &SqlitePool,
    reg: &NodeRegistration<'_>,
    subnet: &OverlaySubnet,
) -> Result<std::net::Ipv4Addr> {
    let cluster_id = reg.cluster_id;
    let node_id = reg.node_id;
    let fingerprint = reg.fingerprint;
    let role = reg.role;
    let display_name = reg.display_name;

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

        // Only overwrite display_name if the caller provides a non-empty value;
        // preserve an existing name when re-registering without a name.
        sqlx::query(
            "UPDATE nodes
             SET fingerprint = ?1, role = ?2,
                 display_name = CASE WHEN ?3 != '' THEN ?3 ELSE display_name END
             WHERE cluster_id = ?4 AND node_id = ?5",
        )
        .bind(fingerprint)
        .bind(role)
        .bind(display_name)
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

    sqlx::query(
        "INSERT INTO nodes (cluster_id, node_id, fingerprint, overlay_ip, role, display_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(cluster_id)
    .bind(node_id)
    .bind(fingerprint)
    .bind(overlay_ip.to_string())
    .bind(role)
    .bind(display_name)
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
pub async fn lookup_node_by_fingerprint(
    pool: &SqlitePool,
    cluster_id: &str,
    fingerprint: &str,
) -> Result<Option<NodeRecord>> {
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT cluster_id, node_id, fingerprint, overlay_ip, role, display_name
         FROM nodes WHERE cluster_id = ?1 AND fingerprint = ?2",
    )
    .bind(cluster_id)
    .bind(fingerprint)
    .fetch_optional(pool)
    .await
    .context("Failed to lookup node by fingerprint")?;

    Ok(row.map(|(cid, nid, fp, ip, role, dn)| NodeRecord {
        cluster_id: cid,
        node_id: nid,
        fingerprint: fp,
        overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        role,
        display_name: dn,
    }))
}

/// Look up a node by its certificate fingerprint across all clusters.
/// Used by handlers that don't know the caller's cluster_id upfront.
pub async fn lookup_node_by_fingerprint_any_cluster(
    pool: &SqlitePool,
    fingerprint: &str,
) -> Result<Option<NodeRecord>> {
    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT cluster_id, node_id, fingerprint, overlay_ip, role, display_name
         FROM nodes WHERE fingerprint = ?1",
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await
    .context("Failed to lookup node by fingerprint")?;

    Ok(row.map(|(cid, nid, fp, ip, role, dn)| NodeRecord {
        cluster_id: cid,
        node_id: nid,
        fingerprint: fp,
        overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        role,
        display_name: dn,
    }))
}

/// List all nodes in a cluster.
pub async fn list_nodes(pool: &SqlitePool, cluster_id: &str) -> Result<Vec<NodeRecord>> {
    let rows: Vec<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT cluster_id, node_id, fingerprint, overlay_ip, role, display_name
         FROM nodes WHERE cluster_id = ?1 ORDER BY overlay_ip",
    )
    .bind(cluster_id)
    .fetch_all(pool)
    .await
    .context("Failed to list nodes")?;

    Ok(rows
        .into_iter()
        .map(|(cid, nid, fp, ip, role, dn)| NodeRecord {
            cluster_id: cid,
            node_id: nid,
            fingerprint: fp,
            overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            role,
            display_name: dn,
        })
        .collect())
}

/// Update a node's role. Returns true if the node was found.
pub async fn update_node_role(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
    new_role: &str,
) -> Result<bool> {
    let result = sqlx::query("UPDATE nodes SET role = ?1 WHERE cluster_id = ?2 AND node_id = ?3")
        .bind(new_role)
        .bind(cluster_id)
        .bind(node_id)
        .execute(pool)
        .await
        .context("Failed to update node role")?;
    Ok(result.rows_affected() > 0)
}

/// Count the number of admin nodes in a cluster.
pub async fn count_admins(pool: &SqlitePool, cluster_id: &str) -> Result<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM nodes WHERE cluster_id = ?1 AND role = 'admin'")
            .bind(cluster_id)
            .fetch_one(pool)
            .await
            .context("Failed to count admins")?;
    Ok(row.0)
}

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

/// Rename a node's display name within a cluster.
///
/// The uniqueness constraint `idx_nodes_display_name` (partial index on
/// non-empty names) enforces that no two nodes in the same cluster share a
/// display name.  If the new name is already in use, the UPDATE will fail with
/// a UNIQUE constraint violation which is surfaced as `Ok(false)`.
///
/// Returns `true` if the node was found and renamed, `false` if the node
/// wasn't found or the name was already taken.
pub async fn rename_node(
    pool: &SqlitePool,
    cluster_id: &str,
    node_uuid: &str,
    new_display_name: &str,
) -> Result<bool> {
    let result =
        sqlx::query("UPDATE nodes SET display_name = ?1 WHERE cluster_id = ?2 AND node_id = ?3")
            .bind(new_display_name)
            .bind(cluster_id)
            .bind(node_uuid)
            .execute(pool)
            .await;

    match result {
        Ok(r) => {
            if r.rows_affected() > 0 {
                tracing::info!(
                    cluster_id,
                    node_id = node_uuid,
                    new_display_name,
                    "Node renamed"
                );
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            // display_name already taken in this cluster
            Ok(false)
        }
        Err(e) => Err(e).context("Failed to rename node"),
    }
}

/// Look up a node by its human-readable display name within a cluster.
///
/// Returns `None` when no node has that display name or if the name is empty.
pub async fn lookup_node_by_display_name(
    pool: &SqlitePool,
    cluster_id: &str,
    display_name: &str,
) -> Result<Option<NodeRecord>> {
    if display_name.is_empty() {
        return Ok(None);
    }

    let row: Option<(String, String, String, String, String, String)> = sqlx::query_as(
        "SELECT cluster_id, node_id, fingerprint, overlay_ip, role, display_name
         FROM nodes WHERE cluster_id = ?1 AND display_name = ?2",
    )
    .bind(cluster_id)
    .bind(display_name)
    .fetch_optional(pool)
    .await
    .context("Failed to lookup node by display name")?;

    Ok(row.map(|(cid, nid, fp, ip, role, dn)| NodeRecord {
        cluster_id: cid,
        node_id: nid,
        fingerprint: fp,
        overlay_ip: ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
        role,
        display_name: dn,
    }))
}

// --- Ingress routes

/// A registered public-ingress route.
#[derive(Debug, Clone)]
pub struct IngressRouteRecord {
    pub domain: String,
    pub cluster_id: String,
    pub node_id: String,
    pub target: String,
    pub mode: String,
    pub public_mode: String,
    pub public_ip: String,
    pub created_at: String,
}

/// Raw row shape for `ingress_routes` queries. Matches the column order used
/// in every `SELECT` in this module so the tuple → record conversion stays
/// consistent across helpers.
type IngressRouteRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl From<IngressRouteRow> for IngressRouteRecord {
    fn from((d, cid, nid, t, m, pm, pi, ca): IngressRouteRow) -> Self {
        Self {
            domain: d,
            cluster_id: cid,
            node_id: nid,
            target: t,
            mode: m,
            public_mode: pm,
            public_ip: pi,
            created_at: ca,
        }
    }
}

/// Insert a new ingress route. Returns `Ok(false)` when the domain is already
/// owned by a different (cluster, node) — caller should surface this as
/// "conflict" to the user.
pub async fn insert_ingress_route(
    pool: &SqlitePool,
    domain: &str,
    cluster_id: &str,
    node_id: &str,
    target: &str,
    mode: &str,
) -> Result<bool> {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    // If the row already exists for the same (cluster_id, node_id), this is an
    // idempotent re-registration (e.g. target changed). Update in place.
    let existing: Option<(String, String, String)> =
        sqlx::query_as("SELECT cluster_id, node_id, target FROM ingress_routes WHERE domain = ?1")
            .bind(domain)
            .fetch_optional(pool)
            .await
            .context("Failed to check existing ingress route")?;

    match existing {
        Some((cid, nid, _)) if cid == cluster_id && nid == node_id => {
            sqlx::query("UPDATE ingress_routes SET target = ?1, mode = ?2 WHERE domain = ?3")
                .bind(target)
                .bind(mode)
                .bind(domain)
                .execute(pool)
                .await
                .context("Failed to update ingress route")?;
            Ok(true)
        }
        Some(_) => Ok(false),
        None => {
            sqlx::query(
                "INSERT INTO ingress_routes
                  (domain, cluster_id, node_id, target, mode, public_mode, public_ip, created_at)
                  VALUES (?1, ?2, ?3, ?4, ?5, 'relay', '', ?6)",
            )
            .bind(domain)
            .bind(cluster_id)
            .bind(node_id)
            .bind(target)
            .bind(mode)
            .bind(&now)
            .execute(pool)
            .await
            .context("Failed to insert ingress route")?;
            Ok(true)
        }
    }
}

/// Delete an ingress route. Returns true if a row was removed. Caller must
/// have verified (cluster_id, node_id) ownership before calling.
pub async fn delete_ingress_route(
    pool: &SqlitePool,
    cluster_id: &str,
    domain: &str,
) -> Result<bool> {
    let r = sqlx::query("DELETE FROM ingress_routes WHERE domain = ?1 AND cluster_id = ?2")
        .bind(domain)
        .bind(cluster_id)
        .execute(pool)
        .await
        .context("Failed to delete ingress route")?;
    Ok(r.rows_affected() > 0)
}

/// Look up an ingress route by domain (global — domain is unique).
pub async fn lookup_ingress_route_by_domain(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Option<IngressRouteRecord>> {
    let row: Option<IngressRouteRow> = sqlx::query_as(
        "SELECT domain, cluster_id, node_id, target, mode, public_mode, public_ip, created_at
             FROM ingress_routes WHERE domain = ?1",
    )
    .bind(domain)
    .fetch_optional(pool)
    .await
    .context("Failed to lookup ingress route")?;
    Ok(row.map(Into::into))
}

/// List ingress routes for a cluster.
pub async fn list_ingress_routes(
    pool: &SqlitePool,
    cluster_id: &str,
) -> Result<Vec<IngressRouteRecord>> {
    let rows: Vec<IngressRouteRow> = sqlx::query_as(
        "SELECT domain, cluster_id, node_id, target, mode, public_mode, public_ip, created_at
             FROM ingress_routes WHERE cluster_id = ?1 ORDER BY domain",
    )
    .bind(cluster_id)
    .fetch_all(pool)
    .await
    .context("Failed to list ingress routes")?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// List all ingress routes for a specific node — used by the public-IP prober
/// when a node's srflx candidate changes.
pub async fn list_ingress_routes_for_node(
    pool: &SqlitePool,
    cluster_id: &str,
    node_id: &str,
) -> Result<Vec<IngressRouteRecord>> {
    let rows: Vec<IngressRouteRow> = sqlx::query_as(
        "SELECT domain, cluster_id, node_id, target, mode, public_mode, public_ip, created_at
             FROM ingress_routes WHERE cluster_id = ?1 AND node_id = ?2 ORDER BY domain",
    )
    .bind(cluster_id)
    .bind(node_id)
    .fetch_all(pool)
    .await
    .context("Failed to list ingress routes for node")?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// List every ingress route across all clusters — used by the periodic health
/// check and DNS zone loader.
pub async fn list_all_ingress_routes(pool: &SqlitePool) -> Result<Vec<IngressRouteRecord>> {
    let rows: Vec<IngressRouteRow> = sqlx::query_as(
        "SELECT domain, cluster_id, node_id, target, mode, public_mode, public_ip, created_at
             FROM ingress_routes",
    )
    .fetch_all(pool)
    .await
    .context("Failed to list all ingress routes")?;
    Ok(rows.into_iter().map(Into::into).collect())
}

/// Update the public mode + IP for an ingress route.
pub async fn set_ingress_public_mode(
    pool: &SqlitePool,
    domain: &str,
    public_mode: &str,
    public_ip: &str,
) -> Result<()> {
    sqlx::query("UPDATE ingress_routes SET public_mode = ?1, public_ip = ?2 WHERE domain = ?3")
        .bind(public_mode)
        .bind(public_ip)
        .bind(domain)
        .execute(pool)
        .await
        .context("Failed to update ingress public mode")?;
    Ok(())
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
                fingerprint TEXT NOT NULL, overlay_ip TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'node',
                display_name TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (cluster_id, node_id))",
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
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_display_name ON nodes (cluster_id, display_name) WHERE display_name != ''",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS clusters (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS setup_codes (
                cluster_id TEXT NOT NULL, code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL, PRIMARY KEY (cluster_id))",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ingress_routes (
                domain TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, node_id TEXT NOT NULL,
                target TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'http',
                public_mode TEXT NOT NULL DEFAULT 'relay',
                public_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL)",
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
        let ip = register_node_full(
            &pool,
            &NodeRegistration {
                cluster_id: "c1",
                node_id: "nas",
                fingerprint: "fp-1",
                role: "admin",
                display_name: "",
            },
            &s,
        )
        .await
        .unwrap();
        assert_eq!(ip, std::net::Ipv4Addr::new(100, 64, 0, 1));

        let ip2 = register_node_full(
            &pool,
            &NodeRegistration {
                cluster_id: "c1",
                node_id: "rack",
                fingerprint: "fp-2",
                role: "node",
                display_name: "",
            },
            &s,
        )
        .await
        .unwrap();
        assert_eq!(ip2, std::net::Ipv4Addr::new(100, 64, 0, 2));

        let nodes = list_nodes(&pool, "c1").await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].role, "admin");
        assert_eq!(nodes[1].role, "node");
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

    #[tokio::test]
    async fn rename_node_basic() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "uuid-aaa", "fp-aaa", &s)
            .await
            .unwrap();

        // Rename succeeds and is reflected in lookup.
        assert!(rename_node(&pool, "c1", "uuid-aaa", "my-node")
            .await
            .unwrap());
        let node = lookup_node_by_display_name(&pool, "c1", "my-node")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.node_id, "uuid-aaa");
        assert_eq!(node.display_name, "my-node");
    }

    #[tokio::test]
    async fn rename_node_not_found() {
        let pool = test_pool().await;
        // Node does not exist — returns false, no error.
        let ok = rename_node(&pool, "c1", "no-such-uuid", "name")
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn rename_node_unique_per_cluster() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "uuid-1", "fp-1", &s)
            .await
            .unwrap();
        register_node(&pool, "c1", "uuid-2", "fp-2", &s)
            .await
            .unwrap();

        assert!(rename_node(&pool, "c1", "uuid-1", "alpha").await.unwrap());
        // Trying to assign the same name to a different node in the same cluster
        // must fail (returns false due to unique constraint).
        assert!(!rename_node(&pool, "c1", "uuid-2", "alpha").await.unwrap());

        // But the same name is allowed in a different cluster.
        register_node(&pool, "c2", "uuid-1", "fp-c2-1", &s)
            .await
            .unwrap();
        assert!(rename_node(&pool, "c2", "uuid-1", "alpha").await.unwrap());
    }

    #[tokio::test]
    async fn rename_preserves_existing_name_on_re_register() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "uuid-aaa", "fp-aaa", &s)
            .await
            .unwrap();
        rename_node(&pool, "c1", "uuid-aaa", "keeper")
            .await
            .unwrap();

        // Re-register with empty display_name — should not overwrite existing name.
        register_node_full(
            &pool,
            &NodeRegistration {
                cluster_id: "c1",
                node_id: "uuid-aaa",
                fingerprint: "fp-new",
                role: "node",
                display_name: "",
            },
            &s,
        )
        .await
        .unwrap();

        let node = lookup_node_by_fingerprint(&pool, "c1", "fp-new")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.display_name, "keeper");
    }

    #[tokio::test]
    async fn lookup_by_display_name_empty_returns_none() {
        let pool = test_pool().await;
        let result = lookup_node_by_display_name(&pool, "c1", "").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn lookup_by_display_name_missing_returns_none() {
        let pool = test_pool().await;
        let s = default_subnet();
        register_node(&pool, "c1", "uuid-aaa", "fp-aaa", &s)
            .await
            .unwrap();
        let result = lookup_node_by_display_name(&pool, "c1", "no-such-name")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    // --- Ingress routes

    #[tokio::test]
    async fn ingress_route_insert_and_lookup() {
        let pool = test_pool().await;
        let ok = insert_ingress_route(
            &pool,
            "app.mlsh.io",
            "c1",
            "n1",
            "http://localhost:3000",
            "http",
        )
        .await
        .unwrap();
        assert!(ok);

        let r = lookup_ingress_route_by_domain(&pool, "app.mlsh.io")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.node_id, "n1");
        assert_eq!(r.public_mode, "relay");
        assert_eq!(r.target, "http://localhost:3000");
    }

    #[tokio::test]
    async fn ingress_route_conflict_across_clusters() {
        let pool = test_pool().await;
        insert_ingress_route(
            &pool,
            "app.mlsh.io",
            "c1",
            "n1",
            "http://localhost:3000",
            "http",
        )
        .await
        .unwrap();
        let ok = insert_ingress_route(
            &pool,
            "app.mlsh.io",
            "c2",
            "n2",
            "http://localhost:4000",
            "http",
        )
        .await
        .unwrap();
        assert!(
            !ok,
            "expected conflict when another cluster owns the domain"
        );
    }

    #[tokio::test]
    async fn ingress_route_idempotent_same_owner() {
        let pool = test_pool().await;
        insert_ingress_route(&pool, "app.mlsh.io", "c1", "n1", "http://a", "http")
            .await
            .unwrap();
        let ok = insert_ingress_route(&pool, "app.mlsh.io", "c1", "n1", "http://b", "http")
            .await
            .unwrap();
        assert!(ok);
        let r = lookup_ingress_route_by_domain(&pool, "app.mlsh.io")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.target, "http://b");
    }

    #[tokio::test]
    async fn ingress_route_delete_requires_cluster_match() {
        let pool = test_pool().await;
        insert_ingress_route(&pool, "app.mlsh.io", "c1", "n1", "http://a", "http")
            .await
            .unwrap();
        assert!(!delete_ingress_route(&pool, "c2", "app.mlsh.io")
            .await
            .unwrap());
        assert!(delete_ingress_route(&pool, "c1", "app.mlsh.io")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn ingress_route_set_public_mode() {
        let pool = test_pool().await;
        insert_ingress_route(&pool, "app.mlsh.io", "c1", "n1", "http://a", "http")
            .await
            .unwrap();
        set_ingress_public_mode(&pool, "app.mlsh.io", "direct", "203.0.113.5")
            .await
            .unwrap();
        let r = lookup_ingress_route_by_domain(&pool, "app.mlsh.io")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.public_mode, "direct");
        assert_eq!(r.public_ip, "203.0.113.5");
    }
}
