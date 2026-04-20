//! DNS resolver management for overlay tunnels.
//!
//! - macOS: writes `/etc/resolver/<zone>` (native per-domain DNS)
//! - Linux: configures systemd-resolved via D-Bus (`org.freedesktop.resolve1`)
//!
//! TODO: fallback chain for Linux systems without systemd-resolved:
//! - NetworkManager D-Bus API (org.freedesktop.NetworkManager) for NM-managed systems
//! - resolvconf binary for Debian-based systems
//! - Direct /etc/resolv.conf overwrite as last resort (dirty, no split DNS)

#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::Result;

/// Validate that a cluster name is safe for use in filesystem paths.
fn validate_cluster_name(cluster: &str) -> Result<()> {
    if cluster.is_empty() {
        anyhow::bail!("Cluster name is empty");
    }
    if !cluster
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Invalid cluster name '{}': must contain only [a-zA-Z0-9_-]",
            cluster
        );
    }
    Ok(())
}

/// Install a per-domain resolver.
///
/// - macOS: writes `/etc/resolver/<cluster>` (native per-domain DNS).
/// - Linux: D-Bus call to systemd-resolved (`SetLinkDNS` + `SetLinkDomains`).
pub fn install_resolver(cluster: &str, ip: &str, #[allow(unused)] port: u16) -> Result<()> {
    validate_cluster_name(cluster)?;

    #[cfg(target_os = "macos")]
    {
        let resolver_dir = std::path::Path::new("/etc/resolver");
        if !resolver_dir.exists() {
            std::fs::create_dir_all(resolver_dir).context("Failed to create /etc/resolver")?;
        }
        let path = resolver_dir.join(cluster);
        // `domain` + `search_order` enable bare-name resolution (`ssh nas` → `nas.<cluster>`).
        let content = if port == 53 {
            format!("nameserver {}\ndomain {}\nsearch_order 1\n", ip, cluster)
        } else {
            format!(
                "nameserver {}\nport {}\ndomain {}\nsearch_order 1\n",
                ip, port, cluster
            )
        };
        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        tracing::info!(
            "Installed DNS resolver: {} → {}:{}",
            path.display(),
            ip,
            port
        );
    }

    #[cfg(target_os = "linux")]
    {
        resolved::install(cluster, ip)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ip, port);
        tracing::warn!("DNS resolver setup not supported on this platform");
    }

    Ok(())
}

/// Remove the resolver for a cluster.
pub fn remove_resolver(cluster: &str) {
    if validate_cluster_name(cluster).is_err() {
        tracing::warn!(
            "Refusing to remove resolver for invalid cluster name: {}",
            cluster
        );
        return;
    }

    #[cfg(target_os = "macos")]
    {
        let path = std::path::Path::new("/etc/resolver").join(cluster);
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!("Failed to remove resolver {}: {}", path.display(), e);
            } else {
                tracing::info!("Removed DNS resolver: {}", path.display());
            }
        }
        let _ = std::process::Command::new("dscacheutil")
            .arg("-flushcache")
            .status();
        let _ = std::process::Command::new("killall")
            .args(["-HUP", "mDNSResponder"])
            .status();
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = resolved::remove() {
            tracing::warn!("Failed to revert resolved link: {}", e);
        }
    }
}

// --- systemd-resolved D-Bus integration

#[cfg(target_os = "linux")]
mod resolved {
    use anyhow::{Context, Result};

    const IFACE_NAME: &str = "mlsh0";

    /// Get the interface index for mlsh0.
    fn ifindex() -> Result<i32> {
        let idx = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", IFACE_NAME))
            .with_context(|| format!("{} interface not found", IFACE_NAME))?;
        idx.trim()
            .parse::<i32>()
            .context("Invalid ifindex for mlsh0")
    }

    /// Configure systemd-resolved for split DNS via D-Bus.
    ///
    /// Calls on org.freedesktop.resolve1.Manager:
    /// - SetLinkDNS(ifindex, [(AF_INET, ip_bytes)])
    /// - SetLinkDomains(ifindex, [(zone, routing_only=true)])
    /// - SetLinkDefaultRoute(ifindex, false)
    /// - FlushCaches()
    pub fn install(cluster: &str, ip: &str) -> Result<()> {
        let idx = ifindex()?;
        let addr: std::net::Ipv4Addr = ip.parse().context("Invalid DNS IP")?;
        let ip_bytes: Vec<u8> = addr.octets().to_vec();

        // Use a short-lived blocking tokio runtime for D-Bus calls.
        // The tunnel's async runtime is already running, so we use
        // spawn_blocking → block_on to avoid nesting runtimes.
        let zone = cluster.to_string();
        let result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let conn = zbus::Connection::system()
                    .await
                    .context("Failed to connect to system D-Bus")?;

                let proxy = zbus::proxy::Builder::<'_, zbus::proxy::Proxy<'_>>::new(&conn)
                    .destination("org.freedesktop.resolve1")?
                    .path("/org/freedesktop/resolve1")?
                    .interface("org.freedesktop.resolve1.Manager")?
                    .build()
                    .await
                    .context("Failed to create resolved proxy")?;

                // SetLinkDNS(i, a(iay)) — array of (address_family, address_bytes)
                // AF_INET = 2
                let dns_servers: Vec<(i32, Vec<u8>)> = vec![(2i32, ip_bytes)];
                proxy
                    .call::<_, _, ()>("SetLinkDNS", &(idx, dns_servers))
                    .await
                    .context("SetLinkDNS failed")?;

                // SetLinkDomains(i, a(sb)) — array of (domain, routing_only).
                // routing_only=false makes the zone a search domain too (bare-name resolution).
                let domains: Vec<(&str, bool)> = vec![(&zone, false)];
                proxy
                    .call::<_, _, ()>("SetLinkDomains", &(idx, domains))
                    .await
                    .context("SetLinkDomains failed")?;

                // SetLinkDefaultRoute(i, b) — false = don't capture all DNS
                proxy
                    .call::<_, _, ()>("SetLinkDefaultRoute", &(idx, false))
                    .await
                    .context("SetLinkDefaultRoute failed")?;

                // Best-effort cache flush
                let _ = proxy.call::<_, _, ()>("FlushCaches", &()).await;

                anyhow::Ok(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("D-Bus thread panicked"))?;

        result?;

        tracing::info!(
            "Installed DNS resolver: resolved mlsh0 → {} (zone ~{})",
            ip,
            cluster
        );
        Ok(())
    }

    /// Revert systemd-resolved link config via D-Bus.
    pub fn remove() -> Result<()> {
        let idx = match ifindex() {
            Ok(i) => i,
            Err(_) => return Ok(()), // interface already gone
        };

        let result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let conn = zbus::Connection::system()
                    .await
                    .context("Failed to connect to system D-Bus")?;

                let proxy = zbus::proxy::Builder::<'_, zbus::proxy::Proxy<'_>>::new(&conn)
                    .destination("org.freedesktop.resolve1")?
                    .path("/org/freedesktop/resolve1")?
                    .interface("org.freedesktop.resolve1.Manager")?
                    .build()
                    .await?;

                let _ = proxy.call::<_, _, ()>("RevertLink", &(idx,)).await;
                let _ = proxy.call::<_, _, ()>("FlushCaches", &()).await;
                anyhow::Ok(())
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("D-Bus thread panicked"))?;

        result?;
        tracing::info!("Removed DNS resolver for mlsh0");
        Ok(())
    }
}
