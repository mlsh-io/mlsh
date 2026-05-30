//! DNS resolver management for overlay tunnels.
//!
//! - macOS: publishes `State:/Network/Service/mlsh-<uuid>/DNS` via SCDynamicStore
//!   (split DNS + search domain, same mechanism as Tailscale).
//! - Linux: configures systemd-resolved via D-Bus (`org.freedesktop.resolve1`).
//! - Windows: adds NRPT (Name Resolution Policy Table) rules via the DnsClient
//!   PowerShell cmdlets for the cluster zone, plus a connection-specific suffix
//!   on the wintun interface for bare-name resolution.
//!
//! TODO: fallback chain for Linux systems without systemd-resolved:
//! - NetworkManager D-Bus API (org.freedesktop.NetworkManager) for NM-managed systems
//! - resolvconf binary for Debian-based systems
//! - Direct /etc/resolv.conf overwrite as last resort (dirty, no split DNS)

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
/// - macOS: SCDynamicStore session publishing split DNS + search domain.
/// - Linux: D-Bus call to systemd-resolved (`SetLinkDNS` + `SetLinkDomains`).
/// - Windows: NRPT rules for the cluster zone (the resolver must be on port 53,
///   which the caller already provides on `overlay_ip`) + a connection-specific
///   DNS suffix on the wintun interface (addressed by `tun_index`).
///
/// `tun_name` is used on macOS; `tun_index` (the OS interface index) on Windows.
/// Each caller passes both — the unused one is ignored on a given platform.
pub fn install_resolver(
    cluster: &str,
    #[allow(unused)] ip: &str,
    #[allow(unused)] port: u16,
    #[allow(unused)] node_uuid: &str,
    #[allow(unused)] tun_name: &str,
    #[allow(unused)] tun_index: u32,
) -> Result<()> {
    validate_cluster_name(cluster)?;

    #[cfg(target_os = "macos")]
    {
        let resolver = macos::install(cluster, ip, port, node_uuid, tun_name)?;
        macos::registry()
            .lock()
            .unwrap()
            .insert(cluster.to_string(), resolver);
        tracing::info!(
            "Installed DNS resolver: SCDynamicStore mlsh-{} → {}:{} (zone {}, if {})",
            node_uuid,
            ip,
            port,
            cluster,
            tun_name
        );
    }

    #[cfg(target_os = "linux")]
    {
        resolved::install(cluster, ip)?;
    }

    #[cfg(target_os = "windows")]
    {
        windows::install(cluster, ip, tun_index)?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
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
        // Dropping the MacOsResolver removes the SCDynamicStore key and flushes caches.
        let _ = macos::registry().lock().unwrap().remove(cluster);
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = resolved::remove() {
            tracing::warn!("Failed to revert resolved link: {}", e);
        }
    }

    #[cfg(target_os = "windows")]
    {
        windows::remove(cluster);
    }
}

// --- macOS SCDynamicStore integration

#[cfg(target_os = "macos")]
mod macos {
    use anyhow::Result;
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::CFRelease;
    use std::collections::HashMap;
    use std::ptr;
    use std::sync::{Mutex, OnceLock};
    use system_configuration_sys::dynamic_store::{
        SCDynamicStoreCreate, SCDynamicStoreRef, SCDynamicStoreRemoveValue, SCDynamicStoreSetValue,
    };

    /// Holds an SCDynamicStore session and the key it published. CoreFoundation
    /// objects are thread-safe (retain/release atomic); we assert Send for the
    /// raw pointer wrapper since access is serialized through a Mutex.
    pub struct MacOsResolver {
        store: SCDynamicStoreRef,
        key: CFString,
    }

    unsafe impl Send for MacOsResolver {}

    pub fn registry() -> &'static Mutex<HashMap<String, MacOsResolver>> {
        static REG: OnceLock<Mutex<HashMap<String, MacOsResolver>>> = OnceLock::new();
        REG.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub fn install(
        cluster: &str,
        ip: &str,
        port: u16,
        node_uuid: &str,
        tun_name: &str,
    ) -> Result<MacOsResolver> {
        let session = CFString::new(&format!("mlsh-{}", node_uuid));
        let store = unsafe {
            SCDynamicStoreCreate(
                ptr::null(),
                session.as_concrete_TypeRef(),
                None,
                ptr::null_mut(),
            )
        };
        if store.is_null() {
            anyhow::bail!("SCDynamicStoreCreate returned null");
        }

        let key = CFString::new(&format!("State:/Network/Service/mlsh-{}/DNS", node_uuid));

        let server_addresses = CFArray::from_CFTypes(&[CFString::new(ip).as_CFType()]).to_untyped();
        let supplemental =
            CFArray::from_CFTypes(&[CFString::new(cluster).as_CFType()]).to_untyped();
        let search = CFArray::from_CFTypes(&[CFString::new(cluster).as_CFType()]).to_untyped();

        let pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::new("ServerAddresses"),
                server_addresses.as_CFType(),
            ),
            (
                CFString::new("ServerPort"),
                CFNumber::from(port as i32).as_CFType(),
            ),
            (
                CFString::new("InterfaceName"),
                CFString::new(tun_name).as_CFType(),
            ),
            (
                CFString::new("SupplementalMatchDomains"),
                supplemental.as_CFType(),
            ),
            (CFString::new("SearchDomains"), search.as_CFType()),
            (
                CFString::new("DomainName"),
                CFString::new(cluster).as_CFType(),
            ),
        ];

        let dict = CFDictionary::from_CFType_pairs(&pairs);

        let ok = unsafe {
            SCDynamicStoreSetValue(store, key.as_concrete_TypeRef(), dict.as_CFTypeRef() as _)
        };

        if ok == 0 {
            unsafe { CFRelease(store as _) };
            anyhow::bail!("SCDynamicStoreSetValue failed");
        }

        Ok(MacOsResolver { store, key })
    }

    impl Drop for MacOsResolver {
        fn drop(&mut self) {
            unsafe {
                SCDynamicStoreRemoveValue(self.store, self.key.as_concrete_TypeRef());
                CFRelease(self.store as _);
            }
            let _ = std::process::Command::new("dscacheutil")
                .arg("-flushcache")
                .status();
            let _ = std::process::Command::new("killall")
                .args(["-HUP", "mDNSResponder"])
                .status();
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

// --- Windows NRPT integration

#[cfg(target_os = "windows")]
mod windows {
    use anyhow::Result;
    use std::process::Command;

    /// Tag stored in the NRPT rule `Comment` field. Lets us find and remove
    /// EXACTLY the rules we created — for this cluster — even after an unclean
    /// shutdown, without touching any rule we don't own.
    fn comment_tag(cluster: &str) -> String {
        format!("mlsh:{cluster}")
    }

    /// Configure split DNS for the cluster zone via NRPT.
    ///
    /// NRPT can only target port 53 and refuses loopback, so the resolver must
    /// be reachable on `overlay_ip:53` (the caller already binds it there on
    /// Windows). Two namespaces are covered: `.<cluster>` (suffix match for
    /// `nas.homelab`, `<uuid>.homelab`, …) and `<cluster>` (exact FQDN, for the
    /// bare cluster name → control node).
    ///
    /// `cluster` is validated `[a-zA-Z0-9_-]` upstream and `ip` comes from our
    /// own `SocketAddr`, so neither can break out of the single-quoted strings.
    pub fn install(cluster: &str, ip: &str, tun_index: u32) -> Result<()> {
        let comment = comment_tag(cluster);

        // Idempotent (like `netsh add route`): purge any stale mlsh rules for
        // this cluster first, then add a fresh one.
        remove_rules(&comment);

        run_ps(&format!(
            "Add-DnsClientNrptRule -Namespace '.{cluster}','{cluster}' \
             -NameServers '{ip}' -Comment '{comment}'"
        ))?;

        // Best-effort: connection-specific suffix so bare names (`ssh nas`)
        // resolve as `nas.<cluster>`. Removed automatically when the wintun
        // interface disappears on tunnel teardown.
        if tun_index != 0 {
            if let Err(e) = run_ps(&format!(
                "Set-DnsClient -InterfaceIndex {tun_index} -ConnectionSpecificSuffix '{cluster}'"
            )) {
                tracing::warn!("Failed to set DNS suffix on if{}: {}", tun_index, e);
            }
        }

        tracing::info!("Installed DNS resolver: NRPT .{cluster} → {ip} (if {tun_index})");
        Ok(())
    }

    /// Remove the NRPT rules we created for this cluster. The connection-specific
    /// suffix is left to disappear with the interface.
    pub fn remove(cluster: &str) {
        remove_rules(&comment_tag(cluster));
        tracing::info!("Removed DNS resolver for zone {cluster}");
    }

    fn remove_rules(comment: &str) {
        let _ = run_ps(&format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{comment}' }} \
             | Remove-DnsClientNrptRule -Force"
        ));
    }

    fn run_ps(script: &str) -> Result<()> {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "powershell: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}
