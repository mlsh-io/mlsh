//! Platform-specific /32 route management for overlay peers.
//!
//! Each peer gets a host route pointing at the TUN device so the OS
//! knows to send traffic for that specific overlay IP through the tunnel.
//!
//! Linux/macOS address the interface by name (`ip` / `route`). Windows
//! addresses it by interface index via `netsh`, because wintun adapter
//! names are unreliable (localized, may contain spaces) whereas the
//! numeric index obtained from `device.if_index()` is unambiguous.

use std::net::Ipv4Addr;

/// Add a /32 host route for a peer via the TUN device.
///
/// `tun_name` is used on Linux/macOS; `tun_index` (the OS interface index)
/// is used on Windows. Each caller passes both — the unused one is ignored
/// on a given platform.
pub fn add_peer_route(peer_ip: Ipv4Addr, tun_name: &str, tun_index: u32) {
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (peer_ip, tun_name, tun_index);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let _ = tun_index;
        let ip = peer_ip.to_string();

        #[cfg(target_os = "macos")]
        let output = std::process::Command::new("route")
            .args(["-n", "add", "-host", &ip, "-interface", tun_name])
            .output();

        #[cfg(target_os = "linux")]
        let output = std::process::Command::new("ip")
            .args(["route", "add", &format!("{}/32", ip), "dev", tun_name])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Added route for {} via {}", ip, tun_name);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // "File exists" means route already present — not an error.
                if !stderr.contains("File exists") {
                    tracing::warn!("Failed to add route for {}: {}", ip, stderr.trim());
                }
            }
            Err(e) => tracing::warn!("Failed to run route command: {}", e),
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = tun_name;
        windows::add(peer_ip, tun_index);
    }
}

/// Remove the /32 host route for a peer.
///
/// `tun_index` is only used on Windows (to scope the `netsh` delete to the
/// wintun interface); Linux/macOS delete by destination prefix alone.
pub fn remove_peer_route(peer_ip: Ipv4Addr, tun_index: u32) {
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (peer_ip, tun_index);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let _ = tun_index;
        let ip = peer_ip.to_string();

        #[cfg(target_os = "macos")]
        let (output, absent) = (
            std::process::Command::new("route")
                .args(["-n", "delete", "-host", &ip])
                .output(),
            "not in table",
        );

        #[cfg(target_os = "linux")]
        let (output, absent) = (
            std::process::Command::new("ip")
                .args(["route", "del", &format!("{}/32", ip)])
                .output(),
            "No such process",
        );

        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Removed route for {}", ip);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains(absent) {
                    tracing::warn!("Failed to remove route for {}: {}", ip, stderr.trim());
                }
            }
            Err(e) => tracing::warn!("Failed to run route command: {}", e),
        }
    }

    #[cfg(target_os = "windows")]
    {
        windows::remove(peer_ip, tun_index);
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::net::Ipv4Addr;
    use std::process::Command;

    /// Add a /32 on-link host route to the wintun interface (by index).
    ///
    /// `netsh` output and exit codes are localized, so instead of parsing an
    /// "already exists" message we make the add idempotent: delete any stale
    /// entry first (ignoring the result), then add a fresh one. This also
    /// cleans up routes left behind by an unclean shutdown.
    pub(super) fn add(peer_ip: Ipv4Addr, tun_index: u32) {
        if tun_index == 0 {
            tracing::warn!(
                "Cannot add route for {}: TUN interface index unavailable",
                peer_ip
            );
            return;
        }
        let prefix = format!("prefix={}/32", peer_ip);
        let iface = format!("interface={}", tun_index);

        let _ = Command::new("netsh")
            .args(["interface", "ipv4", "delete", "route", &prefix, &iface])
            .output();

        let output = Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "add",
                "route",
                &prefix,
                &iface,
                "store=active",
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Added route for {} via if{}", peer_ip, tun_index);
            }
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                tracing::warn!(
                    "Failed to add route for {}: {} {}",
                    peer_ip,
                    out.trim(),
                    err.trim()
                );
            }
            Err(e) => tracing::warn!("Failed to run netsh add route: {}", e),
        }
    }

    /// Remove the /32 host route from the wintun interface (by index).
    /// A failed delete usually means the route was already gone — not critical.
    pub(super) fn remove(peer_ip: Ipv4Addr, tun_index: u32) {
        if tun_index == 0 {
            return;
        }
        let prefix = format!("prefix={}/32", peer_ip);
        let iface = format!("interface={}", tun_index);

        match Command::new("netsh")
            .args(["interface", "ipv4", "delete", "route", &prefix, &iface])
            .output()
        {
            Ok(o) if o.status.success() => {
                tracing::debug!("Removed route for {} via if{}", peer_ip, tun_index);
            }
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                tracing::debug!("netsh delete route for {}: {}", peer_ip, out.trim());
            }
            Err(e) => tracing::debug!("Failed to run netsh delete route: {}", e),
        }
    }
}
