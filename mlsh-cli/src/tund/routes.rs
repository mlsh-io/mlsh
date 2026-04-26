//! Platform-specific /32 route management for overlay peers.
//!
//! Each peer gets a host route pointing at the TUN device so the OS
//! knows to send traffic for that specific overlay IP through the tunnel.

use std::net::Ipv4Addr;

/// Add a /32 host route for a peer via the TUN device.
pub fn add_peer_route(peer_ip: Ipv4Addr, tun_name: &str) {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (peer_ip, tun_name);
        return;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let ip = peer_ip.to_string();

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("route")
            .args(["-n", "add", "-host", &ip, "-interface", tun_name])
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

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["route", "add", &format!("{}/32", ip), "dev", tun_name])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Added route for {} via {}", ip, tun_name);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    tracing::warn!("Failed to add route for {}: {}", ip, stderr.trim());
                }
            }
            Err(e) => tracing::warn!("Failed to run ip route command: {}", e),
        }
    }
}

/// Remove the /32 host route for a peer.
pub fn remove_peer_route(peer_ip: Ipv4Addr) {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = peer_ip;
        return;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let ip = peer_ip.to_string();

    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("route")
            .args(["-n", "delete", "-host", &ip])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Removed route for {}", ip);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("not in table") {
                    tracing::warn!("Failed to remove route for {}: {}", ip, stderr.trim());
                }
            }
            Err(e) => tracing::warn!("Failed to run route command: {}", e),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ip")
            .args(["route", "del", &format!("{}/32", ip)])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                tracing::debug!("Removed route for {}", ip);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("No such process") {
                    tracing::warn!("Failed to remove route for {}: {}", ip, stderr.trim());
                }
            }
            Err(e) => tracing::warn!("Failed to run ip route command: {}", e),
        }
    }
}
