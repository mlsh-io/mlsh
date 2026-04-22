//! Filters local IPs to those that represent real connectivity, excluding
//! container bridges, loopback, link-local, and the overlay TUN itself.

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy)]
pub struct OverlayNet {
    network: u32,
    mask: u32,
}

impl OverlayNet {
    pub fn new(overlay_ip: Ipv4Addr, prefix_len: u8) -> Self {
        let mask: u32 = if prefix_len >= 32 {
            u32::MAX
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let network = u32::from(overlay_ip) & mask;
        Self { network, mask }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.network
    }
}

pub fn is_interesting_ip(ip: Ipv4Addr, iface_name: Option<&str>, overlay: OverlayNet) -> bool {
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return false;
    }

    let octets = ip.octets();
    // Docker default bridge range 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return false;
    }
    // Podman default bridge ranges 10.88.0.0/16 and 10.89.0.0/16
    if octets[0] == 10 && (octets[1] == 88 || octets[1] == 89) {
        return false;
    }
    if overlay.contains(ip) {
        return false;
    }
    if let Some(name) = iface_name {
        if name.starts_with("mlsh") || name.starts_with("utun") || name.starts_with("tun") {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay() -> OverlayNet {
        // 100.64.0.0/10 (default mlsh overlay)
        OverlayNet::new(Ipv4Addr::new(100, 64, 0, 1), 10)
    }

    #[test]
    fn rejects_loopback() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(127, 0, 0, 1),
            None,
            overlay()
        ));
    }

    #[test]
    fn rejects_link_local() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(169, 254, 1, 2),
            None,
            overlay()
        ));
    }

    #[test]
    fn rejects_docker_bridge() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(172, 17, 0, 1),
            None,
            overlay()
        ));
        assert!(!is_interesting_ip(
            Ipv4Addr::new(172, 31, 0, 1),
            None,
            overlay()
        ));
    }

    #[test]
    fn accepts_nearby_non_docker_ranges() {
        // 172.15 and 172.32 are NOT in Docker's default range.
        assert!(is_interesting_ip(
            Ipv4Addr::new(172, 15, 0, 1),
            None,
            overlay()
        ));
        assert!(is_interesting_ip(
            Ipv4Addr::new(172, 32, 0, 1),
            None,
            overlay()
        ));
    }

    #[test]
    fn rejects_podman_bridge() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(10, 88, 0, 1),
            None,
            overlay()
        ));
        assert!(!is_interesting_ip(
            Ipv4Addr::new(10, 89, 0, 1),
            None,
            overlay()
        ));
    }

    #[test]
    fn accepts_other_rfc1918_ten() {
        // 10.0.0.0/8 except the two podman subnets is fine.
        assert!(is_interesting_ip(
            Ipv4Addr::new(10, 0, 0, 1),
            None,
            overlay()
        ));
        assert!(is_interesting_ip(
            Ipv4Addr::new(10, 90, 0, 1),
            None,
            overlay()
        ));
    }

    #[test]
    fn rejects_overlay_subnet() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(100, 64, 0, 1),
            None,
            overlay()
        ));
        assert!(!is_interesting_ip(
            Ipv4Addr::new(100, 100, 50, 30),
            None,
            overlay()
        ));
    }

    #[test]
    fn rejects_tun_by_name() {
        assert!(!is_interesting_ip(
            Ipv4Addr::new(192, 168, 1, 10),
            Some("utun41"),
            overlay()
        ));
        assert!(!is_interesting_ip(
            Ipv4Addr::new(192, 168, 1, 10),
            Some("mlsh0"),
            overlay()
        ));
    }

    #[test]
    fn accepts_normal_lan() {
        assert!(is_interesting_ip(
            Ipv4Addr::new(192, 168, 1, 42),
            Some("en0"),
            overlay()
        ));
        assert!(is_interesting_ip(
            Ipv4Addr::new(192, 168, 1, 42),
            Some("wlan0"),
            overlay()
        ));
    }
}
