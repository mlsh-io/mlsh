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

pub fn is_interesting_ip(ip: Ipv4Addr, _iface_name: Option<&str>, overlay: OverlayNet) -> bool {
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        return false;
    }
    if overlay.contains(ip) {
        return false;
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
    fn accepts_iphone_hotspot() {
        // Apple Personal Hotspot subnet lives inside RFC1918 172.16/12 —
        // used to be rejected as "Docker". Now accepted.
        assert!(is_interesting_ip(
            Ipv4Addr::new(172, 20, 10, 4),
            Some("en0"),
            overlay()
        ));
    }

    #[test]
    fn accepts_rfc1918_ten() {
        assert!(is_interesting_ip(
            Ipv4Addr::new(10, 0, 0, 1),
            Some("en0"),
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
    fn accepts_normal_lan() {
        assert!(is_interesting_ip(
            Ipv4Addr::new(192, 168, 1, 42),
            Some("en0"),
            overlay()
        ));
    }

    #[test]
    fn accepts_vpn_tun() {
        // utun / tun interfaces may be legitimate VPN endpoints whose
        // default route we'd want to follow — no name-based filter.
        assert!(is_interesting_ip(
            Ipv4Addr::new(10, 7, 0, 2),
            Some("utun5"),
            overlay()
        ));
    }
}
