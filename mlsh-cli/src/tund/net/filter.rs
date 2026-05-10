//! Filters local IPs to those that represent real connectivity, excluding
//! container bridges, loopback, link-local, and the overlay TUN itself.

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    /// Wired LAN (Ethernet, Thunderbolt bridge, USB-C dock, etc.).
    LanWired,
    /// Wi-Fi.
    LanWireless,
    /// Cellular modem (iOS/macOS hotspot, Android tether, USB modem).
    Cellular,
    /// VPN-like tunnel (utun, tun, tap, ppp, wg, ...).
    Vpn,
    /// Couldn't classify by name; assume LAN-grade but lowest of the LAN tiers.
    Other,
}

impl InterfaceKind {
    /// RFC 5245-ish base priority. LAN beats srflx (200) and srflx beats
    /// VPN/cellular so direct local connectivity is tried first.
    pub fn base_priority(self) -> u32 {
        match self {
            InterfaceKind::LanWired => 250,
            InterfaceKind::LanWireless => 220,
            InterfaceKind::Vpn => 150,
            InterfaceKind::Other => 110,
            InterfaceKind::Cellular => 80,
        }
    }
}

/// Best-effort classification of an interface by its OS-given name. Cross
/// platform: we don't query SCDynamicStore / rtnetlink — the prefix-based
/// heuristic is good enough for the macOS + Linux targets we ship today.
pub fn interface_kind(name: &str) -> InterfaceKind {
    let n = name.to_ascii_lowercase();

    // VPN / tunnel devices first — they often share `enX`-like prefixes on
    // some systems (e.g. `entun`), but the canonical names are unambiguous.
    if n.starts_with("utun")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("ppp")
        || n.starts_with("wg")
        || n.starts_with("ipsec")
        || n.starts_with("gif")
        || n.starts_with("stf")
    {
        return InterfaceKind::Vpn;
    }

    // Cellular: macOS exposes `pdp_ipN` for the iPhone-tethered modem, Linux
    // typically uses `rmnet*` or `wwan*`.
    if n.starts_with("pdp_ip") || n.starts_with("rmnet") || n.starts_with("wwan") {
        return InterfaceKind::Cellular;
    }

    // Wi-Fi: `wlan*` / `wlp*` / `wlx*` on Linux. macOS exposes Wi-Fi as `en0`
    // historically, but newer Macs and external adapters break that rule, so
    // we don't special-case `en0` — it falls through to LanWired below, which
    // is the safer default (Wi-Fi misclassified as wired only loses ~30
    // priority points).
    if n.starts_with("wlan") || n.starts_with("wlp") || n.starts_with("wlx") || n.starts_with("ath")
    {
        return InterfaceKind::LanWireless;
    }

    // Wired LAN: `enX` on macOS (Ethernet/USB-C), `eth*` / `enp*` / `eno*` /
    // `ens*` on Linux, `bridge*` for Internet Sharing.
    if n.starts_with("en")
        || n.starts_with("eth")
        || n.starts_with("bridge")
        || n.starts_with("bond")
        || n.starts_with("vlan")
    {
        return InterfaceKind::LanWired;
    }

    InterfaceKind::Other
}

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

    #[test]
    fn classifies_macos_interfaces() {
        assert_eq!(interface_kind("en0"), InterfaceKind::LanWired);
        assert_eq!(interface_kind("en6"), InterfaceKind::LanWired);
        assert_eq!(interface_kind("utun0"), InterfaceKind::Vpn);
        assert_eq!(interface_kind("utun15"), InterfaceKind::Vpn);
        assert_eq!(interface_kind("bridge100"), InterfaceKind::LanWired);
        assert_eq!(interface_kind("pdp_ip0"), InterfaceKind::Cellular);
    }

    #[test]
    fn classifies_linux_interfaces() {
        assert_eq!(interface_kind("eth0"), InterfaceKind::LanWired);
        assert_eq!(interface_kind("enp3s0"), InterfaceKind::LanWired);
        assert_eq!(interface_kind("wlan0"), InterfaceKind::LanWireless);
        assert_eq!(interface_kind("wlp4s0"), InterfaceKind::LanWireless);
        assert_eq!(interface_kind("wg0"), InterfaceKind::Vpn);
        assert_eq!(interface_kind("tun0"), InterfaceKind::Vpn);
        assert_eq!(interface_kind("rmnet0"), InterfaceKind::Cellular);
        assert_eq!(interface_kind("wwan0"), InterfaceKind::Cellular);
    }

    #[test]
    fn unknown_interface_is_other() {
        assert_eq!(interface_kind("foo0"), InterfaceKind::Other);
        assert_eq!(interface_kind("zt0"), InterfaceKind::Other); // ZeroTier
    }

    #[test]
    fn priorities_have_lan_above_srflx_and_cellular_below() {
        // The fixed srflx priority lives in mlsh-signal/sessions.rs (200);
        // assert our LAN tiers rank above and Cellular below.
        assert!(InterfaceKind::LanWired.base_priority() > 200);
        assert!(InterfaceKind::LanWireless.base_priority() > 200);
        assert!(InterfaceKind::Vpn.base_priority() < 200);
        assert!(InterfaceKind::Cellular.base_priority() < InterfaceKind::Vpn.base_priority());
    }
}
