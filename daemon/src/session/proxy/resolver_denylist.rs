// SPDX-License-Identifier: GPL-3.0-or-later

//! The destination denylist of SPEC.md §5.4 D6, applied to *resolver* addresses
//! before the daemon hands any of them to the proxy.
//!
//! The daemon is the only component that ever sees a `PUSH_REPLY`. A server that
//! pushes `dhcp-option DNS 127.0.0.53` is asking the client to answer every name
//! from the host's own stub resolver — the system resolver D3 forbids outright —
//! and a resolver socket that is merely pinned to the tun would still reach it.
//! Vetting here means such a push can never become a `DnsSource::Pushed` plan,
//! whatever the proxy-side socket does.
//!
//! RFC1918 and IPv6 unique-local addresses are *allowed*: a VPN's own resolver is
//! almost always 10.x or fd00::/8 behind the tunnel. This mirrors
//! `thisconnect_proxy::egress::check_destination` under a policy that permits
//! private destinations; it is duplicated rather than shared because the daemon
//! does not depend on the proxy crate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether this address may be used as a nameserver reached through the tunnel.
pub(crate) fn is_usable_resolver(addr: IpAddr) -> bool {
    match canonical_ip(addr) {
        IpAddr::V4(v4) => is_usable_v4(v4),
        IpAddr::V6(v6) => is_usable_v6(v6),
    }
}

/// `::ffff:127.0.0.1` is the same destination as `127.0.0.1`; collapsing first
/// means one set of rules covers both spellings.
fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn is_usable_v4(addr: Ipv4Addr) -> bool {
    !addr.is_loopback()
        // 0.0.0.0/8, which several stacks route to the local host.
        && addr.octets()[0] != 0
        && !addr.is_link_local()
        && !addr.is_multicast()
        && !addr.is_broadcast()
}

fn is_usable_v6(addr: Ipv6Addr) -> bool {
    !addr.is_loopback()
        && !addr.is_unspecified()
        && !addr.is_multicast()
        // fe80::/10.
        && addr.segments()[0] & 0xffc0 != 0xfe80
        // Deprecated IPv4-compatible form (::a.b.c.d): another spelling of a v4
        // literal that would otherwise skip every v4 rule above.
        && addr.segments()[..6] != [0, 0, 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn usable(raw: &str) -> bool {
        let addr: IpAddr = raw.parse().expect("a literal address");
        is_usable_resolver(addr)
    }

    #[test]
    fn a_resolver_behind_the_tunnel_is_usable() {
        // Arrange / Act / Assert
        assert!(usable("10.8.0.1"));
        assert!(usable("192.168.1.1"));
        assert!(usable("172.16.0.53"));
        assert!(usable("9.9.9.9"));
        assert!(usable("2620:fe::fe"));
        assert!(usable("fd00::53"));
    }

    /// The whole point: a pushed loopback resolver is the system resolver by
    /// another name (SPEC.md §5.4 D3).
    #[test]
    fn a_loopback_resolver_is_never_usable() {
        assert!(!usable("127.0.0.1"));
        assert!(!usable("127.0.0.53"));
        assert!(!usable("127.255.255.254"));
        assert!(!usable("::1"));
    }

    #[test]
    fn a_v4_mapped_loopback_cannot_smuggle_itself_past_the_v6_rules() {
        assert!(!usable("::ffff:127.0.0.1"));
        assert!(!usable("::ffff:169.254.169.254"));
        assert!(!usable("::ffff:0.0.0.0"));
        // The deprecated v4-compatible spelling of the same thing.
        assert!(!usable("::127.0.0.1"));
        assert!(!usable("::169.254.169.254"));
    }

    #[test]
    fn link_local_and_metadata_addresses_are_never_usable() {
        assert!(!usable("169.254.169.254"));
        assert!(!usable("169.254.0.1"));
        assert!(!usable("fe80::1"));
        assert!(!usable("febf::1"));
    }

    #[test]
    fn unspecified_multicast_and_broadcast_are_never_usable() {
        assert!(!usable("0.0.0.0"));
        assert!(!usable("0.1.2.3"));
        assert!(!usable("224.0.0.1"));
        assert!(!usable("255.255.255.255"));
        assert!(!usable("::"));
        assert!(!usable("ff02::1"));
    }
}
