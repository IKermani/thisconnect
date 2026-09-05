// SPDX-License-Identifier: GPL-3.0-or-later

//! The `allowed_cidrs` admission list from `docs/SPEC.md` §5.6 L3.
//!
//! Hand-rolled rather than pulled in: the whole type is a prefix compare, and
//! an open proxy is the worst failure this component has, so the matching rule
//! should be readable in one screen and covered by its own tests.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CidrError {
    #[error("not an IP address or CIDR block")]
    NotAnAddress,
    #[error("prefix length is not a number")]
    BadPrefix,
    #[error("prefix length is longer than the address family allows")]
    PrefixTooLong,
}

/// An address block. A bare address parses as a host route (`/32`, `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, CidrError> {
        if prefix_len > max_prefix(&network) {
            return Err(CidrError::PrefixTooLong);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// A v4-mapped v6 peer (`::ffff:a.b.c.d`) is compared as the v4 address it
    /// actually is; otherwise a v4 rule silently fails to cover a dual-stack
    /// socket's own peers.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, canonical(addr)) {
            (IpAddr::V4(net), IpAddr::V4(peer)) => {
                prefix_matches(&net.octets(), &peer.octets(), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(peer)) => {
                prefix_matches(&net.octets(), &peer.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| CidrError::NotAnAddress)?;
        let prefix_len = match prefix {
            Some(prefix) => prefix.parse().map_err(|_| CidrError::BadPrefix)?,
            None => max_prefix(&network),
        };
        Self::new(network, prefix_len)
    }
}

/// True when the peer is admitted. Loopback is always admitted: it is the
/// default bind and the empty list must not lock the user out of their own
/// proxy. Every non-loopback peer needs an explicit rule, so an empty list on a
/// non-loopback listener admits nobody — fail closed.
pub fn is_peer_allowed(peer: IpAddr, allowed: &[Cidr]) -> bool {
    if canonical(peer).is_loopback() {
        return true;
    }
    allowed.iter().any(|cidr| cidr.contains(peer))
}

fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn max_prefix(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => Ipv4Addr::BITS as u8,
        IpAddr::V6(_) => Ipv6Addr::BITS as u8,
    }
}

fn prefix_matches(network: &[u8], peer: &[u8], prefix_len: u8) -> bool {
    let whole = usize::from(prefix_len / 8);
    if network[..whole] != peer[..whole] {
        return false;
    }
    let remainder = prefix_len % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - remainder);
    network[whole] & mask == peer[whole] & mask
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn cidr(value: &str) -> Cidr {
        value.parse().expect("test fixture should parse as a cidr")
    }

    fn ip(value: &str) -> IpAddr {
        value
            .parse()
            .expect("test fixture should parse as an address")
    }

    #[test]
    fn bare_address_parses_as_a_host_route() {
        // Arrange / Act
        let v4 = cidr("192.0.2.7");
        let v6 = cidr("2001:db8::1");

        // Assert
        assert_eq!(v4.prefix_len(), 32);
        assert_eq!(v6.prefix_len(), 128);
        assert!(v4.contains(ip("192.0.2.7")));
        assert!(!v4.contains(ip("192.0.2.8")));
    }

    #[test]
    fn non_byte_aligned_prefixes_match_on_the_bit() {
        // Arrange
        let block = cidr("192.0.2.0/28");

        // Act / Assert
        assert!(block.contains(ip("192.0.2.15")));
        assert!(!block.contains(ip("192.0.2.16")));
    }

    #[test]
    fn zero_prefix_matches_the_whole_family_but_not_the_other() {
        // Arrange
        let all_v4 = cidr("0.0.0.0/0");

        // Act / Assert
        assert!(all_v4.contains(ip("198.51.100.4")));
        assert!(!all_v4.contains(ip("2001:db8::1")));
    }

    #[test]
    fn v4_mapped_v6_peer_matches_a_v4_rule() {
        // Arrange
        let block = cidr("198.51.100.0/24");

        // Act / Assert
        assert!(block.contains(ip("::ffff:198.51.100.9")));
        assert!(!block.contains(ip("::ffff:203.0.113.9")));
    }

    #[test]
    fn rejects_malformed_and_oversized_prefixes() {
        // Arrange / Act / Assert
        assert_eq!(
            "nonsense".parse::<Cidr>().err(),
            Some(CidrError::NotAnAddress)
        );
        assert_eq!(
            "10.0.0.0/x".parse::<Cidr>().err(),
            Some(CidrError::BadPrefix)
        );
        assert_eq!(
            "10.0.0.0/33".parse::<Cidr>().err(),
            Some(CidrError::PrefixTooLong)
        );
    }

    #[test]
    fn empty_allow_list_admits_loopback_only() {
        // Arrange
        let allowed: Vec<Cidr> = Vec::new();

        // Act / Assert
        assert!(is_peer_allowed(ip("127.0.0.1"), &allowed));
        assert!(is_peer_allowed(ip("::1"), &allowed));
        assert!(is_peer_allowed(ip("::ffff:127.0.0.1"), &allowed));
        assert!(!is_peer_allowed(ip("192.168.1.5"), &allowed));
    }

    #[test]
    fn listed_block_admits_its_members_and_nothing_else() {
        // Arrange
        let allowed = vec![cidr("192.168.1.0/24")];

        // Act / Assert
        assert!(is_peer_allowed(ip("192.168.1.5"), &allowed));
        assert!(!is_peer_allowed(ip("192.168.2.5"), &allowed));
    }

    #[test]
    fn display_round_trips_through_parsing() {
        // Arrange
        let block = cidr("fd00::/8");

        // Act
        let rendered = block.to_string();

        // Assert
        assert_eq!(rendered, "fd00::/8");
        assert_eq!(cidr(&rendered), block);
    }
}
