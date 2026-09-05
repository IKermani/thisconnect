// SPDX-License-Identifier: GPL-3.0-or-later

//! Validated, typed inputs to tunnel policy (SPEC.md §5.2).
//!
//! Every value here originated in a `.ovpn` profile or a server push, so it is untrusted even
//! after the profile validator saw it: `scripts/verify-ifscope-macos.sh` shipped a root command
//! injection precisely because a peer address travelled from an openvpn log straight onto a
//! command line. Nothing reaches a subprocess argument unless it round-tripped through one of
//! these constructors.

use std::fmt;
use std::net::IpAddr;

use super::PolicyError;

/// The Linux policy table and rule priority are ours alone; fixed values make reconciliation
/// possible without any ownership marking the kernel does not offer.
pub const POLICY_TABLE: &str = "218";
pub const RULE_PRIORITY: &str = "18000";
/// The floor must lose to the real tunnel route and win against nothing else.
pub const FLOOR_METRIC: &str = "4000";
pub const ROUTE_METRIC: &str = "100";

/// `IFNAMSIZ - 1`. Longer names cannot name a real interface on either platform.
const MAX_DEVICE_LEN: usize = 15;
const MIN_MTU: u32 = 576;
const MAX_MTU: u32 = 9000;
/// A v6-carrying tunnel below the IPv6 minimum MTU cannot forward a legal packet.
const MIN_MTU_V6: u32 = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The address-family selector for macOS `route(8)`.
    pub fn route_flag(self) -> &'static str {
        match self {
            Self::V4 => "-inet",
            Self::V6 => "-inet6",
        }
    }

    /// The address-family selector for Linux `ip(8)`.
    pub fn ip_flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }

    pub fn host_prefix(self) -> &'static str {
        match self {
            Self::V4 => "/32",
            Self::V6 => "/128",
        }
    }

    fn matches(self, address: &IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

/// An interface name that is safe to hand to a privileged subprocess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceName(String);

impl DeviceName {
    pub fn parse(raw: &str) -> Result<Self, PolicyError> {
        let invalid = |reason: &'static str| PolicyError::InvalidDevice {
            reason,
            value: raw.to_owned(),
        };
        if raw.is_empty() || raw.len() > MAX_DEVICE_LEN {
            return Err(invalid("length must be 1..=15 bytes"));
        }
        if !raw.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(invalid("must start with an ASCII letter"));
        }
        if !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(invalid("may only contain [A-Za-z0-9_.-]"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// macOS scopes routes by interface index, so a name that is not a utun cannot be the tunnel
    /// openvpn just brought up and must never be scoped against.
    pub fn require_utun(&self) -> Result<(), PolicyError> {
        let digits = self.0.strip_prefix("utun").unwrap_or_default();
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
            return Err(PolicyError::InvalidDevice {
                reason: "macOS tunnel policy only scopes utun<N> interfaces",
                value: self.0.clone(),
            });
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mtu(u32);

impl Mtu {
    pub fn parse(value: u32) -> Result<Self, PolicyError> {
        if !(MIN_MTU..=MAX_MTU).contains(&value) {
            return Err(PolicyError::InvalidMtu(value));
        }
        Ok(Self(value))
    }

    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// How the scoped default route reaches the far side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Topology {
    /// A usable on-link gateway was learned (`topology subnet`): route via that address.
    Gateway(IpAddr),
    /// p2p / net30, no gateway to name: scope the default to the interface itself.
    Interface,
}

/// One address family of a live tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelEndpoint {
    family: Family,
    local: IpAddr,
    topology: Topology,
}

impl TunnelEndpoint {
    pub fn new(
        family: Family,
        local: IpAddr,
        gateway: Option<IpAddr>,
    ) -> Result<Self, PolicyError> {
        validate_address(family, &local)?;
        let topology = match gateway {
            Some(address) => {
                validate_address(family, &address)?;
                if address == local {
                    return Err(PolicyError::InvalidAddress {
                        reason: "gateway must differ from the tunnel local address",
                        value: address.to_string(),
                    });
                }
                Topology::Gateway(address)
            }
            None => Topology::Interface,
        };
        Ok(Self {
            family,
            local,
            topology,
        })
    }

    pub fn family(&self) -> Family {
        self.family
    }

    pub fn local(&self) -> IpAddr {
        self.local
    }

    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// The `from <tunip>/32` selector of the Linux rule.
    pub fn local_host_cidr(&self) -> String {
        format!("{}{}", self.local, self.family.host_prefix())
    }
}

/// Untrusted strings as they arrive from the management interface.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawTunnel<'a> {
    pub device: &'a str,
    pub local_v4: &'a str,
    pub gateway_v4: Option<&'a str>,
    pub local_v6: Option<&'a str>,
    pub gateway_v6: Option<&'a str>,
    pub mtu: u32,
}

/// Everything tunnel policy needs, with every field already proven safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelSpec {
    device: DeviceName,
    v4: TunnelEndpoint,
    v6: Option<TunnelEndpoint>,
    mtu: Mtu,
}

impl TunnelSpec {
    pub fn parse(raw: RawTunnel<'_>) -> Result<Self, PolicyError> {
        let device = DeviceName::parse(raw.device)?;
        let v4 = TunnelEndpoint::new(
            Family::V4,
            parse_address(raw.local_v4)?,
            parse_optional_address(raw.gateway_v4)?,
        )?;
        let v6 = match raw.local_v6 {
            // Mirror v6 only when an address was actually assigned; §5.5 has the proxy refuse
            // AF_INET6 outright otherwise, and a v6 route we cannot source from is a lie.
            Some(local) => Some(TunnelEndpoint::new(
                Family::V6,
                parse_address(local)?,
                parse_optional_address(raw.gateway_v6)?,
            )?),
            None => None,
        };
        let mtu = Mtu::parse(raw.mtu)?;
        if v6.is_some() && mtu.as_u32() < MIN_MTU_V6 {
            return Err(PolicyError::InvalidMtu(mtu.as_u32()));
        }
        Ok(Self {
            device,
            v4,
            v6,
            mtu,
        })
    }

    pub fn device(&self) -> &DeviceName {
        &self.device
    }

    pub fn v4(&self) -> &TunnelEndpoint {
        &self.v4
    }

    pub fn v6(&self) -> Option<&TunnelEndpoint> {
        self.v6.as_ref()
    }

    pub fn mtu(&self) -> Mtu {
        self.mtu
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &TunnelEndpoint> {
        std::iter::once(&self.v4).chain(self.v6.iter())
    }
}

fn parse_optional_address(raw: Option<&str>) -> Result<Option<IpAddr>, PolicyError> {
    match raw {
        Some(value) => parse_address(value).map(Some),
        None => Ok(None),
    }
}

fn parse_address(raw: &str) -> Result<IpAddr, PolicyError> {
    raw.parse::<IpAddr>()
        .map_err(|_| PolicyError::InvalidAddress {
            reason: "not an IP literal",
            value: raw.to_owned(),
        })
}

/// Rejects the addresses that cannot legitimately terminate a tunnel. A tunnel "local" address of
/// `127.0.0.1` or `0.0.0.0` would have the proxy bind somewhere the tunnel does not reach, and a
/// link-local v6 gateway is unusable without a scope id we never carry.
fn validate_address(family: Family, address: &IpAddr) -> Result<(), PolicyError> {
    let reject = |reason: &'static str| {
        Err(PolicyError::InvalidAddress {
            reason,
            value: address.to_string(),
        })
    };
    if !family.matches(address) {
        return reject("address family does not match the endpoint");
    }
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return reject("unspecified, loopback and multicast addresses cannot carry a tunnel");
    }
    match address {
        IpAddr::V4(v4) => {
            if v4.is_broadcast() || v4.is_link_local() || v4.octets()[0] == 0 {
                return reject(
                    "broadcast, link-local and 0.0.0.0/8 addresses cannot carry a tunnel",
                );
            }
        }
        IpAddr::V6(v6) => {
            // `is_unicast_link_local` is still unstable; the prefix test is the same check.
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return reject("link-local v6 addresses need a scope id we never carry");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn raw() -> RawTunnel<'static> {
        RawTunnel {
            device: "utun4",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            local_v6: None,
            gateway_v6: None,
            mtu: 1400,
        }
    }

    #[test]
    fn accepts_a_realistic_tunnel() {
        let spec = TunnelSpec::parse(raw()).expect("valid");

        assert_eq!(spec.device().as_str(), "utun4");
        assert_eq!(
            spec.v4().topology(),
            &Topology::Gateway("10.8.0.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(spec.mtu().as_u32(), 1400);
    }

    #[test]
    fn a_tunnel_without_a_gateway_is_point_to_point() {
        let spec = TunnelSpec::parse(RawTunnel {
            gateway_v4: None,
            ..raw()
        })
        .expect("valid");

        assert_eq!(spec.v4().topology(), &Topology::Interface);
    }

    #[test]
    fn rejects_a_device_name_carrying_shell_metacharacters() {
        let outcome = DeviceName::parse("utun4;touch /tmp/pwned");

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }

    #[test]
    fn rejects_a_device_name_that_would_read_as_an_option() {
        let outcome = DeviceName::parse("-interface");

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }

    #[test]
    fn rejects_an_overlong_device_name() {
        let outcome = DeviceName::parse("utun012345678901");

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }

    #[test]
    fn require_utun_rejects_a_linux_style_device() {
        let device = DeviceName::parse("tun0").expect("valid");

        assert!(device.require_utun().is_err());
        assert!(DeviceName::parse("utun90")
            .expect("valid")
            .require_utun()
            .is_ok());
    }

    #[test]
    fn rejects_an_address_that_is_not_an_ip_literal() {
        let outcome = TunnelSpec::parse(RawTunnel {
            local_v4: "10.8.0.2 -interface en0",
            ..raw()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_a_loopback_tunnel_address() {
        let outcome = TunnelSpec::parse(RawTunnel {
            local_v4: "127.0.0.1",
            gateway_v4: None,
            ..raw()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_a_link_local_gateway() {
        let outcome = TunnelSpec::parse(RawTunnel {
            gateway_v4: Some("169.254.1.1"),
            ..raw()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_a_gateway_equal_to_the_local_address() {
        let outcome = TunnelSpec::parse(RawTunnel {
            gateway_v4: Some("10.8.0.2"),
            ..raw()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_a_v6_address_in_the_v4_endpoint() {
        let outcome = TunnelEndpoint::new(Family::V4, "fd00::2".parse::<IpAddr>().unwrap(), None);

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn rejects_an_mtu_outside_the_supported_range() {
        assert!(matches!(
            TunnelSpec::parse(RawTunnel { mtu: 42, ..raw() }),
            Err(PolicyError::InvalidMtu(42))
        ));
    }

    #[test]
    fn rejects_a_v6_tunnel_below_the_ipv6_minimum_mtu() {
        let outcome = TunnelSpec::parse(RawTunnel {
            local_v6: Some("fd00::2"),
            mtu: 1240,
            ..raw()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidMtu(1240))));
    }

    #[test]
    fn a_v4_only_tunnel_has_no_v6_endpoint_to_mirror() {
        let spec = TunnelSpec::parse(raw()).expect("valid");

        assert!(spec.v6().is_none());
        assert_eq!(spec.endpoints().count(), 1);
    }

    #[test]
    fn renders_the_rule_selector_as_a_host_cidr() {
        let spec = TunnelSpec::parse(RawTunnel {
            local_v6: Some("fd00::2"),
            ..raw()
        })
        .expect("valid");

        assert_eq!(spec.v4().local_host_cidr(), "10.8.0.2/32");
        assert_eq!(spec.v6().expect("v6").local_host_cidr(), "fd00::2/128");
    }
}
