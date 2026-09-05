// SPDX-License-Identifier: GPL-3.0-or-later

//! Configuration for the tunnel-pinned resolver, and the translation from it into hickory's own
//! configuration types (SPEC.md §5.4).
//!
//! Nothing here reads a file, an environment variable, or an OS setting. The nameserver list comes
//! from the daemon's `PUSH_REPLY` capture (D1) plus the user's `tunnel_fallback_dns` (D4), and a
//! server that survives no filter leaves the resolver with nothing to query — which is a refusal,
//! never a reason to look elsewhere.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig as HickoryConfig,
    ResolverOpts, ServerOrderingStrategy,
};

use crate::egress::{check_destination, DestinationPolicy};

/// SPEC.md §5.4 D4. Queried through the tun exactly like a pushed server; they are a different
/// nameserver, never a different code path.
pub const DEFAULT_TUNNEL_FALLBACK_DNS: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
];

/// SPEC.md §5.4 D5. A VPN's resolver can change under us without any signal, so a long TTL is a
/// stale-answer risk rather than a saving.
pub const MAX_CACHED_TTL: Duration = Duration::from_secs(300);

/// Deliberately short. The pool is serial (`num_concurrent_reqs = 1`), so this is paid once per
/// connection per attempt per server, and the outer budget below has to cover the whole product.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Floor for one `resolve()` call. It is a floor and not the whole story: the effective budget is
/// [`effective_total_timeout`], which grows with the size of the pool it wraps.
pub const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute ceiling on one `resolve()` call, so a black-holed pool cannot pin a proxy task
/// indefinitely. With the default query timeout this still covers five nameservers in full.
pub const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_ATTEMPTS: usize = 2;

/// [`hickory_config`] gives every server a UDP *and* a TCP connection, and `try_tcp_on_error`
/// means an unreachable server burns both before the pool moves on.
const CONNECTIONS_PER_SERVER: u32 = 2;

const CACHE_ENTRIES: u64 = 1024;

/// Where the answers came from, so the UI can say plainly that a query went to a third party
/// rather than to the VPN's own resolver (SPEC.md §5.4 D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsSource {
    /// No usable nameserver at all: every resolution is refused.
    None,
    Pushed,
    Fallback,
    PushedWithFallback,
}

impl DnsSource {
    /// True when a query can reach a nameserver the VPN operator did not push.
    pub fn uses_third_party(self) -> bool {
        matches!(self, Self::Fallback | Self::PushedWithFallback)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelDnsConfig {
    /// `dhcp-option DNS`/`DNS6` captured from `PUSH_REPLY` (SPEC.md §5.4 D1).
    pub pushed: Vec<IpAddr>,
    /// User-configured `tunnel_fallback_dns`.
    pub fallback: Vec<IpAddr>,
    /// SPEC.md §5.5. False means A-only, and never happy eyeballs.
    pub tunnel_has_v6: bool,
    pub query_timeout: Duration,
    pub total_timeout: Duration,
    pub attempts: usize,
}

impl Default for TunnelDnsConfig {
    fn default() -> Self {
        Self {
            pushed: Vec::new(),
            fallback: DEFAULT_TUNNEL_FALLBACK_DNS.to_vec(),
            tunnel_has_v6: false,
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
        }
    }
}

/// The nameserver list after filtering, plus the provenance the UI needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Nameservers {
    pub(crate) accepted: Vec<IpAddr>,
    pub(crate) source: DnsSource,
}

/// A pushed nameserver is attacker-controlled input: a hostile or compromised server can push
/// `127.0.0.53` and turn the pinned resolver into a front end for the system stub resolver, which
/// is the exact leak this module exists to prevent. Nameservers are therefore screened for the
/// SSRF-relevant address classes, and a v6 server on a v4-only tunnel is unreachable by
/// construction.
///
/// The caller's [`DestinationPolicy`] is deliberately *not* threaded in here — see [`usable`].
pub(crate) fn select_nameservers(config: &TunnelDnsConfig) -> Nameservers {
    let pushed = usable(&config.pushed, config.tunnel_has_v6);
    let fallback = usable(&config.fallback, config.tunnel_has_v6)
        .into_iter()
        .filter(|ip| !pushed.contains(ip))
        .collect::<Vec<_>>();
    let source = match (pushed.is_empty(), fallback.is_empty()) {
        (true, true) => DnsSource::None,
        (false, true) => DnsSource::Pushed,
        (true, false) => DnsSource::Fallback,
        (false, false) => DnsSource::PushedWithFallback,
    };
    Nameservers {
        // Pushed first; the pool is ordered and queries one server at a time, so a working VPN
        // resolver means the fallback never sees a hostname.
        accepted: pushed.into_iter().chain(fallback).collect(),
        source,
    }
}

/// A nameserver is screened for the SSRF-relevant classes — loopback, link-local, multicast,
/// unspecified — but never for being RFC1918. `allow_private` is a statement about where the
/// user's *traffic* may go, and pushing a private resolver is the normal case for a corporate
/// VPN; applying that clause here would silently break exactly those tunnels for anyone who
/// turned private egress off.
fn usable(servers: &[IpAddr], has_v6: bool) -> Vec<IpAddr> {
    const NAMESERVER_POLICY: DestinationPolicy = DestinationPolicy {
        allow_private: true,
    };
    servers
        .iter()
        .copied()
        .filter(|ip| has_v6 || ip.is_ipv4())
        .filter(|ip| check_destination(*ip, NAMESERVER_POLICY).is_ok())
        .fold(Vec::new(), |mut kept, ip| {
            if !kept.contains(&ip) {
                kept.push(ip);
            }
            kept
        })
}

/// UDP with a TCP connection alongside it: hickory retries a truncated answer over the TCP
/// connection of the same server (SPEC.md §5.4 D2).
pub(crate) fn hickory_config(servers: &[IpAddr]) -> HickoryConfig {
    HickoryConfig::from_name_servers(
        servers
            .iter()
            .copied()
            .map(NameServerConfig::udp_and_tcp)
            .collect(),
    )
}

/// The outer `timeout()` in `resolve()` must outlast the pool it wraps, or SPEC.md §5.4 D4's
/// second half is unreachable: with a black-holed pushed server the first nameserver alone burns
/// `query_timeout * connections * tries`, and a budget sized independently of the pool fires
/// before the appended fallback is ever contacted. Sizing it against the pool is what makes
/// "a captured server is unreachable" reach the fallback rather than return a timeout.
pub(crate) fn effective_total_timeout(
    config: &TunnelDnsConfig,
    nameserver_count: usize,
) -> Duration {
    let tries = u32::try_from(config.attempts.saturating_add(1)).unwrap_or(u32::MAX);
    let servers = u32::try_from(nameserver_count).unwrap_or(u32::MAX);
    let pool = config
        .query_timeout
        .saturating_mul(CONNECTIONS_PER_SERVER)
        .saturating_mul(tries)
        .saturating_mul(servers);
    config.total_timeout.max(pool).min(MAX_TOTAL_TIMEOUT)
}

pub(crate) fn hickory_opts(config: &TunnelDnsConfig) -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = config.query_timeout;
    opts.attempts = config.attempts;
    opts.ip_strategy = match config.tunnel_has_v6 {
        true => LookupIpStrategy::Ipv4AndIpv6,
        false => LookupIpStrategy::Ipv4Only,
    };
    opts.cache_size = CACHE_ENTRIES;
    opts.positive_max_ttl = Some(MAX_CACHED_TTL);
    opts.negative_max_ttl = Some(MAX_CACHED_TTL);
    // `Auto` would read /etc/hosts. Host-file entries are local configuration this proxy has no
    // business honouring, and reading them is one more OS input on the resolution path.
    opts.use_hosts_file = ResolveHosts::Never;
    opts.try_tcp_on_error = true;
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
    // One server at a time: concurrency would hand the hostname to the third-party fallback even
    // when the VPN's own resolver is answering perfectly well.
    opts.num_concurrent_reqs = 1;
    // The source port is chosen by the kernel when the pinned socket binds, so asking hickory to
    // pick one only invites a bind retry loop.
    opts.os_port_selection = true;
    opts
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn config(pushed: &[&str], fallback: &[&str], has_v6: bool) -> TunnelDnsConfig {
        TunnelDnsConfig {
            pushed: pushed.iter().map(|s| ip(s)).collect(),
            fallback: fallback.iter().map(|s| ip(s)).collect(),
            tunnel_has_v6: has_v6,
            ..TunnelDnsConfig::default()
        }
    }

    #[test]
    fn default_fallback_is_quad9_then_cloudflare() {
        // Arrange / Act
        let config = TunnelDnsConfig::default();

        // Assert
        assert_eq!(config.fallback, vec![ip("9.9.9.9"), ip("1.1.1.1")]);
    }

    #[test]
    fn pushed_servers_precede_fallback_servers() {
        // Arrange
        let config = config(&["10.8.0.1"], &["9.9.9.9"], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert_eq!(selected.accepted, vec![ip("10.8.0.1"), ip("9.9.9.9")]);
        assert_eq!(selected.source, DnsSource::PushedWithFallback);
    }

    #[test]
    fn loopback_nameserver_pushed_by_the_server_is_refused() {
        // Arrange
        let config = config(&["127.0.0.53"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert!(selected.accepted.is_empty());
        assert_eq!(selected.source, DnsSource::None);
    }

    #[test]
    fn a_private_nameserver_is_accepted_because_corporate_vpns_push_one() {
        // Arrange: a corporate VPN pushing its own internal resolver, for a user
        // who has turned private egress off.
        let config = config(&["10.0.0.53"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert: the setting governs where traffic may go, not which resolver
        // the tunnel hands us; refusing it would break the tunnel's own DNS.
        assert_eq!(selected.accepted, vec![ip("10.0.0.53")]);
    }

    #[test]
    fn a_loopback_nameserver_is_refused_even_though_private_ones_are_allowed() {
        // Arrange: allowing private nameservers must not be read as "skip the
        // SSRF screen" — a pushed 127.0.0.53 would turn the pinned resolver into
        // a front end for the system stub resolver.
        let config = config(&["127.0.0.53"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert!(selected.accepted.is_empty());
    }

    #[test]
    fn link_local_nameserver_is_refused() {
        // Arrange
        let config = config(&["169.254.169.254"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert!(selected.accepted.is_empty());
    }

    #[test]
    fn ipv6_nameserver_is_dropped_on_a_v4_only_tunnel() {
        // Arrange
        let config = config(&["2620:fe::fe", "10.8.0.1"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert_eq!(selected.accepted, vec![ip("10.8.0.1")]);
    }

    #[test]
    fn ipv6_nameserver_is_kept_on_a_dual_stack_tunnel() {
        // Arrange
        let config = config(&["2620:fe::fe"], &[], true);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert_eq!(selected.accepted, vec![ip("2620:fe::fe")]);
        assert_eq!(selected.source, DnsSource::Pushed);
    }

    #[test]
    fn duplicate_servers_are_collapsed_and_fallback_never_shadows_a_pushed_server() {
        // Arrange
        let config = config(&["9.9.9.9", "9.9.9.9"], &["9.9.9.9", "1.1.1.1"], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert_eq!(selected.accepted, vec![ip("9.9.9.9"), ip("1.1.1.1")]);
    }

    #[test]
    fn fallback_only_configuration_is_reported_as_third_party() {
        // Arrange
        let config = config(&[], &["9.9.9.9"], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert_eq!(selected.source, DnsSource::Fallback);
        assert!(selected.source.uses_third_party());
    }

    #[test]
    fn pushed_only_configuration_is_not_third_party() {
        // Arrange
        let config = config(&["10.8.0.1"], &[], false);

        // Act
        let selected = select_nameservers(&config);

        // Assert
        assert!(!selected.source.uses_third_party());
    }

    #[test]
    fn opts_query_a_only_when_the_tunnel_has_no_ipv6() {
        // Arrange
        let config = config(&[], &[], false);

        // Act
        let opts = hickory_opts(&config);

        // Assert
        assert_eq!(opts.ip_strategy, LookupIpStrategy::Ipv4Only);
    }

    #[test]
    fn opts_query_both_families_on_a_dual_stack_tunnel() {
        // Arrange
        let config = config(&[], &[], true);

        // Act
        let opts = hickory_opts(&config);

        // Assert
        assert_eq!(opts.ip_strategy, LookupIpStrategy::Ipv4AndIpv6);
    }

    #[test]
    fn opts_cap_cached_ttls_at_five_minutes() {
        // Arrange / Act
        let opts = hickory_opts(&TunnelDnsConfig::default());

        // Assert
        assert_eq!(opts.positive_max_ttl, Some(Duration::from_secs(300)));
        assert_eq!(opts.negative_max_ttl, Some(Duration::from_secs(300)));
    }

    #[test]
    fn opts_never_consult_the_system_hosts_file() {
        // Arrange / Act
        let opts = hickory_opts(&TunnelDnsConfig::default());

        // Assert
        assert_eq!(opts.use_hosts_file, ResolveHosts::Never);
    }

    #[test]
    fn opts_query_one_server_at_a_time_in_the_configured_order() {
        // Arrange / Act
        let opts = hickory_opts(&TunnelDnsConfig::default());

        // Assert
        assert_eq!(opts.num_concurrent_reqs, 1);
        assert_eq!(
            opts.server_ordering_strategy,
            ServerOrderingStrategy::UserProvidedOrder
        );
    }

    /// The worst case one nameserver can burn before the serial pool advances to the next.
    fn per_server_worst_case(config: &TunnelDnsConfig) -> Duration {
        config.query_timeout * CONNECTIONS_PER_SERVER * (config.attempts as u32 + 1)
    }

    #[test]
    fn default_budget_outlasts_a_black_holed_first_server_so_the_fallback_is_reached() {
        // Arrange: the D4 case — one unreachable pushed server, one fallback appended after it.
        let config = config(&["10.8.0.1"], &["9.9.9.9"], false);
        let selected = select_nameservers(&config);

        // Act
        let budget = effective_total_timeout(&config, selected.accepted.len());

        // Assert: strictly more than the first server can consume, so the second is queried.
        assert_eq!(selected.accepted.len(), 2);
        assert!(
            budget > per_server_worst_case(&config),
            "budget {budget:?} cannot outlast one black-holed server"
        );
    }

    #[test]
    fn default_budget_covers_every_server_in_the_default_pool() {
        // Arrange
        let config = TunnelDnsConfig::default();
        let count = config.fallback.len();

        // Act
        let budget = effective_total_timeout(&config, count);

        // Assert
        assert!(budget >= per_server_worst_case(&config) * count as u32);
    }

    #[test]
    fn budget_grows_with_the_pool_rather_than_being_fixed() {
        // Arrange
        let config = TunnelDnsConfig::default();

        // Act
        let small = effective_total_timeout(&config, 1);
        let large = effective_total_timeout(&config, 6);

        // Assert
        assert!(large > small);
    }

    #[test]
    fn budget_never_falls_below_the_configured_floor() {
        // Arrange
        let config = TunnelDnsConfig::default();

        // Act
        let budget = effective_total_timeout(&config, 1);

        // Assert
        assert_eq!(budget, DEFAULT_TOTAL_TIMEOUT);
    }

    #[test]
    fn budget_is_capped_so_a_black_holed_pool_cannot_pin_a_task() {
        // Arrange
        let config = TunnelDnsConfig {
            query_timeout: Duration::from_secs(30),
            ..TunnelDnsConfig::default()
        };

        // Act
        let budget = effective_total_timeout(&config, 64);

        // Assert
        assert_eq!(budget, MAX_TOTAL_TIMEOUT);
    }

    #[test]
    fn every_nameserver_gets_a_tcp_connection_for_truncated_answers() {
        // Arrange
        let servers = vec![ip("10.8.0.1")];

        // Act
        let built = hickory_config(&servers);

        // Assert
        assert_eq!(built.name_servers().len(), 1);
        assert_eq!(built.name_servers()[0].connections.len(), 2);
        assert!(built.domain().is_none());
        assert!(built.search().is_empty());
    }
}
