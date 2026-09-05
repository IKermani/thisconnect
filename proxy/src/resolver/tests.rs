// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the tunnel-pinned resolver. The cases that matter are the ones where resolution must
//! *not* happen: no nameserver, a stale tunnel, an `AAAA` on a v4-only tunnel, an answer pointing
//! at the user's own machine.
//!
//! No test here performs a real query. A resolver is either built with no nameserver, or exercised
//! on the answer-filtering path directly, so the suite never depends on the network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod lifecycle;

use std::net::Ipv4Addr;

use super::*;
use crate::egress::{EgressState, TunnelConfig};

const LOOPBACK_DEVICE: &str = if cfg!(target_os = "macos") {
    "lo0"
} else {
    "lo"
};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn egress_state() -> EgressState {
    EgressState::new(DestinationPolicy::default())
}

fn tunnel(state: &EgressState, has_v6: bool) -> Arc<TunEgress> {
    state
        .tunnel_up(&TunnelConfig {
            device: LOOPBACK_DEVICE.to_owned(),
            ipv4: Ipv4Addr::new(10, 255, 255, 2),
            ipv6: has_v6.then(|| "fd00::2".parse().unwrap()),
            mtu: 1240,
        })
        .unwrap()
}

/// A resolver with no nameserver at all: the fail-closed shape.
fn resolver_without_nameservers(state: &EgressState) -> TunnelResolver {
    let config = TunnelDnsConfig {
        pushed: Vec::new(),
        fallback: Vec::new(),
        ..TunnelDnsConfig::default()
    };
    TunnelResolver::new(
        tunnel(state, false),
        &config,
        DestinationPolicy::default(),
        Arc::new(ResolverCounters::new()),
    )
    .unwrap()
}

fn resolver_with_nameservers(state: &EgressState, has_v6: bool) -> TunnelResolver {
    let config = TunnelDnsConfig {
        pushed: vec![ip("10.255.255.1")],
        tunnel_has_v6: has_v6,
        ..TunnelDnsConfig::default()
    };
    TunnelResolver::new(
        tunnel(state, has_v6),
        &config,
        DestinationPolicy::default(),
        Arc::new(ResolverCounters::new()),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// No resolver means no resolution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_name_is_refused_when_no_nameserver_is_configured() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver.resolve("example.com").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::NoTunnelResolver)));
    assert_eq!(resolver.stats().refused_no_resolver, 1);
    assert_eq!(resolver.stats().tunnel_lookups, 0);
}

#[tokio::test]
async fn a_refused_name_is_never_resolved_some_other_way() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let first = resolver.resolve("example.com").await;
    let second = resolver.resolve("example.org").await;

    // Assert
    assert!(first.is_err() && second.is_err());
    assert_eq!(resolver.stats().refused_no_resolver, 2);
    assert_eq!(resolver.stats().local_lookups, 0);
}

#[tokio::test]
async fn a_stale_tunnel_refuses_rather_than_querying_a_stranded_pool() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);
    state.tunnel_down().unwrap();

    // Act
    let result = resolver.resolve("example.com").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::StaleTunnel)));
    assert_eq!(resolver.stats().refused_no_resolver, 1);
}

#[tokio::test]
async fn an_unparseable_name_is_rejected_before_any_query() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);

    // Act
    let empty = resolver.resolve("").await;
    let overlong = resolver.resolve(&"a".repeat(300)).await;

    // Assert
    assert!(matches!(empty, Err(ResolveError::InvalidName)));
    assert!(matches!(overlong, Err(ResolveError::InvalidName)));
}

// ---------------------------------------------------------------------------
// IP literals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_ip_literal_is_returned_without_a_query_and_without_a_lookup_count() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver.resolve("93.184.216.34").await.unwrap();

    // Assert
    assert_eq!(result, vec![ip("93.184.216.34")]);
    assert_eq!(resolver.stats().tunnel_lookups, 0);
    assert_eq!(resolver.stats().refused_no_resolver, 0);
}

#[tokio::test]
async fn a_loopback_literal_is_refused() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver.resolve("127.0.0.1").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::AddressesDenied)));
    assert_eq!(resolver.stats().denied_addresses, 1);
}

#[tokio::test]
async fn a_v4_mapped_loopback_literal_is_refused_too() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver.resolve("::ffff:127.0.0.1").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::AddressesDenied)));
}

#[tokio::test]
async fn an_ipv6_literal_is_refused_on_a_v4_only_tunnel() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver.resolve("2606:4700:4700::1111").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::Ipv6Unsupported)));
}

#[tokio::test]
async fn an_ipv6_literal_is_accepted_on_a_dual_stack_tunnel() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, true);

    // Act
    let result = resolver.resolve("2606:4700:4700::1111").await.unwrap();

    // Assert
    assert_eq!(result, vec![ip("2606:4700:4700::1111")]);
}

#[tokio::test]
async fn resolve_socket_addrs_carries_the_port_through() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_without_nameservers(&state);

    // Act
    let result = resolver
        .resolve_socket_addrs("93.184.216.34", 443)
        .await
        .unwrap();

    // Assert
    assert_eq!(
        result,
        vec!["93.184.216.34:443".parse::<SocketAddr>().unwrap()]
    );
}

// ---------------------------------------------------------------------------
// Answer filtering (SPEC.md §5.5 and §5.4 D6)
// ---------------------------------------------------------------------------

#[test]
fn aaaa_answers_are_discarded_on_a_v4_only_tunnel() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);
    let answers = [ip("2606:4700::1111"), ip("93.184.216.34")];

    // Act
    let accepted = resolver.accept_answers(answers.into_iter()).unwrap();

    // Assert
    assert_eq!(accepted, vec![ip("93.184.216.34")]);
}

#[test]
fn an_aaaa_only_answer_on_a_v4_only_tunnel_is_a_hard_failure() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);

    // Act
    let result = resolver.accept_answers([ip("2606:4700::1111")].into_iter());

    // Assert
    assert!(matches!(result, Err(ResolveError::NotFound)));
    assert_eq!(resolver.stats().tunnel_lookups, 0);
}

#[test]
fn aaaa_answers_are_kept_on_a_dual_stack_tunnel() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, true);
    let answers = [ip("2606:4700::1111"), ip("93.184.216.34")];

    // Act
    let accepted = resolver.accept_answers(answers.into_iter()).unwrap();

    // Assert
    assert_eq!(accepted.len(), 2);
}

#[test]
fn a_name_resolving_to_loopback_is_refused() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);

    // Act
    let result = resolver.accept_answers([ip("127.0.0.1")].into_iter());

    // Assert
    assert!(matches!(result, Err(ResolveError::AddressesDenied)));
    assert_eq!(resolver.stats().denied_addresses, 1);
}

#[test]
fn a_name_resolving_to_the_cloud_metadata_address_is_refused() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);

    // Act
    let result = resolver.accept_answers([ip("169.254.169.254")].into_iter());

    // Assert
    assert!(matches!(result, Err(ResolveError::AddressesDenied)));
}

#[test]
fn a_denied_address_is_dropped_without_failing_a_usable_answer() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);
    let answers = [ip("127.0.0.1"), ip("93.184.216.34")];

    // Act
    let accepted = resolver.accept_answers(answers.into_iter()).unwrap();

    // Assert
    assert_eq!(accepted, vec![ip("93.184.216.34")]);
    assert_eq!(resolver.stats().denied_addresses, 1);
    assert_eq!(resolver.stats().tunnel_lookups, 1);
}

#[test]
fn an_empty_answer_is_not_counted_as_a_lookup() {
    // Arrange
    let state = egress_state();
    let resolver = resolver_with_nameservers(&state, false);

    // Act
    let result = resolver.accept_answers(std::iter::empty());

    // Assert
    assert!(matches!(result, Err(ResolveError::NotFound)));
    assert_eq!(resolver.stats().tunnel_lookups, 0);
    assert_eq!(resolver.stats().failed_lookups, 1);
}

// ---------------------------------------------------------------------------
// Construction and configuration
// ---------------------------------------------------------------------------

#[test]
fn the_default_fallback_servers_are_used_when_nothing_was_pushed() {
    // Arrange
    let state = egress_state();

    // Act
    let resolver = TunnelResolver::new(
        tunnel(&state, false),
        &TunnelDnsConfig::default(),
        DestinationPolicy::default(),
        Arc::new(ResolverCounters::new()),
    )
    .unwrap();

    // Assert
    assert_eq!(resolver.nameservers(), &DEFAULT_TUNNEL_FALLBACK_DNS[..]);
    assert_eq!(resolver.source(), DnsSource::Fallback);
    assert!(resolver.source().uses_third_party());
}

#[test]
fn a_pushed_nameserver_takes_the_resolver_off_the_third_party_path() {
    // Arrange
    let state = egress_state();
    let config = TunnelDnsConfig {
        pushed: vec![ip("10.255.255.1")],
        fallback: Vec::new(),
        ..TunnelDnsConfig::default()
    };

    // Act
    let resolver = TunnelResolver::new(
        tunnel(&state, false),
        &config,
        DestinationPolicy::default(),
        Arc::new(ResolverCounters::new()),
    )
    .unwrap();

    // Assert
    assert_eq!(resolver.source(), DnsSource::Pushed);
    assert!(!resolver.source().uses_third_party());
}

#[test]
fn tunnel_v6_support_is_reported_from_the_configuration() {
    // Arrange
    let state = egress_state();

    // Act
    let resolver = resolver_with_nameservers(&state, true);

    // Assert
    assert!(resolver.tunnel_has_v6());
}
