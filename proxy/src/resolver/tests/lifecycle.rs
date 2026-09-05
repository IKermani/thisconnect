// SPDX-License-Identifier: GPL-3.0-or-later

//! Lifecycle and structural tests: what happens to the resolver when the tunnel comes up or goes
//! away, and the assertion that no file in this module names a system-configuration entry point.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use super::{egress_state, resolver_with_nameservers, resolver_without_nameservers, tunnel};
use crate::egress::DestinationPolicy;
use crate::resolver::{ResolveError, ResolverState, TunnelDnsConfig};

// ---------------------------------------------------------------------------
// State lifecycle (SPEC.md §5.4 D5, D7)
// ---------------------------------------------------------------------------

#[test]
fn tunnel_down_drops_the_resolver_and_its_cache() {
    // Arrange
    let egress = egress_state();
    let state = ResolverState::new(DestinationPolicy::default());
    state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();

    // Act
    state.tunnel_down().unwrap();

    // Assert
    assert!(matches!(
        state.current(),
        Err(ResolveError::NoTunnelResolver)
    ));
}

#[test]
fn tunnel_up_replaces_the_previous_resolver_so_no_answer_survives_a_reconnect() {
    // Arrange
    let egress = egress_state();
    let state = ResolverState::new(DestinationPolicy::default());
    let first = state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();

    // Act
    let second = state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();

    // Assert
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&state.current().unwrap(), &second));
}

#[test]
fn a_resolver_from_a_previous_tunnel_is_no_longer_current() {
    // Arrange
    let egress = egress_state();
    let state = ResolverState::new(DestinationPolicy::default());
    state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();

    // Act
    egress.tunnel_down().unwrap();

    // Assert
    assert!(matches!(
        state.current(),
        Err(ResolveError::NoTunnelResolver)
    ));
}

#[tokio::test]
async fn resolving_with_no_tunnel_is_a_counted_refusal() {
    // Arrange
    let state = ResolverState::new(DestinationPolicy::default());

    // Act
    let result = state.resolve("example.com").await;

    // Assert
    assert!(matches!(result, Err(ResolveError::NoTunnelResolver)));
    assert_eq!(state.stats().refused_no_resolver, 1);
}

#[test]
fn counters_are_per_session_and_survive_a_tunnel_bounce() {
    // Arrange
    let egress = egress_state();
    let state = ResolverState::new(DestinationPolicy::default());
    let resolver = state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();
    resolver.counters().record_lookup();

    // Act
    state.tunnel_down().unwrap();
    state
        .tunnel_up(tunnel(&egress, false), &TunnelDnsConfig::default())
        .unwrap();

    // Assert
    assert_eq!(state.stats().tunnel_lookups, 1);
}

#[test]
fn flushing_the_cache_is_safe_with_and_without_a_nameserver() {
    // Arrange
    let state = egress_state();
    let empty = resolver_without_nameservers(&state);
    let configured = resolver_with_nameservers(&state, false);

    // Act
    empty.flush_cache();
    configured.flush_cache();

    // Assert
    assert_eq!(empty.stats().tunnel_lookups, 0);
}

// ---------------------------------------------------------------------------
// Structural guarantee
// ---------------------------------------------------------------------------

/// The rule this whole module exists for is a *structural* one, so it is asserted structurally:
/// no source file in the resolver may name a constructor or function that reads OS resolver
/// configuration. Comments are stripped first — the module documentation names the banned
/// functions on purpose — and needles are split so this test does not match itself.
#[test]
fn no_source_file_reaches_for_system_resolver_configuration() {
    // Arrange
    const SOURCES: [&str; 4] = [
        include_str!("../../resolver.rs"),
        include_str!("../config.rs"),
        include_str!("../counters.rs"),
        include_str!("../provider.rs"),
    ];
    let banned = [
        concat!("from_system", "_conf"),
        concat!("read_system", "_conf"),
        concat!("builder_", "tokio"),
        concat!("system", "_conf::"),
        concat!("to_socket", "_addrs"),
        concat!("lookup", "_host"),
        concat!("Hosts::", "from_system"),
    ];

    // Act / Assert
    for source in SOURCES {
        let code = strip_comments(source);
        for needle in banned {
            assert!(
                !code.contains(needle),
                "resolver source names a system-configuration entry point: {needle}"
            );
        }
    }
}

/// `Resolver::builder` is the system-config constructor; only `builder_with_config` may appear.
#[test]
fn the_resolver_is_only_ever_built_from_an_explicit_nameserver_list() {
    // Arrange
    let code = strip_comments(include_str!("../../resolver.rs"));

    // Act
    let explicit = code.matches("builder_with_config").count();
    let implicit = code.matches(concat!("Resolver::", "builder(")).count();

    // Assert
    assert_eq!(explicit, 1);
    assert_eq!(implicit, 0);
}

fn strip_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
