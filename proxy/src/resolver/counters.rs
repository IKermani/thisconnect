// SPDX-License-Identifier: GPL-3.0-or-later

//! Session counters for the tunnel-pinned resolver (SPEC.md §5.4 D7).
//!
//! These exist to be shown to the user, not to be debugged with. The pair the GUI renders is
//! `tunnel_lookups` against `local_lookups`: the second is a compile-time zero because this crate
//! has no code path that can resolve a name outside the tunnel, and `refused_no_resolver` is the
//! count of times that guarantee actually stopped a query.

use std::sync::atomic::{AtomicU64, Ordering};

/// Structurally zero: the proxy crate cannot call the system resolver, so there is no counter to
/// increment. Surfaced anyway because the user is entitled to see the number, not to be told it.
pub const LOCAL_LOOKUPS: u64 = 0;

/// Shared across tunnel generations so the numbers are per *session*, not per reconnect.
#[derive(Debug, Default)]
pub struct ResolverCounters {
    tunnel_lookups: AtomicU64,
    refused_no_resolver: AtomicU64,
    denied_addresses: AtomicU64,
    failed_lookups: AtomicU64,
}

impl ResolverCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record_lookup(&self) {
        self.tunnel_lookups.fetch_add(1, Ordering::Relaxed);
    }

    /// A resolution refused because no tunnel resolver was available. Non-zero here is the
    /// leak-prevention working, so it is a first-class number rather than a log line.
    pub(crate) fn record_refusal(&self) {
        self.refused_no_resolver.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_denied_addresses(&self, count: u64) {
        if count > 0 {
            self.denied_addresses.fetch_add(count, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_failure(&self) {
        self.failed_lookups.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ResolverStats {
        ResolverStats {
            tunnel_lookups: self.tunnel_lookups.load(Ordering::Relaxed),
            local_lookups: LOCAL_LOOKUPS,
            refused_no_resolver: self.refused_no_resolver.load(Ordering::Relaxed),
            denied_addresses: self.denied_addresses.load(Ordering::Relaxed),
            failed_lookups: self.failed_lookups.load(Ordering::Relaxed),
        }
    }

    /// Called when a proxy *session* starts, never on a tunnel bounce.
    pub fn reset(&self) {
        self.tunnel_lookups.store(0, Ordering::Relaxed);
        self.refused_no_resolver.store(0, Ordering::Relaxed);
        self.denied_addresses.store(0, Ordering::Relaxed);
        self.failed_lookups.store(0, Ordering::Relaxed);
    }
}

/// An immutable reading of [`ResolverCounters`], for the IPC stats reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResolverStats {
    /// Names resolved through the tunnel-pinned resolver.
    pub tunnel_lookups: u64,
    /// Always [`LOCAL_LOOKUPS`].
    pub local_lookups: u64,
    /// Resolutions refused because no tunnel resolver was available.
    pub refused_no_resolver: u64,
    /// Answers dropped by the destination denylist (SPEC.md §5.4 D6).
    pub denied_addresses: u64,
    pub failed_lookups: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn snapshot_reports_zero_local_lookups_by_construction() {
        // Arrange
        let counters = ResolverCounters::new();

        // Act
        counters.record_lookup();
        let stats = counters.snapshot();

        // Assert
        assert_eq!(stats.tunnel_lookups, 1);
        assert_eq!(stats.local_lookups, 0);
    }

    #[test]
    fn each_counter_moves_independently() {
        // Arrange
        let counters = ResolverCounters::new();

        // Act
        counters.record_refusal();
        counters.record_denied_addresses(2);
        counters.record_failure();
        let stats = counters.snapshot();

        // Assert
        assert_eq!(stats.refused_no_resolver, 1);
        assert_eq!(stats.denied_addresses, 2);
        assert_eq!(stats.failed_lookups, 1);
        assert_eq!(stats.tunnel_lookups, 0);
    }

    #[test]
    fn recording_zero_denied_addresses_is_a_no_op() {
        // Arrange
        let counters = ResolverCounters::new();

        // Act
        counters.record_denied_addresses(0);

        // Assert
        assert_eq!(counters.snapshot().denied_addresses, 0);
    }

    #[test]
    fn reset_clears_every_counter() {
        // Arrange
        let counters = ResolverCounters::new();
        counters.record_lookup();
        counters.record_refusal();

        // Act
        counters.reset();

        // Assert
        assert_eq!(counters.snapshot(), ResolverStats::default());
    }
}
