// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-session proxy counters, shaped exactly like
//! [`thisconnect_shared::ipc::ProxySessionStats`].
//!
//! `local_dns_lookups` is the one that matters: the GUI shows it verbatim as
//! leak proof (SPEC.md §5.4 D7), so any value but zero is a release blocker
//! rather than a metric. Nothing in this crate is allowed to increment it
//! except a resolver that has detected it fell back to the system path.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use thisconnect_shared::ipc::ProxySessionStats;

/// Bounds the memory a hostile LAN can make the peer set hold. Past this the
/// distinct-peer count saturates rather than growing without limit.
const MAX_TRACKED_PEERS: usize = 4096;

/// Shared, lock-light counters. Cloned as an `Arc` into every session.
#[derive(Debug, Default)]
pub struct StatsCollector {
    active_sessions: AtomicU64,
    total_sessions: AtomicU64,
    bytes_to_tunnel: AtomicU64,
    bytes_from_tunnel: AtomicU64,
    tunnel_dns_lookups: AtomicU64,
    local_dns_lookups: AtomicU64,
    auth_failures: AtomicU64,
    distinct_remote_peers: AtomicU64,
    tunnel_has_v6: AtomicBool,
    peers: Mutex<HashSet<IpAddr>>,
}

impl StatsCollector {
    pub fn new(tunnel_has_v6: bool) -> Arc<Self> {
        let collector = Self::default();
        collector
            .tunnel_has_v6
            .store(tunnel_has_v6, Ordering::Relaxed);
        Arc::new(collector)
    }

    /// Counts one live session for as long as the returned guard is held.
    pub fn session_started(self: &Arc<Self>) -> SessionGuard {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.total_sessions.fetch_add(1, Ordering::Relaxed);
        SessionGuard {
            collector: Arc::clone(self),
        }
    }

    pub fn record_bytes(&self, to_tunnel: u64, from_tunnel: u64) {
        self.bytes_to_tunnel.fetch_add(to_tunnel, Ordering::Relaxed);
        self.bytes_from_tunnel
            .fetch_add(from_tunnel, Ordering::Relaxed);
    }

    pub fn record_tunnel_dns_lookup(&self) {
        self.tunnel_dns_lookups.fetch_add(1, Ordering::Relaxed);
    }

    /// A tripwire, not a metric. Calling this at all means a name escaped the
    /// tunnel; the caller is expected to fail the connection as well.
    pub fn record_local_dns_lookup(&self) {
        self.local_dns_lookups.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a remote peer for the SPEC.md §5.6 L4 banner. Loopback peers are
    /// not "remote" and are ignored. Returns whether this peer was new.
    pub fn record_remote_peer(&self, peer: IpAddr) -> bool {
        if peer.is_loopback() {
            return false;
        }
        let mut peers = self.lock_peers();
        if peers.contains(&peer) {
            return false;
        }
        if peers.len() >= MAX_TRACKED_PEERS {
            // Saturated: without the set we can no longer tell new from seen,
            // so the count stops rather than lying upward.
            return false;
        }
        peers.insert(peer);
        self.distinct_remote_peers.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn distinct_remote_peers(&self) -> u32 {
        saturating_u32(self.distinct_remote_peers.load(Ordering::Relaxed))
    }

    pub fn active_sessions(&self) -> u32 {
        saturating_u32(self.active_sessions.load(Ordering::Relaxed))
    }

    pub fn set_tunnel_has_v6(&self, has_v6: bool) {
        self.tunnel_has_v6.store(has_v6, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ProxySessionStats {
        ProxySessionStats {
            active_sessions: self.active_sessions(),
            total_sessions: self.total_sessions.load(Ordering::Relaxed),
            bytes_to_tunnel: self.bytes_to_tunnel.load(Ordering::Relaxed),
            bytes_from_tunnel: self.bytes_from_tunnel.load(Ordering::Relaxed),
            tunnel_dns_lookups: self.tunnel_dns_lookups.load(Ordering::Relaxed),
            local_dns_lookups: self.local_dns_lookups.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            distinct_remote_peers: self.distinct_remote_peers(),
            tunnel_has_v6: self.tunnel_has_v6.load(Ordering::Relaxed),
        }
    }

    fn lock_peers(&self) -> MutexGuard<'_, HashSet<IpAddr>> {
        // A poisoned lock only means some other task panicked; refusing to
        // count a peer would be worse than continuing with the set as it is.
        self.peers.lock().unwrap_or_else(|err| err.into_inner())
    }
}

/// Decrements the live-session gauge however the session ends, including a
/// task abort at tunnel-down.
#[derive(Debug)]
pub struct SessionGuard {
    collector: Arc<StatsCollector>,
}

impl SessionGuard {
    pub fn collector(&self) -> &Arc<StatsCollector> {
        &self.collector
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let previous = self
            .collector
            .active_sessions
            .fetch_sub(1, Ordering::Relaxed);
        debug_assert!(previous > 0, "session guard underflow");
    }
}

fn saturating_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn remote(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
    }

    #[test]
    fn snapshot_starts_at_zero_with_the_tunnel_v6_flag_carried_through() {
        // Arrange
        let stats = StatsCollector::new(true);

        // Act
        let snapshot = stats.snapshot();

        // Assert
        assert_eq!(snapshot.total_sessions, 0);
        assert_eq!(snapshot.local_dns_lookups, 0);
        assert!(snapshot.tunnel_has_v6);
    }

    #[test]
    fn session_guard_raises_then_lowers_the_active_gauge() {
        // Arrange
        let stats = StatsCollector::new(false);

        // Act
        let guard = stats.session_started();
        let during = stats.snapshot();
        drop(guard);
        let after = stats.snapshot();

        // Assert
        assert_eq!(during.active_sessions, 1);
        assert_eq!(during.total_sessions, 1);
        assert_eq!(after.active_sessions, 0);
        assert_eq!(after.total_sessions, 1);
    }

    #[test]
    fn distinct_peers_counts_each_remote_address_once() {
        // Arrange
        let stats = StatsCollector::new(false);

        // Act
        let first = stats.record_remote_peer(remote(1));
        let repeat = stats.record_remote_peer(remote(1));
        let second = stats.record_remote_peer(remote(2));

        // Assert
        assert!(first);
        assert!(!repeat);
        assert!(second);
        assert_eq!(stats.distinct_remote_peers(), 2);
    }

    #[test]
    fn loopback_peers_are_not_counted_as_remote() {
        // Arrange
        let stats = StatsCollector::new(false);

        // Act
        let v4 = stats.record_remote_peer(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let v6 = stats.record_remote_peer(IpAddr::V6(Ipv6Addr::LOCALHOST));

        // Assert
        assert!(!v4);
        assert!(!v6);
        assert_eq!(stats.distinct_remote_peers(), 0);
    }

    #[test]
    fn peer_tracking_saturates_instead_of_growing_without_bound() {
        // Arrange
        let stats = StatsCollector::new(false);
        for index in 0..MAX_TRACKED_PEERS {
            let octets = (index as u32).to_be_bytes();
            stats.record_remote_peer(IpAddr::V4(Ipv4Addr::new(
                10, octets[1], octets[2], octets[3],
            )));
        }

        // Act
        let overflow = stats.record_remote_peer(remote(7));

        // Assert
        assert!(!overflow);
        assert_eq!(stats.distinct_remote_peers() as usize, MAX_TRACKED_PEERS);
    }

    #[test]
    fn byte_and_failure_counters_accumulate_into_the_snapshot() {
        // Arrange
        let stats = StatsCollector::new(false);

        // Act
        stats.record_bytes(10, 20);
        stats.record_bytes(1, 2);
        stats.record_auth_failure();
        stats.record_tunnel_dns_lookup();
        stats.record_tunnel_dns_lookup();

        // Assert
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.bytes_to_tunnel, 11);
        assert_eq!(snapshot.bytes_from_tunnel, 22);
        assert_eq!(snapshot.auth_failures, 1);
        assert_eq!(snapshot.tunnel_dns_lookups, 2);
        assert_eq!(snapshot.local_dns_lookups, 0);
    }
}
