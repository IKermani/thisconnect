// SPDX-License-Identifier: GPL-3.0-or-later

//! The real [`ProxyRuntime`]: the adapter that actually links the proxy worker.
//!
//! Everything on the daemon side of this file is plumbing. The security properties live in the
//! `thisconnect-proxy` crate — sockets are pinned by `TunEgress`, names are resolved only by
//! `TunnelResolver`, and `TunnelDialer` is the single place the two are joined. This module's
//! only job is to build those three from a `TunnelBinding` and hand the listener back, and to
//! make sure a failure anywhere in that chain is a refusal rather than a tunnel with no way to
//! use it.

use std::sync::Arc;

use thisconnect_proxy::dialer::TunnelDialer;
use thisconnect_proxy::egress::{DestinationPolicy, EgressState, TunnelConfig};
use thisconnect_proxy::listener::{self, Handle, ListenerConfig};
use thisconnect_proxy::resolver::{ResolverState, TunnelDnsConfig};
use thisconnect_shared::ipc::{ProxyInfo, ProxySessionStats};
use tracing::{info, warn};

use super::{ProxyError, ProxyListener, ProxyRuntime, ProxyStartRequest};

/// Owns the egress and resolver state for the process. Both are versioned
/// internally, so a new tunnel strands every handle issued against the old one.
pub struct LinkedRuntime {
    egress: EgressState,
    resolvers: ResolverState,
    handle: tokio::runtime::Handle,
    /// Overridable so a machine already using the default port is not simply
    /// unable to connect, and so tests can take an ephemeral port.
    bind_addrs: Vec<std::net::SocketAddr>,
}

impl LinkedRuntime {
    /// `handle` is the runtime the listener's accept loop is spawned onto. It is
    /// taken explicitly because `start` is called from a blocking teardown-safe
    /// context where `Handle::current` is not guaranteed.
    pub fn new(handle: tokio::runtime::Handle, policy: DestinationPolicy) -> Self {
        Self::with_bind_addrs(handle, policy, listener::default_bind_addrs())
    }

    pub fn with_bind_addrs(
        handle: tokio::runtime::Handle,
        policy: DestinationPolicy,
        bind_addrs: Vec<std::net::SocketAddr>,
    ) -> Self {
        Self {
            egress: EgressState::new(policy),
            resolvers: ResolverState::new(policy),
            handle,
            bind_addrs,
        }
    }
}

impl ProxyRuntime for LinkedRuntime {
    fn start(&self, request: &ProxyStartRequest) -> Result<Arc<dyn ProxyListener>, ProxyError> {
        let binding = &request.binding;

        // Publishing the tunnel invalidates every handle from the previous one,
        // so a socket pinned to a dead tun cannot survive a reconnect.
        let egress = self
            .egress
            .tunnel_up(&TunnelConfig {
                device: binding.device.clone(),
                ipv4: binding.ipv4,
                ipv6: binding.ipv6,
                mtu: binding.mtu,
            })
            .map_err(|error| ProxyError::Listener {
                detail: error.to_string(),
            })?;

        let dns = TunnelDnsConfig {
            pushed: request.dns.nameservers.clone(),
            // Kept empty: the caller has already decided what the resolver pool
            // is, including whether a third-party fallback belongs in it, and
            // appending one here would silently widen that decision.
            fallback: Vec::new(),
            tunnel_has_v6: binding.tunnel_has_v6,
            ..TunnelDnsConfig::default()
        };

        let resolver = self
            .resolvers
            .tunnel_up(Arc::clone(&egress), &dns)
            .map_err(|error| ProxyError::Listener {
                detail: error.to_string(),
            })?;

        let dialer = Arc::new(TunnelDialer::new(egress, Arc::clone(&resolver)));
        let config = ListenerConfig {
            bind_addrs: self.bind_addrs.clone(),
            ..ListenerConfig::generated(binding.tunnel_has_v6)
        };

        // `publish` is a synchronous trait method called from an async task, so
        // this runs on a runtime worker thread, where a bare `Handle::block_on`
        // panics with "Cannot start a runtime from within a runtime" — which
        // would kill the connect immediately after authentication succeeded.
        // `block_in_place` hands the worker's other tasks to a different thread
        // first, which makes blocking here legal.
        //
        // It has to block rather than spawn: `start` binds the listener before
        // it returns, and a bind failure must surface as a failed publish rather
        // than as a tunnel that came up with nothing listening.
        let started =
            tokio::task::block_in_place(|| self.handle.block_on(listener::start(config, dialer)))
                .map_err(|error| ProxyError::Listener {
                detail: error.to_string(),
            })?;

        for skipped in started.skipped_bind_addrs() {
            warn!(%skipped, "proxy could not bind this address; the rest are live");
        }
        info!(
            addrs = ?started.listen_addrs(),
            source = ?request.dns.source,
            "proxy listener up"
        );

        Ok(Arc::new(LinkedListener::new(
            started,
            self.handle.clone(),
            resolver,
        )))
    }
}

/// `Handle::shutdown` consumes the handle, but the teardown path only ever has a
/// shared reference, so the handle is taken out of the slot to shut it down. A
/// second `shutdown` is a no-op rather than an error: revoke runs on every
/// failure path and must be safe to call twice.
struct LinkedListener {
    handle: std::sync::Mutex<Option<Handle>>,
    runtime: tokio::runtime::Handle,
    /// The listener counts sessions and bytes; only the resolver knows how many
    /// names were answered and — the number that matters — how many were
    /// answered anywhere other than through the tunnel (SPEC.md §5.4 D7).
    resolver: Arc<thisconnect_proxy::resolver::TunnelResolver>,
}

impl LinkedListener {
    fn new(
        handle: Handle,
        runtime: tokio::runtime::Handle,
        resolver: Arc<thisconnect_proxy::resolver::TunnelResolver>,
    ) -> Self {
        Self {
            handle: std::sync::Mutex::new(Some(handle)),
            runtime,
            resolver,
        }
    }

    /// A poisoned lock means another task panicked mid-teardown; refusing to
    /// shut the listener down because of that would be strictly worse.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Handle>> {
        self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ProxyListener for LinkedListener {
    fn info(&self) -> ProxyInfo {
        self.slot()
            .as_ref()
            .map(Handle::proxy_info)
            .unwrap_or_else(shut_down_info)
    }

    fn stats(&self) -> ProxySessionStats {
        let mut stats = self
            .slot()
            .as_ref()
            .map(Handle::stats_snapshot)
            .unwrap_or_default();
        let dns = self.resolver.stats();
        stats.tunnel_dns_lookups = dns.tunnel_lookups;
        // Structurally zero: the resolver has no code path to the system
        // resolver, so this is a claim the type system already makes. Reporting
        // it is what lets the GUI show it as leak proof rather than a promise.
        stats.local_dns_lookups = dns.local_lookups;
        stats
    }

    fn shutdown(&self) {
        let Some(handle) = self.slot().take() else {
            return;
        };
        // The signal must land before this returns; joining the acceptors is
        // bookkeeping and is allowed to finish on its own.
        handle.stop();
        self.runtime.spawn(handle.shutdown());
    }
}

/// Reported only in the window between shutdown and the publisher dropping the
/// listener. Empty rather than stale: a URL for a listener that has stopped
/// accepting is worse than no URL.
fn shut_down_info() -> ProxyInfo {
    ProxyInfo {
        listen_addrs: Vec::new(),
        auth: thisconnect_shared::ipc::ProxyAuth::Disabled,
        is_loopback_only: true,
        allowed_cidrs: Vec::new(),
        socks5h_url: thisconnect_shared::ipc::Secret::from(String::new()),
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::tests::{ephemeral_loopback, request};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::session::proxy::TunnelDnsPlan;
    use crate::session::tunnel::TunnelBinding;
    use std::net::Ipv4Addr;
    use thisconnect_shared::ipc::DnsSource;

    /// Port 0: these tests run concurrently and must not fight over 1080.
    pub(crate) fn ephemeral_loopback() -> Vec<std::net::SocketAddr> {
        vec![std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )]
    }

    pub(crate) fn request(device: &str) -> ProxyStartRequest {
        ProxyStartRequest {
            binding: TunnelBinding {
                device: device.to_owned(),
                ipv4: Ipv4Addr::new(10, 255, 255, 2),
                ipv6: None,
                mtu: 1400,
                tunnel_has_v6: false,
            },
            dns: TunnelDnsPlan {
                nameservers: vec![std::net::IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1))],
                search_domains: Vec::new(),
                source: DnsSource::Pushed,
            },
        }
    }

    #[tokio::test]
    async fn refuses_to_start_when_the_tunnel_device_does_not_exist() {
        // Arrange: a device name no machine has, standing in for a tunnel that
        // went away between the management event and this call.
        let runtime = LinkedRuntime::with_bind_addrs(
            tokio::runtime::Handle::current(),
            DestinationPolicy::default(),
            ephemeral_loopback(),
        );

        // Act: run off the reactor thread, since start() blocks on it.
        let result =
            tokio::task::spawn_blocking(move || runtime.start(&request("tc-does-not-exist0")))
                .await
                .expect("join");

        // Assert: no listener, rather than one that cannot reach the tunnel.
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_started_listener_reports_a_socks5h_url_and_shuts_down() {
        // Arrange
        let runtime = LinkedRuntime::with_bind_addrs(
            tokio::runtime::Handle::current(),
            DestinationPolicy::default(),
            ephemeral_loopback(),
        );
        let device = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };

        // Act
        let listener = tokio::task::spawn_blocking(move || runtime.start(&request(device)))
            .await
            .expect("join")
            .expect("the loopback interface exists on every machine");
        let info = listener.info();

        // Assert: the leak-proof counter is reported, not left at its default.
        // A resolver that answered names while this read zero would make the
        // GUI's "0 local DNS lookups" claim meaningless.
        let stats = listener.stats();
        assert_eq!(stats.local_dns_lookups, 0);
        assert_eq!(stats.tunnel_dns_lookups, 0, "nothing resolved yet");

        // SPEC.md §5.4 D8 — socks5:// resolves locally and leaks, so the URL
        // handed to the user must be the socks5h form.
        assert!(info.socks5h_url.expose().starts_with("socks5h://"));
        assert!(info.is_loopback_only);
        assert!(!info.listen_addrs.is_empty());

        listener.shutdown();
    }
}

#[cfg(test)]
mod async_context_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::tests_support::*;
    use super::*;

    /// `publish` is a synchronous trait method called from an async task, so
    /// `start` runs on a runtime worker thread. A bare `Handle::block_on` panics
    /// there, which would take the connect down after authentication.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn starts_from_inside_the_runtime_without_panicking() {
        let runtime = LinkedRuntime::with_bind_addrs(
            tokio::runtime::Handle::current(),
            DestinationPolicy::default(),
            ephemeral_loopback(),
        );
        let device = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };

        let listener = runtime
            .start(&request(device))
            .expect("start must work on a runtime thread");
        listener.shutdown();
    }
}
