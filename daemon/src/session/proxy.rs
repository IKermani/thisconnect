// SPDX-License-Identifier: GPL-3.0-or-later

//! The proxy half of the tunnel lifecycle: what starts when a tunnel comes up
//! and what must be gone before anything else is torn down.
//!
//! [`ProxyPublisher`] is the [`EgressPublisher`] the daemon installs. On
//! `publish` it decides which resolver the session may use (SPEC.md §5.4 D4),
//! starts the listener through a [`ProxyRuntime`], and reports success only once
//! the listener is actually accepting. On `revoke` it closes that listener and
//! kills its sessions *first*, so no socket pinned to the tunnel can outlive it
//! (SPEC.md §5.3, §5.6 L6).
//!
//! The listener itself lives in the unprivileged `thisconnect-proxy` crate, which
//! this crate does not depend on — see [`ProxyRuntime`] for the seam and
//! [`UnavailableRuntime`] for what a build without it does.

pub mod capture;
mod resolver_denylist;

#[cfg(test)]
pub(crate) mod tests;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use thisconnect_shared::ipc::{DnsSource, ProxyInfo, ProxySessionStats};
use tracing::{info, warn};

use crate::policy::PolicyError;

use super::dns::{DnsCapture, MissingDns};
use super::tunnel::{EgressPublisher, TunnelBinding};
use super::SessionConfig;

pub use capture::{DnsCaptureCell, TappedTransportFactory};

use resolver_denylist::is_usable_resolver;

/// Which resolver the session's listener was given, and where it came from.
///
/// `search_domains` travel with it because they are part of the same push; a
/// fallback plan has none, and inventing one would send names somewhere the user
/// never agreed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelDnsPlan {
    pub nameservers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub source: DnsSource,
}

/// Everything the listener needs to exist: what to pin sockets to, and what to
/// resolve names with. Nothing else — the proxy is unprivileged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyStartRequest {
    pub binding: TunnelBinding,
    pub dns: TunnelDnsPlan,
}

/// Why the tunnel's own push could not supply the resolver.
///
/// Distinct from [`MissingDns`] because "the server pushed a resolver we refuse
/// to query" is a different fact from "the server pushed nothing usable", and
/// the first is the one worth being loud about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResolverGap {
    #[error(transparent)]
    NotPushed(#[from] MissingDns),

    /// SPEC.md §5.4 D6. A pushed loopback or link-local resolver is an attempt to
    /// have the client answer names off-tunnel, so it is never used and never
    /// reported as `DnsSource::Pushed`.
    #[error("all {denied} pushed DNS servers were addresses no tunnel query may go to")]
    Denied { denied: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Fail closed: with no resolver reachable through the tunnel there is no
    /// leak-free way to answer a `DOMAINNAME` request, and the system resolver is
    /// never an option (SPEC.md §5.4 D3).
    #[error("no DNS server is usable through this tunnel ({reason}) and no configured fallback is usable either")]
    NoResolver { reason: ResolverGap },

    #[error("the proxy listener did not start: {detail}")]
    Listener { detail: String },

    #[error("this build has no proxy worker linked in, so a tunnel would come up with nothing able to egress through it")]
    Unavailable,
}

/// Starts the listener for one tunnel.
///
/// The implementation belongs to whoever owns the `thisconnect-proxy` crate: it
/// maps a [`ProxyStartRequest`] onto `egress::EgressState::tunnel_up`, builds a
/// `resolver::TunnelResolver` over the same egress from [`TunnelDnsPlan`], and
/// then calls `listener::start`. It must return an error rather than a listener
/// if any of those steps fails, and must leave nothing running when it does.
pub trait ProxyRuntime: Send + Sync {
    fn start(&self, request: &ProxyStartRequest) -> Result<Arc<dyn ProxyListener>, ProxyError>;
}

/// A running listener. Held for exactly as long as the tunnel is up.
pub trait ProxyListener: Send + Sync {
    fn info(&self) -> ProxyInfo;

    fn stats(&self) -> ProxySessionStats;

    /// Stops accepting and aborts every live session.
    ///
    /// Called from the teardown path before anything else, so it must not block
    /// on a runtime worker thread: signal, abort, return. Sockets pinned to a tun
    /// that is going away hang for ~15 minutes if they are merely closed
    /// (`tcp_retries2`), which is the whole reason this is step one.
    fn shutdown(&self);
}

/// What the IPC handler may ask about the listener. `None` means "not up", which
/// answers `TunnelNotReady` rather than an invented empty shape.
pub trait ProxyStatus: Send + Sync {
    fn info(&self) -> Option<ProxyInfo>;

    fn stats(&self) -> Option<ProxySessionStats>;
}

/// Session-independent proxy tunables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxySettings {
    /// Used only when the tunnel pushed no usable resolver, and always queried
    /// through the tun (SPEC.md §5.4 D4).
    pub fallback_dns: Vec<IpAddr>,
}

impl ProxySettings {
    pub fn from_config(config: &SessionConfig) -> Self {
        Self {
            fallback_dns: config.fallback_dns.clone(),
        }
    }
}

/// The [`EgressPublisher`] the daemon installs in production.
pub struct ProxyPublisher {
    runtime: Arc<dyn ProxyRuntime>,
    settings: ProxySettings,
    capture: Arc<DnsCaptureCell>,
    listener: Mutex<Option<Arc<dyn ProxyListener>>>,
}

impl ProxyPublisher {
    pub fn new(runtime: Arc<dyn ProxyRuntime>, settings: ProxySettings) -> Self {
        Self {
            runtime,
            settings,
            capture: Arc::new(DnsCaptureCell::new()),
            listener: Mutex::new(None),
        }
    }

    /// The slot the management-log tap writes the tunnel's DNS into. Handed to
    /// the transport so the capture exists before `publish` needs it.
    pub fn capture(&self) -> Arc<DnsCaptureCell> {
        Arc::clone(&self.capture)
    }

    pub fn is_listening(&self) -> bool {
        lock(&self.listener).is_some()
    }

    /// Chooses the resolver for this tunnel. Captured push wins; otherwise the
    /// configured fallback, through the tun, loudly. Never the system resolver.
    fn plan_dns(&self, binding: &TunnelBinding) -> Result<TunnelDnsPlan, ProxyError> {
        match self.capture.current() {
            DnsCapture::Captured(dns) => {
                if dns.tunnel_has_v6 != binding.tunnel_has_v6 {
                    // The installed policy wins: it describes what was actually
                    // put on the machine and read back, the push only what was
                    // asked for.
                    warn!(
                        pushed = dns.tunnel_has_v6,
                        installed = binding.tunnel_has_v6,
                        "the push and the installed policy disagree about IPv6; the installed policy wins"
                    );
                }
                let vetted = usable_servers(&dns.nameservers, binding.tunnel_has_v6);
                if vetted.usable.is_empty() {
                    return self.fallback_plan(vetted.gap(), binding);
                }
                if vetted.denied > 0 {
                    warn!(
                        denied = vetted.denied,
                        "the tunnel pushed DNS servers this client may never query; they were dropped"
                    );
                }
                info!(
                    servers = vetted.usable.len(),
                    domains = dns.search_domains.len(),
                    "resolving through the tunnel's own DNS"
                );
                Ok(TunnelDnsPlan {
                    nameservers: vetted.usable,
                    search_domains: dns.search_domains.clone(),
                    source: DnsSource::Pushed,
                })
            }
            DnsCapture::Missing(reason) => self.fallback_plan(reason.into(), binding),
        }
    }

    fn fallback_plan(
        &self,
        reason: ResolverGap,
        binding: &TunnelBinding,
    ) -> Result<TunnelDnsPlan, ProxyError> {
        // The configured fallback is vetted by the same rule as the push: a
        // `fallback_dns` of 127.0.0.1 in the config would otherwise be the system
        // resolver wearing a tunnel-shaped hat.
        let vetted = usable_servers(&self.settings.fallback_dns, binding.tunnel_has_v6);
        if vetted.denied > 0 {
            warn!(
                denied = vetted.denied,
                "configured fallback DNS servers were dropped: no tunnel query may go to them"
            );
        }
        if vetted.usable.is_empty() {
            return Err(ProxyError::NoResolver { reason });
        }
        // The GUI repeats this from `TunnelInfo::dns_source`; it is a warning
        // here too because a third party seeing every query is a real change in
        // the user's exposure, not a detail.
        warn!(
            %reason,
            servers = vetted.usable.len(),
            "the tunnel pushed no usable DNS; queries go through the tun to the configured fallback, where a third party sees them"
        );
        Ok(TunnelDnsPlan {
            nameservers: vetted.usable,
            search_domains: Vec::new(),
            source: DnsSource::TunnelFallback,
        })
    }

    /// Takes the listener out of the slot and stops it. Idempotent.
    fn stop_listener(&self) {
        let taken = lock(&self.listener).take();
        if let Some(listener) = taken {
            listener.shutdown();
            info!("proxy listener closed and its sessions killed");
        }
    }
}

impl EgressPublisher for ProxyPublisher {
    fn publish(&self, binding: &TunnelBinding) -> Result<(), PolicyError> {
        // A listener from an earlier tunnel would still be pinned to it. There
        // is exactly one connection in v1, so this is belt and braces.
        self.stop_listener();

        let dns = self.plan_dns(binding).map_err(refused)?;
        let source = dns.source;
        let request = ProxyStartRequest {
            binding: binding.clone(),
            dns,
        };
        let listener = match self.runtime.start(&request) {
            Ok(listener) => listener,
            Err(error) => {
                // Nothing of ours is running, but the runtime may have started
                // and dropped its own state; say so and fail the connect rather
                // than leaving a tunnel that looks up with no way to use it.
                warn!(%error, "the proxy listener failed to start; the tunnel will be torn down");
                return Err(refused(error));
            }
        };
        let addrs = listener.info().listen_addrs.len();
        *lock(&self.listener) = Some(listener);
        info!(addrs, ?source, "proxy listener up");
        Ok(())
    }

    fn revoke(&self) {
        self.stop_listener();
        // The next session captures its own push; a stale one would silently
        // point the new tunnel's resolver at the old tunnel's server.
        self.capture.reset();
    }
}

impl ProxyStatus for ProxyPublisher {
    fn info(&self) -> Option<ProxyInfo> {
        lock(&self.listener)
            .as_ref()
            .map(|listener| listener.info())
    }

    fn stats(&self) -> Option<ProxySessionStats> {
        lock(&self.listener)
            .as_ref()
            .map(|listener| listener.stats())
    }
}

/// The outcome of vetting one list of nameservers, keeping the two reasons a
/// server was dropped apart so the caller can say which one happened.
struct VettedServers {
    usable: Vec<IpAddr>,
    denied: usize,
    wrong_family: usize,
}

impl VettedServers {
    /// A denylisted server is the more alarming of the two, so it wins the
    /// report when a list contained both kinds.
    fn gap(&self) -> ResolverGap {
        if self.denied > 0 {
            return ResolverGap::Denied {
                denied: self.denied,
            };
        }
        ResolverGap::NotPushed(MissingDns::UnreachableFamily {
            discarded: self.wrong_family,
        })
    }
}

/// Two independent rules, applied to pushed and configured servers alike.
///
/// A v4-only tunnel must never be handed a v6 nameserver: every query against it
/// would leave through the default route or fail (SPEC.md §5.5). And no server
/// on the destination denylist may be queried at all (SPEC.md §5.4 D6), because
/// reaching one means resolving somewhere other than through the tunnel.
fn usable_servers(servers: &[IpAddr], tunnel_has_v6: bool) -> VettedServers {
    servers.iter().copied().fold(
        VettedServers {
            usable: Vec::new(),
            denied: 0,
            wrong_family: 0,
        },
        |acc, server| {
            if !is_usable_resolver(server) {
                return VettedServers {
                    denied: acc.denied + 1,
                    ..acc
                };
            }
            if !tunnel_has_v6 && !server.is_ipv4() {
                return VettedServers {
                    wrong_family: acc.wrong_family + 1,
                    ..acc
                };
            }
            VettedServers {
                usable: [acc.usable, vec![server]].concat(),
                ..acc
            }
        },
    )
}

/// `EgressPublisher` speaks `PolicyError`, and a proxy that will not start is a
/// refusal to publish the tunnel identity, which is what that error means here.
fn refused(error: ProxyError) -> PolicyError {
    PolicyError::Verification {
        probe: "proxy listener".to_owned(),
        detail: error.to_string(),
    }
}

/// What a build with no proxy worker linked in gets. It fails the connect rather
/// than reporting a tunnel that nothing can use (SPEC.md §3.1 point 5).
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableRuntime;

impl ProxyRuntime for UnavailableRuntime {
    fn start(&self, _request: &ProxyStartRequest) -> Result<Arc<dyn ProxyListener>, ProxyError> {
        Err(ProxyError::Unavailable)
    }
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
