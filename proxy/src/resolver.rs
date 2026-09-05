// SPDX-License-Identifier: GPL-3.0-or-later

//! Tunnel-pinned resolver (SPEC.md §5.4).
//!
//! Every name the proxy resolves is resolved here, over a socket created by
//! [`crate::egress::TunEgress`], or it is not resolved at all. There is no fallback to the system
//! resolver on error, on timeout, or on an empty capture: `getaddrinfo`, `ToSocketAddrs` and
//! `tokio::net::lookup_host` are banned in this crate and `clippy.toml` enforces it in CI. A
//! `tunnel_fallback_dns` server (SPEC.md §5.4 D4) is a *different nameserver* queried through the
//! same tun, never a different code path.
//!
//! Three properties are load-bearing and each has a test below:
//!
//!   * With no usable nameserver, every resolution is refused and counted. The refusal counter
//!     being non-zero is the leak prevention working, which is why it is user-visible.
//!   * On a v4-only tunnel only `A` is queried, and an `AAAA` answer that arrives anyway is
//!     discarded rather than used (SPEC.md §5.5).
//!   * Answers are run through [`check_destination`] before they are returned, so a name that
//!     resolves to `127.0.0.1` or `169.254.169.254` is an SSRF that ends here (SPEC.md §5.4 D6).

mod config;
mod counters;
mod provider;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use hickory_resolver::proto::rr::Name;
use hickory_resolver::Resolver;
use thiserror::Error;
use tokio::time::timeout;

use crate::egress::{check_destination, DestinationPolicy, TunEgress};
use provider::EgressRuntimeProvider;

pub use config::{
    DnsSource, TunnelDnsConfig, DEFAULT_ATTEMPTS, DEFAULT_QUERY_TIMEOUT, DEFAULT_TOTAL_TIMEOUT,
    DEFAULT_TUNNEL_FALLBACK_DNS, MAX_CACHED_TTL, MAX_TOTAL_TIMEOUT,
};
pub use counters::{ResolverCounters, ResolverStats, LOCAL_LOOKUPS};

/// RFC 1035 wire-format ceiling on a domain name.
const MAX_NAME_LEN: usize = 253;

#[derive(Debug, Error)]
pub enum ResolveError {
    /// The one that matters: no tunnel resolver, so no resolution. Never a reason to look elsewhere.
    #[error("no tunnel-pinned resolver is available")]
    NoTunnelResolver,
    #[error("the tunnel changed while the name was being resolved")]
    StaleTunnel,
    #[error("resolver state is unavailable")]
    StateUnavailable,
    #[error("the tunnel-pinned resolver could not be constructed")]
    NotConstructed,
    #[error("destination name is not a valid DNS name")]
    InvalidName,
    #[error("name has no address through the tunnel")]
    NotFound,
    /// Every answer was refused by SPEC.md §5.4 D6 — kept distinct from [`Self::NotFound`] because
    /// it means something actively tried to point the proxy at the user's own machine.
    #[error("every address for this name was refused by policy")]
    AddressesDenied,
    #[error("the tunnel has no IPv6; refusing an IPv6-only destination")]
    Ipv6Unsupported,
    #[error("the tunnel resolver did not answer in time")]
    Timeout,
    /// Deliberately opaque: a hickory error carries the queried name in its `Display`, and that
    /// name must never reach a log line at info level.
    #[error("the tunnel resolver failed")]
    Backend,
}

/// A resolver pinned to one tunnel generation.
///
/// Construction with no usable nameserver is not an error — the daemon may bring the proxy up
/// before a `PUSH_REPLY` lands — but such a resolver refuses every name, loudly and countably.
pub struct TunnelResolver {
    inner: Option<Resolver<EgressRuntimeProvider>>,
    egress: Arc<TunEgress>,
    nameservers: Vec<IpAddr>,
    source: DnsSource,
    tunnel_has_v6: bool,
    policy: DestinationPolicy,
    total_timeout: std::time::Duration,
    counters: Arc<ResolverCounters>,
}

impl std::fmt::Debug for TunnelResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelResolver")
            .field("device", &self.egress.device())
            .field("nameservers", &self.nameservers.len())
            .field("source", &self.source)
            .field("tunnel_has_v6", &self.tunnel_has_v6)
            .finish()
    }
}

impl TunnelResolver {
    /// Builds a resolver whose sockets all come from `egress`. Note the absence of any
    /// constructor that reads `/etc/resolv.conf`: hickory's system-configuration builders are
    /// never called, so there is no path by which a system nameserver can enter this type.
    pub fn new(
        egress: Arc<TunEgress>,
        config: &TunnelDnsConfig,
        policy: DestinationPolicy,
        counters: Arc<ResolverCounters>,
    ) -> Result<Self, ResolveError> {
        let selected = config::select_nameservers(config);
        let inner = match selected.accepted.is_empty() {
            true => None,
            false => Some(
                Resolver::builder_with_config(
                    config::hickory_config(&selected.accepted),
                    EgressRuntimeProvider::new(Arc::clone(&egress)),
                )
                .with_options(config::hickory_opts(config))
                .build()
                .map_err(|_| ResolveError::NotConstructed)?,
            ),
        };
        let total_timeout = config::effective_total_timeout(config, selected.accepted.len());
        Ok(Self {
            inner,
            egress,
            nameservers: selected.accepted,
            source: selected.source,
            tunnel_has_v6: config.tunnel_has_v6,
            policy,
            total_timeout,
            counters,
        })
    }

    /// SPEC.md §5.5, surfaced so the UI can explain a v6-only destination failing.
    pub fn tunnel_has_v6(&self) -> bool {
        self.tunnel_has_v6
    }

    /// Whether queries can reach a third-party fallback rather than the VPN's own resolver.
    pub fn source(&self) -> DnsSource {
        self.source
    }

    pub fn nameservers(&self) -> &[IpAddr] {
        &self.nameservers
    }

    pub fn stats(&self) -> ResolverStats {
        self.counters.snapshot()
    }

    pub fn counters(&self) -> &Arc<ResolverCounters> {
        &self.counters
    }

    /// SPEC.md §5.4 D5.
    pub fn flush_cache(&self) {
        if let Some(inner) = self.inner.as_ref() {
            inner.clear_cache();
        }
    }

    /// Resolve `host` through the tunnel. An IP literal is validated and returned without a query.
    ///
    /// The future is abortable: dropping it cancels the lookup, and it is bounded by
    /// `total_timeout` so a black-holed nameserver cannot pin a proxy task.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        if let Ok(literal) = host.parse::<IpAddr>() {
            return self.accept_literal(literal);
        }
        let name = self.parse_name(host)?;
        let inner = match self.inner.as_ref() {
            Some(inner) => inner,
            None => {
                self.counters.record_refusal();
                return Err(ResolveError::NoTunnelResolver);
            }
        };
        // A tunnel that went down mid-flight would otherwise resolve against a stranded pool.
        if !self.egress.is_current() {
            self.counters.record_refusal();
            return Err(ResolveError::StaleTunnel);
        }
        let answer = match timeout(self.total_timeout, inner.lookup_ip(name)).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(err)) => return Err(self.classify(err)),
            Err(_) => {
                self.counters.record_failure();
                return Err(ResolveError::Timeout);
            }
        };
        self.accept_answers(answer.iter())
    }

    /// Convenience for the dialer: the same guarantees, shaped for `TcpSocket::connect`.
    pub async fn resolve_socket_addrs(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        let addrs = self.resolve(host).await?;
        Ok(addrs
            .into_iter()
            .map(|addr| SocketAddr::new(addr, port))
            .collect())
    }

    fn accept_literal(&self, literal: IpAddr) -> Result<Vec<IpAddr>, ResolveError> {
        if literal.is_ipv6() && !self.tunnel_has_v6 && literal.to_canonical().is_ipv6() {
            return Err(ResolveError::Ipv6Unsupported);
        }
        check_destination(literal, self.policy).map_err(|_| {
            self.counters.record_denied_addresses(1);
            ResolveError::AddressesDenied
        })?;
        Ok(vec![literal])
    }

    fn parse_name(&self, host: &str) -> Result<Name, ResolveError> {
        if host.is_empty() || host.len() > MAX_NAME_LEN {
            return Err(ResolveError::InvalidName);
        }
        Name::from_utf8(host).map_err(|_| ResolveError::InvalidName)
    }

    /// SPEC.md §5.5 then §5.4 D6, in that order: drop anything from a family the tunnel cannot
    /// carry, then drop anything pointing back at the user's own machine.
    fn accept_answers(
        &self,
        answers: impl Iterator<Item = IpAddr>,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let (accepted, denied) = answers
            .filter(|addr| self.tunnel_has_v6 || addr.to_canonical().is_ipv4())
            .fold(
                (Vec::new(), 0u64),
                |(mut kept, denied), addr| match check_destination(addr, self.policy) {
                    Ok(()) => {
                        kept.push(addr);
                        (kept, denied)
                    }
                    Err(_) => (kept, denied + 1),
                },
            );
        self.counters.record_denied_addresses(denied);
        if accepted.is_empty() {
            self.counters.record_failure();
            return match denied {
                0 => Err(ResolveError::NotFound),
                _ => Err(ResolveError::AddressesDenied),
            };
        }
        self.counters.record_lookup();
        Ok(accepted)
    }

    fn classify(&self, err: hickory_resolver::net::NetError) -> ResolveError {
        self.counters.record_failure();
        // The name lives in `err`'s Display, so it is logged at debug and never above.
        tracing::debug!(kind = ?std::mem::discriminant(&err), "tunnel resolution failed");
        if err.is_no_records_found() {
            return ResolveError::NotFound;
        }
        match err {
            hickory_resolver::net::NetError::Timeout => ResolveError::Timeout,
            _ => ResolveError::Backend,
        }
    }
}

/// Publishes the current [`TunnelResolver`] to the proxy, mirroring
/// [`crate::egress::EgressState`]. Tunnel up and tunnel down both flush the cache, because a
/// cached answer from one tunnel is a wrong answer on the next (SPEC.md §5.4 D5).
#[derive(Debug)]
pub struct ResolverState {
    current: RwLock<Option<Arc<TunnelResolver>>>,
    counters: Arc<ResolverCounters>,
    policy: DestinationPolicy,
}

impl ResolverState {
    pub fn new(policy: DestinationPolicy) -> Self {
        Self {
            current: RwLock::new(None),
            counters: Arc::new(ResolverCounters::new()),
            policy,
        }
    }

    pub fn tunnel_up(
        &self,
        egress: Arc<TunEgress>,
        config: &TunnelDnsConfig,
    ) -> Result<Arc<TunnelResolver>, ResolveError> {
        let resolver = Arc::new(TunnelResolver::new(
            egress,
            config,
            self.policy,
            Arc::clone(&self.counters),
        )?);
        let mut slot = self
            .current
            .write()
            .map_err(|_| ResolveError::StateUnavailable)?;
        if let Some(previous) = slot.as_ref() {
            previous.flush_cache();
        }
        *slot = Some(Arc::clone(&resolver));
        Ok(resolver)
    }

    pub fn tunnel_down(&self) -> Result<(), ResolveError> {
        let mut slot = self
            .current
            .write()
            .map_err(|_| ResolveError::StateUnavailable)?;
        if let Some(previous) = slot.as_ref() {
            previous.flush_cache();
        }
        *slot = None;
        Ok(())
    }

    pub fn current(&self) -> Result<Arc<TunnelResolver>, ResolveError> {
        let slot = self
            .current
            .read()
            .map_err(|_| ResolveError::StateUnavailable)?;
        match slot.as_ref() {
            Some(resolver) if resolver.egress.is_current() => Ok(Arc::clone(resolver)),
            _ => Err(ResolveError::NoTunnelResolver),
        }
    }

    /// The entry point the dialer uses. A missing or stale resolver is a counted refusal, not a
    /// reason to resolve some other way.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let resolver = match self.current() {
            Ok(resolver) => resolver,
            Err(err) => {
                self.counters.record_refusal();
                return Err(err);
            }
        };
        resolver.resolve(host).await
    }

    pub fn stats(&self) -> ResolverStats {
        self.counters.snapshot()
    }

    pub fn counters(&self) -> &Arc<ResolverCounters> {
        &self.counters
    }
}
