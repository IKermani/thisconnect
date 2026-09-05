// SPDX-License-Identifier: GPL-3.0-or-later

//! The production [`Dialer`]: the only place a client's destination becomes a socket.
//!
//! Everything the proxy accepts arrives here as a [`Target`], and there are exactly two shapes.
//! An IP literal is dialled through the tunnel-pinned egress. A name is resolved by the
//! tunnel-pinned resolver and *then* dialled through the same egress. There is no third path,
//! and in particular there is no path that hands a hostname to the operating system — that is the
//! product's entire security claim (SPEC.md §5.4 D3).
//!
//! Both halves are already fail-closed on their own: `TunEgress` refuses to produce an unpinned
//! socket and `TunnelResolver` refuses to answer without a tunnel resolver. This module's job is
//! to join them without inventing a fallback between the two.

use std::sync::Arc;

use crate::egress::{EgressError, TunEgress};
use crate::resolver::{ResolveError, TunnelResolver};
use crate::socks5::{DialError, Dialer, Target};

/// Dials only through the tunnel. Cloning is cheap; both halves are shared.
#[derive(Clone)]
pub struct TunnelDialer {
    egress: Arc<TunEgress>,
    resolver: Arc<TunnelResolver>,
}

impl TunnelDialer {
    pub fn new(egress: Arc<TunEgress>, resolver: Arc<TunnelResolver>) -> Self {
        Self { egress, resolver }
    }

    pub fn egress(&self) -> &Arc<TunEgress> {
        &self.egress
    }

    pub fn resolver(&self) -> &Arc<TunnelResolver> {
        &self.resolver
    }
}

impl Dialer for TunnelDialer {
    type Stream = tokio::net::TcpStream;

    async fn tcp(&self, target: &Target) -> Result<Self::Stream, DialError> {
        match target {
            Target::Ip(addr) => self.egress.tcp(*addr).await.map_err(dial_error),
            Target::Domain { host, port } => {
                let candidates = self
                    .resolver
                    .resolve_socket_addrs(host, *port)
                    .await
                    .map_err(resolve_error)?;

                // Every candidate came from the tunnel resolver and has already been
                // through the destination denylist, so trying the next one on a
                // connect failure widens nothing.
                let mut last = DialError::NameNotResolved;
                for addr in candidates {
                    match self.egress.tcp(addr).await {
                        Ok(stream) => return Ok(stream),
                        Err(error) => last = dial_error(error),
                    }
                }
                Err(last)
            }
        }
    }
}

/// A resolution failure is never a reason to try another route — it is the answer.
fn resolve_error(error: ResolveError) -> DialError {
    match error {
        // The distinction matters to the operator, not to the client: both mean
        // "no address through the tunnel", and neither may fall back.
        ResolveError::NotFound => DialError::NameNotResolved,
        // Something actively pointed the name at the user's own machine.
        ResolveError::AddressesDenied => DialError::PolicyRejected,
        ResolveError::InvalidName | ResolveError::Ipv6Unsupported => DialError::PolicyRejected,
        // A slow resolver is a transient tunnel condition, not a missing name.
        ResolveError::Timeout | ResolveError::Backend => DialError::NetworkUnreachable,
        // No resolver at all, or the tunnel moved under us. Reported as
        // unreachable so the client retries rather than caching a name failure.
        ResolveError::NoTunnelResolver
        | ResolveError::StaleTunnel
        | ResolveError::StateUnavailable
        | ResolveError::NotConstructed => DialError::NetworkUnreachable,
    }
}

fn dial_error(error: EgressError) -> DialError {
    match error {
        // SPEC.md §5.2: the Linux floor route answers EHOSTUNREACH, and macOS
        // answers ENETUNREACH when no scoped route exists. Both mean the tunnel
        // is not carrying traffic, which is the fail-closed state, not a bug.
        EgressError::HostUnreachable => DialError::HostUnreachable,
        EgressError::NetworkUnreachable
        | EgressError::TunnelNotReady
        | EgressError::StaleTunnel
        | EgressError::Ipv6Unsupported => DialError::NetworkUnreachable,
        EgressError::ConnectionRefused(_) => DialError::ConnectionRefused,
        EgressError::DestinationDenied { .. } | EgressError::InvalidPort => {
            DialError::PolicyRejected
        }
        _ => DialError::Other,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::egress::{DenyReason, DestinationPolicy, EgressState, TunnelConfig};
    use crate::resolver::{ResolverState, TunnelDnsConfig};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// A tunnel identity on an interface that exists everywhere, carrying a
    /// plausible tunnel address. Nothing here completes a connection: both tests
    /// assert a refusal that happens before any socket is bound.
    fn egress() -> (EgressState, Arc<TunEgress>) {
        let state = EgressState::new(DestinationPolicy::default());
        let handle = state
            .tunnel_up(&TunnelConfig {
                device: loopback_device().to_owned(),
                // Not 127.0.0.1: EgressState rightly refuses loopback as a
                // tunnel source address.
                ipv4: Ipv4Addr::new(10, 255, 255, 2),
                ipv6: None,
                mtu: 1500,
            })
            .expect("the loopback interface exists on every machine");
        (state, handle)
    }

    #[cfg(target_os = "macos")]
    fn loopback_device() -> &'static str {
        "lo0"
    }

    #[cfg(not(target_os = "macos"))]
    fn loopback_device() -> &'static str {
        "lo"
    }

    fn dialer_without_resolver() -> TunnelDialer {
        let (_state, egress) = egress();
        let resolvers = ResolverState::new(DestinationPolicy::default());
        // Deliberately never brought up: this is the "no tunnel resolver" case.
        let resolver = resolvers
            .tunnel_up(Arc::clone(&egress), &TunnelDnsConfig::default())
            .expect("constructing a resolver needs no network");
        TunnelDialer::new(egress, resolver)
    }

    #[tokio::test]
    async fn a_name_is_never_resolved_by_the_system_when_no_tunnel_resolver_exists() {
        // Arrange: a config carrying no pushed nameservers at all.
        let (_state, egress) = egress();
        let resolvers = ResolverState::new(DestinationPolicy::default());
        let resolver = resolvers
            .tunnel_up(
                Arc::clone(&egress),
                &TunnelDnsConfig {
                    pushed: Vec::new(),
                    fallback: Vec::new(),
                    ..TunnelDnsConfig::default()
                },
            )
            .expect("construct");
        let dialer = TunnelDialer::new(egress, resolver);

        // Act
        let result = dialer
            .tcp(&Target::Domain {
                host: "example.com".to_owned(),
                port: 443,
            })
            .await;

        // Assert: a refusal, not an answer. If this ever succeeds, the name was
        // resolved off-tunnel and the product's claim is void.
        assert!(matches!(
            result,
            Err(DialError::NetworkUnreachable) | Err(DialError::NameNotResolved)
        ));
    }

    #[tokio::test]
    async fn a_denied_ip_literal_is_refused_before_any_socket_is_opened() {
        // Arrange
        let dialer = dialer_without_resolver();

        // Act: loopback is on the destination denylist (SPEC.md §5.4 D6); pinning
        // a socket does not stop it reaching the user's own machine.
        let result = dialer
            .tcp(&Target::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                22,
            )))
            .await;

        // Assert
        assert!(matches!(result, Err(DialError::PolicyRejected)));
    }

    #[test]
    fn every_egress_failure_maps_to_a_refusal_and_never_to_success() {
        // Arrange / Act / Assert: the mapping must be total, because a variant
        // falling through to a permissive default is how fail-open is
        // reintroduced later.
        for error in [
            EgressError::TunnelNotReady,
            EgressError::StaleTunnel,
            EgressError::Ipv6Unsupported,
            EgressError::HostUnreachable,
            EgressError::NetworkUnreachable,
            EgressError::InvalidPort,
            EgressError::DestinationDenied {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                reason: DenyReason::Loopback,
            },
        ] {
            let mapped = dial_error(error);
            assert!(!matches!(mapped, DialError::NameNotResolved));
        }
    }

    #[test]
    fn a_missing_resolver_is_reported_as_unreachable_not_as_an_unknown_name() {
        // Arrange / Act / Assert: NXDOMAIN is cacheable by clients, and caching
        // "this name does not exist" because the tunnel was down is wrong.
        assert!(matches!(
            resolve_error(ResolveError::NoTunnelResolver),
            DialError::NetworkUnreachable
        ));
        assert!(matches!(
            resolve_error(ResolveError::NotFound),
            DialError::NameNotResolved
        ));
    }
}
