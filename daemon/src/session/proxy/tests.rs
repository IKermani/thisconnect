// SPDX-License-Identifier: GPL-3.0-or-later

//! Lifecycle tests for the proxy publisher, driven entirely by doubles: the
//! listener is a counter, the runtime is a switch, and the DNS capture is fed
//! the same log lines openvpn emits.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

use thisconnect_shared::ipc::{ProxyAuth, Secret};

use super::*;

const PUSH_WITH_DNS: &str = ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,route-gateway 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'";

pub(crate) struct StubListener {
    shutdowns: AtomicUsize,
}

impl StubListener {
    fn new() -> Self {
        Self {
            shutdowns: AtomicUsize::new(0),
        }
    }

    fn shutdowns(&self) -> usize {
        self.shutdowns.load(Ordering::SeqCst)
    }
}

impl ProxyListener for StubListener {
    fn info(&self) -> ProxyInfo {
        ProxyInfo {
            listen_addrs: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)],
            auth: ProxyAuth::Credentials {
                username: "user".to_owned(),
                password: Secret::new("pass"),
            },
            is_loopback_only: true,
            allowed_cidrs: Vec::new(),
            socks5h_url: Secret::new("socks5h://user:pass@127.0.0.1:1080"),
        }
    }

    fn stats(&self) -> ProxySessionStats {
        ProxySessionStats {
            active_sessions: 2,
            ..ProxySessionStats::default()
        }
    }

    fn shutdown(&self) {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) struct StubRuntime {
    /// Index of the first `start` that fails, so a test can let one session come
    /// up and then refuse the next.
    fails_from: usize,
    listener: Arc<StubListener>,
    starts: AtomicUsize,
    requests: Mutex<Vec<ProxyStartRequest>>,
}

impl StubRuntime {
    fn with(fails_from: usize) -> Arc<Self> {
        Arc::new(Self {
            fails_from,
            listener: Arc::new(StubListener::new()),
            starts: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn working() -> Arc<Self> {
        Self::with(usize::MAX)
    }

    fn refusing() -> Arc<Self> {
        Self::with(0)
    }

    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> ProxyStartRequest {
        lock(&self.requests).last().cloned().expect("a start")
    }
}

impl ProxyRuntime for StubRuntime {
    fn start(&self, request: &ProxyStartRequest) -> Result<Arc<dyn ProxyListener>, ProxyError> {
        let index = self.starts.fetch_add(1, Ordering::SeqCst);
        lock(&self.requests).push(request.clone());
        if index >= self.fails_from {
            return Err(ProxyError::Listener {
                detail: "bind refused".to_owned(),
            });
        }
        Ok(Arc::clone(&self.listener) as Arc<dyn ProxyListener>)
    }
}

fn binding(tunnel_has_v6: bool) -> TunnelBinding {
    TunnelBinding {
        device: "utun9".to_owned(),
        ipv4: Ipv4Addr::new(10, 8, 0, 2),
        ipv6: None,
        mtu: 1400,
        tunnel_has_v6,
    }
}

fn settings(fallback: &[&str]) -> ProxySettings {
    ProxySettings {
        fallback_dns: fallback
            .iter()
            .map(|raw| raw.parse().expect("a fallback address"))
            .collect(),
    }
}

fn publisher(runtime: Arc<StubRuntime>, fallback: &[&str]) -> ProxyPublisher {
    ProxyPublisher::new(runtime as Arc<dyn ProxyRuntime>, settings(fallback))
}

/// A publisher that is already listening, for the IPC handler's tests.
pub(crate) fn listening_publisher() -> Arc<ProxyPublisher> {
    let publisher = Arc::new(publisher(StubRuntime::working(), &["9.9.9.9"]));
    publisher.publish(&binding(false)).expect("publish");
    publisher
}

/// A publisher no tunnel was ever published to.
pub(crate) fn idle_publisher() -> Arc<ProxyPublisher> {
    Arc::new(publisher(StubRuntime::working(), &["9.9.9.9"]))
}

#[test]
fn publishing_a_tunnel_starts_the_listener() {
    // Arrange
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);

    // Act
    let outcome = publisher.publish(&binding(false));

    // Assert
    assert!(outcome.is_ok());
    assert_eq!(runtime.starts(), 1);
    assert!(publisher.is_listening());
    assert!(ProxyStatus::info(&publisher).is_some());
    assert_eq!(
        ProxyStatus::stats(&publisher)
            .expect("stats")
            .active_sessions,
        2
    );
}

#[test]
fn a_listener_that_refuses_to_start_fails_the_publish_and_leaves_nothing_up() {
    let publisher = publisher(StubRuntime::refusing(), &["9.9.9.9"]);

    let outcome = publisher.publish(&binding(false));

    assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    assert!(!publisher.is_listening());
    assert!(ProxyStatus::info(&publisher).is_none());
}

#[test]
fn revoking_closes_the_listener_before_anything_else_can_use_it() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.publish(&binding(false)).expect("publish");

    publisher.revoke();

    assert_eq!(runtime.listener.shutdowns(), 1);
    assert!(!publisher.is_listening());
    assert!(ProxyStatus::stats(&publisher).is_none());
}

#[test]
fn revoking_twice_does_not_shut_a_listener_down_twice() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.publish(&binding(false)).expect("publish");

    publisher.revoke();
    publisher.revoke();

    assert_eq!(runtime.listener.shutdowns(), 1);
}

#[test]
fn republishing_stops_the_earlier_listener_rather_than_running_two() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.publish(&binding(false)).expect("first publish");

    publisher.publish(&binding(false)).expect("second publish");

    assert_eq!(runtime.starts(), 2);
    assert_eq!(runtime.listener.shutdowns(), 1);
    assert!(publisher.is_listening());
}

/// The listener of the tunnel that is going away is stopped first, so a refused
/// restart can never leave the previous session's sockets accepting.
#[test]
fn a_republish_that_fails_leaves_nothing_listening() {
    let runtime = StubRuntime::with(1);
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.publish(&binding(false)).expect("first publish");

    let outcome = publisher.publish(&binding(false));

    assert!(outcome.is_err());
    assert_eq!(runtime.listener.shutdowns(), 1);
    assert!(!publisher.is_listening());
    assert!(ProxyStatus::info(&publisher).is_none());
}

#[test]
fn nothing_is_reportable_before_a_tunnel_is_published() {
    let publisher = publisher(StubRuntime::working(), &["9.9.9.9"]);

    assert!(ProxyStatus::info(&publisher).is_none());
    assert!(ProxyStatus::stats(&publisher).is_none());
}

#[test]
fn a_session_with_no_captured_dns_takes_the_configured_fallback_and_says_so() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9", "1.1.1.1"]);

    publisher.publish(&binding(false)).expect("publish");

    let dns = runtime.last_request().dns;
    assert_eq!(dns.source, DnsSource::TunnelFallback);
    assert_eq!(dns.nameservers.len(), 2);
    assert!(dns.search_domains.is_empty());
}

#[test]
fn a_captured_push_is_preferred_over_the_fallback() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(PUSH_WITH_DNS);

    publisher.publish(&binding(false)).expect("publish");

    let dns = runtime.last_request().dns;
    assert_eq!(dns.source, DnsSource::Pushed);
    assert_eq!(
        dns.nameservers,
        vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]
    );
}

#[test]
fn a_v4_only_tunnel_never_receives_a_v6_nameserver() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["2620:fe::fe", "9.9.9.9"]);

    publisher.publish(&binding(false)).expect("publish");

    let dns = runtime.last_request().dns;
    assert_eq!(dns.nameservers, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
}

#[test]
fn a_dual_stack_tunnel_keeps_the_v6_nameserver() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["2620:fe::fe"]);

    publisher.publish(&binding(true)).expect("publish");

    assert_eq!(runtime.last_request().dns.nameservers.len(), 1);
}

/// Fail closed: no resolver of a family the tunnel can carry means no leak-free
/// way to answer a name, and the system resolver is never the answer.
#[test]
fn a_tunnel_with_no_usable_resolver_refuses_to_publish_rather_than_leaking() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["2620:fe::fe"]);

    let outcome = publisher.publish(&binding(false));

    assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    assert_eq!(runtime.starts(), 0);
    assert!(!publisher.is_listening());
}

#[test]
fn a_push_carrying_only_a_v6_server_on_a_v4_tunnel_falls_back_instead_of_failing() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS6 fd00::53'",
    );

    publisher.publish(&binding(false)).expect("publish");

    assert_eq!(runtime.last_request().dns.source, DnsSource::TunnelFallback);
}

#[test]
fn revoking_clears_the_capture_so_the_next_session_cannot_inherit_it() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(PUSH_WITH_DNS);
    publisher.publish(&binding(false)).expect("publish");

    publisher.revoke();
    publisher.publish(&binding(false)).expect("republish");

    assert_eq!(runtime.last_request().dns.source, DnsSource::TunnelFallback);
}

/// SPEC.md §5.4 D6 + D3. A server that pushes the host's own stub resolver is
/// asking every name to be answered off-tunnel; the push must not survive
/// vetting, and the plan must not claim `Pushed`.
#[test]
fn a_pushed_loopback_resolver_never_reaches_the_listener() {
    // Arrange
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 127.0.0.53'",
    );

    // Act
    publisher.publish(&binding(false)).expect("publish");

    // Assert
    let dns = runtime.last_request().dns;
    assert_eq!(dns.source, DnsSource::TunnelFallback);
    assert_eq!(dns.nameservers, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
}

#[test]
fn a_pushed_link_local_metadata_resolver_never_reaches_the_listener() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 169.254.169.254'",
    );

    publisher.publish(&binding(false)).expect("publish");

    let dns = runtime.last_request().dns;
    assert_eq!(dns.source, DnsSource::TunnelFallback);
    assert!(!dns
        .nameservers
        .contains(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
}

/// A mixed push keeps only the server that may actually be queried.
#[test]
fn a_push_mixing_a_denied_and_a_tunnel_resolver_keeps_only_the_tunnel_one() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["9.9.9.9"]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 127.0.0.1,dhcp-option DNS 10.8.0.1'",
    );

    publisher.publish(&binding(false)).expect("publish");

    let dns = runtime.last_request().dns;
    assert_eq!(dns.source, DnsSource::Pushed);
    assert_eq!(
        dns.nameservers,
        vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]
    );
}

/// A denylisted fallback in the config is the system resolver by another name;
/// with nothing else usable the publish must fail rather than start a listener
/// that resolves locally.
#[test]
fn a_denylisted_configured_fallback_fails_the_publish_rather_than_resolving_locally() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["127.0.0.1"]);

    let outcome = publisher.publish(&binding(false));

    assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    assert_eq!(runtime.starts(), 0);
    assert!(!publisher.is_listening());
}

#[test]
fn a_push_of_only_denied_servers_with_no_usable_fallback_refuses_to_publish() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &["::1"]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 0.0.0.0'",
    );

    let outcome = publisher.publish(&binding(true));

    assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    assert_eq!(runtime.starts(), 0);
}

#[test]
fn a_push_of_only_denied_servers_reports_a_denied_gap_not_a_family_mismatch() {
    let runtime = StubRuntime::working();
    let publisher = publisher(Arc::clone(&runtime), &[]);
    publisher.capture().observe_line(
        ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 127.0.0.1'",
    );

    let outcome = publisher.plan_dns(&binding(false));

    assert!(matches!(
        outcome,
        Err(ProxyError::NoResolver {
            reason: ResolverGap::Denied { denied: 1 }
        })
    ));
}
