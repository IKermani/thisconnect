// SPDX-License-Identifier: GPL-3.0-or-later

//! The mixed SOCKS5/HTTP listener. See `docs/SPEC.md` §5.6 L1-L6.
//!
//! This is the seam the daemon drives from the tunnel lifecycle: [`start`] only
//! after the tunnel is up and verified, [`Handle::shutdown`] the moment it goes
//! away. Shutdown is not advisory — it aborts every live session, because a
//! socket bound to a tun address that has vanished blocks for ~15 minutes
//! (`tcp_retries2`) rather than erroring.
//!
//! Two policies are enforced here and nowhere else:
//!
//! * a non-loopback bind without credentials is refused at startup, not warned
//!   about (§5.6 L3), and
//! * `allowed_cidrs` is checked on accept, *before* any protocol greeting, so a
//!   peer that is not admitted never gets to speak.

mod cidr;
mod session;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use thisconnect_shared::ipc::{ProxyAuth, ProxyInfo, ProxySessionStats, Secret};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::credentials::{socks5h_url_without_auth, ProxyCredentials};
use crate::http::HttpConfig;
use crate::socks5::{AuthPolicy, AuthRateLimiter, Dialer, Socks5Config, DEFAULT_HANDSHAKE_TIMEOUT};
use crate::stats::StatsCollector;

pub use cidr::{Cidr, CidrError};
pub use session::SessionError;

pub const DEFAULT_PROXY_PORT: u16 = 1080;

/// Authentication posture for the listener as a whole. Both front ends share
/// it: SOCKS5 and HTTP CONNECT must never disagree about whether auth is on.
#[derive(Debug)]
pub enum AuthSetting {
    Required(ProxyCredentials),
    /// Reachable only when the user explicitly turned authentication off, and
    /// then only on loopback.
    Disabled,
}

impl AuthSetting {
    fn is_required(&self) -> bool {
        matches!(self, AuthSetting::Required(_))
    }

    fn policy(&self) -> AuthPolicy {
        match self {
            AuthSetting::Required(credentials) => AuthPolicy::Required(credentials.to_socks5()),
            AuthSetting::Disabled => AuthPolicy::Disabled,
        }
    }

    fn ipc(&self) -> ProxyAuth {
        match self {
            AuthSetting::Required(credentials) => credentials.to_ipc_auth(),
            AuthSetting::Disabled => ProxyAuth::Disabled,
        }
    }
}

#[derive(Debug)]
pub struct ListenerConfig {
    pub bind_addrs: Vec<SocketAddr>,
    pub auth: AuthSetting,
    /// Default empty. An empty list admits loopback and nothing else.
    pub allowed_cidrs: Vec<Cidr>,
    /// From `PUSH_REPLY`; gates IPv6 destinations (SPEC.md §5.5).
    pub tunnel_has_v6: bool,
    pub handshake_timeout: Duration,
}

impl ListenerConfig {
    /// The shipping default: loopback v4 and v6, freshly generated credentials.
    pub fn generated(tunnel_has_v6: bool) -> Self {
        Self::new(
            default_bind_addrs(),
            AuthSetting::Required(ProxyCredentials::generate()),
            tunnel_has_v6,
        )
    }

    pub fn new(bind_addrs: Vec<SocketAddr>, auth: AuthSetting, tunnel_has_v6: bool) -> Self {
        Self {
            bind_addrs,
            auth,
            allowed_cidrs: Vec::new(),
            tunnel_has_v6,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// A refusal, not a warning: an unauthenticated proxy on a routable address
    /// relays traffic under the user's VPN identity and IP.
    fn validate(&self) -> Result<(), ListenerError> {
        if self.bind_addrs.is_empty() {
            return Err(ListenerError::NoBindAddress);
        }
        if self.auth.is_required() {
            return Ok(());
        }
        match self.bind_addrs.iter().find(|addr| !addr.ip().is_loopback()) {
            Some(addr) => Err(ListenerError::NonLoopbackWithoutAuth(*addr)),
            None => Ok(()),
        }
    }
}

pub fn default_bind_addrs() -> Vec<SocketAddr> {
    vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PROXY_PORT),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DEFAULT_PROXY_PORT),
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("refusing to bind non-loopback address {0} without proxy authentication")]
    NonLoopbackWithoutAuth(SocketAddr),
    #[error("no bind address configured")]
    NoBindAddress,
    #[error("cannot bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
}

/// The daemon's grip on a running listener. Dropping it shuts the listener
/// down; [`Handle::shutdown`] additionally waits for the sessions to be gone.
#[derive(Debug)]
pub struct Handle {
    listen_addrs: Vec<SocketAddr>,
    skipped_addrs: Vec<SocketAddr>,
    config: Arc<ListenerConfig>,
    stats: Arc<StatsCollector>,
    shutdown: watch::Sender<bool>,
    acceptors: Vec<JoinHandle<()>>,
}

impl Handle {
    /// The addresses actually bound, which is what the GUI must display: a
    /// configured port of 0 becomes a real port here.
    pub fn listen_addrs(&self) -> &[SocketAddr] {
        &self.listen_addrs
    }

    /// Configured loopback addresses that could not be bound — typically
    /// `[::1]` on a host with IPv6 disabled. The GUI shows these so a missing
    /// half of the default pair is visible rather than silent.
    pub fn skipped_bind_addrs(&self) -> &[SocketAddr] {
        &self.skipped_addrs
    }

    /// Drives the permanent SPEC.md §5.6 L4 banner.
    pub fn is_loopback_only(&self) -> bool {
        self.listen_addrs.iter().all(|addr| addr.ip().is_loopback())
    }

    pub fn distinct_remote_peers(&self) -> u32 {
        self.stats.distinct_remote_peers()
    }

    /// Shared with the resolver, which owns the DNS counters (SPEC.md §5.4 D7).
    pub fn stats(&self) -> Arc<StatsCollector> {
        Arc::clone(&self.stats)
    }

    pub fn stats_snapshot(&self) -> ProxySessionStats {
        self.stats.snapshot()
    }

    pub fn proxy_info(&self) -> ProxyInfo {
        ProxyInfo {
            listen_addrs: self.listen_addrs.clone(),
            auth: self.config.auth.ipc(),
            is_loopback_only: self.is_loopback_only(),
            allowed_cidrs: self
                .config
                .allowed_cidrs
                .iter()
                .map(Cidr::to_string)
                .collect(),
            socks5h_url: self.socks5h_url(),
        }
    }

    /// Stops accepting and aborts every live session before returning. Called
    /// on any transition away from `CONNECTED` (SPEC.md §5.6 L6).
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        for acceptor in std::mem::take(&mut self.acceptors) {
            let _ = acceptor.await;
        }
        info!("proxy listener stopped");
    }

    fn socks5h_url(&self) -> Secret {
        let addr = self
            .listen_addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| self.listen_addrs.first())
            .copied()
            .unwrap_or_else(|| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_PROXY_PORT)
            });
        match &self.config.auth {
            AuthSetting::Required(credentials) => credentials.socks5h_url(addr),
            AuthSetting::Disabled => socks5h_url_without_auth(addr),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Fail closed: a dropped handle must not leave an orphan listener with
        // no way to stop it.
        let _ = self.shutdown.send(true);
    }
}

/// The crate's only `TcpListener::bind`, taking an already-resolved
/// `SocketAddr`. tokio's own sealed `ToSocketAddrs` hands a `&str` host to
/// `getaddrinfo` on a blocking pool, which is a name resolution outside the
/// tunnel (SPEC.md §5.4 D3); `clippy.toml` bans the constructor everywhere so
/// that this is the only place the argument type can be checked by eye.
#[allow(clippy::disallowed_methods)]
pub(crate) async fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// What [`bind_all`] managed to bind, and what it had to give up on.
struct BindOutcome {
    listeners: Vec<TcpListener>,
    skipped: Vec<SocketAddr>,
}

/// The shipping default is the loopback pair `127.0.0.1` and `[::1]`
/// (SPEC.md §5.6 L1), and a host with IPv6 switched off cannot bind the second
/// one. Losing the working v4 listener over that would take the product's only
/// feature with it, so a loopback bind failure is skipped rather than fatal.
/// A non-loopback failure is a real refusal and still fails the call, and so
/// does failing to bind anything at all.
async fn bind_all(addrs: &[SocketAddr]) -> Result<BindOutcome, ListenerError> {
    let mut listeners = Vec::with_capacity(addrs.len());
    let mut skipped = Vec::new();
    let mut first_failure = None;

    for addr in addrs {
        match bind_tcp(*addr).await {
            Ok(listener) => listeners.push(listener),
            Err(source) if addr.ip().is_loopback() => {
                warn!(%addr, error = %source, "cannot bind loopback address, skipping it");
                skipped.push(*addr);
                first_failure.get_or_insert(ListenerError::Bind {
                    addr: *addr,
                    source,
                });
            }
            Err(source) => {
                return Err(ListenerError::Bind {
                    addr: *addr,
                    source,
                })
            }
        }
    }

    match first_failure {
        Some(failure) if listeners.is_empty() => Err(failure),
        _ => Ok(BindOutcome { listeners, skipped }),
    }
}

/// Binds the configured addresses and starts accepting.
///
/// A non-loopback bind failure fails the whole call and closes the listeners
/// already bound: a half-open proxy on a routable address is worse than none.
/// See [`bind_all`] for why loopback is treated differently.
pub async fn start<D>(config: ListenerConfig, dialer: Arc<D>) -> Result<Handle, ListenerError>
where
    D: Dialer + Send + Sync + 'static,
    D::Stream: Send + 'static,
{
    config.validate()?;

    let BindOutcome { listeners, skipped } = bind_all(&config.bind_addrs).await?;

    let listen_addrs = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .collect::<Vec<_>>();

    let stats = StatsCollector::new(config.tunnel_has_v6);
    let config = Arc::new(config);
    let runtime = Arc::new(session::Runtime {
        socks5: Socks5Config {
            auth: config.auth.policy(),
            tunnel_has_v6: config.tunnel_has_v6,
            handshake_timeout: config.handshake_timeout,
        },
        http: HttpConfig {
            auth: config.auth.policy(),
            tunnel_has_v6: config.tunnel_has_v6,
            handshake_timeout: config.handshake_timeout,
        },
        limiter: AuthRateLimiter::new(),
        allowed_cidrs: config.allowed_cidrs.clone(),
        stats: Arc::clone(&stats),
        dialer,
    });

    let (shutdown, _) = watch::channel(false);
    let acceptors = listeners
        .into_iter()
        .map(|listener| {
            let runtime = Arc::clone(&runtime);
            let signal = shutdown.subscribe();
            tokio::spawn(session::accept_loop(listener, runtime, signal))
        })
        .collect();

    info!(
        addrs = ?listen_addrs,
        skipped = ?skipped,
        authenticated = config.auth.is_required(),
        "proxy listener started"
    );

    Ok(Handle {
        listen_addrs,
        skipped_addrs: skipped,
        config,
        stats,
        shutdown,
        acceptors,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::listener::session::tests::{connect_to, StubDialer};

    fn loopback_v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn routable() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)), 1080)
    }

    #[test]
    fn non_loopback_bind_without_auth_is_refused() {
        // Arrange
        let config = ListenerConfig::new(vec![routable()], AuthSetting::Disabled, false);

        // Act
        let result = config.validate();

        // Assert
        assert!(matches!(
            result,
            Err(ListenerError::NonLoopbackWithoutAuth(addr)) if addr == routable()
        ));
    }

    #[test]
    fn non_loopback_bind_with_auth_is_permitted() {
        // Arrange
        let config = ListenerConfig::new(
            vec![routable()],
            AuthSetting::Required(ProxyCredentials::generate()),
            false,
        );

        // Act / Assert
        assert!(config.validate().is_ok());
    }

    #[test]
    fn loopback_bind_without_auth_is_permitted_because_the_user_asked_for_it() {
        // Arrange
        let config = ListenerConfig::new(vec![loopback_v4()], AuthSetting::Disabled, false);

        // Act / Assert
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_mixed_bind_list_is_refused_on_its_routable_member() {
        // Arrange
        let config = ListenerConfig::new(
            vec![loopback_v4(), routable()],
            AuthSetting::Disabled,
            false,
        );

        // Act / Assert
        assert!(matches!(
            config.validate(),
            Err(ListenerError::NonLoopbackWithoutAuth(_))
        ));
    }

    #[test]
    fn an_empty_bind_list_is_refused() {
        // Arrange
        let config = ListenerConfig::new(Vec::new(), AuthSetting::Disabled, false);

        // Act / Assert
        assert!(matches!(
            config.validate(),
            Err(ListenerError::NoBindAddress)
        ));
    }

    #[test]
    fn the_default_bind_is_loopback_on_port_1080() {
        // Arrange / Act
        let addrs = default_bind_addrs();

        // Assert
        assert!(addrs.iter().all(|addr| addr.ip().is_loopback()));
        assert!(addrs.iter().all(|addr| addr.port() == DEFAULT_PROXY_PORT));
        assert_eq!(addrs.len(), 2);
    }

    #[tokio::test]
    async fn proxy_info_reports_the_bound_port_and_a_socks5h_url() {
        // Arrange
        let credentials = ProxyCredentials::generate();
        let expected_user = credentials.username().to_string();
        let config = ListenerConfig::new(
            vec![loopback_v4()],
            AuthSetting::Required(credentials),
            false,
        );

        // Act
        let handle = match start(config, Arc::new(StubDialer::default())).await {
            Ok(handle) => handle,
            Err(err) => panic!("listener should start: {err}"),
        };
        let info = handle.proxy_info();

        // Assert
        assert!(info.is_loopback_only);
        assert_ne!(info.listen_addrs[0].port(), 0);
        let url = info.socks5h_url.expose();
        assert!(url.starts_with(&format!("socks5h://{expected_user}:")));
        assert!(url.ends_with(&format!("@{}", info.listen_addrs[0])));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn start_refuses_a_non_loopback_bind_without_auth_before_binding() {
        // Arrange
        let config = ListenerConfig::new(vec![routable()], AuthSetting::Disabled, false);

        // Act
        let result = start(config, Arc::new(StubDialer::default())).await;

        // Assert — a bind failure would prove the check ran too late.
        assert!(matches!(
            result,
            Err(ListenerError::NonLoopbackWithoutAuth(_))
        ));
    }

    /// Occupies a loopback port so that a second bind of it fails.
    async fn occupied_loopback() -> (TcpListener, SocketAddr) {
        let listener = match bind_tcp(loopback_v4()).await {
            Ok(listener) => listener,
            Err(err) => panic!("bind should succeed: {err}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => panic!("local_addr should succeed: {err}"),
        };
        (listener, addr)
    }

    #[tokio::test]
    async fn a_loopback_bind_failure_does_not_take_down_the_addresses_that_did_bind() {
        // Arrange — stands in for [::1] on a host with IPv6 disabled.
        let (_held, taken) = occupied_loopback().await;
        let config = ListenerConfig::new(vec![taken, loopback_v4()], AuthSetting::Disabled, false);

        // Act
        let handle = match start(config, Arc::new(StubDialer::default())).await {
            Ok(handle) => handle,
            Err(err) => panic!("the working loopback address should still serve: {err}"),
        };

        // Assert
        assert_eq!(handle.listen_addrs().len(), 1);
        assert_eq!(handle.skipped_bind_addrs(), &[taken]);
        assert!(connect_to(handle.listen_addrs()[0]).await.is_ok());
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn a_listener_that_bound_nothing_at_all_is_an_error() {
        // Arrange
        let (_held, taken) = occupied_loopback().await;
        let config = ListenerConfig::new(vec![taken], AuthSetting::Disabled, false);

        // Act
        let result = start(config, Arc::new(StubDialer::default())).await;

        // Assert
        assert!(matches!(
            result,
            Err(ListenerError::Bind { addr, .. }) if addr == taken
        ));
    }

    #[tokio::test]
    async fn a_routable_bind_failure_stays_fatal() {
        // Arrange — a routable address is an explicit exposure request, so
        // failing to bind it must not be downgraded to a skip.
        let config = ListenerConfig::new(
            vec![loopback_v4(), routable()],
            AuthSetting::Required(ProxyCredentials::generate()),
            false,
        );

        // Act
        let result = start(config, Arc::new(StubDialer::default())).await;

        // Assert
        assert!(matches!(
            result,
            Err(ListenerError::Bind { addr, .. }) if addr == routable()
        ));
    }

    /// SPEC.md §5.4 D3 says the ban on system name resolution is enforced by a
    /// lint, not by convention. tokio's `&str` socket impls call `getaddrinfo`
    /// from inside tokio, where the ban on `std::net::ToSocketAddrs` cannot
    /// reach them, so the constructors that accept a `&str` must be banned by
    /// name. Deleting one of these entries silently reopens the leak.
    #[test]
    fn clippy_bans_every_socket_constructor_that_can_resolve_a_hostname() {
        // Arrange
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("clippy.toml");
        let config = std::fs::read_to_string(&path).expect("clippy.toml should be readable");

        // Act / Assert
        for banned in [
            "std::net::ToSocketAddrs::to_socket_addrs",
            "tokio::net::lookup_host",
            "tokio::net::TcpStream::connect",
            "tokio::net::TcpListener::bind",
            "tokio::net::UdpSocket::bind",
            "tokio::net::UdpSocket::connect",
            "tokio::net::UdpSocket::send_to",
            "std::net::TcpStream::connect",
            "std::net::UdpSocket::bind",
        ] {
            assert!(
                config.contains(&format!("path = \"{banned}\"")),
                "clippy.toml no longer bans {banned}"
            );
        }
    }

    /// The lint is the guarantee, but it only fires on paths clippy resolves.
    /// This asserts the stronger property for the module: no source file here
    /// hands a string to a socket constructor at all, so there is nothing for
    /// a future reader to copy.
    #[test]
    fn the_listener_module_never_passes_a_string_address_to_a_socket_call() {
        // Arrange
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let files = [
            src.join("listener.rs"),
            src.join("listener").join("session.rs"),
            src.join("listener").join("cidr.rs"),
        ];

        // Act / Assert
        for file in files {
            let body = std::fs::read_to_string(&file)
                .unwrap_or_else(|err| panic!("{} should be readable: {err}", file.display()));
            for call in ["::bind(\"", "::connect(\"", "::send_to(\""] {
                assert!(
                    !body.contains(call),
                    "{} passes a string address to {call}",
                    file.display()
                );
            }
        }
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_new_connections() {
        // Arrange
        let config = ListenerConfig::new(vec![loopback_v4()], AuthSetting::Disabled, false);
        let handle = match start(config, Arc::new(StubDialer::default())).await {
            Ok(handle) => handle,
            Err(err) => panic!("listener should start: {err}"),
        };
        let addr = handle.listen_addrs()[0];

        // Act
        handle.shutdown().await;

        // Assert
        assert!(connect_to(addr).await.is_err());
    }
}
