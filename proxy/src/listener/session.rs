// SPDX-License-Identifier: GPL-3.0-or-later

//! Accept loop, first-byte protocol dispatch, and session accounting.
//!
//! The first byte is *peeked*, never consumed: both front ends parse their own
//! version byte, so consuming it here would corrupt every handshake.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::cidr::{is_peer_allowed, Cidr};
use crate::http::{self, HttpConfig, HttpError};
use crate::socks5::{self, AuthRateLimiter, Dialer, Socks5Config, Socks5Error};
use crate::stats::StatsCollector;

/// Keeps an accept loop from spinning on a persistent error such as `EMFILE`.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Everything a session needs, shared by every acceptor.
#[derive(Debug)]
pub(crate) struct Runtime<D> {
    pub(crate) socks5: Socks5Config,
    pub(crate) http: HttpConfig,
    /// One limiter for both front ends: a prober must not get a fresh budget by
    /// switching protocol (SPEC.md §5.6 L5).
    pub(crate) limiter: AuthRateLimiter,
    pub(crate) allowed_cidrs: Vec<Cidr>,
    pub(crate) stats: Arc<StatsCollector>,
    pub(crate) dialer: Arc<D>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    Socks5,
    Http,
    /// SOCKS4 has no domain-name form worth supporting and no auth; it is
    /// refused rather than translated.
    Socks4,
    Unsupported(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("could not read the protocol byte: {0}")]
    Peek(#[source] io::Error),
    #[error("client sent no protocol byte")]
    Empty,
    #[error("client sent no protocol byte within the handshake timeout")]
    DispatchTimeout,
    #[error("socks4 is not supported")]
    Socks4,
    #[error("unrecognised protocol byte {0:#04x}")]
    Unsupported(u8),
    #[error(transparent)]
    Socks5(#[from] Socks5Error),
    #[error(transparent)]
    Http(#[from] HttpError),
}

pub(crate) async fn accept_loop<D>(
    listener: TcpListener,
    runtime: Arc<Runtime<D>>,
    mut shutdown: watch::Receiver<bool>,
) where
    D: Dialer + Send + Sync + 'static,
    D::Stream: Send + 'static,
{
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            // A dropped sender is also a shutdown: the handle is gone.
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    while sessions.try_join_next().is_some() {}
                    admit(stream, peer.ip(), &runtime, &mut sessions);
                }
                Err(err) => {
                    warn!(error = %err, "proxy listener accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
        }
    }
    // SPEC.md §5.6 L6. Sockets pinned to a tun address that has gone away block
    // for ~15 minutes instead of failing, so the sessions are aborted, not
    // waited for.
    sessions.shutdown().await;
}

/// Admission control, applied before any protocol byte is read. Returns whether
/// the connection was accepted.
pub(crate) fn admit<D>(
    stream: TcpStream,
    peer: IpAddr,
    runtime: &Arc<Runtime<D>>,
    sessions: &mut JoinSet<()>,
) -> bool
where
    D: Dialer + Send + Sync + 'static,
    D::Stream: Send + 'static,
{
    if !is_peer_allowed(peer, &runtime.allowed_cidrs) {
        // Dropped without a greeting: an unlisted peer learns nothing about
        // which protocols this port speaks (SPEC.md §5.6 L3).
        warn!("refused a proxy connection from a peer outside allowed_cidrs");
        drop(stream);
        return false;
    }
    if runtime.stats.record_remote_peer(peer) {
        info!(
            distinct_remote_peers = runtime.stats.distinct_remote_peers(),
            "a new remote peer used the proxy"
        );
    }

    let runtime = Arc::clone(runtime);
    sessions.spawn(async move {
        let _session = runtime.stats.session_started();
        if let Err(err) = serve(stream, peer, &runtime).await {
            // Never above debug: a failure message can carry the authority the
            // client asked for.
            debug!(error = %err, "proxy session ended in error");
        }
    });
    true
}

async fn serve<D>(
    mut stream: TcpStream,
    peer: IpAddr,
    runtime: &Runtime<D>,
) -> Result<(), SessionError>
where
    D: Dialer,
{
    let first = peek_first_byte(&stream, runtime.socks5.handshake_timeout).await?;
    let outcome = match classify(first) {
        Protocol::Socks5 => socks5::serve(
            &mut stream,
            peer,
            &runtime.socks5,
            &runtime.limiter,
            &*runtime.dialer,
        )
        .await
        .map_err(SessionError::from),
        Protocol::Http => http::serve(
            &mut stream,
            peer,
            &runtime.http,
            &runtime.limiter,
            &*runtime.dialer,
        )
        .await
        .map_err(SessionError::from),
        Protocol::Socks4 => Err(SessionError::Socks4),
        Protocol::Unsupported(byte) => Err(SessionError::Unsupported(byte)),
    };

    match outcome {
        Ok((to_tunnel, from_tunnel)) => {
            runtime.stats.record_bytes(to_tunnel, from_tunnel);
            Ok(())
        }
        Err(err) => {
            if is_auth_failure(&err) {
                runtime.stats.record_auth_failure();
                warn!("proxy authentication failed");
            }
            Err(err)
        }
    }
}

/// Reads the dispatch byte without consuming it: `socks5::handshake` and
/// `http::handshake` both expect to see it themselves.
async fn peek_first_byte(stream: &TcpStream, timeout: Duration) -> Result<u8, SessionError> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(timeout, stream.peek(&mut first)).await {
        Ok(Ok(0)) => Err(SessionError::Empty),
        Ok(Ok(_)) => Ok(first[0]),
        Ok(Err(err)) => Err(SessionError::Peek(err)),
        Err(_elapsed) => Err(SessionError::DispatchTimeout),
    }
}

fn classify(first: u8) -> Protocol {
    match first {
        0x05 => Protocol::Socks5,
        0x04 => Protocol::Socks4,
        // Every HTTP method token starts with an ASCII uppercase letter, and no
        // SOCKS version byte is in that range.
        b'A'..=b'Z' => Protocol::Http,
        other => Protocol::Unsupported(other),
    }
}

fn is_auth_failure(err: &SessionError) -> bool {
    matches!(
        err,
        SessionError::Socks5(Socks5Error::AuthFailed | Socks5Error::AuthRateLimited)
            | SessionError::Http(HttpError::AuthFailed | HttpError::AuthRateLimited)
    )
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    use crate::listener::{start, AuthSetting, Handle, ListenerConfig};
    use crate::socks5::{AuthPolicy, DialError, Target};

    /// Records every target it was asked for and echoes whatever is written to
    /// it, so a caller can prove the session was relayed end to end.
    #[derive(Debug, Default)]
    pub(crate) struct StubDialer {
        targets: Mutex<Vec<Target>>,
        fail: Option<DialError>,
    }

    impl StubDialer {
        pub(crate) fn targets(&self) -> Vec<Target> {
            match self.targets.lock() {
                Ok(targets) => targets.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl Dialer for StubDialer {
        type Stream = DuplexStream;

        async fn tcp(&self, target: &Target) -> Result<Self::Stream, DialError> {
            match self.targets.lock() {
                Ok(mut targets) => targets.push(target.clone()),
                Err(poisoned) => poisoned.into_inner().push(target.clone()),
            }
            if let Some(err) = self.fail {
                return Err(err);
            }
            let (near, mut far) = duplex(4096);
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(read) = far.read(&mut buf).await {
                    if read == 0 || far.write_all(&buf[..read]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(near)
        }
    }

    /// A dispatch refusal must close the connection having written nothing.
    fn closed_without_reply(read: io::Result<usize>, response: &[u8]) -> bool {
        response.is_empty() && matches!(read, Ok(0) | Err(_))
    }

    /// The tests' only `TcpStream::connect`. `clippy.toml` bans the
    /// constructor because tokio resolves a `&str` host through
    /// `getaddrinfo`; taking a `SocketAddr` is what makes this call
    /// resolution-free, and the allow is scoped to that fact.
    #[allow(clippy::disallowed_methods)]
    pub(crate) async fn connect_to(addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }

    fn loopback_v4() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)
    }

    async fn started(dialer: Arc<StubDialer>) -> (Handle, SocketAddr) {
        let config = ListenerConfig::new(vec![loopback_v4()], AuthSetting::Disabled, false);
        let handle = match start(config, dialer).await {
            Ok(handle) => handle,
            Err(err) => panic!("listener should start: {err}"),
        };
        let bound = handle.listen_addrs()[0];
        (handle, bound)
    }

    fn test_runtime(allowed: Vec<Cidr>) -> Arc<Runtime<StubDialer>> {
        Arc::new(Runtime {
            socks5: Socks5Config::new(AuthPolicy::Disabled, false),
            http: HttpConfig::new(AuthPolicy::Disabled, false),
            limiter: AuthRateLimiter::new(),
            allowed_cidrs: allowed,
            stats: StatsCollector::new(false),
            dialer: Arc::new(StubDialer::default()),
        })
    }

    #[test]
    fn first_byte_selects_the_protocol() {
        // Arrange / Act / Assert
        assert_eq!(classify(0x05), Protocol::Socks5);
        assert_eq!(classify(0x04), Protocol::Socks4);
        assert_eq!(classify(b'C'), Protocol::Http);
        assert_eq!(classify(b'G'), Protocol::Http);
        assert_eq!(classify(b'c'), Protocol::Unsupported(b'c'));
        assert_eq!(classify(0x00), Protocol::Unsupported(0x00));
        assert_eq!(classify(0x16), Protocol::Unsupported(0x16));
    }

    #[tokio::test]
    async fn socks5_greeting_reaches_the_socks5_front_end_with_the_name_unresolved() {
        // Arrange
        let dialer = Arc::new(StubDialer::default());
        let (handle, addr) = started(Arc::clone(&dialer)).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };

        // Act — greeting, then CONNECT example.com:443 by name.
        let _ = client.write_all(&[0x05, 0x01, 0x00]).await;
        let mut greeting = [0u8; 2];
        let _ = client.read_exact(&mut greeting).await;
        let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        let _ = client.write_all(&request).await;
        let mut reply = [0u8; 10];
        let _ = client.read_exact(&mut reply).await;

        // Assert
        assert_eq!(greeting, [0x05, 0x00]);
        assert_eq!(reply[0..2], [0x05, 0x00]);
        assert_eq!(
            dialer.targets(),
            vec![Target::Domain {
                host: "example.com".to_string(),
                port: 443
            }]
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn an_ascii_method_reaches_the_http_front_end() {
        // Arrange
        let dialer = Arc::new(StubDialer::default());
        let (handle, addr) = started(Arc::clone(&dialer)).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };

        // Act
        let _ = client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await;
        let mut head = [0u8; 12];
        let _ = client.read_exact(&mut head).await;

        // Assert
        assert_eq!(&head, b"HTTP/1.1 200");
        assert_eq!(
            dialer.targets(),
            vec![Target::Domain {
                host: "example.com".to_string(),
                port: 443
            }]
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn socks4_is_closed_without_a_reply() {
        // Arrange
        let (handle, addr) = started(Arc::new(StubDialer::default())).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };

        // Act
        let _ = client.write_all(&[0x04, 0x01, 0x00, 0x50]).await;
        let mut response = Vec::new();
        let read = client.read_to_end(&mut response).await;

        // Assert — the connection ends with nothing written back. A reset is
        // as good as a clean EOF here: the unread request bytes make the peer
        // send RST on close.
        assert!(closed_without_reply(read, &response));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn an_unrecognised_first_byte_is_closed_without_a_reply() {
        // Arrange
        let (handle, addr) = started(Arc::new(StubDialer::default())).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };

        // Act — a TLS ClientHello aimed at the proxy port.
        let _ = client.write_all(&[0x16, 0x03, 0x01]).await;
        let mut response = Vec::new();
        let read = client.read_to_end(&mut response).await;

        // Assert — the connection ends with nothing written back. A reset is
        // as good as a clean EOF here: the unread request bytes make the peer
        // send RST on close.
        assert!(closed_without_reply(read, &response));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn a_peer_outside_allowed_cidrs_is_dropped_before_any_greeting() {
        // Arrange — a real connected pair, admitted under a forged remote peer.
        let listener = match crate::listener::bind_tcp(loopback_v4()).await {
            Ok(listener) => listener,
            Err(err) => panic!("bind should succeed: {err}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => panic!("local_addr should succeed: {err}"),
        };
        let client_side = tokio::spawn(async move { connect_to(addr).await });
        let (server_side, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => panic!("accept should succeed: {err}"),
        };
        let mut client = match client_side.await {
            Ok(Ok(client)) => client,
            _ => panic!("client should connect"),
        };
        let runtime = test_runtime(vec![]);
        let mut sessions = JoinSet::new();

        // Act
        let admitted = admit(
            server_side,
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
            &runtime,
            &mut sessions,
        );
        let mut response = Vec::new();
        let read = client.read_to_end(&mut response).await;

        // Assert
        assert!(!admitted);
        assert!(sessions.is_empty());
        assert!(matches!(read, Ok(0)));
        assert!(response.is_empty());
        assert_eq!(runtime.stats.snapshot().total_sessions, 0);
    }

    #[tokio::test]
    async fn a_listed_peer_is_admitted_and_counted_as_a_distinct_remote() {
        // Arrange
        let listener = match crate::listener::bind_tcp(loopback_v4()).await {
            Ok(listener) => listener,
            Err(err) => panic!("bind should succeed: {err}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(err) => panic!("local_addr should succeed: {err}"),
        };
        let client_side = tokio::spawn(async move { connect_to(addr).await });
        let (server_side, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => panic!("accept should succeed: {err}"),
        };
        let _client = client_side.await;
        let allowed = match "203.0.113.0/24".parse::<Cidr>() {
            Ok(cidr) => vec![cidr],
            Err(err) => panic!("cidr should parse: {err}"),
        };
        let runtime = test_runtime(allowed);
        let mut sessions = JoinSet::new();
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));

        // Act
        let admitted = admit(server_side, peer, &runtime, &mut sessions);

        // Assert
        assert!(admitted);
        assert_eq!(runtime.stats.distinct_remote_peers(), 1);
        tokio::task::yield_now().await;
        assert_eq!(runtime.stats.snapshot().total_sessions, 1);
        sessions.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_kills_a_live_session() {
        // Arrange — a session parked mid-relay.
        let dialer = Arc::new(StubDialer::default());
        let (handle, addr) = started(Arc::clone(&dialer)).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };
        let _ = client.write_all(&[0x05, 0x01, 0x00]).await;
        let mut greeting = [0u8; 2];
        let _ = client.read_exact(&mut greeting).await;
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&[198, 51, 100, 7]);
        request.extend_from_slice(&443u16.to_be_bytes());
        let _ = client.write_all(&request).await;
        let mut reply = [0u8; 10];
        let _ = client.read_exact(&mut reply).await;
        let live = handle.stats_snapshot().active_sessions;

        // Act
        handle.shutdown().await;
        let mut leftover = Vec::new();
        let read = client.read_to_end(&mut leftover).await;

        // Assert — the relay is gone, so the client sees the socket close.
        assert_eq!(live, 1);
        assert!(matches!(read, Ok(0)));
    }

    #[tokio::test]
    async fn relayed_bytes_are_counted_for_the_session() {
        // Arrange
        let dialer = Arc::new(StubDialer::default());
        let (handle, addr) = started(Arc::clone(&dialer)).await;
        let mut client = match connect_to(addr).await {
            Ok(client) => client,
            Err(err) => panic!("connect should succeed: {err}"),
        };
        let _ = client.write_all(&[0x05, 0x01, 0x00]).await;
        let mut greeting = [0u8; 2];
        let _ = client.read_exact(&mut greeting).await;
        let mut request = vec![0x05, 0x01, 0x00, 0x01];
        request.extend_from_slice(&[198, 51, 100, 7]);
        request.extend_from_slice(&443u16.to_be_bytes());
        let _ = client.write_all(&request).await;
        let mut reply = [0u8; 10];
        let _ = client.read_exact(&mut reply).await;

        // Act — write, read the echo back, then close so the relay finishes.
        let _ = client.write_all(b"hello").await;
        let mut echoed = [0u8; 5];
        let _ = client.read_exact(&mut echoed).await;
        drop(client);
        for _ in 0..50 {
            if handle.stats_snapshot().bytes_to_tunnel > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Assert
        let stats = handle.stats_snapshot();
        assert_eq!(&echoed, b"hello");
        assert_eq!(stats.bytes_to_tunnel, 5);
        assert_eq!(stats.bytes_from_tunnel, 5);
        assert_eq!(stats.local_dns_lookups, 0);
        handle.shutdown().await;
    }
}
