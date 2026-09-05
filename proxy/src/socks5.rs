// SPDX-License-Identifier: GPL-3.0-or-later

//! SOCKS5 server protocol (RFC 1928) with RFC 1929 username/password
//! sub-negotiation. See `docs/SPEC.md` §5.6.
//!
//! The handshake is deliberately hand-rolled: the one property that matters is
//! that a `DOMAINNAME` request never touches a local resolver, and a generic
//! SOCKS crate resolves before it dials. Hostnames are handed to the [`Dialer`]
//! verbatim; nothing in this file calls `to_socket_addrs` or `lookup_host`.
//!
//! The caller dispatches on the first byte of the connection (`0x05` → here)
//! and must *peek* rather than consume it: [`handshake`] reads the version byte
//! itself.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VER_SOCKS5: u8 = 0x05;
/// RFC 1929 sub-negotiation carries its *own* version, which is 0x01. Sending
/// 0x05 here is the classic SOCKS5 implementation bug.
const VER_USERPASS: u8 = 0x01;

const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xFF;

const AUTH_OK: u8 = 0x00;
const AUTH_DENIED: u8 = 0x01;

const CMD_CONNECT: u8 = 0x01;

const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

const MAX_DOMAIN_LEN: usize = 255;
const AUTH_FAILURE_BURST: f64 = 5.0;
const AUTH_FAILURE_WINDOW_SECS: f64 = 60.0;
/// Bounds the memory a hostile LAN can make the rate limiter hold.
const MAX_TRACKED_PEERS: usize = 4096;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Destination
// ---------------------------------------------------------------------------

/// A destination exactly as the client asked for it.
///
/// `Domain` is never resolved in this module — that is the whole point of the
/// leak-free path. The dialer resolves it through the tunnel-pinned resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain { port, .. } => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => write!(f, "{addr}"),
            Target::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Egress abstraction
// ---------------------------------------------------------------------------

/// Why an upstream connection could not be made, in the granularity SOCKS5
/// reply codes can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DialError {
    #[error("destination name has no address through the tunnel")]
    NameNotResolved,
    #[error("destination host unreachable")]
    HostUnreachable,
    #[error("destination network unreachable")]
    NetworkUnreachable,
    #[error("connection refused by destination")]
    ConnectionRefused,
    #[error("destination rejected by policy")]
    PolicyRejected,
    #[error("upstream connection failed")]
    Other,
}

impl DialError {
    fn reply_code(self) -> u8 {
        match self {
            // NXDOMAIN and the fail-closed `unreachable` floor route both land
            // here: SPEC.md §5.2 and §5.6.
            DialError::NameNotResolved | DialError::HostUnreachable => REP_HOST_UNREACHABLE,
            DialError::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
            DialError::ConnectionRefused => REP_CONNECTION_REFUSED,
            DialError::PolicyRejected => REP_NOT_ALLOWED,
            DialError::Other => REP_GENERAL_FAILURE,
        }
    }
}

impl From<io::Error> for DialError {
    fn from(err: io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::ConnectionRefused => DialError::ConnectionRefused,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::AddrNotAvailable => {
                DialError::NetworkUnreachable
            }
            io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => DialError::HostUnreachable,
            io::ErrorKind::PermissionDenied => DialError::PolicyRejected,
            _ => DialError::Other,
        }
    }
}

/// Opens tunnel-pinned outbound connections. `proxy::egress` implements this;
/// this module depends on the abstraction so it stays testable and so a
/// hostname can be passed through without ever being resolved here.
pub trait Dialer {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn tcp(
        &self,
        target: &Target,
    ) -> impl std::future::Future<Output = Result<Self::Stream, DialError>> + Send;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Proxy credentials. Compared in constant time, never logged, never displayed.
pub struct Credentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl Credentials {
    pub fn new(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Constant-time comparison (SPEC.md §5.6 L5). Returns a [`Choice`] rather
    /// than a `bool` so a branch cannot creep into the comparison itself.
    pub fn verify(&self, username: &[u8], password: &[u8]) -> Choice {
        self.username.ct_eq(username) & self.password.ct_eq(password)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(redacted)")
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        // Best effort without a `zeroize` dependency in this crate: overwrite,
        // then fence so the writes are not elided as dead stores.
        for byte in self.username.iter_mut().chain(self.password.iter_mut()) {
            *byte = 0;
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Authentication posture. Never both methods — offering `0x00` alongside
/// `0x02` lets any local UID skip auth entirely.
#[derive(Debug)]
pub enum AuthPolicy {
    Required(Credentials),
    /// Only when the user explicitly disabled authentication.
    Disabled,
}

#[derive(Debug)]
pub struct Socks5Config {
    pub auth: AuthPolicy,
    /// From `PUSH_REPLY`; gates `ATYP=0x04` (SPEC.md §5.5).
    pub tunnel_has_v6: bool,
    pub handshake_timeout: Duration,
}

impl Socks5Config {
    pub fn new(auth: AuthPolicy, tunnel_has_v6: bool) -> Self {
        Self {
            auth,
            tunnel_has_v6,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    fn offered_method(&self) -> u8 {
        match self.auth {
            AuthPolicy::Required(_) => METHOD_USERPASS,
            AuthPolicy::Disabled => METHOD_NONE,
        }
    }
}

// ---------------------------------------------------------------------------
// Auth failure rate limiting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl Bucket {
    fn full(now: Instant) -> Self {
        Self {
            tokens: AUTH_FAILURE_BURST,
            updated: now,
        }
    }

    fn refilled(&self, now: Instant) -> Self {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        let gained = elapsed * (AUTH_FAILURE_BURST / AUTH_FAILURE_WINDOW_SECS);
        Self {
            tokens: (self.tokens + gained).min(AUTH_FAILURE_BURST),
            updated: now,
        }
    }

    fn consumed(&self) -> Self {
        Self {
            tokens: (self.tokens - 1.0).max(0.0),
            updated: self.updated,
        }
    }
}

/// The tracked peer with the most tokens left, i.e. the one whose throttle
/// state is closest to meaningless.
fn most_refilled(buckets: &HashMap<IpAddr, Bucket>, now: Instant) -> Option<IpAddr> {
    buckets
        .iter()
        .max_by(|(_, a), (_, b)| {
            a.refilled(now)
                .tokens
                .partial_cmp(&b.refilled(now).tokens)
                // Token counts are finite by construction, so this arm is
                // unreachable; ordering them equal keeps eviction total.
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(peer, _)| *peer)
}

/// Token bucket over failed authentications, keyed on source IP: 5 per minute
/// (SPEC.md §5.6 L5).
#[derive(Debug, Default)]
pub struct AuthRateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_capacity(&self, peer: IpAddr) -> bool {
        self.has_capacity_at(peer, Instant::now())
    }

    pub fn record_failure(&self, peer: IpAddr) {
        self.record_failure_at(peer, Instant::now());
    }

    fn has_capacity_at(&self, peer: IpAddr, now: Instant) -> bool {
        let buckets = self.lock();
        match buckets.get(&peer) {
            Some(bucket) => bucket.refilled(now).tokens >= 1.0,
            None => true,
        }
    }

    fn record_failure_at(&self, peer: IpAddr, now: Instant) {
        let mut buckets = self.lock();
        let next = buckets
            .get(&peer)
            .map(|bucket| bucket.refilled(now))
            .unwrap_or_else(|| Bucket::full(now))
            .consumed();
        if buckets.len() >= MAX_TRACKED_PEERS && !buckets.contains_key(&peer) {
            // Idle peers have refilled to capacity and carry no information.
            buckets.retain(|_, bucket| bucket.refilled(now).tokens < AUTH_FAILURE_BURST);

            // Refilling alone is not a bound: a flood from more than
            // MAX_TRACKED_PEERS distinct sources inside one refill window leaves
            // every bucket partially drained, so the retain above evicts nothing
            // and the map grows without limit. Evict the peer closest to
            // refilled — the least-throttled, and so the least worth tracking —
            // until there is room. Keeping the most-drained peers means an
            // attacker cannot flush their own throttle by flooding from others.
            while buckets.len() >= MAX_TRACKED_PEERS {
                let Some(evict) = most_refilled(&buckets, now) else {
                    break;
                };
                buckets.remove(&evict);
            }
        }
        buckets.insert(peer, next);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, Bucket>> {
        // A poisoned lock only means some other task panicked; the counters are
        // still meaningful and refusing service here would be worse.
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("i/o error during socks5 handshake: {0}")]
    Io(#[from] io::Error),
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("unsupported socks version {0:#04x}")]
    BadVersion(u8),
    #[error("client offered no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("username/password sub-negotiation version {0:#04x}, expected 0x01")]
    BadAuthVersion(u8),
    #[error("authentication failed")]
    AuthFailed,
    #[error("authentication failures rate-limited for this source")]
    AuthRateLimited,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("invalid destination: {0}")]
    InvalidDestination(&'static str),
    #[error("command {0:#04x} not supported")]
    CommandNotSupported(u8),
    #[error("address type not supported by this tunnel")]
    AddressTypeNotSupported,
    #[error(transparent)]
    Dial(#[from] DialError),
}

impl Socks5Error {
    /// The REP byte to answer with, or `None` when the failure happened before
    /// a request reply is defined (the greeting and auth phases answer with
    /// their own protocol-specific bytes, and framing errors just close).
    fn reply_code(&self) -> Option<u8> {
        match self {
            Socks5Error::CommandNotSupported(_) => Some(REP_COMMAND_NOT_SUPPORTED),
            Socks5Error::AddressTypeNotSupported => Some(REP_ADDRESS_TYPE_NOT_SUPPORTED),
            Socks5Error::InvalidDestination(_) => Some(REP_GENERAL_FAILURE),
            Socks5Error::Dial(err) => Some(err.reply_code()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// A completed CONNECT: the upstream stream, plus the destination as asked for.
#[derive(Debug)]
pub struct Established<S> {
    pub target: Target,
    pub upstream: S,
}

/// Runs the full SOCKS5 handshake and opens the upstream connection.
///
/// Every reply the protocol defines for a failure is written before returning;
/// the caller only has to drop the client connection on `Err`.
pub async fn handshake<C, D>(
    client: &mut C,
    peer: IpAddr,
    config: &Socks5Config,
    limiter: &AuthRateLimiter,
    dialer: &D,
) -> Result<Established<D::Stream>, Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: Dialer,
{
    let target = match tokio::time::timeout(
        config.handshake_timeout,
        negotiate(client, peer, config, limiter),
    )
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => return Err(Socks5Error::HandshakeTimeout),
    };

    match dialer.tcp(&target).await {
        Ok(upstream) => {
            write_reply(client, REP_SUCCESS).await?;
            Ok(Established { target, upstream })
        }
        Err(err) => {
            write_reply(client, err.reply_code()).await?;
            Err(Socks5Error::Dial(err))
        }
    }
}

/// [`handshake`] plus a bidirectional relay, which is all a plain CONNECT
/// session ever needs.
pub async fn serve<C, D>(
    mut client: C,
    peer: IpAddr,
    config: &Socks5Config,
    limiter: &AuthRateLimiter,
    dialer: &D,
) -> Result<(u64, u64), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: Dialer,
{
    let mut session = handshake(&mut client, peer, config, limiter, dialer).await?;
    let copied = tokio::io::copy_bidirectional(&mut client, &mut session.upstream).await?;
    Ok(copied)
}

async fn negotiate<C>(
    client: &mut C,
    peer: IpAddr,
    config: &Socks5Config,
    limiter: &AuthRateLimiter,
) -> Result<Target, Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    greet(client, config).await?;
    if let AuthPolicy::Required(credentials) = &config.auth {
        authenticate(client, peer, credentials, limiter).await?;
    }
    match read_request(client, config).await {
        Ok(target) => Ok(target),
        Err(err) => {
            if let Some(rep) = err.reply_code() {
                write_reply(client, rep).await?;
            }
            Err(err)
        }
    }
}

async fn greet<C>(client: &mut C, config: &Socks5Config) -> Result<(), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VER_SOCKS5 {
        return Err(Socks5Error::BadVersion(head[0]));
    }
    let count = usize::from(head[1]);
    if count == 0 {
        return Err(Socks5Error::Malformed("empty method list"));
    }
    let mut methods = vec![0u8; count];
    client.read_exact(&mut methods).await?;

    let wanted = config.offered_method();
    if !methods.contains(&wanted) {
        client.write_all(&[VER_SOCKS5, METHOD_UNACCEPTABLE]).await?;
        client.flush().await?;
        return Err(Socks5Error::NoAcceptableMethod);
    }
    client.write_all(&[VER_SOCKS5, wanted]).await?;
    client.flush().await?;
    Ok(())
}

async fn authenticate<C>(
    client: &mut C,
    peer: IpAddr,
    credentials: &Credentials,
    limiter: &AuthRateLimiter,
) -> Result<(), Socks5Error>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0u8; 1];
    client.read_exact(&mut version).await?;
    if version[0] != VER_USERPASS {
        // We cannot speak a sub-negotiation version we do not know, so there is
        // no well-defined reply: close.
        return Err(Socks5Error::BadAuthVersion(version[0]));
    }
    let username = read_length_prefixed(client).await?;
    let password = read_length_prefixed(client).await?;

    if !limiter.has_capacity(peer) {
        tracing::warn!(%peer, "socks5 authentication rate-limited");
        deny_auth(client).await?;
        return Err(Socks5Error::AuthRateLimited);
    }

    if bool::from(credentials.verify(&username, &password)) {
        client.write_all(&[VER_USERPASS, AUTH_OK]).await?;
        client.flush().await?;
        return Ok(());
    }

    limiter.record_failure(peer);
    tracing::warn!(%peer, "socks5 authentication failed");
    deny_auth(client).await?;
    Err(Socks5Error::AuthFailed)
}

async fn deny_auth<C>(client: &mut C) -> Result<(), Socks5Error>
where
    C: AsyncWrite + Unpin,
{
    client.write_all(&[VER_USERPASS, AUTH_DENIED]).await?;
    client.flush().await?;
    Ok(())
}

async fn read_length_prefixed<C>(client: &mut C) -> Result<Vec<u8>, Socks5Error>
where
    C: AsyncRead + Unpin,
{
    let mut len = [0u8; 1];
    client.read_exact(&mut len).await?;
    let mut buf = vec![0u8; usize::from(len[0])];
    if !buf.is_empty() {
        client.read_exact(&mut buf).await?;
    }
    Ok(buf)
}

async fn read_request<C>(client: &mut C, config: &Socks5Config) -> Result<Target, Socks5Error>
where
    C: AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [version, command, reserved, atyp] = head;
    if version != VER_SOCKS5 {
        return Err(Socks5Error::BadVersion(version));
    }
    if reserved != 0x00 {
        return Err(Socks5Error::Malformed("RSV is not zero"));
    }

    // The address is consumed before the command is judged so the stream stays
    // framed and the more specific ATYP error wins.
    let target = read_target(client, atyp, config).await?;

    // BIND is refused permanently; UDP ASSOCIATE is v1.1 (SPEC.md §5.6) and is
    // refused the same way until the two-socket association lands.
    if command != CMD_CONNECT {
        return Err(Socks5Error::CommandNotSupported(command));
    }
    Ok(target)
}

async fn read_target<C>(
    client: &mut C,
    atyp: u8,
    config: &Socks5Config,
) -> Result<Target, Socks5Error>
where
    C: AsyncRead + Unpin,
{
    let address = match atyp {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let raw = read_length_prefixed(client).await?;
            let port = read_port(client).await?;
            return domain_target(&raw, port, config);
        }
        _ => return Err(Socks5Error::Malformed("unknown address type")),
    };
    let port = read_port(client).await?;
    finish_ip_target(address, port, config)
}

async fn read_port<C>(client: &mut C) -> Result<u16, Socks5Error>
where
    C: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

fn finish_ip_target(
    address: IpAddr,
    port: u16,
    config: &Socks5Config,
) -> Result<Target, Socks5Error> {
    if address.is_ipv6() && !config.tunnel_has_v6 {
        // A v4-only tunnel reaching a v6 destination is a hard failure, never
        // something to work around (SPEC.md §5.5).
        return Err(Socks5Error::AddressTypeNotSupported);
    }
    if port == 0 {
        return Err(Socks5Error::InvalidDestination("port 0"));
    }
    Ok(Target::Ip(SocketAddr::new(address, port)))
}

fn domain_target(raw: &[u8], port: u16, config: &Socks5Config) -> Result<Target, Socks5Error> {
    let host = validate_hostname(raw)?;
    // An IP literal in a DOMAINNAME field is an address, not a name: treating
    // it as one keeps it away from the resolver entirely.
    if let Ok(address) = host.parse::<IpAddr>() {
        return finish_ip_target(address, port, config);
    }
    if port == 0 {
        return Err(Socks5Error::InvalidDestination("port 0"));
    }
    Ok(Target::Domain {
        host: host.to_owned(),
        port,
    })
}

/// Rejects everything that is not printable ASCII: NUL, control bytes, spaces
/// and raw non-ASCII (an IDN must arrive already in A-label form).
fn validate_hostname(raw: &[u8]) -> Result<&str, Socks5Error> {
    if raw.is_empty() {
        return Err(Socks5Error::InvalidDestination("empty hostname"));
    }
    if raw.len() > MAX_DOMAIN_LEN {
        return Err(Socks5Error::InvalidDestination("hostname too long"));
    }
    if raw.contains(&0x00) {
        return Err(Socks5Error::InvalidDestination("NUL in hostname"));
    }
    if raw.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
        return Err(Socks5Error::InvalidDestination("non-printable hostname"));
    }
    std::str::from_utf8(raw).map_err(|_| Socks5Error::InvalidDestination("hostname is not UTF-8"))
}

/// `BND.ADDR` is always `0.0.0.0:0`: the tun IP must not be disclosed to a
/// possibly-LAN client (SPEC.md §5.6).
async fn write_reply<C>(client: &mut C, reply: u8) -> Result<(), Socks5Error>
where
    C: AsyncWrite + Unpin,
{
    let frame = [VER_SOCKS5, reply, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0];
    client.write_all(&frame).await?;
    client.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, DuplexStream, Join, ReadBuf};

    /// Feeds the parser one configured chunk per poll so a request split across
    /// packet boundaries is exercised deterministically.
    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().rev().collect(),
            }
        }
    }

    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.chunks.pop() {
                Some(chunk) => {
                    let take = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..take]);
                    if take < chunk.len() {
                        self.chunks.push(chunk[take..].to_vec());
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Ready(Ok(())),
            }
        }
    }

    type Client = Join<ChunkedReader, Vec<u8>>;

    fn client_from(chunks: Vec<Vec<u8>>) -> Client {
        tokio::io::join(ChunkedReader::new(chunks), Vec::new())
    }

    fn written(client: Client) -> Vec<u8> {
        client.into_inner().1
    }

    struct StubDialer {
        result: Result<(), DialError>,
    }

    impl StubDialer {
        fn ok() -> Self {
            Self { result: Ok(()) }
        }

        fn failing(err: DialError) -> Self {
            Self { result: Err(err) }
        }
    }

    impl Dialer for StubDialer {
        type Stream = DuplexStream;

        async fn tcp(&self, _target: &Target) -> Result<Self::Stream, DialError> {
            self.result.map(|_| duplex(8).0)
        }
    }

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn auth_config() -> Socks5Config {
        Socks5Config::new(
            AuthPolicy::Required(Credentials::new(b"user".to_vec(), b"pass".to_vec())),
            false,
        )
    }

    fn open_config() -> Socks5Config {
        Socks5Config::new(AuthPolicy::Disabled, false)
    }

    fn auth_frame(user: &[u8], pass: &[u8]) -> Vec<u8> {
        let mut frame = vec![VER_USERPASS, user.len() as u8];
        frame.extend_from_slice(user);
        frame.push(pass.len() as u8);
        frame.extend_from_slice(pass);
        frame
    }

    fn connect_v4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut frame = vec![VER_SOCKS5, CMD_CONNECT, 0x00, ATYP_V4];
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    fn connect_domain(host: &[u8], port: u16) -> Vec<u8> {
        let mut frame = vec![VER_SOCKS5, CMD_CONNECT, 0x00, ATYP_DOMAIN, host.len() as u8];
        frame.extend_from_slice(host);
        frame.extend_from_slice(&port.to_be_bytes());
        frame
    }

    async fn run(
        chunks: Vec<Vec<u8>>,
        config: &Socks5Config,
        dialer: &StubDialer,
    ) -> (Result<Target, Socks5Error>, Vec<u8>) {
        let limiter = AuthRateLimiter::new();
        run_with_limiter(chunks, config, dialer, &limiter).await
    }

    async fn run_with_limiter(
        chunks: Vec<Vec<u8>>,
        config: &Socks5Config,
        dialer: &StubDialer,
        limiter: &AuthRateLimiter,
    ) -> (Result<Target, Socks5Error>, Vec<u8>) {
        let mut client = client_from(chunks);
        let outcome = handshake(&mut client, peer(), config, limiter, dialer)
            .await
            .map(|session| session.target);
        (outcome, written(client))
    }

    #[tokio::test]
    async fn completes_full_authenticated_connect_handshake() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_USERPASS],
            auth_frame(b"user", b"pass"),
            connect_v4([93, 184, 216, 34], 443),
        ];

        // Act
        let (result, out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            result.ok(),
            Some(Target::Ip(SocketAddr::from(([93, 184, 216, 34], 443))))
        );
        assert_eq!(
            out,
            vec![
                VER_SOCKS5,
                METHOD_USERPASS,
                VER_USERPASS,
                AUTH_OK,
                VER_SOCKS5,
                REP_SUCCESS,
                0x00,
                ATYP_V4,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        );
    }

    #[tokio::test]
    async fn success_reply_never_discloses_the_tun_address() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_v4([10, 0, 0, 1], 80),
        ];

        // Act
        let (_result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            &out[2..],
            &[VER_SOCKS5, REP_SUCCESS, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn parses_a_request_split_across_packet_boundaries() {
        // Arrange: one byte per read, including inside the length prefixes.
        let mut stream = vec![VER_SOCKS5, 1, METHOD_NONE];
        stream.extend(connect_domain(b"example.com", 443));
        let chunks = stream.into_iter().map(|byte| vec![byte]).collect();

        // Act
        let (result, _out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            result.ok(),
            Some(Target::Domain {
                host: "example.com".to_owned(),
                port: 443
            })
        );
    }

    #[tokio::test]
    async fn passes_the_hostname_to_the_dialer_verbatim() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"news.example.co.uk", 8443),
        ];

        // Act
        let (result, _out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            result.ok(),
            Some(Target::Domain {
                host: "news.example.co.uk".to_owned(),
                port: 8443
            })
        );
    }

    #[tokio::test]
    async fn treats_an_ip_literal_in_a_domainname_field_as_an_address() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"198.51.100.7", 443),
        ];

        // Act
        let (result, _out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            result.ok(),
            Some(Target::Ip(SocketAddr::from(([198, 51, 100, 7], 443))))
        );
    }

    #[tokio::test]
    async fn offers_only_userpass_when_auth_is_on() {
        // Arrange: client offers NO-AUTH only.
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE]];

        // Act
        let (result, out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::NoAcceptableMethod)));
        assert_eq!(out, vec![VER_SOCKS5, METHOD_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn offers_only_no_auth_when_auth_is_explicitly_disabled() {
        // Arrange: client offers USER/PASS only.
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_USERPASS]];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::NoAcceptableMethod)));
        assert_eq!(out, vec![VER_SOCKS5, METHOD_UNACCEPTABLE]);
    }

    #[tokio::test]
    async fn rejects_a_non_socks5_greeting_version() {
        // Arrange
        let chunks = vec![vec![0x04, 1, METHOD_NONE]];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::BadVersion(0x04))));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn rejects_subnegotiation_version_five_instead_of_one() {
        // Arrange: the classic bug — RFC 1929 uses VER=0x01, not 0x05.
        let mut frame = auth_frame(b"user", b"pass");
        frame[0] = VER_SOCKS5;
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_USERPASS], frame];

        // Act
        let (result, out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::BadAuthVersion(0x05))));
        assert_eq!(out, vec![VER_SOCKS5, METHOD_USERPASS]);
    }

    #[tokio::test]
    async fn rejects_wrong_password_with_an_rfc1929_denial() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_USERPASS],
            auth_frame(b"user", b"wrong"),
            connect_v4([1, 1, 1, 1], 443),
        ];

        // Act
        let (result, out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::AuthFailed)));
        assert_eq!(
            out,
            vec![VER_SOCKS5, METHOD_USERPASS, VER_USERPASS, AUTH_DENIED]
        );
    }

    #[tokio::test]
    async fn rejects_wrong_username_with_the_right_password() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_USERPASS],
            auth_frame(b"root", b"pass"),
        ];

        // Act
        let (result, _out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::AuthFailed)));
    }

    #[test]
    fn credential_check_returns_a_constant_time_choice() {
        // Arrange
        let credentials = Credentials::new(b"user".to_vec(), b"password".to_vec());

        // Act
        let good: Choice = credentials.verify(b"user", b"password");
        let prefix: Choice = credentials.verify(b"user", b"pass");
        let long: Choice = credentials.verify(b"user", b"password-and-more");

        // Assert
        assert!(bool::from(good));
        assert!(!bool::from(prefix));
        assert!(!bool::from(long));
    }

    #[test]
    fn rate_limiter_allows_five_failures_per_minute_per_source() {
        // Arrange
        let limiter = AuthRateLimiter::new();
        let now = Instant::now();

        // Act
        for _ in 0..5 {
            assert!(limiter.has_capacity_at(peer(), now));
            limiter.record_failure_at(peer(), now);
        }

        // Assert
        assert!(!limiter.has_capacity_at(peer(), now));
        assert!(limiter.has_capacity_at(peer(), now + Duration::from_secs(13)));
    }

    #[test]
    fn rate_limiter_map_stays_bounded_under_a_distributed_flood() {
        // Arrange: every source fails once at the same instant, so no bucket
        // ever refills and the retain pass has nothing to evict.
        let limiter = AuthRateLimiter::new();
        let now = Instant::now();

        // Act: more distinct sources than the cap, which is the shape of a
        // botnet probing a non-loopback listener.
        for i in 0..(MAX_TRACKED_PEERS + 500) {
            let octets = ((i as u32) + 1).to_be_bytes();
            let source = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            limiter.record_failure_at(source, now);
        }

        // Assert: memory is bounded rather than growing with the attacker's
        // source count.
        assert!(limiter.lock().len() <= MAX_TRACKED_PEERS);
    }

    #[test]
    fn rate_limiter_evicting_under_pressure_keeps_the_most_throttled_peer() {
        // Arrange: one source is fully throttled, then a flood arrives.
        let limiter = AuthRateLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            limiter.record_failure_at(peer(), now);
        }
        assert!(!limiter.has_capacity_at(peer(), now));

        // Act
        for i in 0..(MAX_TRACKED_PEERS + 100) {
            let octets = ((i as u32) + 1).to_be_bytes();
            let source = IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            limiter.record_failure_at(source, now);
        }

        // Assert: an attacker cannot clear their own throttle by flooding from
        // other addresses.
        assert!(!limiter.has_capacity_at(peer(), now));
    }

    #[test]
    fn rate_limiter_keys_on_source_address() {
        // Arrange
        let limiter = AuthRateLimiter::new();
        let now = Instant::now();
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

        // Act
        for _ in 0..5 {
            limiter.record_failure_at(peer(), now);
        }

        // Assert
        assert!(!limiter.has_capacity_at(peer(), now));
        assert!(limiter.has_capacity_at(other, now));
    }

    #[tokio::test]
    async fn refuses_authentication_once_the_bucket_is_empty() {
        // Arrange
        let limiter = AuthRateLimiter::new();
        for _ in 0..5 {
            limiter.record_failure(peer());
        }
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_USERPASS],
            auth_frame(b"user", b"pass"),
        ];

        // Act
        let (result, out) =
            run_with_limiter(chunks, &auth_config(), &StubDialer::ok(), &limiter).await;

        // Assert: even correct credentials are refused while rate-limited.
        assert!(matches!(result, Err(Socks5Error::AuthRateLimited)));
        assert_eq!(
            out,
            vec![VER_SOCKS5, METHOD_USERPASS, VER_USERPASS, AUTH_DENIED]
        );
    }

    #[tokio::test]
    async fn rejects_bind_command_with_reply_seven() {
        // Arrange
        let mut request = connect_v4([1, 1, 1, 1], 443);
        request[1] = 0x02;
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], request];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(
            result,
            Err(Socks5Error::CommandNotSupported(0x02))
        ));
        assert_eq!(out[3], REP_COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn rejects_udp_associate_with_reply_seven_in_v1() {
        // Arrange
        let mut request = connect_v4([1, 1, 1, 1], 443);
        request[1] = 0x03;
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], request];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(
            result,
            Err(Socks5Error::CommandNotSupported(0x03))
        ));
        assert_eq!(out[3], REP_COMMAND_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn rejects_ipv6_destination_when_the_tunnel_is_v4_only() {
        // Arrange
        let mut request = vec![VER_SOCKS5, CMD_CONNECT, 0x00, ATYP_V6];
        request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&443u16.to_be_bytes());
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], request];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::AddressTypeNotSupported)));
        assert_eq!(out[3], REP_ADDRESS_TYPE_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn accepts_ipv6_destination_when_the_tunnel_has_v6() {
        // Arrange
        let config = Socks5Config::new(AuthPolicy::Disabled, true);
        let mut request = vec![VER_SOCKS5, CMD_CONNECT, 0x00, ATYP_V6];
        request.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        request.extend_from_slice(&443u16.to_be_bytes());
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], request];

        // Act
        let (result, _out) = run(chunks, &config, &StubDialer::ok()).await;

        // Assert
        assert_eq!(
            result.ok(),
            Some(Target::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443
            )))
        );
    }

    #[tokio::test]
    async fn rejects_ipv6_literal_in_domainname_when_the_tunnel_is_v4_only() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"2001:db8::1", 443),
        ];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::AddressTypeNotSupported)));
        assert_eq!(out[3], REP_ADDRESS_TYPE_NOT_SUPPORTED);
    }

    #[tokio::test]
    async fn rejects_domainname_containing_a_nul_byte() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"exam\0ple.com", 443),
        ];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
        assert_eq!(out[3], REP_GENERAL_FAILURE);
    }

    #[tokio::test]
    async fn rejects_domainname_containing_a_control_byte() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"exam\x0dple.com", 443),
        ];

        // Act
        let (result, _out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
    }

    #[tokio::test]
    async fn rejects_empty_domainname() {
        // Arrange
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], connect_domain(b"", 443)];

        // Act
        let (result, _out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
    }

    #[test]
    fn rejects_hostname_longer_than_255_bytes() {
        // Arrange
        let raw = vec![b'a'; 256];

        // Act
        let result = validate_hostname(&raw);

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
    }

    #[test]
    fn accepts_hostname_of_exactly_255_bytes() {
        // Arrange
        let raw = vec![b'a'; MAX_DOMAIN_LEN];

        // Act
        let result = validate_hostname(&raw);

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_raw_non_ascii_hostname() {
        // Arrange: an IDN must arrive as an A-label.
        let raw = "münchen.example".as_bytes();

        // Act
        let result = validate_hostname(raw);

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
    }

    #[tokio::test]
    async fn rejects_request_with_non_zero_reserved_byte() {
        // Arrange
        let mut request = connect_v4([1, 1, 1, 1], 443);
        request[2] = 0x01;
        let chunks = vec![vec![VER_SOCKS5, 1, METHOD_NONE], request];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::Malformed(_))));
        assert_eq!(out, vec![VER_SOCKS5, METHOD_NONE]);
    }

    #[tokio::test]
    async fn rejects_destination_port_zero() {
        // Arrange
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_v4([1, 1, 1, 1], 0),
        ];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::InvalidDestination(_))));
        assert_eq!(out[3], REP_GENERAL_FAILURE);
    }

    #[tokio::test]
    async fn rejects_greeting_with_an_empty_method_list() {
        // Arrange
        let chunks = vec![vec![VER_SOCKS5, 0]];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::Malformed(_))));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn times_out_a_silent_client() {
        // Arrange
        let mut config = open_config();
        config.handshake_timeout = Duration::from_millis(20);
        // A live but silent peer: the far half is held open so reads pend.
        let (mut client, _held_open) = duplex(8);
        let limiter = AuthRateLimiter::new();

        // Act
        let result = handshake(&mut client, peer(), &config, &limiter, &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::HandshakeTimeout)));
    }

    async fn dial_failure_reply(err: DialError) -> u8 {
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            connect_domain(b"example.com", 443),
        ];
        let (_result, out) = run(chunks, &open_config(), &StubDialer::failing(err)).await;
        out[3]
    }

    #[tokio::test]
    async fn maps_resolve_failure_to_reply_four() {
        assert_eq!(dial_failure_reply(DialError::NameNotResolved).await, 0x04);
    }

    #[tokio::test]
    async fn maps_host_unreachable_to_reply_four() {
        assert_eq!(dial_failure_reply(DialError::HostUnreachable).await, 0x04);
    }

    #[tokio::test]
    async fn maps_connection_refused_to_reply_five() {
        assert_eq!(dial_failure_reply(DialError::ConnectionRefused).await, 0x05);
    }

    #[tokio::test]
    async fn maps_network_unreachable_to_reply_three() {
        assert_eq!(
            dial_failure_reply(DialError::NetworkUnreachable).await,
            0x03
        );
    }

    #[tokio::test]
    async fn maps_policy_rejection_to_reply_two() {
        assert_eq!(dial_failure_reply(DialError::PolicyRejected).await, 0x02);
    }

    #[tokio::test]
    async fn maps_unclassified_failure_to_reply_one() {
        assert_eq!(dial_failure_reply(DialError::Other).await, 0x01);
    }

    #[test]
    fn maps_io_error_kinds_to_dial_errors() {
        // Arrange / Act / Assert
        assert_eq!(
            DialError::from(io::Error::from(io::ErrorKind::ConnectionRefused)),
            DialError::ConnectionRefused
        );
        assert_eq!(
            DialError::from(io::Error::from(io::ErrorKind::NetworkUnreachable)),
            DialError::NetworkUnreachable
        );
        assert_eq!(
            DialError::from(io::Error::from(io::ErrorKind::HostUnreachable)),
            DialError::HostUnreachable
        );
        assert_eq!(
            DialError::from(io::Error::from(io::ErrorKind::PermissionDenied)),
            DialError::PolicyRejected
        );
        assert_eq!(
            DialError::from(io::Error::from(io::ErrorKind::BrokenPipe)),
            DialError::Other
        );
    }

    #[test]
    fn credentials_debug_never_exposes_the_secret() {
        // Arrange
        let credentials = Credentials::new(b"user".to_vec(), b"hunter2".to_vec());

        // Act
        let rendered = format!("{credentials:?}");

        // Assert
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("user"));
    }

    #[tokio::test]
    async fn truncated_request_closes_without_a_reply() {
        // Arrange: header promises an IPv4 address and port, stream ends early.
        let chunks = vec![
            vec![VER_SOCKS5, 1, METHOD_NONE],
            vec![VER_SOCKS5, CMD_CONNECT, 0x00, ATYP_V4, 1, 1],
        ];

        // Act
        let (result, out) = run(chunks, &open_config(), &StubDialer::ok()).await;

        // Assert
        assert!(matches!(result, Err(Socks5Error::Io(_))));
        assert_eq!(out, vec![VER_SOCKS5, METHOD_NONE]);
    }
}
