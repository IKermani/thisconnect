// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTP proxy front end: `CONNECT` tunnelling only. See `docs/SPEC.md` §5.6.
//!
//! Hand-rolled for the same reason [`crate::socks5`] is: the one property that
//! matters is that the authority the client asked for is handed to the
//! [`Dialer`] verbatim. A general-purpose HTTP client library resolves before it
//! dials, and that resolution is the leak. Nothing in this file calls
//! `to_socket_addrs` or `lookup_host`.
//!
//! Deliberate privacy deviation from RFC 9110's SHOULD: this proxy emits no
//! `Via`, no `X-Forwarded-For` and no `Server`/`Proxy-Agent` header. Those
//! headers exist to make an intermediary attributable, which is precisely the
//! property a leak-free VPN proxy must not add.
//!
//! The caller dispatches on the first byte of the connection (ASCII uppercase →
//! here) and must *peek* rather than consume it: [`handshake`] parses the whole
//! request line itself.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::socks5::{AuthPolicy, AuthRateLimiter, DialError, Dialer, Target};

/// The whole request head, terminated by CRLFCRLF. A client that never sends
/// the terminator hits [`HttpConfig::handshake_timeout`]; one that sends more
/// than this without it gets 431 and is closed.
const MAX_HEAD_BYTES: usize = 8192;
/// A CONNECT authority is at most 255 + `:65535`; anything near this is abuse.
const MAX_REQUEST_LINE: usize = 1024;
const MAX_HEADER_COUNT: usize = 64;
const READ_CHUNK: usize = 1024;
const MAX_HOST_LEN: usize = 255;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The upstream connect gets its own bound. Left to the OS, a SYN to a
/// black-holed destination is retried for roughly a quarter of an hour, and for
/// all of it the task, the client socket and the tunnel-pinned source port stay
/// held by a client that only had to name an unreachable host.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

const CHALLENGE: &str = "Proxy-Authenticate: Basic realm=\"thisconnect\", charset=\"UTF-8\"";

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

/// A status line, as `(code, reason)`. Kept as a pair rather than an enum so
/// the wire form has exactly one definition.
type Status = (u16, &'static str);

const ST_BAD_REQUEST: Status = (400, "Bad Request");
const ST_FORBIDDEN: Status = (403, "Forbidden");
const ST_PROXY_AUTH_REQUIRED: Status = (407, "Proxy Authentication Required");
const ST_REQUEST_TIMEOUT: Status = (408, "Request Timeout");
const ST_HEAD_TOO_LARGE: Status = (431, "Request Header Fields Too Large");
const ST_NOT_IMPLEMENTED: Status = (501, "Not Implemented");
const ST_BAD_GATEWAY: Status = (502, "Bad Gateway");
const ST_UNAVAILABLE: Status = (503, "Service Unavailable");
const ST_GATEWAY_TIMEOUT: Status = (504, "Gateway Timeout");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Mirrors `Socks5Config`; the two front ends share a listener and must not
/// disagree about auth or about IPv6 availability.
#[derive(Debug)]
pub struct HttpConfig {
    pub auth: AuthPolicy,
    /// From `PUSH_REPLY`; gates IPv6 literal destinations (SPEC.md §5.5).
    pub tunnel_has_v6: bool,
    pub handshake_timeout: Duration,
    /// Bounds the upstream connect, which the handshake timeout does not cover:
    /// negotiation is finished by the time we dial.
    pub connect_timeout: Duration,
}

impl HttpConfig {
    pub fn new(auth: AuthPolicy, tunnel_has_v6: bool) -> Self {
        Self {
            auth,
            tunnel_has_v6,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("i/o error during http proxy handshake: {0}")]
    Io(#[from] io::Error),
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("request head exceeds the {MAX_HEAD_BYTES} byte cap")]
    HeadTooLarge,
    #[error("request carries more than {MAX_HEADER_COUNT} headers")]
    TooManyHeaders,
    #[error("method {0:?} is not supported by this proxy")]
    MethodNotSupported(String),
    #[error("absolute-form proxying is not implemented")]
    AbsoluteFormUnsupported,
    #[error("invalid destination: {0}")]
    InvalidDestination(&'static str),
    #[error("proxy authentication required")]
    AuthRequired,
    #[error("proxy authentication failed")]
    AuthFailed,
    #[error("authentication failures rate-limited for this source")]
    AuthRateLimited,
    #[error("tunnel has no IPv6 address; refusing an IPv6 destination")]
    Ipv6Unsupported,
    #[error("upstream connection timed out")]
    DialTimeout,
    #[error(transparent)]
    Dial(#[from] DialError),
}

impl HttpError {
    /// The status to answer with, or `None` when the connection is already gone
    /// and there is nothing to write to.
    fn status(&self) -> Option<Status> {
        match self {
            HttpError::Io(_) => None,
            HttpError::HandshakeTimeout => Some(ST_REQUEST_TIMEOUT),
            HttpError::Malformed(_) | HttpError::InvalidDestination(_) => Some(ST_BAD_REQUEST),
            HttpError::HeadTooLarge | HttpError::TooManyHeaders => Some(ST_HEAD_TOO_LARGE),
            HttpError::MethodNotSupported(_) | HttpError::AbsoluteFormUnsupported => {
                Some(ST_NOT_IMPLEMENTED)
            }
            // Rate limiting answers with the same status as a wrong password so
            // a prober cannot distinguish "throttled" from "wrong".
            HttpError::AuthRequired | HttpError::AuthFailed | HttpError::AuthRateLimited => {
                Some(ST_PROXY_AUTH_REQUIRED)
            }
            HttpError::Ipv6Unsupported => Some(ST_FORBIDDEN),
            HttpError::DialTimeout => Some(ST_GATEWAY_TIMEOUT),
            HttpError::Dial(err) => Some(dial_status(*err)),
        }
    }
}

/// The `Dialer` contract has no distinct "tunnel not published yet" variant; a
/// handle issued before the tunnel is up, or invalidated by a reconnect,
/// surfaces as `NetworkUnreachable`. 503 is the honest answer for both: the
/// proxy is up, the path is not.
fn dial_status(err: DialError) -> Status {
    match err {
        DialError::NetworkUnreachable => ST_UNAVAILABLE,
        DialError::PolicyRejected => ST_FORBIDDEN,
        DialError::NameNotResolved
        | DialError::HostUnreachable
        | DialError::ConnectionRefused
        | DialError::Other => ST_BAD_GATEWAY,
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// A completed CONNECT: the upstream stream, the destination as asked for, and
/// any bytes the client optimistically pipelined after the request head (a TLS
/// ClientHello, typically). Dropping `pending` would corrupt the session.
#[derive(Debug)]
pub struct Established<S> {
    pub target: Target,
    pub upstream: S,
    pub pending: Vec<u8>,
}

/// Parses the request, authenticates, and opens the upstream connection.
///
/// Every failure the protocol can express is written as a status response
/// before returning; the caller only has to drop the client connection on
/// `Err`.
pub async fn handshake<C, D>(
    client: &mut C,
    peer: IpAddr,
    config: &HttpConfig,
    limiter: &AuthRateLimiter,
    dialer: &D,
) -> Result<Established<D::Stream>, HttpError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: Dialer,
{
    let head = match tokio::time::timeout(
        config.handshake_timeout,
        negotiate(client, peer, config, limiter),
    )
    .await
    {
        Ok(result) => result?,
        Err(_elapsed) => {
            respond(client, ST_REQUEST_TIMEOUT, false).await?;
            return Err(HttpError::HandshakeTimeout);
        }
    };

    let upstream = match dial_upstream(dialer, &head.target, config.connect_timeout).await {
        Ok(upstream) => upstream,
        Err(err) => {
            if let Some(status) = err.status() {
                respond(client, status, false).await?;
            }
            return Err(err);
        }
    };

    // No headers on a 2xx to CONNECT: RFC 9110 forbids content framing here,
    // and every header we could add is an attribution leak.
    client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await?;
    client.flush().await?;
    Ok(Established {
        target: head.target,
        upstream,
        pending: head.pending,
    })
}

/// The dial needs its own deadline. [`HttpConfig::handshake_timeout`] has
/// already been satisfied by the time we get here, so without this a CONNECT to
/// an address that silently drops SYNs holds the task for as long as the OS
/// retries — minutes, not seconds.
async fn dial_upstream<D>(
    dialer: &D,
    target: &Target,
    limit: Duration,
) -> Result<D::Stream, HttpError>
where
    D: Dialer,
{
    match tokio::time::timeout(limit, dialer.tcp(target)).await {
        Ok(result) => result.map_err(HttpError::Dial),
        Err(_elapsed) => Err(HttpError::DialTimeout),
    }
}

/// [`handshake`] plus a bidirectional relay, which is all a CONNECT session
/// ever needs.
pub async fn serve<C, D>(
    mut client: C,
    peer: IpAddr,
    config: &HttpConfig,
    limiter: &AuthRateLimiter,
    dialer: &D,
) -> Result<(u64, u64), HttpError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    D: Dialer,
{
    let mut session = handshake(&mut client, peer, config, limiter, dialer).await?;
    let pipelined = session.pending.len() as u64;
    if !session.pending.is_empty() {
        session.upstream.write_all(&session.pending).await?;
    }
    let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut session.upstream).await?;
    Ok((up + pipelined, down))
}

struct Negotiated {
    target: Target,
    pending: Vec<u8>,
}

async fn negotiate<C>(
    client: &mut C,
    peer: IpAddr,
    config: &HttpConfig,
    limiter: &AuthRateLimiter,
) -> Result<Negotiated, HttpError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    match negotiate_inner(client, peer, config, limiter).await {
        Ok(negotiated) => Ok(negotiated),
        Err(err) => {
            if let Some(status) = err.status() {
                let challenge = matches!(
                    err,
                    HttpError::AuthRequired | HttpError::AuthFailed | HttpError::AuthRateLimited
                );
                respond(client, status, challenge).await?;
            }
            Err(err)
        }
    }
}

async fn negotiate_inner<C>(
    client: &mut C,
    peer: IpAddr,
    config: &HttpConfig,
    limiter: &AuthRateLimiter,
) -> Result<Negotiated, HttpError>
where
    C: AsyncRead + Unpin,
{
    let raw = read_head(client).await?;
    let head = std::str::from_utf8(&raw.head)
        .map_err(|_| HttpError::Malformed("request head is not ASCII"))?;
    let request = parse_head(head)?;
    authorize(&request, peer, config, limiter)?;
    let target = target_from_authority(request.target, config)?;
    Ok(Negotiated {
        target,
        pending: raw.pending,
    })
}

// ---------------------------------------------------------------------------
// Reading the head as a stream
// ---------------------------------------------------------------------------

struct RawHead {
    /// The head without its CRLFCRLF terminator.
    head: Vec<u8>,
    /// Bytes the client sent after the terminator.
    pending: Vec<u8>,
}

/// Reads until CRLFCRLF. Never assumes one `read()` yields a whole request: a
/// request split across packet boundaries and a terminator straddling two reads
/// are both normal.
async fn read_head<C>(client: &mut C) -> Result<RawHead, HttpError>
where
    C: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(READ_CHUNK);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if let Some(end) = find_terminator(&buf) {
            return Ok(RawHead {
                head: buf[..end].to_vec(),
                pending: buf[end + 4..].to_vec(),
            });
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(HttpError::HeadTooLarge);
        }
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(HttpError::Malformed("closed before end of request head"));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

fn find_terminator(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct Head<'a> {
    target: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

fn parse_head(head: &str) -> Result<Head<'_>, HttpError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(HttpError::HeadTooLarge);
    }
    let target = parse_request_line(request_line)?;

    let mut headers = Vec::new();
    for line in lines {
        // A bare CR inside the head means the client framed a line with
        // something other than CRLF; obs-fold continuations are a classic
        // request-smuggling primitive. Both are refused rather than normalised.
        if line.contains('\r') || line.contains('\n') {
            return Err(HttpError::Malformed("bare CR or LF in header block"));
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError::Malformed("obsolete line folding"));
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(HttpError::TooManyHeaders);
        }
        headers.push(parse_header(line)?);
    }

    reject_ambiguous_framing(&headers)?;
    Ok(Head { target, headers })
}

/// `METHOD SP request-target SP HTTP-version`, with exactly one space between
/// each part and nothing after the version.
fn parse_request_line(line: &str) -> Result<&str, HttpError> {
    if !line.is_ascii() {
        return Err(HttpError::Malformed("non-ASCII request line"));
    }
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts
        .next()
        .ok_or(HttpError::Malformed("truncated request line"))?;
    let version = parts
        .next()
        .ok_or(HttpError::Malformed("truncated request line"))?;
    if parts.next().is_some() {
        return Err(HttpError::Malformed("trailing data in request line"));
    }
    if method.is_empty() || target.is_empty() {
        return Err(HttpError::Malformed("empty request line field"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::Malformed("unsupported HTTP version"));
    }

    // ---- v1.1 seam: absolute-form plaintext proxying -----------------------
    // `GET http://host/path HTTP/1.1` belongs here. It is deferred, not
    // overlooked: forwarding a request body makes this process a full HTTP
    // intermediary, and RFC 9112 §6.3 desync (duplicate `Content-Length`, or
    // `Transfer-Encoding` plus `Content-Length` read differently by us and by
    // the origin) turns that into request smuggling against the destination.
    // Shipping it requires strict framing validation and a per-hop connection
    // model that CONNECT does not need, so v1 refuses it outright instead of
    // half-implementing it.
    if method != "CONNECT" {
        if target.starts_with("http://") || target.starts_with("https://") {
            return Err(HttpError::AbsoluteFormUnsupported);
        }
        return Err(HttpError::MethodNotSupported(method.to_owned()));
    }
    Ok(target)
}

fn parse_header(line: &str) -> Result<(&str, &str), HttpError> {
    let (name, value) = line
        .split_once(':')
        .ok_or(HttpError::Malformed("header without a colon"))?;
    if name.is_empty() || !name.bytes().all(is_tchar) {
        // Whitespace before the colon is the "Content-Length : 0" smuggling
        // trick; `is_tchar` rejects it along with every other separator.
        return Err(HttpError::Malformed("invalid header name"));
    }
    let value = value.trim_matches(|c| c == ' ' || c == '\t');
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(HttpError::Malformed("control byte in header value"));
    }
    Ok((name, value))
}

/// RFC 9110 §9.3.6: a CONNECT request has no content. Any framing header is
/// therefore either a smuggling attempt or a broken client; both get 400.
fn reject_ambiguous_framing(headers: &[(&str, &str)]) -> Result<(), HttpError> {
    let framing = headers.iter().any(|(name, _)| {
        name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
    });
    if framing {
        return Err(HttpError::Malformed("framing header on a CONNECT request"));
    }
    let authorizations = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
        .count();
    if authorizations > 1 {
        return Err(HttpError::Malformed("duplicate Proxy-Authorization"));
    }
    Ok(())
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

fn authorize(
    head: &Head<'_>,
    peer: IpAddr,
    config: &HttpConfig,
    limiter: &AuthRateLimiter,
) -> Result<(), HttpError> {
    let credentials = match &config.auth {
        AuthPolicy::Disabled => return Ok(()),
        AuthPolicy::Required(credentials) => credentials,
    };
    let header = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"));
    // A first request without the header is how every HTTP client discovers the
    // challenge, so it is not counted as a failure by the rate limiter.
    let Some((_, value)) = header else {
        return Err(HttpError::AuthRequired);
    };

    if !limiter.has_capacity(peer) {
        tracing::warn!(%peer, "http proxy authentication rate-limited");
        return Err(HttpError::AuthRateLimited);
    }

    let accepted = decode_basic(value)
        .map(|(user, pass)| bool::from(credentials.verify(&user, &pass)))
        .unwrap_or(false);
    if accepted {
        return Ok(());
    }
    limiter.record_failure(peer);
    tracing::warn!(%peer, "http proxy authentication failed");
    Err(HttpError::AuthFailed)
}

/// RFC 7617 `Basic <base64(user ":" pass)>`. The userid cannot contain a colon,
/// so the split is at the first one; the password may contain any others.
fn decode_basic(value: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = BASE64.decode(token.trim()).ok()?;
    let colon = decoded.iter().position(|byte| *byte == b':')?;
    Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
}

// ---------------------------------------------------------------------------
// Destination
// ---------------------------------------------------------------------------

/// Splits `host:port` and classifies the host, without ever resolving it.
fn target_from_authority(authority: &str, config: &HttpConfig) -> Result<Target, HttpError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inside, tail) = rest
            .split_once(']')
            .ok_or(HttpError::InvalidDestination("unterminated IPv6 literal"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or(HttpError::InvalidDestination("missing port"))?;
        let address = inside
            .parse::<Ipv6Addr>()
            .map_err(|_| HttpError::InvalidDestination("bad IPv6 literal"))?;
        return ip_target(IpAddr::V6(address), parse_port(port)?, config);
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or(HttpError::InvalidDestination("missing port"))?;
    if host.contains(':') {
        return Err(HttpError::InvalidDestination("unbracketed IPv6 literal"));
    }
    let port = parse_port(port)?;
    validate_host(host)?;
    // An IP literal in the host position is an address, not a name: treating it
    // as one keeps it away from the resolver entirely.
    match host.parse::<IpAddr>() {
        Ok(address) => ip_target(address, port, config),
        Err(_) => Ok(Target::Domain {
            host: host.to_owned(),
            port,
        }),
    }
}

fn ip_target(address: IpAddr, port: u16, config: &HttpConfig) -> Result<Target, HttpError> {
    if address.is_ipv6() && !config.tunnel_has_v6 {
        // A v4-only tunnel reaching a v6 destination is a hard failure, never
        // something to work around (SPEC.md §5.5).
        return Err(HttpError::Ipv6Unsupported);
    }
    Ok(Target::Ip(SocketAddr::new(address, port)))
}

/// Rejects everything that is not printable ASCII: NUL, control bytes, CR, LF,
/// spaces and raw non-ASCII (an IDN must arrive already in A-label form). This
/// is what makes a header-injection attempt in the authority a 400.
fn validate_host(host: &str) -> Result<(), HttpError> {
    if host.is_empty() {
        return Err(HttpError::InvalidDestination("empty host"));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(HttpError::InvalidDestination("host too long"));
    }
    if host.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(HttpError::InvalidDestination("non-printable host"));
    }
    Ok(())
}

fn parse_port(raw: &str) -> Result<u16, HttpError> {
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::InvalidDestination("bad port"));
    }
    let port = raw
        .parse::<u16>()
        .map_err(|_| HttpError::InvalidDestination("port out of range"))?;
    if port == 0 {
        return Err(HttpError::InvalidDestination("port 0"));
    }
    Ok(port)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Error responses carry explicit zero-length framing and close the connection.
/// No `Via`, `X-Forwarded-For`, `Server` or `Proxy-Agent` — see the module docs.
async fn respond<C>(client: &mut C, status: Status, challenge: bool) -> Result<(), HttpError>
where
    C: AsyncWrite + Unpin,
{
    let (code, reason) = status;
    let challenge = if challenge {
        format!("{CHALLENGE}\r\n")
    } else {
        String::new()
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n{challenge}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    client.write_all(response.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{duplex, DuplexStream, Join, ReadBuf};

    use crate::socks5::Credentials;

    /// Feeds the parser one configured chunk per poll so a request split across
    /// packet boundaries is exercised deterministically. An empty chunk list
    /// yields a stream that never produces data and never ends, which is how a
    /// client that withholds CRLFCRLF is simulated.
    struct ChunkedReader {
        chunks: Vec<Vec<u8>>,
        stall: bool,
    }

    impl ChunkedReader {
        fn new(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().rev().collect(),
                stall: false,
            }
        }

        fn stalling(chunks: Vec<Vec<u8>>) -> Self {
            Self {
                chunks: chunks.into_iter().rev().collect(),
                stall: true,
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
                // Ready(Ok(())) with nothing written is EOF; Pending is a peer
                // that is simply not talking.
                None if self.stall => Poll::Pending,
                None => Poll::Ready(Ok(())),
            }
        }
    }

    type Client = Join<ChunkedReader, Vec<u8>>;

    fn client_from(chunks: Vec<Vec<u8>>) -> Client {
        tokio::io::join(ChunkedReader::new(chunks), Vec::new())
    }

    fn stalling_client(chunks: Vec<Vec<u8>>) -> Client {
        tokio::io::join(ChunkedReader::stalling(chunks), Vec::new())
    }

    fn written(client: Client) -> String {
        String::from_utf8_lossy(&client.into_inner().1).into_owned()
    }

    struct StubDialer {
        result: Result<(), DialError>,
        /// Never resolves, which is what a destination that swallows SYNs looks
        /// like to the dialer.
        black_holed: bool,
    }

    impl StubDialer {
        fn ok() -> Self {
            Self {
                result: Ok(()),
                black_holed: false,
            }
        }

        fn failing(err: DialError) -> Self {
            Self {
                result: Err(err),
                black_holed: false,
            }
        }

        fn black_holed() -> Self {
            Self {
                result: Ok(()),
                black_holed: true,
            }
        }
    }

    impl Dialer for StubDialer {
        type Stream = DuplexStream;

        async fn tcp(&self, _target: &Target) -> Result<Self::Stream, DialError> {
            if self.black_holed {
                std::future::pending::<()>().await;
            }
            self.result.map(|_| duplex(8).0)
        }
    }

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn auth_config() -> HttpConfig {
        HttpConfig::new(
            AuthPolicy::Required(Credentials::new(b"user".to_vec(), b"pass".to_vec())),
            false,
        )
    }

    fn open_config() -> HttpConfig {
        HttpConfig::new(AuthPolicy::Disabled, false)
    }

    fn basic(user: &str, pass: &str) -> String {
        BASE64.encode(format!("{user}:{pass}"))
    }

    fn connect_request(authority: &str) -> Vec<u8> {
        format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
    }

    async fn run(
        chunks: Vec<Vec<u8>>,
        config: &HttpConfig,
        dialer: &StubDialer,
    ) -> (Result<Target, HttpError>, String) {
        let limiter = AuthRateLimiter::new();
        let mut client = client_from(chunks);
        let result = handshake(&mut client, peer(), config, &limiter, dialer)
            .await
            .map(|session| session.target);
        (result, written(client))
    }

    // ---- happy path -------------------------------------------------------

    #[tokio::test]
    async fn connect_without_auth_establishes_and_keeps_the_host_unresolved() {
        let (result, out) = run(
            vec![connect_request("example.com:443")],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(
            result,
            Ok(Target::Domain { ref host, port: 443 }) if host == "example.com"
        ));
        assert_eq!(out, "HTTP/1.1 200 Connection established\r\n\r\n");
    }

    #[tokio::test]
    async fn established_response_carries_no_attribution_headers() {
        let (_, out) = run(
            vec![connect_request("example.com:443")],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        let lowered = out.to_ascii_lowercase();
        assert!(!lowered.contains("via:"));
        assert!(!lowered.contains("x-forwarded-for"));
        assert!(!lowered.contains("server:"));
        assert!(!lowered.contains("proxy-agent"));
    }

    #[tokio::test]
    async fn connect_to_an_ipv4_literal_is_treated_as_an_address() {
        let (result, _) = run(
            vec![connect_request("192.0.2.7:8080")],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(
            result,
            Ok(Target::Ip(addr)) if addr == SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 8080)
        ));
    }

    #[tokio::test]
    async fn bytes_pipelined_after_the_head_are_preserved() {
        let mut request = connect_request("example.com:443");
        request.extend_from_slice(b"\x16\x03\x01early");
        let limiter = AuthRateLimiter::new();
        let mut client = client_from(vec![request]);

        let session = handshake(
            &mut client,
            peer(),
            &open_config(),
            &limiter,
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(session, Ok(ref s) if s.pending == b"\x16\x03\x01early"));
    }

    #[tokio::test]
    async fn a_request_split_across_packet_boundaries_parses() {
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("user", "pass")
        );
        let chunks = request
            .as_bytes()
            .chunks(3)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();

        let (result, out) = run(chunks, &auth_config(), &StubDialer::ok()).await;

        assert!(matches!(result, Ok(Target::Domain { .. })));
        assert!(out.starts_with("HTTP/1.1 200 "));
    }

    #[tokio::test]
    async fn a_terminator_straddling_two_reads_is_found() {
        let request = connect_request("example.com:443");
        let split = request.len() - 2;
        let chunks = vec![request[..split].to_vec(), request[split..].to_vec()];

        let (result, _) = run(chunks, &open_config(), &StubDialer::ok()).await;

        assert!(matches!(result, Ok(Target::Domain { .. })));
    }

    // ---- authentication ---------------------------------------------------

    #[tokio::test]
    async fn missing_credentials_answer_407_with_the_challenge() {
        let (result, out) = run(
            vec![connect_request("example.com:443")],
            &auth_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::AuthRequired)));
        assert!(out.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"));
        assert!(
            out.contains("Proxy-Authenticate: Basic realm=\"thisconnect\", charset=\"UTF-8\"\r\n")
        );
    }

    #[tokio::test]
    async fn wrong_credentials_answer_407_and_never_dial() {
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("user", "wrong")
        );

        let (result, out) = run(
            vec![request.into_bytes()],
            &auth_config(),
            &StubDialer::failing(DialError::Other),
        )
        .await;

        assert!(matches!(result, Err(HttpError::AuthFailed)));
        assert!(out.starts_with("HTTP/1.1 407 "));
    }

    #[tokio::test]
    async fn a_non_basic_scheme_is_an_auth_failure() {
        let request =
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer abcdef\r\n\r\n";

        let (result, _) = run(
            vec![request.as_bytes().to_vec()],
            &auth_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::AuthFailed)));
    }

    #[tokio::test]
    async fn undecodable_base64_is_an_auth_failure_not_a_panic() {
        let request = "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic !!!!\r\n\r\n";

        let (result, _) = run(
            vec![request.as_bytes().to_vec()],
            &auth_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::AuthFailed)));
    }

    #[tokio::test]
    async fn repeated_failures_are_rate_limited_with_the_same_status() {
        let limiter = AuthRateLimiter::new();
        let config = auth_config();
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            basic("user", "wrong")
        );

        let mut last = Ok(());
        let mut out = String::new();
        for _ in 0..8 {
            let mut client = client_from(vec![request.clone().into_bytes()]);
            last = handshake(&mut client, peer(), &config, &limiter, &StubDialer::ok())
                .await
                .map(|_| ());
            out = written(client);
        }

        assert!(matches!(last, Err(HttpError::AuthRateLimited)));
        assert!(out.starts_with("HTTP/1.1 407 "));
    }

    #[test]
    fn duplicate_proxy_authorization_is_rejected_before_comparison() {
        let head = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\nProxy-Authorization: Basic {}",
            basic("user", "pass"),
            basic("user", "wrong")
        );

        assert!(matches!(parse_head(&head), Err(HttpError::Malformed(_))));
    }

    // ---- framing and limits ------------------------------------------------

    #[tokio::test]
    async fn an_oversized_header_block_answers_431() {
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
        while request.len() < MAX_HEAD_BYTES + 512 {
            request.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }

        let (result, out) = run(vec![request], &open_config(), &StubDialer::ok()).await;

        assert!(matches!(result, Err(HttpError::HeadTooLarge)));
        assert!(out.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
    }

    #[tokio::test]
    async fn an_oversized_request_line_answers_431() {
        let host = "a".repeat(MAX_REQUEST_LINE);
        let request = format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n");

        let (result, out) = run(
            vec![request.into_bytes()],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::HeadTooLarge)));
        assert!(out.starts_with("HTTP/1.1 431 "));
    }

    #[test]
    fn too_many_headers_are_rejected() {
        let mut head = String::from("CONNECT example.com:443 HTTP/1.1");
        for index in 0..=MAX_HEADER_COUNT {
            head.push_str(&format!("\r\nX-{index}: v"));
        }

        assert!(matches!(parse_head(&head), Err(HttpError::TooManyHeaders)));
    }

    #[tokio::test]
    async fn a_client_that_never_sends_crlfcrlf_times_out_rather_than_pinning_a_task() {
        let config = HttpConfig {
            handshake_timeout: Duration::from_millis(20),
            ..open_config()
        };
        let limiter = AuthRateLimiter::new();
        let mut client = stalling_client(vec![b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec()]);

        let result = handshake(&mut client, peer(), &config, &limiter, &StubDialer::ok()).await;

        assert!(matches!(result, Err(HttpError::HandshakeTimeout)));
        assert!(written(client).starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    }

    /// The negotiation is complete here, so the handshake timeout is spent. A
    /// dial that never completes must not be able to hold the task open.
    #[tokio::test]
    async fn a_black_holed_destination_cannot_pin_the_task_past_the_connect_timeout() {
        // Arrange
        let config = HttpConfig {
            connect_timeout: Duration::from_millis(20),
            // Long enough that a timeout can only have come from the dial.
            handshake_timeout: Duration::from_secs(60),
            ..open_config()
        };

        // Act
        let (result, out) = run(
            vec![connect_request("example.com:443")],
            &config,
            &StubDialer::black_holed(),
        )
        .await;

        // Assert
        assert!(matches!(result, Err(HttpError::DialTimeout)));
        assert!(out.starts_with("HTTP/1.1 504 Gateway Timeout\r\n"));
    }

    #[test]
    fn the_connect_timeout_is_bounded_by_default() {
        // Arrange / Act
        let config = open_config();

        // Assert — an unset bound is the whole defect; the OS one is ~15 minutes.
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert!(config.connect_timeout <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn eof_before_the_terminator_is_a_400_not_a_hang() {
        let (result, out) = run(
            vec![b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec()],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::Malformed(_))));
        assert!(out.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    }

    #[test]
    fn framing_headers_on_a_connect_are_rejected() {
        let head =
            "CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn whitespace_before_the_header_colon_is_rejected() {
        let head = "CONNECT example.com:443 HTTP/1.1\r\nContent-Length : 5";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn obsolete_line_folding_is_rejected() {
        let head = "CONNECT example.com:443 HTTP/1.1\r\nX-A: one\r\n  two";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn a_bare_lf_inside_the_head_is_rejected() {
        let head = "CONNECT example.com:443 HTTP/1.1\r\nX-A: one\nX-B: two";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    // ---- method and version ------------------------------------------------

    #[tokio::test]
    async fn absolute_form_answers_501_and_is_not_proxied() {
        let request = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let (result, out) = run(
            vec![request.as_bytes().to_vec()],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::AbsoluteFormUnsupported)));
        assert!(out.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
    }

    #[tokio::test]
    async fn an_unknown_method_answers_501() {
        let (result, out) = run(
            vec![b"FROB / HTTP/1.1\r\n\r\n".to_vec()],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::MethodNotSupported(_))));
        assert!(out.starts_with("HTTP/1.1 501 "));
    }

    #[test]
    fn an_unsupported_http_version_is_rejected() {
        let head = "CONNECT example.com:443 HTTP/2.0";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    #[test]
    fn a_request_line_with_extra_spaces_is_rejected() {
        let head = "CONNECT  example.com:443 HTTP/1.1";

        assert!(matches!(parse_head(head), Err(HttpError::Malformed(_))));
    }

    // ---- destination validation --------------------------------------------

    #[tokio::test]
    async fn an_ipv6_literal_on_a_v4_only_tunnel_answers_403() {
        let (result, out) = run(
            vec![connect_request("[2001:db8::1]:443")],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::Ipv6Unsupported)));
        assert!(out.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    }

    #[test]
    fn an_ipv6_literal_is_accepted_when_the_tunnel_has_v6() {
        let config = HttpConfig::new(AuthPolicy::Disabled, true);

        let target = target_from_authority("[2001:db8::1]:443", &config);

        assert!(matches!(target, Ok(Target::Ip(addr)) if addr.port() == 443 && addr.is_ipv6()));
    }

    #[test]
    fn an_unbracketed_ipv6_literal_is_rejected() {
        let result = target_from_authority("2001:db8::1:443", &open_config());

        assert!(matches!(result, Err(HttpError::InvalidDestination(_))));
    }

    #[tokio::test]
    async fn a_crlf_injection_attempt_in_the_authority_is_a_400() {
        // The CR ends the request line, so the injected header lands in the
        // header block and the request line loses its version field.
        let request = "CONNECT example.com:443\r\nX-Injected: 1 HTTP/1.1\r\nHost: x\r\n\r\n";

        let (result, out) = run(
            vec![request.as_bytes().to_vec()],
            &open_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(matches!(result, Err(HttpError::Malformed(_))));
        assert!(out.starts_with("HTTP/1.1 400 "));
    }

    #[test]
    fn control_and_whitespace_bytes_in_the_host_are_rejected() {
        for authority in [
            "exa mple.com:443",
            "exa\x07mple.com:443",
            "exa\x00mple.com:443",
        ] {
            assert!(
                matches!(
                    target_from_authority(authority, &open_config()),
                    Err(HttpError::InvalidDestination(_)) | Err(HttpError::Malformed(_))
                ),
                "{authority} was not rejected"
            );
        }
    }

    #[test]
    fn an_overlong_host_is_rejected() {
        let authority = format!("{}:443", "a".repeat(MAX_HOST_LEN + 1));

        assert!(matches!(
            target_from_authority(&authority, &open_config()),
            Err(HttpError::InvalidDestination(_))
        ));
    }

    #[test]
    fn port_zero_a_missing_port_and_a_non_numeric_port_are_rejected() {
        for authority in [
            "example.com:0",
            "example.com",
            "example.com:https",
            "example.com:99999",
            "example.com:",
        ] {
            assert!(
                matches!(
                    target_from_authority(authority, &open_config()),
                    Err(HttpError::InvalidDestination(_))
                ),
                "{authority} was not rejected"
            );
        }
    }

    // ---- dial failure mapping ----------------------------------------------

    #[tokio::test]
    async fn dial_failures_map_to_their_status_codes() {
        let cases = [
            (DialError::NameNotResolved, "HTTP/1.1 502 Bad Gateway\r\n"),
            (DialError::HostUnreachable, "HTTP/1.1 502 "),
            (DialError::ConnectionRefused, "HTTP/1.1 502 "),
            (DialError::Other, "HTTP/1.1 502 "),
            (
                DialError::NetworkUnreachable,
                "HTTP/1.1 503 Service Unavailable\r\n",
            ),
            (DialError::PolicyRejected, "HTTP/1.1 403 Forbidden\r\n"),
        ];

        for (err, expected) in cases {
            let (result, out) = run(
                vec![connect_request("example.com:443")],
                &open_config(),
                &StubDialer::failing(err),
            )
            .await;

            assert!(matches!(result, Err(HttpError::Dial(_))));
            assert!(out.starts_with(expected), "{err:?} produced {out:?}");
        }
    }

    #[tokio::test]
    async fn error_responses_close_the_connection_and_frame_an_empty_body() {
        let (_, out) = run(
            vec![connect_request("example.com:443")],
            &auth_config(),
            &StubDialer::ok(),
        )
        .await;

        assert!(out.contains("Content-Length: 0\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
