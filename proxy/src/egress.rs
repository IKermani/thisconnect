// SPDX-License-Identifier: GPL-3.0-or-later

//! Tunnel-pinned egress dialer (SPEC.md 5.3).
//!
//! Every socket the proxy opens on behalf of a client is created here. The whole product's
//! security property is that no socket created by the proxy can reach the network by any path
//! other than the tun device, and that a socket which cannot be pinned is never created at all.
//!
//! Two rules drive the shape of this module:
//!
//!   * The tunnel identity is immutable and versioned. `if_nametoindex()` is re-resolved on every
//!     tunnel-up because utun names and indexes are recycled across reconnects, and a stale
//!     ifindex silently binds to whatever interface inherited it — a leak, not an error.
//!   * Everything fails closed. There is no code path in this file that falls back to an
//!     unpinned socket.

use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use thiserror::Error;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

/// Why a destination was refused, so callers can log it without re-deriving the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    Loopback,
    Unspecified,
    LinkLocal,
    Multicast,
    Broadcast,
    /// RFC1918 / RFC4193, refused only when the operator turns private egress off.
    Private,
    /// Deprecated or ambiguous encodings that can smuggle a denied literal past a family check.
    Reserved,
}

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("tunnel not ready")]
    TunnelNotReady,
    #[error("tunnel changed since this handle was issued")]
    StaleTunnel,
    #[error("egress state is unavailable")]
    StateUnavailable,
    #[error("interface name {0:?} is not usable")]
    InvalidInterfaceName(String),
    #[error("interface {0:?} does not exist")]
    UnknownInterface(String),
    #[error("tunnel has no IPv6 address; refusing AF_INET6 egress")]
    Ipv6Unsupported,
    #[error("tunnel source address {0} is not a usable unicast address")]
    InvalidTunnelAddress(IpAddr),
    #[error("destination {addr} refused by policy ({reason:?})")]
    DestinationDenied { addr: IpAddr, reason: DenyReason },
    #[error("destination port 0 is not connectable")]
    InvalidPort,
    #[error("cannot pin socket to {device}: {source}")]
    Pin {
        device: String,
        #[source]
        source: io::Error,
    },
    #[error("cannot bind socket to tunnel address {addr}: {source}")]
    Bind {
        addr: IpAddr,
        #[source]
        source: io::Error,
    },
    /// Distinct so the UI can say "tunnel not ready" instead of a generic network error.
    #[error("network unreachable through the tunnel")]
    NetworkUnreachable,
    /// The Linux fail-closed floor route (`unreachable default`, SPEC.md 5.2) answers with this.
    #[error("host unreachable through the tunnel")]
    HostUnreachable,
    #[error("connection refused by {0}")]
    ConnectionRefused(SocketAddr),
    #[error("egress i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("socket pinning is not implemented for this platform")]
    UnsupportedPlatform,
}

/// Destination policy for SPEC.md 5.4 D6. Pinning does not stop a socket reaching the user's own
/// machine or LAN, so the denylist is applied to IP literals and to post-resolution addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationPolicy {
    /// Corporate VPNs legitimately need RFC1918 destinations, so this defaults to allowed.
    pub allow_private: bool,
}

impl Default for DestinationPolicy {
    fn default() -> Self {
        Self {
            allow_private: true,
        }
    }
}

/// The tunnel facts the daemon learns from `>UPDOWN:ENV` (SPEC.md 4.3 item 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub device: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: u32,
}

/// An immutable, versioned tunnel identity. Never mutated: a tunnel change publishes a new one and
/// invalidates every handle to the old one.
#[derive(Debug)]
pub struct TunEgress {
    device: String,
    ifindex: NonZeroU32,
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
    mtu: u32,
    policy: DestinationPolicy,
    generation: u64,
    /// Shared with the owning `EgressState`; a bump here strands this handle.
    live_generation: Arc<AtomicU64>,
}

impl TunEgress {
    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex.get()
    }

    pub fn ipv4(&self) -> Ipv4Addr {
        self.ipv4
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// False once the tunnel has been replaced or torn down.
    pub fn is_current(&self) -> bool {
        self.live_generation.load(Ordering::Acquire) == self.generation
    }

    fn ensure_current(&self) -> Result<(), EgressError> {
        if self.is_current() {
            return Ok(());
        }
        Err(EgressError::StaleTunnel)
    }

    /// Open a TCP connection to `dst` through the tunnel, or fail. Never falls back.
    pub async fn tcp(&self, dst: SocketAddr) -> Result<TcpStream, EgressError> {
        self.ensure_current()?;
        let dst = canonicalize(dst);
        if dst.port() == 0 {
            return Err(EgressError::InvalidPort);
        }
        check_destination(dst.ip(), self.policy)?;
        match dst {
            SocketAddr::V4(_) => self.connect_v4(dst).await,
            SocketAddr::V6(_) => self.connect_v6(dst).await,
        }
    }

    /// A tunnel-pinned IPv4 UDP socket, for the pinned resolver (SPEC.md 5.4 D2).
    pub fn udp(&self) -> Result<UdpSocket, EgressError> {
        self.ensure_current()?;
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        self.pin_v4(&sock)?;
        self.bind_socket(&sock, IpAddr::V4(self.ipv4))?;
        sock.set_nonblocking(true)?;
        Ok(UdpSocket::from_std(std::net::UdpSocket::from(sock))?)
    }

    /// A tunnel-pinned IPv6 UDP socket. Refused outright on a v4-only tunnel (SPEC.md 5.5).
    pub fn udp_v6(&self) -> Result<UdpSocket, EgressError> {
        self.ensure_current()?;
        let local = self.ipv6.ok_or(EgressError::Ipv6Unsupported)?;
        let sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        self.pin_v6(&sock)?;
        self.bind_socket(&sock, IpAddr::V6(local))?;
        sock.set_nonblocking(true)?;
        Ok(UdpSocket::from_std(std::net::UdpSocket::from(sock))?)
    }

    async fn connect_v4(&self, dst: SocketAddr) -> Result<TcpStream, EgressError> {
        let sock = TcpSocket::new_v4()?;
        self.pin_v4(&sock)?;
        let local = SocketAddr::new(IpAddr::V4(self.ipv4), 0);
        sock.bind(local).map_err(|source| EgressError::Bind {
            addr: local.ip(),
            source,
        })?;
        sock.connect(dst).await.map_err(|e| classify_dial(e, dst))
    }

    async fn connect_v6(&self, dst: SocketAddr) -> Result<TcpStream, EgressError> {
        let local = self.ipv6.ok_or(EgressError::Ipv6Unsupported)?;
        let sock = TcpSocket::new_v6()?;
        self.pin_v6(&sock)?;
        let local = SocketAddr::new(IpAddr::V6(local), 0);
        sock.bind(local).map_err(|source| EgressError::Bind {
            addr: local.ip(),
            source,
        })?;
        sock.connect(dst).await.map_err(|e| classify_dial(e, dst))
    }

    fn bind_socket<S: AsFd>(&self, sock: &S, addr: IpAddr) -> Result<(), EgressError> {
        let sock = socket2::SockRef::from(sock);
        sock.bind(&SocketAddr::new(addr, 0).into())
            .map_err(|source| EgressError::Bind { addr, source })
    }

    fn pin_error(&self, source: io::Error) -> EgressError {
        EgressError::Pin {
            device: self.device.clone(),
            source,
        }
    }
}

#[cfg(target_os = "linux")]
impl TunEgress {
    fn pin_v4<S: AsFd + AsRawFd>(&self, sock: &S) -> Result<(), EgressError> {
        // Source-address binding is the pin on Linux (SPEC.md 5.3): the `ip rule from <tunip>`
        // installed by the daemon is what selects table 218. IP_BIND_ADDRESS_NO_PORT only defers
        // source-port selection until connect() knows the destination.
        set_bind_address_no_port(sock.as_raw_fd()).map_err(|e| self.pin_error(e))
    }

    fn pin_v6<S: AsFd + AsRawFd>(&self, _sock: &S) -> Result<(), EgressError> {
        // IP_BIND_ADDRESS_NO_PORT has no IPv6 counterpart; the v6 rule keys on the source address
        // exactly as the v4 one does, so the bind below is the whole pin.
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl TunEgress {
    fn pin_v4<S: AsFd>(&self, sock: &S) -> Result<(), EgressError> {
        socket2::SockRef::from(sock)
            .bind_device_by_index_v4(Some(self.ifindex))
            .map_err(|e| self.pin_error(e))
    }

    fn pin_v6<S: AsFd>(&self, sock: &S) -> Result<(), EgressError> {
        socket2::SockRef::from(sock)
            .bind_device_by_index_v6(Some(self.ifindex))
            .map_err(|e| self.pin_error(e))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl TunEgress {
    fn pin_v4<S: AsFd>(&self, _sock: &S) -> Result<(), EgressError> {
        Err(EgressError::UnsupportedPlatform)
    }

    fn pin_v6<S: AsFd>(&self, _sock: &S) -> Result<(), EgressError> {
        Err(EgressError::UnsupportedPlatform)
    }
}

/// Publishes the current tunnel identity to the proxy. Tunnel changes replace the whole
/// `TunEgress`; handles issued for an older generation refuse to dial rather than binding to a
/// recycled interface.
#[derive(Debug)]
pub struct EgressState {
    current: RwLock<Option<Arc<TunEgress>>>,
    live_generation: Arc<AtomicU64>,
    policy: DestinationPolicy,
}

impl EgressState {
    pub fn new(policy: DestinationPolicy) -> Self {
        Self {
            current: RwLock::new(None),
            live_generation: Arc::new(AtomicU64::new(0)),
            policy,
        }
    }

    /// Re-resolves the ifindex from the device *name* and publishes a fresh identity.
    pub fn tunnel_up(&self, config: &TunnelConfig) -> Result<Arc<TunEgress>, EgressError> {
        let ifindex = resolve_ifindex(&config.device)?;
        validate_tunnel_source(IpAddr::V4(config.ipv4))?;
        if let Some(v6) = config.ipv6 {
            validate_tunnel_source(IpAddr::V6(v6))?;
        }
        let generation = self.live_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let egress = Arc::new(TunEgress {
            device: config.device.clone(),
            ifindex,
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            mtu: config.mtu,
            policy: self.policy,
            generation,
            live_generation: Arc::clone(&self.live_generation),
        });
        let mut slot = self
            .current
            .write()
            .map_err(|_| EgressError::StateUnavailable)?;
        *slot = Some(Arc::clone(&egress));
        Ok(egress)
    }

    /// Strands every outstanding handle. Callers must also force-close live sessions.
    pub fn tunnel_down(&self) -> Result<(), EgressError> {
        self.live_generation.fetch_add(1, Ordering::AcqRel);
        let mut slot = self
            .current
            .write()
            .map_err(|_| EgressError::StateUnavailable)?;
        *slot = None;
        Ok(())
    }

    pub fn current(&self) -> Result<Arc<TunEgress>, EgressError> {
        let slot = self
            .current
            .read()
            .map_err(|_| EgressError::StateUnavailable)?;
        match slot.as_ref() {
            Some(egress) if egress.is_current() => Ok(Arc::clone(egress)),
            _ => Err(EgressError::TunnelNotReady),
        }
    }

    pub fn generation(&self) -> u64 {
        self.live_generation.load(Ordering::Acquire)
    }
}

/// The source bind is load-bearing, not cosmetic: on Linux `ip rule from <tunip>` is the *entire*
/// pin, so a degenerate source address (`0.0.0.0`, `::`, a multicast or link-local literal from a
/// missing `>UPDOWN:ENV` field) would `bind()` successfully, match no rule, fall through to the
/// main table and egress over the physical interface. Refusing the identity outright is the only
/// fail-closed answer, because by dial time the address looks perfectly bindable.
fn validate_tunnel_source(addr: IpAddr) -> Result<(), EgressError> {
    let usable = match addr {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                // 0.0.0.0/8 is unroutable as a source in the same way `0.0.0.0` itself is.
                && v4.octets()[0] != 0
        }
        IpAddr::V6(v6) => {
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && v6.segments()[0] & 0xffc0 != 0xfe80
                // A v4-mapped or v4-compatible literal is not an address a tun device holds; it
                // would bind as v6 while the v6 rule keys on a native prefix.
                && v6.to_ipv4_mapped().is_none()
                && v6.segments()[..6] != [0, 0, 0, 0, 0, 0]
        }
    };
    if usable {
        return Ok(());
    }
    Err(EgressError::InvalidTunnelAddress(addr))
}

/// `if_nametoindex` is re-run on every tunnel-up: utun indexes are recycled, and a cached one
/// silently pins to a different interface.
fn resolve_ifindex(device: &str) -> Result<NonZeroU32, EgressError> {
    let name =
        CString::new(device).map_err(|_| EgressError::InvalidInterfaceName(device.to_owned()))?;
    // SAFETY: `name` is a live, NUL-terminated C string that outlives the call, and
    // `if_nametoindex` only reads from it. It returns 0 on failure and never takes ownership.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index).ok_or_else(|| EgressError::UnknownInterface(device.to_owned()))
}

/// Wraps the one unavoidable `setsockopt` (SPEC.md 5.3): neither socket2 0.6 nor tokio expose
/// `IP_BIND_ADDRESS_NO_PORT`, and without it source-port selection happens at bind time without a
/// destination, defeating 4-tuple uniqueness and producing EADDRINUSE under proxy load.
#[cfg(target_os = "linux")]
fn set_bind_address_no_port(fd: std::os::fd::RawFd) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: `fd` is a valid open socket borrowed for the duration of the call; the value pointer
    // refers to an initialised `c_int` that outlives the call, and the length passed is exactly
    // `size_of::<c_int>()`, so the kernel reads only initialised memory of the size it expects.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            std::ptr::addr_of!(on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    tolerate_missing_option(rc)
}

/// Kernels < 4.2 have no `IP_BIND_ADDRESS_NO_PORT`; every other failure is real and fails closed.
/// Compiled on every platform so this branch stays unit-testable on the macOS dev machine.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tolerate_missing_option(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
        return Ok(());
    }
    Err(err)
}

/// Collapses `::ffff:a.b.c.d` to its IPv4 form so one denylist and one family check cover both
/// spellings of the same destination.
fn canonicalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// SPEC.md 5.4 D6. Applied to IP literals and to post-resolution addresses alike.
pub fn check_destination(addr: IpAddr, policy: DestinationPolicy) -> Result<(), EgressError> {
    let denied = match canonical_ip(addr) {
        IpAddr::V4(v4) => deny_reason_v4(v4, policy),
        IpAddr::V6(v6) => deny_reason_v6(v6, policy),
    };
    match denied {
        Some(reason) => Err(EgressError::DestinationDenied { addr, reason }),
        None => Ok(()),
    }
}

fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

fn deny_reason_v4(addr: Ipv4Addr, policy: DestinationPolicy) -> Option<DenyReason> {
    if addr.is_loopback() {
        return Some(DenyReason::Loopback);
    }
    if addr.octets()[0] == 0 {
        return Some(DenyReason::Unspecified);
    }
    if addr.is_link_local() {
        return Some(DenyReason::LinkLocal);
    }
    if addr.is_multicast() {
        return Some(DenyReason::Multicast);
    }
    if addr.is_broadcast() {
        return Some(DenyReason::Broadcast);
    }
    if addr.is_private() && !policy.allow_private {
        return Some(DenyReason::Private);
    }
    None
}

fn deny_reason_v6(addr: Ipv6Addr, policy: DestinationPolicy) -> Option<DenyReason> {
    if addr.is_loopback() {
        return Some(DenyReason::Loopback);
    }
    if addr.is_unspecified() {
        return Some(DenyReason::Unspecified);
    }
    if addr.is_multicast() {
        return Some(DenyReason::Multicast);
    }
    if addr.segments()[0] & 0xffc0 == 0xfe80 {
        return Some(DenyReason::LinkLocal);
    }
    // Deprecated IPv4-compatible form (::a.b.c.d): another spelling of a v4 literal that would
    // otherwise skip the v4 rules above.
    if !addr.is_loopback() && !addr.is_unspecified() && addr.segments()[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(DenyReason::Reserved);
    }
    // RFC 4193 unique-local, the v6 counterpart of RFC1918.
    if addr.segments()[0] & 0xfe00 == 0xfc00 && !policy.allow_private {
        return Some(DenyReason::Private);
    }
    None
}

/// ENETUNREACH is surfaced distinctly so the UI can say "tunnel not ready" (SPEC.md 5.2).
fn classify_dial(err: io::Error, dst: SocketAddr) -> EgressError {
    match err.raw_os_error() {
        Some(code) if code == libc::ENETUNREACH => EgressError::NetworkUnreachable,
        Some(code) if code == libc::EHOSTUNREACH => EgressError::HostUnreachable,
        Some(code) if code == libc::ECONNREFUSED => EgressError::ConnectionRefused(dst),
        _ => EgressError::Io(err),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const LOOPBACK_DEVICE: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    fn policy() -> DestinationPolicy {
        DestinationPolicy::default()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn deny_reason(s: &str, policy: DestinationPolicy) -> Option<DenyReason> {
        match check_destination(ip(s), policy) {
            Err(EgressError::DestinationDenied { reason, .. }) => Some(reason),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(()) => None,
        }
    }

    /// A loopback-pinned egress standing in for a tunnel, so the macOS pin path is exercised for
    /// real against an interface that exists on every machine. It mirrors `tunnel_up` minus the
    /// source-address check, which rejects 127.0.0.1 by design — the only address that is both
    /// bindable and pinnable on every developer and CI machine.
    fn loopback_egress(state: &EgressState) -> Arc<TunEgress> {
        let egress = Arc::new(TunEgress {
            device: LOOPBACK_DEVICE.to_owned(),
            ifindex: resolve_ifindex(LOOPBACK_DEVICE).unwrap(),
            ipv4: Ipv4Addr::LOCALHOST,
            ipv6: None,
            mtu: 1240,
            policy: state.policy,
            generation: state.live_generation.fetch_add(1, Ordering::AcqRel) + 1,
            live_generation: Arc::clone(&state.live_generation),
        });
        *state.current.write().unwrap() = Some(Arc::clone(&egress));
        egress
    }

    fn tunnel_config(ipv4: &str, ipv6: Option<&str>) -> TunnelConfig {
        TunnelConfig {
            device: LOOPBACK_DEVICE.to_owned(),
            ipv4: ipv4.parse().unwrap(),
            ipv6: ipv6.map(|s| s.parse().unwrap()),
            mtu: 1240,
        }
    }

    fn tunnel_up_err(ipv4: &str, ipv6: Option<&str>) -> EgressError {
        EgressState::new(policy())
            .tunnel_up(&tunnel_config(ipv4, ipv6))
            .expect_err("degenerate tunnel source address must be refused")
    }

    #[test]
    fn denies_every_localhost_and_link_local_form() {
        // Arrange / Act / Assert
        assert_eq!(
            deny_reason("127.0.0.1", policy()),
            Some(DenyReason::Loopback)
        );
        assert_eq!(
            deny_reason("127.255.255.254", policy()),
            Some(DenyReason::Loopback)
        );
        assert_eq!(deny_reason("::1", policy()), Some(DenyReason::Loopback));
        assert_eq!(
            deny_reason("0.0.0.0", policy()),
            Some(DenyReason::Unspecified)
        );
        assert_eq!(
            deny_reason("0.1.2.3", policy()),
            Some(DenyReason::Unspecified)
        );
        assert_eq!(deny_reason("::", policy()), Some(DenyReason::Unspecified));
        assert_eq!(
            deny_reason("169.254.169.254", policy()),
            Some(DenyReason::LinkLocal)
        );
        assert_eq!(
            deny_reason("fe80::1", policy()),
            Some(DenyReason::LinkLocal)
        );
        assert_eq!(
            deny_reason("febf::1", policy()),
            Some(DenyReason::LinkLocal)
        );
    }

    #[test]
    fn denies_multicast_and_broadcast() {
        assert_eq!(
            deny_reason("224.0.0.1", policy()),
            Some(DenyReason::Multicast)
        );
        assert_eq!(
            deny_reason("239.255.255.250", policy()),
            Some(DenyReason::Multicast)
        );
        assert_eq!(
            deny_reason("ff02::1", policy()),
            Some(DenyReason::Multicast)
        );
        assert_eq!(
            deny_reason("255.255.255.255", policy()),
            Some(DenyReason::Broadcast)
        );
    }

    #[test]
    fn denies_v4_mapped_spellings_of_denied_v4_addresses() {
        assert_eq!(
            deny_reason("::ffff:127.0.0.1", policy()),
            Some(DenyReason::Loopback)
        );
        assert_eq!(
            deny_reason("::ffff:169.254.169.254", policy()),
            Some(DenyReason::LinkLocal)
        );
        assert_eq!(
            deny_reason("::ffff:0.0.0.0", policy()),
            Some(DenyReason::Unspecified)
        );
        assert_eq!(
            deny_reason("::ffff:224.0.0.1", policy()),
            Some(DenyReason::Multicast)
        );
    }

    #[test]
    fn denies_deprecated_v4_compatible_form() {
        assert_eq!(
            deny_reason("::127.0.0.1", policy()),
            Some(DenyReason::Reserved)
        );
        assert_eq!(
            deny_reason("::1.2.3.4", policy()),
            Some(DenyReason::Reserved)
        );
    }

    #[test]
    fn allows_rfc1918_by_default_and_denies_it_when_configured() {
        let restricted = DestinationPolicy {
            allow_private: false,
        };

        assert_eq!(deny_reason("10.0.0.1", policy()), None);
        assert_eq!(deny_reason("192.168.1.1", policy()), None);
        assert_eq!(deny_reason("172.16.0.1", policy()), None);
        assert_eq!(deny_reason("fd00::1", policy()), None);

        assert_eq!(
            deny_reason("10.0.0.1", restricted),
            Some(DenyReason::Private)
        );
        assert_eq!(
            deny_reason("192.168.1.1", restricted),
            Some(DenyReason::Private)
        );
        assert_eq!(
            deny_reason("fd00::1", restricted),
            Some(DenyReason::Private)
        );
        assert_eq!(
            deny_reason("::ffff:10.0.0.1", restricted),
            Some(DenyReason::Private)
        );
    }

    #[test]
    fn allows_ordinary_public_destinations() {
        assert_eq!(deny_reason("93.184.216.34", policy()), None);
        assert_eq!(deny_reason("2606:4700:4700::1111", policy()), None);
        assert_eq!(
            deny_reason(
                "172.32.0.1",
                DestinationPolicy {
                    allow_private: false
                }
            ),
            None
        );
    }

    #[test]
    fn resolves_ifindex_from_device_name() {
        let index = resolve_ifindex(LOOPBACK_DEVICE).unwrap();

        assert!(index.get() > 0);
    }

    #[test]
    fn rejects_unknown_and_malformed_device_names() {
        assert!(matches!(
            resolve_ifindex("tc-does-not-exist0"),
            Err(EgressError::UnknownInterface(_))
        ));
        assert!(matches!(
            resolve_ifindex("bad\0name"),
            Err(EgressError::InvalidInterfaceName(_))
        ));
    }

    #[test]
    fn rejects_unspecified_tunnel_source_address() {
        // The leak this guards: bind(0.0.0.0:0) succeeds, `ip rule from <tunip>` never matches,
        // and every proxied connection egresses over the physical interface.
        assert!(matches!(
            tunnel_up_err("0.0.0.0", None),
            EgressError::InvalidTunnelAddress(IpAddr::V4(_))
        ));
        assert!(matches!(
            tunnel_up_err("10.8.0.2", Some("::")),
            EgressError::InvalidTunnelAddress(IpAddr::V6(_))
        ));
    }

    #[test]
    fn rejects_non_unicast_tunnel_source_addresses() {
        for addr in [
            "0.1.2.3",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                matches!(
                    tunnel_up_err(addr, None),
                    EgressError::InvalidTunnelAddress(_)
                ),
                "{addr} was accepted as a tunnel source"
            );
        }

        for addr in ["::1", "ff02::1", "fe80::1", "febf::1", "::ffff:10.8.0.2"] {
            assert!(
                matches!(
                    tunnel_up_err("10.8.0.2", Some(addr)),
                    EgressError::InvalidTunnelAddress(IpAddr::V6(_))
                ),
                "{addr} was accepted as a tunnel v6 source"
            );
        }
    }

    #[test]
    fn accepts_ordinary_tunnel_source_addresses() {
        let state = EgressState::new(policy());

        let egress = state
            .tunnel_up(&tunnel_config("10.8.0.2", Some("fd00:dead:beef::2")))
            .unwrap();

        assert_eq!(egress.ipv4(), Ipv4Addr::new(10, 8, 0, 2));
        assert!(egress.ipv6().is_some());
        assert!(egress.is_current());
    }

    #[test]
    fn tunnel_up_bumps_generation_and_strands_the_previous_handle() {
        let state = EgressState::new(policy());

        let first = loopback_egress(&state);
        let second = loopback_egress(&state);

        assert!(!first.is_current());
        assert!(second.is_current());
        assert!(second.generation() > first.generation());
        assert_eq!(state.generation(), second.generation());
    }

    #[test]
    fn tunnel_down_makes_current_report_not_ready() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        state.tunnel_down().unwrap();

        assert!(!egress.is_current());
        assert!(matches!(state.current(), Err(EgressError::TunnelNotReady)));
    }

    #[test]
    fn current_reports_not_ready_before_any_tunnel_up() {
        let state = EgressState::new(policy());

        assert!(matches!(state.current(), Err(EgressError::TunnelNotReady)));
    }

    #[tokio::test]
    async fn stale_handle_refuses_to_dial() {
        let state = EgressState::new(policy());
        let stale = loopback_egress(&state);
        let _fresh = loopback_egress(&state);

        let result = stale.tcp("93.184.216.34:80".parse().unwrap()).await;

        assert!(matches!(result, Err(EgressError::StaleTunnel)));
    }

    #[tokio::test]
    async fn stale_handle_refuses_to_create_a_udp_socket() {
        let state = EgressState::new(policy());
        let stale = loopback_egress(&state);
        state.tunnel_down().unwrap();

        assert!(matches!(stale.udp(), Err(EgressError::StaleTunnel)));
    }

    #[tokio::test]
    async fn refuses_denied_destination_before_dialling() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        let result = egress.tcp("127.0.0.1:9".parse().unwrap()).await;

        assert!(matches!(
            result,
            Err(EgressError::DestinationDenied {
                reason: DenyReason::Loopback,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn refuses_mapped_loopback_destination() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        let result = egress.tcp("[::ffff:127.0.0.1]:9".parse().unwrap()).await;

        assert!(matches!(
            result,
            Err(EgressError::DestinationDenied {
                reason: DenyReason::Loopback,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn refuses_port_zero() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        let result = egress.tcp("93.184.216.34:0".parse().unwrap()).await;

        assert!(matches!(result, Err(EgressError::InvalidPort)));
    }

    #[tokio::test]
    async fn refuses_ipv6_egress_on_a_v4_only_tunnel() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        let tcp = egress
            .tcp("[2606:4700:4700::1111]:53".parse().unwrap())
            .await;

        assert!(matches!(tcp, Err(EgressError::Ipv6Unsupported)));
        assert!(matches!(egress.udp_v6(), Err(EgressError::Ipv6Unsupported)));
    }

    #[test]
    fn tolerates_enoprotoopt_and_propagates_other_errors() {
        // Arrange: setsockopt reports failure via -1 plus errno.
        assert!(tolerate_missing_option(0).is_ok());

        set_errno(libc::ENOPROTOOPT);
        assert!(tolerate_missing_option(-1).is_ok());

        set_errno(libc::EACCES);
        let err = tolerate_missing_option(-1).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    fn set_errno(value: libc::c_int) {
        // SAFETY: `__error`/`__errno_location` return a valid pointer to this thread's errno for
        // the lifetime of the thread; writing an int through it is the documented way to set it.
        unsafe {
            #[cfg(target_os = "macos")]
            {
                *libc::__error() = value;
            }
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = value;
            }
        }
    }

    #[tokio::test]
    async fn pinned_udp_socket_is_bound_to_the_tunnel_address() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);

        let sock = egress.udp().unwrap();

        assert_eq!(
            sock.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    /// The real pin: bind to an actual interface index and complete a connection through it.
    /// `connect_v4` is called directly because the denylist correctly refuses loopback.
    #[tokio::test]
    async fn pinned_tcp_socket_connects_through_the_named_interface() {
        let state = EgressState::new(policy());
        let egress = loopback_egress(&state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dst = listener.local_addr().unwrap();

        let stream = egress.connect_v4(dst).await.unwrap();

        assert_eq!(stream.peer_addr().unwrap(), dst);
        assert_eq!(
            stream.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[test]
    fn classifies_unreachable_errors_distinctly() {
        let dst: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let net = classify_dial(io::Error::from_raw_os_error(libc::ENETUNREACH), dst);
        let host = classify_dial(io::Error::from_raw_os_error(libc::EHOSTUNREACH), dst);
        let refused = classify_dial(io::Error::from_raw_os_error(libc::ECONNREFUSED), dst);
        let other = classify_dial(io::Error::from_raw_os_error(libc::ETIMEDOUT), dst);

        assert!(matches!(net, EgressError::NetworkUnreachable));
        assert!(matches!(host, EgressError::HostUnreachable));
        assert!(matches!(refused, EgressError::ConnectionRefused(_)));
        assert!(matches!(other, EgressError::Io(_)));
    }

    #[test]
    fn canonicalize_collapses_only_mapped_addresses() {
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:80".parse().unwrap();
        let native: SocketAddr = "[2606:4700:4700::1111]:80".parse().unwrap();

        assert_eq!(canonicalize(mapped), "1.2.3.4:80".parse().unwrap());
        assert_eq!(canonicalize(native), native);
    }
}
