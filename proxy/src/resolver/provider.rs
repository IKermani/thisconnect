// SPDX-License-Identifier: GPL-3.0-or-later

//! The hickory [`RuntimeProvider`] that makes an unpinned DNS socket structurally impossible
//! (SPEC.md §5.4 D2).
//!
//! hickory only ever obtains sockets through this trait, and both implementations here go through
//! [`TunEgress`]. There is no `bind_addr` honoured, no unspecified-address bind, and no branch that
//! produces a socket the tunnel did not create: a resolver built on this provider cannot send a
//! query out of the physical interface even if its configuration says to.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::net::runtime::{RuntimeProvider, TokioHandle, TokioTime};
use tokio::net::{TcpStream, UdpSocket};

use crate::egress::{EgressError, TunEgress};

/// Applied when hickory passes no deadline of its own, so a black-holed nameserver cannot hold a
/// connection attempt open for the kernel's full SYN retry budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct EgressRuntimeProvider {
    egress: Arc<TunEgress>,
    handle: TokioHandle,
}

impl EgressRuntimeProvider {
    pub(crate) fn new(egress: Arc<TunEgress>) -> Self {
        Self {
            egress,
            handle: TokioHandle::default(),
        }
    }
}

impl RuntimeProvider for EgressRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        // The caller's `bind_addr` is deliberately discarded: the only source address this proxy
        // may ever use is the tunnel's, and honouring a hint would make that negotiable.
        let egress = Arc::clone(&self.egress);
        let deadline = wait_for.unwrap_or(CONNECT_TIMEOUT);
        Box::pin(async move {
            match tokio::time::timeout(deadline, egress.tcp(server_addr)).await {
                Ok(Ok(stream)) => {
                    stream.set_nodelay(true)?;
                    Ok(AsyncIoTokioAsStd(stream))
                }
                Ok(Err(err)) => Err(to_io_error(err)),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tunnel-pinned DNS connection timed out",
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        _local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        // Same reasoning as `connect_tcp`: the local address is the tunnel's, chosen by the egress
        // dialer. Only the destination family is taken from the caller.
        let egress = Arc::clone(&self.egress);
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => egress.udp(),
                SocketAddr::V6(_) => egress.udp_v6(),
            };
            socket.map_err(to_io_error)
        })
    }
}

/// hickory speaks `io::Error`, so the egress failure has to be flattened — but the *kind* is
/// preserved, because "tunnel not ready" and "refused by policy" must stay distinguishable from a
/// generic network error all the way up to the SOCKS5 reply code.
fn to_io_error(err: EgressError) -> io::Error {
    let kind = match &err {
        EgressError::TunnelNotReady | EgressError::StaleTunnel => io::ErrorKind::NotConnected,
        EgressError::DestinationDenied { .. } => io::ErrorKind::PermissionDenied,
        EgressError::Ipv6Unsupported => io::ErrorKind::Unsupported,
        EgressError::NetworkUnreachable => io::ErrorKind::NetworkUnreachable,
        EgressError::HostUnreachable => io::ErrorKind::HostUnreachable,
        EgressError::ConnectionRefused(_) => io::ErrorKind::ConnectionRefused,
        EgressError::Io(inner) => inner.kind(),
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, err)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::egress::{DenyReason, DestinationPolicy, EgressState, TunnelConfig};

    const LOOPBACK_DEVICE: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    fn state_with_tunnel() -> (EgressState, Arc<TunEgress>) {
        let state = EgressState::new(DestinationPolicy::default());
        let egress = state
            .tunnel_up(&TunnelConfig {
                device: LOOPBACK_DEVICE.to_owned(),
                ipv4: Ipv4Addr::new(10, 255, 255, 2),
                ipv6: None,
                mtu: 1240,
            })
            .unwrap();
        (state, egress)
    }

    #[test]
    fn tunnel_not_ready_maps_to_not_connected() {
        // Arrange / Act
        let err = to_io_error(EgressError::TunnelNotReady);

        // Assert
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn a_denied_destination_maps_to_permission_denied() {
        // Arrange
        let denied = EgressError::DestinationDenied {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            reason: DenyReason::Loopback,
        };

        // Act
        let err = to_io_error(denied);

        // Assert
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn an_io_failure_keeps_its_original_kind() {
        // Arrange
        let inner = io::Error::from(io::ErrorKind::ConnectionReset);

        // Act
        let err = to_io_error(EgressError::Io(inner));

        // Assert
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn udp_binding_is_refused_once_the_tunnel_is_gone() {
        // Arrange
        let (state, egress) = state_with_tunnel();
        let provider = EgressRuntimeProvider::new(egress);
        state.tunnel_down().unwrap();

        // Act
        let bound = provider
            .bind_udp(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
            )
            .await;

        // Assert
        assert_eq!(
            bound.map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[tokio::test]
    async fn ipv6_udp_binding_is_refused_on_a_v4_only_tunnel() {
        // Arrange
        let (_state, egress) = state_with_tunnel();
        let provider = EgressRuntimeProvider::new(egress);

        // Act
        let bound = provider
            .bind_udp(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                "[2620:fe::fe]:53".parse().unwrap(),
            )
            .await;

        // Assert
        assert_eq!(
            bound.map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[tokio::test]
    async fn a_loopback_nameserver_cannot_be_dialled_over_tcp() {
        // Arrange
        let (_state, egress) = state_with_tunnel();
        let provider = EgressRuntimeProvider::new(egress);

        // Act
        let dialled = provider
            .connect_tcp("127.0.0.1:53".parse().unwrap(), None, None)
            .await;

        // Assert
        assert_eq!(
            dialled.map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
