// SPDX-License-Identifier: GPL-3.0-or-later

//! SPEC.md §5.5, executed rather than asserted about a helper.
//!
//! The claim is that a v4-only tunnel refuses `AF_INET6` *outright*: SOCKS5 `ATYP=0x04` gets
//! REP `0x08`, an HTTP `CONNECT` to a v6 literal gets 403, and neither ever reaches the dialer.
//! The unit tests cover each parser in isolation; this drives the real listener over a real
//! socket, which is the only thing that proves the refusal survives assembly.
//!
//! The dialer records every target it is handed. A refusal that still dialled would be a leak
//! wearing an error code, so "the dialer was never called" is the assertion that matters.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The ban exists so that no production path can hand a hostname to getaddrinfo. Every address
// here is an already-resolved loopback `SocketAddr` produced by the listener itself.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thisconnect_proxy::listener::{self, AuthSetting, ListenerConfig};
use thisconnect_proxy::socks5::{DialError, Dialer, Target};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;

#[derive(Default)]
struct RecordingDialer {
    dialed: Mutex<Vec<String>>,
}

impl RecordingDialer {
    fn dialed(&self) -> Vec<String> {
        self.dialed.lock().expect("dial log").clone()
    }
}

impl Dialer for RecordingDialer {
    type Stream = DuplexStream;

    async fn tcp(&self, target: &Target) -> Result<Self::Stream, DialError> {
        self.dialed
            .lock()
            .expect("dial log")
            .push(format!("{target:?}"));
        let (ours, theirs) = duplex(64);
        drop(ours);
        Ok(theirs)
    }
}

async fn start_v4_only_proxy() -> (listener::Handle, Arc<RecordingDialer>, SocketAddr) {
    let dialer = Arc::new(RecordingDialer::default());
    let config = ListenerConfig {
        handshake_timeout: Duration::from_secs(5),
        ..ListenerConfig::new(
            vec!["127.0.0.1:0".parse().expect("bind addr")],
            AuthSetting::Disabled,
            false,
        )
    };
    let handle = listener::start(config, Arc::clone(&dialer))
        .await
        .expect("listener started");
    let addr = handle.listen_addrs().first().copied().expect("bound addr");
    (handle, dialer, addr)
}

/// SOCKS5 greeting with the no-auth method, then a CONNECT carrying `atyp`/`addr`.
async fn socks5_connect(addr: SocketAddr, atyp: u8, raw_addr: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .expect("method reply");
    assert_eq!(greeting, [0x05, 0x00], "no-auth should have been selected");

    let mut request = vec![0x05, 0x01, 0x00, atyp];
    request.extend_from_slice(raw_addr);
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await.expect("request");

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("reply");
    reply.to_vec()
}

#[tokio::test]
async fn a_v4_only_tunnel_refuses_a_socks5_v6_literal_without_dialing() {
    let (handle, dialer, addr) = start_v4_only_proxy().await;

    let reply = socks5_connect(
        addr,
        0x04,
        &[
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
    )
    .await;

    assert_eq!(reply[0], 0x05, "reply must be SOCKS5");
    assert_eq!(
        reply[1], 0x08,
        "§5.5 requires REP 0x08 (address type not supported) for ATYP=0x04 on a v4-only tunnel"
    );
    assert!(
        dialer.dialed().is_empty(),
        "the refusal must happen before the dial, not after it: {:?}",
        dialer.dialed()
    );

    handle.shutdown().await;
}

#[tokio::test]
async fn a_v4_only_tunnel_refuses_an_http_connect_to_a_v6_literal_without_dialing() {
    let (handle, dialer, addr) = start_v4_only_proxy().await;

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\nHost: [2606:4700:4700::1111]:443\r\n\r\n")
        .await
        .expect("request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("response");

    assert!(
        response.starts_with("HTTP/1.1 403"),
        "§5.5 requires 403 for a v6 literal on a v4-only tunnel, got: {response:?}"
    );
    assert!(
        dialer.dialed().is_empty(),
        "the refusal must happen before the dial: {:?}",
        dialer.dialed()
    );

    handle.shutdown().await;
}

/// The control. Without it the two refusals above are equally satisfied by a listener that
/// rejects everything, or by a dialer that is never wired up at all.
#[tokio::test]
async fn the_same_proxy_still_dials_a_v4_literal() {
    let (handle, dialer, addr) = start_v4_only_proxy().await;

    let reply = socks5_connect(addr, 0x01, &[1, 1, 1, 1]).await;

    assert_eq!(reply[1], 0x00, "a v4 destination must still succeed");
    assert_eq!(
        dialer.dialed().len(),
        1,
        "the v4 destination should have reached the dialer"
    );

    handle.shutdown().await;
}
