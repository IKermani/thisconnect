// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the management-log tap and the DNS capture it fills.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

const PUSH_LINE: &str = ">LOG:1741000000,I,PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example,ifconfig 10.8.0.2 255.255.255.0'";

fn servers(cell: &DnsCaptureCell) -> Vec<IpAddr> {
    cell.current()
        .captured()
        .map(|dns| dns.nameservers.clone())
        .unwrap_or_default()
}

#[test]
fn takes_the_resolver_out_of_an_accepted_push_reply() {
    // Arrange
    let cell = DnsCaptureCell::new();

    // Act
    cell.observe_line(PUSH_LINE);

    // Assert
    assert_eq!(servers(&cell), vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]);
    assert_eq!(
        cell.current().captured().expect("capture").search_domains,
        vec!["corp.example".to_owned()]
    );
}

#[test]
fn starts_out_reporting_that_no_push_was_ever_seen() {
    let cell = DnsCaptureCell::new();

    assert!(cell.current().captured().is_none());
}

#[test]
fn ignores_a_log_line_that_is_not_a_push_reply() {
    let cell = DnsCaptureCell::new();

    cell.observe_line(">LOG:1741000000,I,OPTIONS IMPORT: --ifconfig/up options modified");

    assert!(cell.current().captured().is_none());
}

#[test]
fn ignores_a_management_line_that_is_not_a_log_event() {
    let cell = DnsCaptureCell::new();

    cell.observe_line(">PASSWORD:Need 'Auth' username/password");

    assert!(cell.current().captured().is_none());
}

/// A renegotiation that pushes a thinner option set must not send the rest of
/// the session's queries to the third-party fallback.
#[test]
fn a_later_push_without_dns_does_not_demote_a_captured_resolver() {
    let cell = DnsCaptureCell::new();
    cell.observe_line(PUSH_LINE);

    cell.observe_line(
        ">LOG:1741000009,I,PUSH: Received control message: 'PUSH_REPLY,ping 10,ping-restart 60'",
    );

    assert_eq!(servers(&cell), vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]);
}

#[test]
fn resetting_forgets_the_previous_sessions_resolver() {
    let cell = DnsCaptureCell::new();
    cell.observe_line(PUSH_LINE);

    cell.reset();

    assert!(cell.current().captured().is_none());
}

#[tokio::test]
async fn the_tap_hands_every_byte_through_unchanged() {
    // Arrange
    let (client, mut server) = tokio::io::duplex(4096);
    let capture = Arc::new(DnsCaptureCell::new());
    let mut tapped = TappedStream {
        inner: client,
        scanner: LineScanner::default(),
        capture: Arc::clone(&capture),
    };
    let payload = b">INFO:OpenVPN Management Interface Version 6\r\nSUCCESS: ok\r\n";

    // Act
    server.write_all(payload).await.expect("write");
    let mut received = vec![0_u8; payload.len()];
    tapped.read_exact(&mut received).await.expect("read");

    // Assert
    assert_eq!(received, payload);
}

#[tokio::test]
async fn a_push_reply_split_across_reads_is_still_captured() {
    let (client, mut server) = tokio::io::duplex(4096);
    let capture = Arc::new(DnsCaptureCell::new());
    let mut tapped = TappedStream {
        inner: client,
        scanner: LineScanner::default(),
        capture: Arc::clone(&capture),
    };
    let (head, tail) = PUSH_LINE.split_at(40);

    server.write_all(head.as_bytes()).await.expect("head");
    let mut buf = vec![0_u8; head.len()];
    tapped.read_exact(&mut buf).await.expect("read head");
    server
        .write_all(format!("{tail}\r\n").as_bytes())
        .await
        .expect("tail");
    let mut rest = vec![0_u8; tail.len() + 2];
    tapped.read_exact(&mut rest).await.expect("read tail");

    assert_eq!(
        servers(&capture),
        vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]
    );
}

#[tokio::test]
async fn a_line_that_cannot_be_a_log_event_is_never_buffered() {
    let capture = DnsCaptureCell::new();
    let mut scanner = LineScanner::default();

    scanner.push(b">PASSWORD:", &capture);

    assert!(scanner.skipping);
    assert!(scanner.line.is_empty());
}

#[test]
fn a_log_line_longer_than_the_management_reader_accepts_is_dropped() {
    let capture = DnsCaptureCell::new();
    let mut scanner = LineScanner::default();
    let flood = format!(">LOG:{}", "x".repeat(MAX_INBOUND_LINE_BYTES + 16));

    scanner.push(flood.as_bytes(), &capture);
    scanner.push(b"\n", &capture);

    assert!(scanner.line.is_empty());
    assert!(!scanner.skipping);
    assert!(capture.current().captured().is_none());
}

#[test]
fn binding_a_new_management_socket_clears_the_previous_capture() {
    let capture = Arc::new(DnsCaptureCell::new());
    capture.observe_line(PUSH_LINE);
    let factory = TappedTransportFactory::new(
        Arc::new(crate::session::transport::UnixTransportFactory),
        Arc::clone(&capture),
    );

    // The bind itself is expected to fail: the point is that a new session
    // never inherits the last one's resolver.
    let _ = factory.bind(Path::new("/nonexistent/thisconnect/mgmt.sock"));

    assert!(capture.current().captured().is_none());
}
