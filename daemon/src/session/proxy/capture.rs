// SPDX-License-Identifier: GPL-3.0-or-later

//! Getting the tunnel's DNS out of openvpn and into the proxy lifecycle.
//!
//! The resolver arrives exactly once, inside a `>LOG:` line, and it arrives
//! *before* the tunnel is up — so before anything the connect orchestrator could
//! subscribe to exists. The observation therefore happens one layer down, on the
//! management stream itself: every inbound line is scanned, `>LOG:` lines are
//! handed to the pure parser in [`super::super::dns`], and everything else is
//! discarded without being buffered.
//!
//! The tap never modifies the stream and never keeps the raw text: a control
//! message carries server-chosen material that must not be logged or persisted
//! (SPEC.md §5.4 D1). Only the parsed values survive one line.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{info, warn};

use crate::mgmt::{LogEvent, MAX_INBOUND_LINE_BYTES};
use crate::session::dns::{DnsCapture, PushReply};
use crate::session::spawn::BoxFuture;
use crate::session::transport::{BoxStream, MgmtTransport, MgmtTransportFactory};
use crate::session::SessionError;

/// Only this shape can carry a `PUSH_REPLY`; anything else is skipped without
/// being copied, which keeps prompts and auth tokens out of the tap's buffer.
const LOG_PREFIX: &[u8] = b">LOG:";

/// openvpn logs the push as `PUSH: Received control message: 'PUSH_REPLY,…'`.
const CONTROL_MESSAGE_MARKER: &str = "Received control message:";
const PUSH_REPLY_KIND: &str = "PUSH_REPLY";

/// The session's DNS capture, shared between the tap that fills it and the
/// publisher that reads it.
#[derive(Debug)]
pub struct DnsCaptureCell {
    capture: Mutex<DnsCapture>,
}

impl Default for DnsCaptureCell {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCaptureCell {
    /// Starts out as "the tunnel is up and no push was ever seen", which is the
    /// honest state before openvpn has said anything.
    pub fn new() -> Self {
        Self {
            capture: Mutex::new(DnsCapture::none_received()),
        }
    }

    pub fn current(&self) -> DnsCapture {
        lock(&self.capture).clone()
    }

    pub fn reset(&self) {
        *lock(&self.capture) = DnsCapture::none_received();
    }

    /// Folds one inbound management line in. Anything that is not an accepted
    /// `PUSH_REPLY` leaves the cell untouched.
    pub fn observe_line(&self, line: &str) {
        let Some(payload) = line.strip_prefix(">LOG:") else {
            return;
        };
        let text = LogEvent::parse(payload).text;
        if !is_push_reply(&text) {
            return;
        }
        let Some(reply) = PushReply::from_log_text(&text) else {
            return;
        };
        self.absorb(
            reply.capture(),
            reply.dropped_addresses(),
            reply.dropped_domains(),
        );
    }

    fn absorb(&self, capture: DnsCapture, dropped_addresses: usize, dropped_domains: usize) {
        if dropped_addresses > 0 || dropped_domains > 0 {
            warn!(
                dropped_addresses,
                dropped_domains, "discarded malformed values from the tunnel's push"
            );
        }
        let mut slot = lock(&self.capture);
        match &capture {
            DnsCapture::Captured(dns) => {
                info!(
                    servers = dns.nameservers.len(),
                    domains = dns.search_domains.len(),
                    has_v6 = dns.tunnel_has_v6,
                    "captured the tunnel's DNS from the server's push"
                );
                *slot = capture;
            }
            // A renegotiation that pushes a thinner option set must not demote a
            // resolver we already have: worst case the session keeps querying a
            // server that has gone away, which fails closed. Losing it would send
            // every later query to the third-party fallback instead.
            DnsCapture::Missing(reason) => {
                if slot.captured().is_none() {
                    warn!(%reason, "the tunnel's push carried no usable DNS server");
                    *slot = capture;
                }
            }
        }
    }
}

/// Wraps a transport so every management line the daemon reads is also offered
/// to the DNS capture.
pub struct TappedTransportFactory {
    inner: Arc<dyn MgmtTransportFactory>,
    capture: Arc<DnsCaptureCell>,
}

impl TappedTransportFactory {
    pub fn new(inner: Arc<dyn MgmtTransportFactory>, capture: Arc<DnsCaptureCell>) -> Self {
        Self { inner, capture }
    }
}

impl MgmtTransportFactory for TappedTransportFactory {
    fn bind(&self, path: &Path) -> Result<Box<dyn MgmtTransport>, SessionError> {
        // A new management socket is a new session; whatever the last one
        // captured describes a tunnel that no longer exists.
        self.capture.reset();
        Ok(Box::new(TappedTransport {
            inner: self.inner.bind(path)?,
            capture: Arc::clone(&self.capture),
        }))
    }
}

struct TappedTransport {
    inner: Box<dyn MgmtTransport>,
    capture: Arc<DnsCaptureCell>,
}

impl MgmtTransport for TappedTransport {
    fn accept(&self, timeout: Duration) -> BoxFuture<'_, Result<BoxStream, SessionError>> {
        Box::pin(async move {
            let stream = self.inner.accept(timeout).await?;
            let tapped = TappedStream {
                inner: stream,
                scanner: LineScanner::default(),
                capture: Arc::clone(&self.capture),
            };
            Ok(Box::new(tapped) as BoxStream)
        })
    }
}

/// Passes bytes through untouched and mirrors the inbound half into the capture.
struct TappedStream<S> {
    inner: S,
    scanner: LineScanner,
    capture: Arc<DnsCaptureCell>,
}

impl<S: AsyncRead + Unpin> AsyncRead for TappedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let outcome = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(outcome, Poll::Ready(Ok(()))) {
            this.scanner.push(&buf.filled()[before..], &this.capture);
        }
        outcome
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TappedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Reassembles lines across reads. Lines that cannot be a `>LOG:` are skipped
/// byte by byte rather than buffered, so the only management text this type ever
/// holds is a log line.
#[derive(Debug, Default)]
struct LineScanner {
    line: Vec<u8>,
    skipping: bool,
}

impl LineScanner {
    fn push(&mut self, bytes: &[u8], capture: &DnsCaptureCell) {
        for &byte in bytes {
            if byte == b'\n' {
                self.finish(capture);
            } else if !self.skipping {
                self.absorb(byte);
            }
        }
    }

    fn absorb(&mut self, byte: u8) {
        self.line.push(byte);
        let still_possible = if self.line.len() <= LOG_PREFIX.len() {
            LOG_PREFIX.starts_with(&self.line)
        } else {
            self.line.len() <= MAX_INBOUND_LINE_BYTES
        };
        if !still_possible {
            self.skipping = true;
            self.line.clear();
        }
    }

    fn finish(&mut self, capture: &DnsCaptureCell) {
        if !self.skipping && self.line.starts_with(LOG_PREFIX) {
            if let Ok(text) = std::str::from_utf8(&self.line) {
                capture.observe_line(text.trim_end_matches('\r'));
            }
        }
        self.line.clear();
        self.skipping = false;
    }
}

/// The kind is matched where openvpn actually puts it — first thing in the
/// control message body — and not merely searched for. A message whose *body*
/// happens to contain `PUSH_REPLY` is a server-controlled string: accepting it
/// would let a peer smuggle a `dhcp-option DNS` of its choosing through any
/// other message and take over the session's resolver.
fn is_push_reply(text: &str) -> bool {
    let Some((_, message)) = text.split_once(CONTROL_MESSAGE_MARKER) else {
        return false;
    };
    let message = message.trim_start();
    let body = message.strip_prefix(['\'', '"']).unwrap_or(message);
    let Some(rest) = body.strip_prefix(PUSH_REPLY_KIND) else {
        return false;
    };
    // A push with no options at all is `'PUSH_REPLY'`; anything else that
    // continues the token is a different kind whose name merely starts the same.
    rest.is_empty() || rest.starts_with([',', '\'', '"'])
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests;
