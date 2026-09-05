// SPDX-License-Identifier: GPL-3.0-or-later

//! IPC server: accept, authenticate, then speak line-delimited JSON (SPEC.md 7.4).
//!
//! Authentication happens in the accept loop, before the connection is handed to
//! a task and before a single byte of it is read, so no unauthenticated peer
//! ever reaches command dispatch.

pub mod listener;
pub mod proto;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::peerauth::{PeerAuthenticator, PeerIdentity};
use proto::{Command, ErrorCode, Request, Response};

/// A control command is a few hundred bytes; anything larger is a bug or an
/// attempt to exhaust a privileged process's memory.
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// How long in-flight connections get to finish once shutdown is signalled.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("command is not implemented in this build")]
    NotImplemented,
    /// Reserved for handlers the supervisor module registers.
    #[allow(dead_code)]
    #[error("internal error")]
    Internal,
}

impl HandlerError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::NotImplemented => ErrorCode::NotImplemented,
            Self::Internal => ErrorCode::Internal,
        }
    }
}

pub trait CommandHandler: Send + Sync + 'static {
    fn handle(&self, peer: &PeerIdentity, command: Command) -> Result<Value, HandlerError>;
}

/// Answers only what the skeleton owns. Connection lifecycle lands here once the
/// supervisor is wired in; until then it says so rather than faking a state.
pub struct SkeletonHandler;

impl CommandHandler for SkeletonHandler {
    fn handle(&self, _peer: &PeerIdentity, command: Command) -> Result<Value, HandlerError> {
        match command {
            Command::Ping => Ok(json!({ "pong": true })),
            Command::Version => Ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
            Command::Status => Err(HandlerError::NotImplemented),
        }
    }
}

pub struct IpcServer {
    listener: UnixListener,
    authenticator: Arc<dyn PeerAuthenticator>,
    handler: Arc<dyn CommandHandler>,
}

impl IpcServer {
    pub fn new(
        listener: UnixListener,
        authenticator: Arc<dyn PeerAuthenticator>,
        handler: Arc<dyn CommandHandler>,
    ) -> Self {
        Self {
            listener,
            authenticator,
            handler,
        }
    }

    /// Runs until `shutdown` flips to true, then drains in-flight connections.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    // A dropped sender means the supervisor is gone: stop too.
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept() => {
                    match accepted {
                        Ok((stream, _addr)) => {
                            self.dispatch(stream, &mut connections, shutdown.clone());
                        }
                        Err(err) => {
                            // Per-connection failure; the listener stays up.
                            warn!(error = %err, "accept failed");
                        }
                    }
                }
            }
        }

        info!("draining IPC connections");
        if tokio::time::timeout(DRAIN_TIMEOUT, drain(&mut connections))
            .await
            .is_err()
        {
            warn!("IPC connections did not drain in time; aborting them");
            connections.abort_all();
        }
    }

    fn dispatch(
        &self,
        stream: UnixStream,
        connections: &mut JoinSet<()>,
        shutdown: watch::Receiver<bool>,
    ) {
        let peer = match self.authenticator.authenticate(&stream) {
            Ok(peer) => peer,
            Err(err) => {
                // Fail closed: the peer learns nothing beyond a closed socket.
                warn!(error = %err, "rejected unauthenticated IPC peer");
                return;
            }
        };
        debug!(uid = peer.uid, pid = ?peer.pid, "authenticated IPC peer");
        let handler = Arc::clone(&self.handler);
        connections.spawn(async move {
            if let Err(err) = serve_connection(stream, peer, handler, shutdown).await {
                debug!(error = %err, "IPC connection ended");
            }
        });
    }
}

async fn drain(connections: &mut JoinSet<()>) {
    while connections.join_next().await.is_some() {}
}

/// Line framing is hand-rolled on a size-limited reader rather than built on
/// `LinesCodec`, because driving a `Framed` needs the `futures` `Sink`/`Stream`
/// extension traits, which are not in this crate's dependency set. The wire
/// format is identical.
async fn serve_connection(
    stream: UnixStream,
    peer: PeerIdentity,
    handler: Arc<dyn CommandHandler>,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).take(MAX_REQUEST_BYTES);
    let mut line = Vec::with_capacity(1024);

    loop {
        line.clear();
        reader.set_limit(MAX_REQUEST_BYTES);

        // `read_until` is not cancel-safe, which is fine here: the only thing
        // that cancels it is shutdown, and the connection is closed on shutdown.
        let read = tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            read = reader.read_until(b'\n', &mut line) => read?,
        };

        if read == 0 {
            return Ok(());
        }
        if !line.ends_with(b"\n") {
            // Either the peer exceeded the cap or it closed mid-line. Framing is
            // unrecoverable past that point: answer once, then close.
            let too_large = Response::failure(None, ErrorCode::BadRequest, "request too large");
            write_response(&mut write_half, &too_large).await?;
            return Ok(());
        }

        let response = match std::str::from_utf8(&line) {
            Ok(text) => respond(&peer, handler.as_ref(), text.trim_end()),
            Err(_) => Response::failure(None, ErrorCode::BadRequest, "malformed request"),
        };
        let malformed = !response.ok;
        write_response(&mut write_half, &response).await?;
        if malformed {
            // The peer and the daemon disagree about the protocol; continuing to
            // parse its stream is not worth the risk.
            return Ok(());
        }
    }
}

fn respond(peer: &PeerIdentity, handler: &dyn CommandHandler, line: &str) -> Response {
    let request: Request = match serde_json::from_str(line) {
        Ok(request) => request,
        // A serde error message quotes the peer's own input; keep it off the
        // wire and out of the log.
        Err(_) => return Response::failure(None, ErrorCode::BadRequest, "malformed request"),
    };

    match handler.handle(peer, request.cmd) {
        Ok(data) => Response::success(request.id, data),
        Err(err) => {
            if matches!(err, HandlerError::Internal) {
                error!(command = ?request.cmd, "command handler failed");
            }
            Response::failure(request.id, err.code(), &err.to_string())
        }
    }
}

async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &Response,
) -> std::io::Result<()> {
    // Serialising our own types cannot fail; degrade rather than panic.
    let mut encoded = serde_json::to_string(response).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"internal","message":"internal error"}}"#.to_owned()
    });
    encoded.push('\n');
    writer.write_all(encoded.as_bytes()).await
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::peerauth::AuthError;
    use std::path::PathBuf;

    struct AcceptAll;

    impl PeerAuthenticator for AcceptAll {
        fn authenticate(&self, _stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
            Ok(PeerIdentity {
                uid: 501,
                gid: Some(20),
                pid: Some(1),
            })
        }

        fn describe(&self) -> &'static str {
            "test: accept all"
        }
    }

    struct DenyAll;

    impl PeerAuthenticator for DenyAll {
        fn authenticate(&self, _stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
            Err(AuthError::NotAuthorised {
                uid: 501,
                gid: Some(20),
            })
        }

        fn describe(&self) -> &'static str {
            "test: deny all"
        }
    }

    fn scratch_path(name: &str) -> PathBuf {
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        std::env::temp_dir().join(format!("thisconnect-ipc-{pid}-{name}"))
    }

    struct Harness {
        path: PathBuf,
        shutdown: watch::Sender<bool>,
    }

    impl Harness {
        fn start(name: &str, authenticator: Arc<dyn PeerAuthenticator>) -> Self {
            let path = scratch_path(name);
            let _ = std::fs::remove_file(&path);
            let config = listener::ListenerConfig::new(path.clone());
            let listener = listener::bind_fallback(&config).expect("bind");
            let (shutdown, rx) = watch::channel(false);
            let server = IpcServer::new(listener, authenticator, Arc::new(SkeletonHandler));
            tokio::spawn(server.run(rx));
            Self { path, shutdown }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = self.shutdown.send(true);
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn round_trip(path: &PathBuf, request: &str) -> Option<String> {
        let stream = UnixStream::connect(path).await.ok()?;
        let (read_half, mut write_half) = stream.into_split();
        write_half.write_all(request.as_bytes()).await.ok()?;
        let mut reply = String::new();
        BufReader::new(read_half).read_line(&mut reply).await.ok()?;
        (!reply.is_empty()).then_some(reply)
    }

    #[tokio::test]
    async fn answers_ping_for_an_authenticated_peer() {
        let harness = Harness::start("ping.sock", Arc::new(AcceptAll));

        let reply = round_trip(&harness.path, "{\"id\":\"1\",\"cmd\":\"ping\"}\n").await;

        assert_eq!(
            reply.as_deref(),
            Some("{\"id\":\"1\",\"ok\":true,\"data\":{\"pong\":true}}\n")
        );
    }

    #[tokio::test]
    async fn closes_the_connection_of_an_unauthenticated_peer_without_answering() {
        let harness = Harness::start("denied.sock", Arc::new(DenyAll));

        let reply = round_trip(&harness.path, "{\"cmd\":\"ping\"}\n").await;

        assert_eq!(reply, None);
    }

    #[tokio::test]
    async fn rejects_a_malformed_line_without_echoing_the_input() {
        let harness = Harness::start("malformed.sock", Arc::new(AcceptAll));

        let reply = round_trip(&harness.path, "not json at all\n")
            .await
            .expect("reply");

        assert!(reply.contains("\"code\":\"bad-request\""));
        assert!(!reply.contains("not json at all"));
    }

    #[tokio::test]
    async fn rejects_a_request_carrying_an_unknown_field() {
        let harness = Harness::start("unknown-field.sock", Arc::new(AcceptAll));

        let reply = round_trip(&harness.path, "{\"cmd\":\"ping\",\"uid\":0}\n")
            .await
            .expect("reply");

        assert!(reply.contains("\"code\":\"bad-request\""));
    }

    #[tokio::test]
    async fn rejects_an_oversized_line_instead_of_buffering_it() {
        let harness = Harness::start("oversized.sock", Arc::new(AcceptAll));
        let oversized = format!("{}\n", "a".repeat(MAX_REQUEST_BYTES as usize + 16));
        let stream = UnixStream::connect(&harness.path).await.expect("connect");
        let (read_half, mut write_half) = stream.into_split();
        // The server answers and closes before the write finishes, so the write
        // runs concurrently and its EPIPE is expected.
        tokio::spawn(async move {
            let _ = write_half.write_all(oversized.as_bytes()).await;
        });

        let mut reply = String::new();
        BufReader::new(read_half)
            .read_line(&mut reply)
            .await
            .expect("read reply");

        assert!(reply.contains("request too large"));
    }

    #[tokio::test]
    async fn reports_status_as_not_implemented_rather_than_inventing_a_state() {
        let harness = Harness::start("status.sock", Arc::new(AcceptAll));

        let reply = round_trip(&harness.path, "{\"cmd\":\"status\"}\n")
            .await
            .expect("reply");

        assert!(reply.contains("\"code\":\"not-implemented\""));
    }

    #[tokio::test]
    async fn stops_accepting_once_shutdown_is_signalled() {
        let harness = Harness::start("shutdown.sock", Arc::new(AcceptAll));
        harness.shutdown.send(true).expect("signal");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reply = round_trip(&harness.path, "{\"cmd\":\"ping\"}\n").await;

        assert_eq!(reply, None);
    }

    #[test]
    fn skeleton_handler_reports_the_crate_version() {
        let peer = PeerIdentity {
            uid: 0,
            gid: None,
            pid: None,
        };

        let data = SkeletonHandler
            .handle(&peer, Command::Version)
            .expect("version");

        assert_eq!(data["version"], env!("CARGO_PKG_VERSION"));
    }
}
