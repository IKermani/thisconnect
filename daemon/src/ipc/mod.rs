// SPDX-License-Identifier: GPL-3.0-or-later

//! IPC server: accept, authenticate, then speak line-delimited JSON (SPEC.md 7.4).
//!
//! Authentication happens in the accept loop, before the connection is handed to
//! a task and before a single byte of it is read, so no unauthenticated peer
//! ever reaches message dispatch.
//!
//! Traffic is bidirectional. Credential prompts and state events originate in
//! the daemon and are pushed without being asked for, while requests are
//! dispatched concurrently rather than one at a time — `connect` cannot answer
//! until the prompt it raises has been replied to over this same connection, so
//! serialising them deadlocks. Both directions funnel through one writer task so
//! the socket has a single owner and neither can interleave a partial line into
//! the other's message.

pub mod listener;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use thisconnect_shared::ipc::{
    ClientMessage, DaemonMessage, ErrorCode, IpcError, RequestId, MAX_MESSAGE_BYTES,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::peerauth::{PeerAuthenticator, PeerIdentity};

/// A control message is normally a few hundred bytes. The exception is
/// `profile_import`, which carries a `.ovpn` body with inline certificates, so
/// the cap is the protocol's own documented ceiling rather than something
/// tighter. Anything past it is a bug or an attempt to exhaust a privileged
/// process's memory.
pub const MAX_REQUEST_BYTES: u64 = MAX_MESSAGE_BYTES as u64;

/// How long in-flight connections get to finish once shutdown is signalled.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on messages queued toward one client. A GUI that stops reading must not
/// be able to grow the daemon's memory without limit.
const WRITE_QUEUE: usize = 256;

/// Dispatches a decoded client message and yields the reply to send back.
///
/// Returns a boxed future rather than being an `async fn` in a trait: the
/// implementation is stored behind `Arc<dyn ...>`, and making that object-safe
/// without `async-trait` means spelling the future out.
pub trait MessageHandler: Send + Sync + 'static {
    fn dispatch<'a>(
        &'a self,
        message: ClientMessage,
    ) -> Pin<Box<dyn Future<Output = DaemonMessage> + Send + 'a>>;
}

/// Daemon-initiated messages are produced by a single `SessionManager`, so there
/// is one receiver for the whole process. A connection leases it for as long as
/// it is served and returns it on close.
///
/// The consequence, which is deliberate for v1: if two GUIs connect, only the
/// one holding the lease sees prompts and events. The other can still issue
/// requests and read their responses. A second GUI is not a supported
/// configuration; this degrades rather than dropping messages on the floor.
type OutboundLease = Arc<Mutex<mpsc::Receiver<DaemonMessage>>>;

pub struct IpcServer {
    listener: UnixListener,
    authenticator: Arc<dyn PeerAuthenticator>,
    handler: Arc<dyn MessageHandler>,
    outbound: OutboundLease,
}

impl IpcServer {
    pub fn new(
        listener: UnixListener,
        authenticator: Arc<dyn PeerAuthenticator>,
        handler: Arc<dyn MessageHandler>,
        outbound: mpsc::Receiver<DaemonMessage>,
    ) -> Self {
        Self {
            listener,
            authenticator,
            handler,
            outbound: Arc::new(Mutex::new(outbound)),
        }
    }

    /// Runs until `shutdown` flips to true, then drains in-flight connections.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();

        loop {
            let accepted = tokio::select! {
                _ = shutdown.changed() => break,
                accepted = self.listener.accept() => accepted,
            };

            let (stream, _) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    warn!(%error, "accept failed");
                    continue;
                }
            };

            // Authenticate before the connection reaches a task, so an
            // unauthorised peer never gets as far as being read from.
            let peer = match self.authenticator.authenticate(&stream) {
                Ok(peer) => peer,
                Err(error) => {
                    // The peer learns nothing: no error is written back, the
                    // socket simply closes.
                    warn!(%error, "rejected an unauthenticated peer");
                    continue;
                }
            };

            debug!(uid = peer.uid, "client connected");
            let handler = Arc::clone(&self.handler);
            let outbound = Arc::clone(&self.outbound);
            let shutdown = shutdown.clone();
            connections.spawn(async move {
                if let Err(error) =
                    serve_connection(stream, peer, handler, outbound, shutdown).await
                {
                    debug!(%error, "connection closed");
                }
            });

            reap_finished(&mut connections);
        }

        drain(&mut connections).await;
    }
}

/// `JoinSet` only reclaims a finished task when it is polled, so a long-lived
/// server would otherwise accumulate one entry per connection it ever served.
fn reap_finished(connections: &mut JoinSet<()>) {
    while connections.try_join_next().is_some() {}
}

async fn drain(connections: &mut JoinSet<()>) {
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
}

async fn serve_connection(
    stream: UnixStream,
    peer: PeerIdentity,
    handler: Arc<dyn MessageHandler>,
    outbound: OutboundLease,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let (read_half, write_half) = stream.into_split();
    let (tx, rx) = mpsc::channel::<DaemonMessage>(WRITE_QUEUE);

    let writer = tokio::spawn(write_loop(write_half, rx));
    let pump = tokio::spawn(pump_outbound(Arc::clone(&outbound), tx.clone()));

    let result = read_loop(read_half, &peer, &handler, &tx, &mut shutdown).await;

    // Dropping every sender ends the writer; aborting the pump releases the
    // lease so the next connection can take it.
    pump.abort();
    drop(tx);
    let _ = writer.await;
    result
}

/// Moves daemon-initiated messages onto this connection's write queue for as
/// long as the connection holds the lease.
async fn pump_outbound(outbound: OutboundLease, tx: mpsc::Sender<DaemonMessage>) {
    let mut guard = outbound.lock().await;
    while let Some(message) = guard.recv().await {
        if tx.send(message).await.is_err() {
            return;
        }
    }
}

async fn read_loop(
    read_half: tokio::net::unix::OwnedReadHalf,
    peer: &PeerIdentity,
    handler_arc: &Arc<dyn MessageHandler>,
    tx: &mpsc::Sender<DaemonMessage>,
    shutdown: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(read_half).take(MAX_REQUEST_BYTES);
    let mut line = Vec::with_capacity(1024);

    loop {
        line.clear();
        reader.set_limit(MAX_REQUEST_BYTES);

        // `read_until` is not cancel-safe, which is fine here: the only thing
        // that cancels it is shutdown, and the connection closes on shutdown.
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
            let _ = tx.send(protocol_error("message too large")).await;
            return Ok(());
        }

        let message = match std::str::from_utf8(&line).map(str::trim_end) {
            Ok(text) => serde_json::from_str::<ClientMessage>(text).ok(),
            Err(_) => None,
        };

        let Some(message) = message else {
            // A serde error quotes the peer's own input verbatim; keep it off
            // the wire and out of the log.
            let _ = tx.send(protocol_error("malformed message")).await;
            return Ok(());
        };

        debug!(uid = peer.uid, "dispatching client message");
        // Dispatched on its own task, never awaited inline. `connect` does not
        // answer until the tunnel is up or the attempt failed, and getting there
        // requires the credential prompt to be answered — over this same
        // connection. Awaiting the reply here means the prompt reply is never
        // read, so connect waits for credentials that can never arrive. Replies
        // carry the request id and the writer task serialises them, so answering
        // out of order is well-defined.
        let handler = Arc::clone(handler_arc);
        let tx = tx.clone();
        tokio::spawn(async move {
            let reply = handler.dispatch(message).await;
            let _ = tx.send(reply).await;
        });
    }
}

/// A framing failure has no correlation id to echo, because the id lives inside
/// the message we could not parse.
fn protocol_error(message: &str) -> DaemonMessage {
    DaemonMessage::Error {
        id: RequestId(String::new()),
        error: IpcError::new(ErrorCode::MalformedMessage, message),
    }
}

async fn write_loop(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::Receiver<DaemonMessage>,
) {
    while let Some(message) = rx.recv().await {
        // Serialising our own types cannot fail; degrade rather than panic.
        let mut encoded = serde_json::to_string(&message).unwrap_or_else(|_| {
            r#"{"type":"error","id":"","error":{"code":"internal","message":"internal error"}}"#
                .to_owned()
        });
        encoded.push('\n');
        if writer.write_all(encoded.as_bytes()).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::peerauth::AuthError;
    use std::path::PathBuf;
    use thisconnect_shared::ipc::{Request, Response, PROTOCOL_VERSION};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

    /// Answers every request with `Ack` and records nothing: these tests are
    /// about framing, not about what the session does.
    struct EchoHandler;

    impl MessageHandler for EchoHandler {
        fn dispatch<'a>(
            &'a self,
            message: ClientMessage,
        ) -> Pin<Box<dyn Future<Output = DaemonMessage> + Send + 'a>> {
            Box::pin(async move {
                match message {
                    ClientMessage::Hello { id, .. } => DaemonMessage::Hello {
                        id,
                        protocol_version: PROTOCOL_VERSION,
                        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
                    },
                    ClientMessage::Request { id, .. } => DaemonMessage::Response {
                        id,
                        response: Response::Ack,
                    },
                    ClientMessage::PromptReply { id, .. } => DaemonMessage::Response {
                        id,
                        response: Response::Ack,
                    },
                }
            })
        }
    }

    struct AllowAll;

    impl PeerAuthenticator for AllowAll {
        fn authenticate(&self, _stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
            Ok(PeerIdentity {
                uid: 501,
                gid: None,
                pid: None,
            })
        }
        fn describe(&self) -> &'static str {
            "allow-all (test)"
        }
    }

    struct DenyAll;

    impl PeerAuthenticator for DenyAll {
        fn authenticate(&self, _stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
            Err(AuthError::NotAuthorised { uid: 0, gid: None })
        }
        fn describe(&self) -> &'static str {
            "deny-all (test)"
        }
    }

    struct Harness {
        path: PathBuf,
        shutdown: watch::Sender<bool>,
        outbound: mpsc::Sender<DaemonMessage>,
    }

    fn socket_path(name: &str) -> PathBuf {
        let pid = std::process::id();
        std::env::temp_dir().join(format!("thisconnect-ipc-{pid}-{name}.sock"))
    }

    fn start(auth: Arc<dyn PeerAuthenticator>, name: &str) -> Harness {
        let path = socket_path(name);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (outbound, outbound_rx) = mpsc::channel(16);
        let server = IpcServer::new(listener, auth, Arc::new(EchoHandler), outbound_rx);
        tokio::spawn(server.run(shutdown_rx));
        Harness {
            path,
            shutdown,
            outbound,
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = self.shutdown.send(true);
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// The server binds on a spawned task, so the first connect can lose the
    /// race. Retry briefly, then surface the last error rather than a bare panic.
    async fn connect(path: &PathBuf) -> std::io::Result<UnixStream> {
        let mut attempt = Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no attempt was made",
        ));
        for _ in 0..50 {
            attempt = UnixStream::connect(path).await;
            if attempt.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        attempt
    }

    #[tokio::test]
    async fn answers_a_hello_for_an_authenticated_peer() {
        // Arrange
        let h = start(Arc::new(AllowAll), "hello");
        let stream = connect(&h.path).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act
        let hello = serde_json::to_string(&ClientMessage::Hello {
            id: RequestId("1".to_owned()),
            protocol_version: PROTOCOL_VERSION,
            client_name: "test".to_owned(),
        })
        .expect("encode");
        w.write_all(format!("{hello}\n").as_bytes())
            .await
            .expect("write");

        // Assert
        let line = lines.next_line().await.expect("read").expect("a line");
        let reply: DaemonMessage = serde_json::from_str(&line).expect("decode");
        assert!(matches!(reply, DaemonMessage::Hello { .. }));
        let _ = h.shutdown.send(true);
    }

    #[tokio::test]
    async fn closes_an_unauthenticated_peer_without_answering() {
        // Arrange
        let h = start(Arc::new(DenyAll), "denied");
        let stream = connect(&h.path).await.expect("connect");
        let (r, _w) = stream.into_split();

        // Act
        let mut lines = TokioBufReader::new(r).lines();

        // Assert: EOF, not an error message that would confirm the socket works.
        assert!(lines.next_line().await.expect("read").is_none());
        let _ = h.shutdown.send(true);
    }

    #[tokio::test]
    async fn rejects_a_malformed_line_without_echoing_the_input() {
        // Arrange
        let h = start(Arc::new(AllowAll), "malformed");
        let stream = connect(&h.path).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act
        w.write_all(b"{\"type\":\"nonsense\",\"secret\":\"hunter2\"}\n")
            .await
            .expect("write");

        // Assert
        let line = lines.next_line().await.expect("read").expect("a line");
        assert!(!line.contains("hunter2"));
        assert!(line.contains("malformed"));
        let _ = h.shutdown.send(true);
    }

    #[tokio::test]
    async fn pushes_a_daemon_initiated_event_without_being_asked() {
        // Arrange
        let h = start(Arc::new(AllowAll), "pushed");
        let stream = connect(&h.path).await.expect("connect");
        let (r, _w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act: nothing is sent by the client at all.
        h.outbound
            .send(DaemonMessage::Error {
                id: RequestId("srv".to_owned()),
                error: IpcError::new(ErrorCode::Internal, "pushed"),
            })
            .await
            .expect("send");

        // Assert
        let line = lines.next_line().await.expect("read").expect("a line");
        assert!(line.contains("pushed"));
        let _ = h.shutdown.send(true);
    }

    #[tokio::test]
    async fn a_request_and_a_pushed_event_do_not_interleave() {
        // Arrange
        let h = start(Arc::new(AllowAll), "interleave");
        let stream = connect(&h.path).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act
        h.outbound
            .send(DaemonMessage::Error {
                id: RequestId("srv".to_owned()),
                error: IpcError::new(ErrorCode::Internal, "pushed"),
            })
            .await
            .expect("send");
        let req = serde_json::to_string(&ClientMessage::Request {
            id: RequestId("42".to_owned()),
            request: Request::Status,
        })
        .expect("encode");
        w.write_all(format!("{req}\n").as_bytes())
            .await
            .expect("write");

        // Assert: both arrive, each as one complete decodable line.
        for _ in 0..2 {
            let line = lines.next_line().await.expect("read").expect("a line");
            serde_json::from_str::<DaemonMessage>(&line).expect("each line decodes whole");
        }
        let _ = h.shutdown.send(true);
    }

    /// Answers the first request only after a second one has been seen, which is
    /// the shape of `connect`: it cannot finish until the prompt it raises is
    /// replied to over the same connection.
    struct BlockingHandler {
        release: tokio::sync::Notify,
    }

    impl MessageHandler for BlockingHandler {
        fn dispatch<'a>(
            &'a self,
            message: ClientMessage,
        ) -> Pin<Box<dyn Future<Output = DaemonMessage> + Send + 'a>> {
            Box::pin(async move {
                match message {
                    ClientMessage::Request { id, .. } => {
                        self.release.notified().await;
                        DaemonMessage::Response {
                            id,
                            response: Response::Ack,
                        }
                    }
                    ClientMessage::PromptReply { id, .. } => {
                        self.release.notify_waiters();
                        DaemonMessage::Response {
                            id,
                            response: Response::Ack,
                        }
                    }
                    ClientMessage::Hello { id, .. } => DaemonMessage::Hello {
                        id,
                        protocol_version: PROTOCOL_VERSION,
                        daemon_version: "test".to_owned(),
                    },
                }
            })
        }
    }

    #[tokio::test]
    async fn a_long_running_request_does_not_block_the_reply_that_unblocks_it() {
        // Arrange
        let path = socket_path("nodeadlock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (_outbound, outbound_rx) = mpsc::channel(16);
        let handler = Arc::new(BlockingHandler {
            release: tokio::sync::Notify::new(),
        });
        tokio::spawn(
            IpcServer::new(listener, Arc::new(AllowAll), handler, outbound_rx).run(shutdown_rx),
        );

        let stream = connect(&path).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act: the request cannot complete until the prompt reply is read, so a
        // read loop that awaits each dispatch inline never gets there.
        let req = serde_json::to_string(&ClientMessage::Request {
            id: RequestId("slow".to_owned()),
            request: Request::Status,
        })
        .expect("encode");
        w.write_all(format!("{req}\n").as_bytes())
            .await
            .expect("write");
        let reply = serde_json::to_string(&ClientMessage::PromptReply {
            id: RequestId("unblock".to_owned()),
            prompt_id: thisconnect_shared::ipc::PromptId("p".to_owned()),
            reply: thisconnect_shared::ipc::PromptReply::Cancel,
        })
        .expect("encode");
        w.write_all(format!("{reply}\n").as_bytes())
            .await
            .expect("write");

        // Assert: both answers arrive.
        let mut seen = 0;
        while seen < 2 {
            let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .expect("the second request must be read while the first is pending")
                .expect("read")
                .expect("a line");
            serde_json::from_str::<DaemonMessage>(&line).expect("decode");
            seen += 1;
        }

        let _ = shutdown.send(true);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn rejects_an_oversized_line_instead_of_buffering_it() {
        // Arrange
        let h = start(Arc::new(AllowAll), "oversized");
        let stream = connect(&h.path).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut lines = TokioBufReader::new(r).lines();

        // Act: no newline, more bytes than the cap.
        let flood = vec![b'a'; (MAX_REQUEST_BYTES + 1) as usize];
        let _ = w.write_all(&flood).await;

        // Assert
        let line = lines.next_line().await.expect("read").expect("a line");
        assert!(line.contains("too large"));
        let _ = h.shutdown.send(true);
    }

    #[tokio::test]
    async fn stops_accepting_once_shutdown_is_signalled() {
        // Arrange
        let h = start(Arc::new(AllowAll), "shutdown");
        let _ = connect(&h.path).await.expect("connect");

        // Act
        let _ = h.shutdown.send(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Assert: the socket file may still exist, but nothing serves it.
        if let Ok(stream) = UnixStream::connect(&h.path).await {
            let (r, _w) = stream.into_split();
            let mut lines = TokioBufReader::new(r).lines();
            assert!(lines.next_line().await.expect("read").is_none());
        }
    }
}
