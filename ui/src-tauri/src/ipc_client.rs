// SPDX-License-Identifier: GPL-3.0-or-later
//! IPC client actor: owns the AF_UNIX connection to `thisconnectd` (SPEC.md
//! §7.4, design doc §3). Commands talk to it over an mpsc channel so exactly
//! one write is ever in flight — mirroring the daemon's own management-
//! protocol discipline (SPEC.md §4.3 point 2).
//!
//! Nothing in this crate wires the actor's public API into the Tauri command
//! layer yet (that's a later task), so the module is otherwise-unreachable
//! from outside itself; `dead_code` is suppressed accordingly until that
//! wiring lands.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use thisconnect_shared::ipc::{
    check_protocol_version, decode_line, encode_line, ClientMessage, CredentialPrompt,
    DaemonMessage, Event, IpcError, PromptId, PromptReply, Request, RequestId, Response,
    PROTOCOL_VERSION,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

pub const SOCKET_PATH_ENV: &str = "THISCONNECT_SOCKET";
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/thisconnect.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SOCKET_PATH: &str = "/run/thisconnect/thisconnectd.sock";

pub fn socket_path() -> PathBuf {
    std::env::var(SOCKET_PATH_ENV)
        .unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_owned())
        .into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonUnreachableReason {
    NotRunning,
    PermissionDenied,
    ProtocolMismatch { daemon_version: String },
}

#[derive(Debug)]
pub enum ActorEvent {
    Daemon(Event),
    Prompt {
        prompt_id: PromptId,
        prompt: CredentialPrompt,
    },
    PromptCancelled {
        prompt_id: PromptId,
    },
    ConnectionLost(DaemonUnreachableReason),
    ConnectionRestored,
}

/// Out-of-band notification sink. Production wires this to `AppHandle::emit`
/// (Task 7 wires the real one); tests use a channel so assertions don't need
/// a running Tauri app.
pub trait EventSink: Send + Sync + 'static {
    fn send(&self, event: ActorEvent);
}

impl EventSink for mpsc::UnboundedSender<ActorEvent> {
    fn send(&self, event: ActorEvent) {
        let _ = mpsc::UnboundedSender::send(self, event);
    }
}

#[derive(Debug)]
pub struct IpcErrorWrapper(pub IpcError);
impl std::fmt::Display for IpcErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", self.0.message, self.0.code)
    }
}
impl std::error::Error for IpcErrorWrapper {}

#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    #[error("daemon returned an error: {0}")]
    Daemon(#[from] IpcErrorWrapper),
    #[error("request timed out")]
    Timeout,
    #[error("IPC actor is not running")]
    ActorGone,
}

enum ActorCommand {
    Request {
        request: Request,
        reply: oneshot::Sender<Result<Response, IpcError>>,
    },
    PromptReply {
        prompt_id: PromptId,
        reply: PromptReply,
    },
}

#[derive(Clone)]
pub struct IpcClientHandle {
    tx: mpsc::UnboundedSender<ActorCommand>,
}

impl IpcClientHandle {
    pub async fn request(&self, request: Request) -> Result<Response, IpcClientError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ActorCommand::Request { request, reply: tx })
            .map_err(|_| IpcClientError::ActorGone)?;
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(err))) => Err(IpcClientError::Daemon(IpcErrorWrapper(err))),
            Ok(Err(_)) => Err(IpcClientError::ActorGone),
            Err(_) => Err(IpcClientError::Timeout),
        }
    }

    pub fn prompt_reply(
        &self,
        prompt_id: PromptId,
        reply: PromptReply,
    ) -> Result<(), IpcClientError> {
        self.tx
            .send(ActorCommand::PromptReply { prompt_id, reply })
            .map_err(|_| IpcClientError::ActorGone)
    }
}

pub fn spawn(sink: impl EventSink, path: PathBuf) -> IpcClientHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(run_actor(rx, sink, path));
    IpcClientHandle { tx }
}

async fn run_actor(
    mut rx: mpsc::UnboundedReceiver<ActorCommand>,
    sink: impl EventSink,
    path: PathBuf,
) {
    match connect_and_serve(&mut rx, &sink, &path).await {
        Ok(()) => {}
        Err(reason) => {
            warn!(?reason, "daemon connection ended");
            sink.send(ActorEvent::ConnectionLost(reason));
        }
    }
}

/// Accumulates bytes into complete lines. Cancel-safe by construction inside
/// `tokio::select!`: `AsyncReadExt::read` either fully applies its result to
/// `buf` or, if this future loses the select race, is dropped having read
/// nothing — unlike `AsyncBufReadExt::read_line`, which can silently drop
/// already-consumed bytes on cancellation. Same shape as
/// `daemon/src/mgmt/codec.rs`'s `LineSplitter`, solving the same
/// interleaved-command/event read problem (SPEC.md §4.3 point 2) on the GUI
/// side of the same protocol.
struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> LineReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Returns the next complete line already buffered, without touching the
    /// socket. Call this before `read_more` on every loop iteration — a
    /// single `read_more` call can deliver more than one line's worth of
    /// bytes, so this must be drained in a loop, not called once per read.
    fn take_line(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == b'\n')?;
        let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
        line.pop(); // trailing '\n'
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }

    /// Reads more bytes into the buffer. Cancel-safe (see struct doc).
    /// `Ok(0)` means EOF.
    async fn read_more(&mut self) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        let mut chunk = [0u8; 4096];
        let n = self.inner.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }
}

async fn connect_and_serve(
    rx: &mut mpsc::UnboundedReceiver<ActorCommand>,
    sink: &impl EventSink,
    path: &PathBuf,
) -> Result<(), DaemonUnreachableReason> {
    let stream = UnixStream::connect(path)
        .await
        .map_err(classify_connect_error)?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = LineReader::new(read_half);

    let hello_id = RequestId(uuid::Uuid::new_v4().to_string());
    let hello = ClientMessage::Hello {
        id: hello_id,
        protocol_version: PROTOCOL_VERSION,
        client_name: "thisconnect-ui".to_owned(),
    };
    send_line(&mut write_half, &hello)
        .await
        .map_err(|_| DaemonUnreachableReason::NotRunning)?;

    let daemon_version = loop {
        let line = match reader.take_line() {
            Some(line) => line,
            None => {
                let bytes_read = reader
                    .read_more()
                    .await
                    .map_err(|_| DaemonUnreachableReason::NotRunning)?;
                if bytes_read == 0 {
                    return Err(DaemonUnreachableReason::NotRunning);
                }
                continue;
            }
        };
        match decode_line::<DaemonMessage>(&line) {
            Ok(DaemonMessage::Hello {
                protocol_version,
                daemon_version,
                ..
            }) => {
                if check_protocol_version(protocol_version).is_err() {
                    return Err(DaemonUnreachableReason::ProtocolMismatch { daemon_version });
                }
                break daemon_version;
            }
            _ => continue,
        }
    };
    debug!(daemon_version, "connected to thisconnectd");
    sink.send(ActorEvent::ConnectionRestored);

    let mut pending: HashMap<RequestId, oneshot::Sender<Result<Response, IpcError>>> =
        HashMap::new();

    loop {
        while let Some(line) = reader.take_line() {
            handle_incoming(&line, sink, &mut pending);
        }
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return Ok(()) };
                if handle_command(cmd, &mut write_half, &mut pending).await.is_err() {
                    return Err(DaemonUnreachableReason::NotRunning);
                }
            }
            read_result = reader.read_more() => {
                match read_result {
                    Ok(0) => return Err(DaemonUnreachableReason::NotRunning),
                    Ok(_) => {}
                    Err(_) => return Err(DaemonUnreachableReason::NotRunning),
                }
            }
        }
    }
}

async fn handle_command(
    cmd: ActorCommand,
    write_half: &mut (impl AsyncWriteExt + Unpin),
    pending: &mut HashMap<RequestId, oneshot::Sender<Result<Response, IpcError>>>,
) -> std::io::Result<()> {
    match cmd {
        ActorCommand::Request { request, reply } => {
            let id = RequestId(uuid::Uuid::new_v4().to_string());
            pending.insert(id.clone(), reply);
            send_line(write_half, &ClientMessage::Request { id, request }).await
        }
        ActorCommand::PromptReply { prompt_id, reply } => {
            let id = RequestId(uuid::Uuid::new_v4().to_string());
            send_line(
                write_half,
                &ClientMessage::PromptReply {
                    id,
                    prompt_id,
                    reply,
                },
            )
            .await
        }
    }
}

fn handle_incoming(
    line: &str,
    sink: &impl EventSink,
    pending: &mut HashMap<RequestId, oneshot::Sender<Result<Response, IpcError>>>,
) {
    match decode_line::<DaemonMessage>(line) {
        Ok(DaemonMessage::Response { id, response }) => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Ok(response));
            }
        }
        Ok(DaemonMessage::Error { id, error }) => {
            if let Some(tx) = pending.remove(&id) {
                let _ = tx.send(Err(error));
            }
        }
        Ok(DaemonMessage::Prompt { prompt_id, prompt }) => {
            sink.send(ActorEvent::Prompt { prompt_id, prompt });
        }
        Ok(DaemonMessage::Event { event }) => {
            if let Event::PromptCancelled { prompt_id } = &event {
                sink.send(ActorEvent::PromptCancelled {
                    prompt_id: prompt_id.clone(),
                });
            }
            sink.send(ActorEvent::Daemon(event));
        }
        Ok(DaemonMessage::Hello { .. }) => {}
        Err(err) => warn!(%err, "malformed line from daemon"),
    }
}

fn classify_connect_error(err: std::io::Error) -> DaemonUnreachableReason {
    match err.raw_os_error() {
        Some(code) if code == libc::EACCES => DaemonUnreachableReason::PermissionDenied,
        _ => DaemonUnreachableReason::NotRunning,
    }
}

async fn send_line<T: serde::Serialize>(
    write_half: &mut (impl AsyncWriteExt + Unpin),
    message: &T,
) -> std::io::Result<()> {
    let line = encode_line(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    write_half.write_all(line.as_bytes()).await?;
    write_half.write_all(b"\n").await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    /// A fixture daemon: answers `Hello`, then echoes back `Response::Ack` for
    /// every `Request`, whatever it is. Enough to prove handshake +
    /// correlation without reimplementing the daemon's session logic.
    async fn run_fixture_daemon(listener: UnixListener) {
        let (stream, _) = listener.accept().await.expect("fixture accept");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read hello");
        let ClientMessage::Hello { id, .. } =
            decode_line::<ClientMessage>(line.trim_end()).expect("decode hello")
        else {
            panic!("expected Hello first");
        };
        send_line(
            &mut write_half,
            &DaemonMessage::Hello {
                id,
                protocol_version: PROTOCOL_VERSION,
                daemon_version: "test-fixture".to_owned(),
            },
        )
        .await
        .expect("send hello reply");

        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await.expect("fixture read");
            if n == 0 {
                return;
            }
            if let Ok(ClientMessage::Request { id, .. }) =
                decode_line::<ClientMessage>(line.trim_end())
            {
                send_line(
                    &mut write_half,
                    &DaemonMessage::Response {
                        id,
                        response: Response::Ack,
                    },
                )
                .await
                .expect("fixture reply");
            }
        }
    }

    #[tokio::test]
    async fn handshake_then_request_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.sock");
        let listener = UnixListener::bind(&path).expect("bind fixture socket");
        tokio::spawn(run_fixture_daemon(listener));

        let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<ActorEvent>();
        let handle = spawn(sink_tx, path);

        // Give the actor a moment to connect and complete the handshake.
        let restored = tokio::time::timeout(Duration::from_secs(2), sink_rx.recv())
            .await
            .expect("no timeout")
            .expect("channel open");
        assert!(matches!(restored, ActorEvent::ConnectionRestored));

        let response = handle
            .request(Request::ProfileList)
            .await
            .expect("request should succeed");
        assert!(matches!(response, Response::Ack));
    }
}
