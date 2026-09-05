// SPDX-License-Identifier: GPL-3.0-or-later

//! The async management client: handshake, single-outstanding-command queue and hold handling
//! (SPEC.md §4.3 points 2, 3, 4). The tunnel state machine it folds events through lives in
//! `tunnel`.

use std::collections::VecDeque;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::challenge::encode_cr_response;
use super::codec::{classify, CommandReply, Frame, LineSplitter, ReplyAccumulator};
use super::escape::{build_command, check_line_length};
use super::event::Event;
use super::tunnel::{self, TunnelState, TunnelTracker};
use super::{MgmtError, ANNOUNCED_VERSION, COMMAND_TIMEOUT, MIN_MANAGEMENT_VERSION};

const COMMAND_CHANNEL: usize = 16;
/// Lossy on purpose: this channel carries bulk `>LOG:` traffic. Nothing that gates the fail-closed
/// path may depend on it — tunnel connectivity travels on the `watch` instead.
const EVENT_CHANNEL: usize = 512;
const OUTBOX_LIMIT: usize = 32;
const READ_CHUNK: usize = 4096;

struct Command {
    line: Zeroizing<String>,
    /// `None` for commands the actor issued itself, such as re-releasing a hold.
    reply: Option<oneshot::Sender<Result<CommandReply, MgmtError>>>,
}

struct Pending {
    reply: Option<oneshot::Sender<Result<CommandReply, MgmtError>>>,
    deadline: Instant,
}

/// A live management channel plus the task driving it.
pub struct Connected {
    pub client: MgmtClient,
    /// Management interface version announced in the greeting.
    pub version: u32,
    pub task: JoinHandle<Result<(), MgmtError>>,
}

#[derive(Clone)]
pub struct MgmtClient {
    commands: mpsc::Sender<Command>,
    events: broadcast::Sender<Event>,
    tunnel: watch::Receiver<TunnelState>,
}

impl MgmtClient {
    /// Drives the greeting, the version floor check and the handshake before returning.
    pub async fn connect<S>(stream: S) -> Result<Connected, MgmtError>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL);
        let (event_tx, event_rx) = broadcast::channel(EVENT_CHANNEL);
        let (tunnel_tx, tunnel_rx) = watch::channel(TunnelState::default());

        // Subscribed before the actor starts, so the greeting cannot be missed.
        let task = tokio::spawn(run_actor(
            reader,
            writer,
            command_rx,
            event_tx.clone(),
            tunnel_tx,
        ));
        let client = Self {
            commands: command_tx,
            events: event_tx,
            tunnel: tunnel_rx,
        };

        match client.bring_up(event_rx).await {
            Ok(version) => Ok(Connected {
                client,
                version,
                task,
            }),
            Err(err) => {
                task.abort();
                Err(err)
            }
        }
    }

    async fn bring_up(&self, events: broadcast::Receiver<Event>) -> Result<u32, MgmtError> {
        let version = await_greeting(events).await?;
        if version < MIN_MANAGEMENT_VERSION {
            return Err(MgmtError::UnsupportedVersion { found: version });
        }
        self.handshake().await?;
        Ok(version)
    }

    /// Announce a version >= 4 first: `version <n>` for n <= 3 produces no reply at all.
    async fn handshake(&self) -> Result<(), MgmtError> {
        let commands = [
            format!("version {ANNOUNCED_VERSION}"),
            "state on".to_owned(),
            "bytecount 5".to_owned(),
            "log on all".to_owned(),
            "hold release".to_owned(),
        ];
        for command in commands {
            let reply = self.send(command).await?;
            if reply.is_error() {
                return Err(MgmtError::CommandFailed { text: reply.text });
            }
        }
        Ok(())
    }

    /// Best-effort event feed for logging and credential prompts. It drops the oldest entries
    /// under load, so a subscriber must never derive connectivity from it: use `tunnel_state`.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// The authoritative tunnel state (SPEC.md §5.3). Never lossy: the latest value is always
    /// observable, and it reads disconnected once the management channel is gone.
    pub fn tunnel_state(&self) -> watch::Receiver<TunnelState> {
        self.tunnel.clone()
    }

    /// Queues one command and waits for its terminal line. Only one is ever in flight.
    pub async fn send(&self, line: impl Into<String>) -> Result<CommandReply, MgmtError> {
        let line = Zeroizing::new(line.into());
        check_line_length(&line)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command {
                line,
                reply: Some(reply_tx),
            })
            .await
            .map_err(|_| MgmtError::Closed)?;
        reply_rx.await.map_err(|_| MgmtError::Closed)?
    }

    pub async fn hold_release(&self) -> Result<CommandReply, MgmtError> {
        self.send("hold release").await
    }

    pub async fn send_username(
        &self,
        kind: &str,
        username: &str,
    ) -> Result<CommandReply, MgmtError> {
        self.send(build_command("username", &[kind, username])?)
            .await
    }

    pub async fn send_password(
        &self,
        kind: &str,
        password: &str,
    ) -> Result<CommandReply, MgmtError> {
        self.send(build_command("password", &[kind, password])?)
            .await
    }

    /// Answers `>INFOMSG:CR_TEXT:`.
    pub async fn send_cr_response(&self, response: &str) -> Result<CommandReply, MgmtError> {
        let encoded = encode_cr_response(response);
        self.send(format!("cr-response {}", encoded.as_str())).await
    }

    pub async fn signal(&self, signal: &str) -> Result<CommandReply, MgmtError> {
        self.send(build_command("signal", &[signal])?).await
    }
}

async fn await_greeting(mut events: broadcast::Receiver<Event>) -> Result<u32, MgmtError> {
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        let received = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| MgmtError::Greeting)?;
        match received {
            Ok(Event::Info(text)) => {
                return parse_greeting_version(&text).ok_or(MgmtError::Greeting)
            }
            Ok(_) => continue,
            // Fail closed: a lagged greeting means the version floor cannot be proven.
            Err(broadcast::error::RecvError::Lagged(_)) => return Err(MgmtError::Greeting),
            Err(broadcast::error::RecvError::Closed) => return Err(MgmtError::Eof),
        }
    }
}

/// `OpenVPN Management Interface Version 6 -- type 'help' for more info`
fn parse_greeting_version(text: &str) -> Option<u32> {
    let tail = text.split("Version ").nth(1)?;
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

enum Progress {
    Read(usize),
    Command(Option<Command>),
    Expired,
}

async fn run_actor<R, W>(
    reader: R,
    writer: W,
    commands: mpsc::Receiver<Command>,
    events: broadcast::Sender<Event>,
    tunnel: watch::Sender<TunnelState>,
) -> Result<(), MgmtError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let outcome = drive(reader, writer, commands, &events, &tunnel).await;
    // Whatever ended the channel, the tun can now vanish without another event ever arriving.
    tunnel::publish_disconnected(&tunnel);
    outcome
}

async fn drive<R, W>(
    mut reader: R,
    mut writer: W,
    mut commands: mpsc::Receiver<Command>,
    events: &broadcast::Sender<Event>,
    tunnel: &watch::Sender<TunnelState>,
) -> Result<(), MgmtError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut tracker = TunnelTracker::default();
    let mut splitter = LineSplitter::new();
    let mut accumulator = ReplyAccumulator::new();
    let mut outbox: VecDeque<Command> = VecDeque::new();
    let mut pending: Option<Pending> = None;
    let mut buf = vec![0_u8; READ_CHUNK];

    loop {
        if pending.is_none() {
            if let Some(command) = outbox.pop_front() {
                write_line(&mut writer, &command.line).await?;
                pending = Some(Pending {
                    reply: command.reply,
                    deadline: Instant::now() + COMMAND_TIMEOUT,
                });
                continue;
            }
        }

        let deadline = pending.as_ref().map(|slot| slot.deadline);
        let progress = tokio::select! {
            biased;
            read = reader.read(&mut buf) => Progress::Read(read?),
            _ = wait_until(deadline) => Progress::Expired,
            command = commands.recv(), if outbox.len() < OUTBOX_LIMIT => Progress::Command(command),
        };

        match progress {
            Progress::Read(0) => {
                answer_pending(pending.take(), Err(MgmtError::Eof));
                return Ok(());
            }
            Progress::Read(count) => {
                let (next, lines) = splitter.push(&buf[..count])?;
                splitter = next;
                for line in lines {
                    let (next_acc, routed) = route_line(&line, &accumulator, &mut outbox);
                    accumulator = next_acc;
                    match routed {
                        Routed::Event(event) => {
                            // A fold error is fatal by SPEC.md §4.3 point 6; the disconnect is
                            // already published, and dropping `pending` reports `Closed`.
                            tracker = tunnel::observe_and_publish(&tracker, &event, tunnel)?;
                            let _ = events.send(event);
                        }
                        Routed::Reply(Some(reply)) => answer_pending(pending.take(), Ok(reply)),
                        Routed::Reply(None) => {}
                    }
                }
            }
            Progress::Expired => {
                answer_pending(pending.take(), Err(MgmtError::Timeout));
                return Err(MgmtError::Timeout);
            }
            Progress::Command(Some(command)) => outbox.push_back(command),
            Progress::Command(None) => return Ok(()),
        }
    }
}

enum Routed {
    Event(Event),
    Reply(Option<CommandReply>),
}

/// Events are surfaced immediately and never reach the accumulator.
fn route_line(
    line: &str,
    accumulator: &ReplyAccumulator,
    outbox: &mut VecDeque<Command>,
) -> (ReplyAccumulator, Routed) {
    let frame = classify(line);
    if let Frame::Event(event) = frame {
        // The hold flag is persistent: every reconnect and every auth retry re-enters hold.
        if matches!(event, Event::Hold { .. }) && outbox.len() < OUTBOX_LIMIT {
            outbox.push_back(Command {
                line: Zeroizing::new("hold release".to_owned()),
                reply: None,
            });
        }
        return (accumulator.clone(), Routed::Event(event));
    }
    let (next, reply) = accumulator.accept(&frame);
    (next, Routed::Reply(reply))
}

fn answer_pending(pending: Option<Pending>, outcome: Result<CommandReply, MgmtError>) {
    if let Some(slot) = pending {
        if let Some(reply) = slot.reply {
            let _ = reply.send(outcome);
        }
    }
}

async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(instant) => tokio::time::sleep_until(instant).await,
        None => std::future::pending().await,
    }
}

async fn write_line<W>(writer: &mut W, line: &str) -> Result<(), MgmtError>
where
    W: AsyncWrite + Unpin + Send,
{
    check_line_length(line)?;
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

    use super::*;

    /// A fake openvpn that records every command line and replies only when the test says so.
    fn spawn_openvpn(
        server: DuplexStream,
        version: u32,
    ) -> (UnboundedReceiver<String>, UnboundedSender<String>) {
        let (line_tx, line_rx) = mpsc::unbounded_channel();
        let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<String>();
        let greeting = format!(
            ">INFO:OpenVPN Management Interface Version {version} -- type 'help' for more info\r\n"
        );

        tokio::spawn(async move {
            let (read_half, mut write_half) = tokio::io::split(server);
            let _ = write_half.write_all(greeting.as_bytes()).await;
            let mut lines = BufReader::new(read_half).lines();
            loop {
                tokio::select! {
                    line = lines.next_line() => match line {
                        Ok(Some(line)) => { let _ = line_tx.send(line); }
                        _ => break,
                    },
                    injected = inject_rx.recv() => match injected {
                        Some(text) => {
                            let _ = write_half.write_all(format!("{text}\r\n").as_bytes()).await;
                        }
                        None => break,
                    },
                }
            }
        });

        (line_rx, inject_tx)
    }

    async fn answer_handshake(
        sent: &mut UnboundedReceiver<String>,
        inject: &UnboundedSender<String>,
    ) -> Vec<String> {
        let mut seen = Vec::new();
        for _ in 0..5 {
            let line = sent.recv().await.expect("handshake command");
            seen.push(line);
            inject.send("SUCCESS: ok".to_owned()).expect("inject");
        }
        seen
    }

    async fn connect_with(
        version: u32,
    ) -> (
        Connected,
        UnboundedReceiver<String>,
        UnboundedSender<String>,
        Vec<String>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut sent, inject) = spawn_openvpn(server_io, version);
        let connecting = tokio::spawn(MgmtClient::connect(client_io));
        let handshake = answer_handshake(&mut sent, &inject).await;
        let connected = connecting.await.expect("join").expect("connect");
        (connected, sent, inject, handshake)
    }

    #[tokio::test]
    async fn handshake_announces_version_six_then_enables_notifications_and_releases_hold() {
        let (connected, _sent, _inject, handshake) = connect_with(6).await;

        assert_eq!(connected.version, 6);
        assert_eq!(
            handshake,
            vec![
                "version 6",
                "state on",
                "bytecount 5",
                "log on all",
                "hold release"
            ]
        );
    }

    #[tokio::test]
    async fn refuses_a_management_version_below_five() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (_sent, _inject) = spawn_openvpn(server_io, 4);

        let outcome = MgmtClient::connect(client_io).await;

        assert!(matches!(
            outcome,
            Err(MgmtError::UnsupportedVersion { found: 4 })
        ));
    }

    #[tokio::test]
    async fn re_releases_hold_on_every_hold_event() {
        let (connected, mut sent, inject, _) = connect_with(6).await;
        let mut events = connected.client.subscribe();

        for _ in 0..2 {
            inject
                .send(">HOLD:Waiting for hold release:0".to_owned())
                .expect("inject");
            let line = sent.recv().await.expect("hold release");
            assert_eq!(line, "hold release");
            inject
                .send("SUCCESS: hold released".to_owned())
                .expect("inject");
        }

        let first = events.recv().await.expect("event");
        assert!(matches!(first, Event::Hold { .. }));
    }

    #[tokio::test]
    async fn dispatches_an_event_that_arrives_before_the_reply_of_a_command() {
        let (connected, mut sent, inject, _) = connect_with(6).await;
        let mut events = connected.client.subscribe();

        let client = connected.client.clone();
        let call = tokio::spawn(async move { client.send("state").await });

        assert_eq!(sent.recv().await.expect("command"), "state");
        inject
            .send(">LOG:1741000000,I,MANAGEMENT: CMD 'state'".to_owned())
            .expect("inject");
        inject
            .send(">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,".to_owned())
            .expect("inject");
        inject.send("SUCCESS: ok".to_owned()).expect("inject");

        let reply = call.await.expect("join").expect("reply");
        assert_eq!(reply.text, "ok");
        assert!(
            reply.lines.is_empty(),
            "interleaved events must not enter the reply body"
        );
        assert!(matches!(events.recv().await.expect("log"), Event::Log(_)));
        assert!(matches!(
            events.recv().await.expect("state"),
            Event::State(_)
        ));
    }

    #[tokio::test]
    async fn keeps_strictly_one_command_outstanding() {
        let (connected, mut sent, inject, _) = connect_with(6).await;

        let first_client = connected.client.clone();
        let first = tokio::spawn(async move { first_client.send("state").await });
        let second_client = connected.client.clone();
        let second = tokio::spawn(async move { second_client.send("status").await });

        let first_line = sent.recv().await.expect("first command");
        assert!(sent.try_recv().is_err(), "the second command must wait");

        inject.send("SUCCESS: one".to_owned()).expect("inject");
        let second_line = sent.recv().await.expect("second command");
        inject.send("SUCCESS: two".to_owned()).expect("inject");

        assert_ne!(first_line, second_line);
        assert!(first.await.expect("join").is_ok());
        assert!(second.await.expect("join").is_ok());
    }

    #[tokio::test]
    async fn terminates_a_multiline_command_on_a_bare_end() {
        let (connected, mut sent, inject, _) = connect_with(6).await;

        let client = connected.client.clone();
        let call = tokio::spawn(async move { client.send("version").await });

        assert_eq!(sent.recv().await.expect("command"), "version");
        inject
            .send("OpenVPN Version: 2.7.6".to_owned())
            .expect("inject");
        inject
            .send("Management Version: 6".to_owned())
            .expect("inject");
        inject.send("END".to_owned()).expect("inject");

        let reply = call.await.expect("join").expect("reply");
        assert_eq!(reply.lines.len(), 2);
    }

    #[tokio::test]
    async fn escapes_credentials_with_the_config_file_lexer() {
        let (connected, mut sent, inject, _) = connect_with(6).await;

        let client = connected.client.clone();
        let call =
            tokio::spawn(async move { client.send_password("Auth", " pa\"ss\\word ").await });

        assert_eq!(
            sent.recv().await.expect("command"),
            "password \"Auth\" \" pa\\\"ss\\\\word \""
        );
        inject.send("SUCCESS: ok".to_owned()).expect("inject");
        assert!(call.await.expect("join").is_ok());
    }

    #[tokio::test]
    async fn refuses_to_send_a_line_openvpn_would_silently_truncate() {
        let (connected, _sent, _inject, _) = connect_with(6).await;

        let outcome = connected.client.send("x".repeat(901)).await;

        assert!(matches!(
            outcome,
            Err(MgmtError::LineTooLong { bytes: 901 })
        ));
    }

    #[tokio::test]
    async fn reports_eof_to_a_caller_waiting_on_a_reply() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut sent, inject) = spawn_openvpn(server_io, 6);
        let connecting = tokio::spawn(MgmtClient::connect(client_io));
        answer_handshake(&mut sent, &inject).await;
        let connected = connecting.await.expect("join").expect("connect");

        let client = connected.client.clone();
        let call = tokio::spawn(async move { client.send("state").await });
        assert_eq!(sent.recv().await.expect("command"), "state");
        drop(inject);
        drop(sent);

        assert!(matches!(call.await.expect("join"), Err(MgmtError::Eof)));
    }

    /// The full 10 s expiry is not asserted here: it would need tokio's `test-util` feature to
    /// pause the clock, and a real 10 s test is not worth the wall time.
    #[tokio::test]
    async fn waits_for_a_reply_instead_of_failing_a_command_early() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (_sent, _inject) = spawn_openvpn(server_io, 6);

        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            MgmtClient::connect(client_io),
        )
        .await;

        assert!(
            outcome.is_err(),
            "connect must wait for the handshake reply"
        );
    }

    const CONNECTED_LINE: &str = ">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,";
    const RECONNECTING_LINE: &str = ">STATE:1741000001,RECONNECTING,tls-error,,,,,";

    /// The regression this guards: connectivity used to ride the lossy event broadcast, so a
    /// consumer busy closing sessions during a log storm never saw the transition away from
    /// CONNECTED and left egress sockets pinned to a dead tun (SPEC.md §5.3).
    #[tokio::test]
    async fn publishes_the_disconnect_even_when_the_event_broadcast_has_lagged() {
        let (connected, _sent, inject, _) = connect_with(6).await;
        let mut lagging = connected.client.subscribe();
        let mut tunnel = connected.client.tunnel_state();

        inject.send(CONNECTED_LINE.to_owned()).expect("inject");
        tunnel.changed().await.expect("connected published");
        assert!(tunnel.borrow().connected);
        for index in 0..(EVENT_CHANNEL + 64) {
            inject
                .send(format!(">LOG:1741000000,I,filler {index}"))
                .expect("inject");
        }
        inject.send(RECONNECTING_LINE.to_owned()).expect("inject");

        tunnel.changed().await.expect("disconnect published");
        assert!(!tunnel.borrow().connected);
        assert!(
            matches!(
                lagging.recv().await,
                Err(broadcast::error::RecvError::Lagged(_))
            ),
            "the test must actually overrun the event channel"
        );
    }

    #[tokio::test]
    async fn reports_a_disconnect_when_the_management_socket_closes() {
        let (connected, sent, inject, _) = connect_with(6).await;
        let mut tunnel = connected.client.tunnel_state();
        inject.send(CONNECTED_LINE.to_owned()).expect("inject");
        tunnel.changed().await.expect("connected published");

        drop(inject);
        drop(sent);

        tunnel.changed().await.expect("disconnect published");
        assert!(!tunnel.borrow().connected);
        assert!(tunnel.borrow().identity.is_none());
    }

    #[test]
    fn parses_the_version_out_of_the_greeting() {
        assert_eq!(
            parse_greeting_version(
                "OpenVPN Management Interface Version 6 -- type 'help' for more info"
            ),
            Some(6)
        );
        assert_eq!(parse_greeting_version("garbage"), None);
    }
}
