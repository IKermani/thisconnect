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
use super::{
    MgmtError, ANNOUNCED_VERSION, COMMAND_TIMEOUT, MIN_MANAGEMENT_VERSION, REPLY_BEARING_VERSION,
};

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
    /// False only for a command this openvpn is known to answer with silence. Such a command must
    /// not occupy the pending slot: the slot is what makes the next reply attributable, and the
    /// protocol carries no correlation id, so a slot waiting for a reply that never comes both
    /// stalls for the command timeout and then fails the whole channel.
    expects_reply: bool,
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
    /// Subscribed before the handshake released the hold, so no event emitted
    /// during or immediately after it can be missed.
    pub events: broadcast::Receiver<Event>,
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

        // Taken BEFORE the handshake, which ends by releasing the hold. openvpn
        // answers a released hold with `>PASSWORD:` immediately, and a broadcast
        // send with no receiver is dropped on the floor — so a subscription made
        // after `connect` returns misses the credential prompt and the connect
        // stalls in Authenticating forever. Handing this receiver to the caller
        // is what makes the prompt impossible to miss.
        let events = client.events.subscribe();

        match client.bring_up(event_rx).await {
            Ok(version) => Ok(Connected {
                client,
                version,
                task,
                events,
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
        self.handshake(version).await?;
        Ok(version)
    }

    /// Announce a version >= 4 first: `version <n>` for n <= 3 produces no reply at all.
    ///
    /// Announce no more than the peer offered. openvpn 2.6.19 greets with version 5 and answers
    /// `version <n>` with silence for *every* n, so the reply is not awaited below that version —
    /// verified against 2.6.19, where awaiting it stalled the connect and tore down the channel.
    /// 2.7.6 answers, and its reply is awaited so it cannot land on the next command instead.
    async fn handshake(&self, greeted: u32) -> Result<(), MgmtError> {
        let announced = greeted.min(ANNOUNCED_VERSION);
        if greeted >= REPLY_BEARING_VERSION {
            let reply = self.send(format!("version {announced}")).await?;
            if reply.is_error() {
                return Err(MgmtError::CommandFailed { text: reply.text });
            }
        } else {
            self.send_unacknowledged(format!("version {announced}"))
                .await?;
        }
        let commands = [
            "state on".to_owned(),
            "bytecount 5".to_owned(),
            // `log on`, never `log on all`. Verified against openvpn 2.7.6: the
            // `all` form answers SUCCESS *first*, then dumps the log history as
            // plain data lines, then END. A client that treats SUCCESS as
            // terminal attributes that history and its END to the NEXT command,
            // and every reply after it is off by one — the connection then
            // stalls before the credential prompt is ever handled. We want the
            // real-time stream, not the history, so `log on` is both correct and
            // sufficient.
            "log on".to_owned(),
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
                expects_reply: true,
            })
            .await
            .map_err(|_| MgmtError::Closed)?;
        reply_rx.await.map_err(|_| MgmtError::Closed)?
    }

    /// Queues a command whose reply must not be awaited. See [`Command::expects_reply`].
    async fn send_unacknowledged(&self, line: impl Into<String>) -> Result<(), MgmtError> {
        let line = Zeroizing::new(line.into());
        check_line_length(&line)?;

        self.commands
            .send(Command {
                line,
                reply: None,
                expects_reply: false,
            })
            .await
            .map_err(|_| MgmtError::Closed)
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
                if command.expects_reply {
                    pending = Some(Pending {
                        reply: command.reply,
                        deadline: Instant::now() + COMMAND_TIMEOUT,
                    });
                }
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
                    let (next_acc, routed) =
                        route_line(&line, &accumulator, &mut outbox, pending.is_some());
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
///
/// `has_pending` guards against reply desync. The protocol has no correlation
/// id, so a line arriving while nothing is outstanding — a trailing multiline
/// body, or an unsolicited SUCCESS — would otherwise seed the accumulator and be
/// handed to whichever command is sent next. That is exactly how `log on all`
/// stalled the connect path before the credential prompt: one command's tail
/// became the next command's reply, and every reply after it was off by one.
fn route_line(
    line: &str,
    accumulator: &ReplyAccumulator,
    outbox: &mut VecDeque<Command>,
    has_pending: bool,
) -> (ReplyAccumulator, Routed) {
    let frame = classify(line);
    if let Frame::Event(event) = frame {
        // The hold flag is persistent: every reconnect and every auth retry re-enters hold.
        if matches!(event, Event::Hold { .. }) && outbox.len() < OUTBOX_LIMIT {
            outbox.push_back(Command {
                line: Zeroizing::new("hold release".to_owned()),
                reply: None,
                expects_reply: true,
            });
        }
        return (accumulator.clone(), Routed::Event(event));
    }
    if !has_pending {
        // Nothing is waiting for this. Discard rather than accumulate.
        return (ReplyAccumulator::new(), Routed::Reply(None));
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

    /// openvpn 2.6.19 greets with version 5 and answers `version <n>` with silence. Replying to
    /// only the four commands after it is exactly what the real 2.6.19 does, so a handshake that
    /// completes here is one that completes there.
    #[tokio::test]
    async fn handshake_does_not_await_a_reply_openvpn_2_6_never_sends() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut sent, inject) = spawn_openvpn(server_io, 5);
        let connecting = tokio::spawn(MgmtClient::connect(client_io));

        let announced = sent.recv().await.expect("version command");
        let mut seen = vec![announced];
        for _ in 0..4 {
            let line = sent.recv().await.expect("handshake command");
            seen.push(line);
            inject.send("SUCCESS: ok".to_owned()).expect("inject");
        }
        let connected = connecting.await.expect("join").expect("connect");

        assert_eq!(connected.version, 5);
        // Announced down to what the peer offered, never above it.
        assert_eq!(
            seen,
            vec![
                "version 5",
                "state on",
                "bytecount 5",
                "log on",
                "hold release"
            ]
        );
    }

    /// The reply-bearing path must keep waiting, or 2.7's answer to `version` lands on `state on`
    /// and every reply after it is off by one.
    #[tokio::test]
    async fn a_version_six_peer_still_has_its_version_reply_awaited() {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut sent, _inject) = spawn_openvpn(server_io, 6);
        let connecting = tokio::spawn(MgmtClient::connect(client_io));

        assert_eq!(sent.recv().await.expect("version"), "version 6");
        // Nothing further is written until that reply arrives.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), sent.recv())
                .await
                .is_err(),
            "the next command was written before the version reply arrived"
        );
        connecting.abort();
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
                "log on",
                "hold release"
            ]
        );
    }

    #[tokio::test]
    async fn an_event_emitted_while_the_hold_is_released_is_not_lost() {
        // Arrange: openvpn answers a released hold with `>PASSWORD:` immediately.
        // A broadcast send with no receiver is dropped, so if `Connected` did not
        // already hold a subscription the prompt would vanish and the connect
        // would stall in Authenticating forever.
        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut sent, inject) = spawn_openvpn(server_io, 6);
        let connecting = tokio::spawn(MgmtClient::connect(client_io));

        // Act: reply to each handshake command, and emit the prompt on the very
        // same turn as the hold release, before the caller could subscribe.
        for _ in 0..5 {
            let line = sent.recv().await.expect("handshake command");
            inject.send("SUCCESS: ok".to_owned()).expect("inject");
            if line == "hold release" {
                inject
                    .send(">PASSWORD:Need 'Auth' username/password".to_owned())
                    .expect("inject");
            }
        }
        let mut connected = connecting.await.expect("join").expect("connect");

        // Assert: the greeting is legitimately ahead of it in the same stream.
        let found = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match connected.events.recv().await {
                    Ok(Event::Password(_)) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await
        .expect("the prompt must not be dropped");
        assert!(found, "the credential prompt never reached the subscriber");
    }

    #[tokio::test]
    async fn the_handshake_never_asks_for_the_log_history() {
        // Arrange / Act
        let (_connected, _sent, _inject, handshake) = connect_with(6).await;

        // Assert: verified against openvpn 2.7.6 — `log on all` answers SUCCESS,
        // then dumps the history as plain data lines, then END. Treating that
        // SUCCESS as terminal hands the history and its END to the next command
        // and every reply afterwards is off by one, which stalls the connect
        // before the credential prompt is ever seen.
        assert!(
            !handshake.iter().any(|command| command == "log on all"),
            "the handshake must not request the log history: {handshake:?}"
        );
    }

    #[tokio::test]
    async fn a_line_arriving_with_no_command_outstanding_is_not_given_to_the_next_one() {
        // Arrange: a trailing multiline body, as `log on all` produces.
        let (connected, mut sent, inject, _handshake) = connect_with(6).await;
        inject
            .send("stray history line\r\n".to_owned())
            .expect("inject");
        inject.send("END\r\n".to_owned()).expect("inject");
        tokio::task::yield_now().await;

        // Act: the next real command must get its own reply, not the leftovers.
        let pending = tokio::spawn(async move { connected.client.hold_release().await });
        let line = sent.recv().await.expect("command");
        assert_eq!(line, "hold release");
        inject
            .send("SUCCESS: hold release succeeded\r\n".to_owned())
            .expect("inject");

        // Assert
        let reply = pending.await.expect("join").expect("reply");
        assert!(reply.lines.is_empty(), "orphan lines leaked into the reply");
        assert_eq!(reply.text, "hold release succeeded");
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
