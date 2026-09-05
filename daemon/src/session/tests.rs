// SPDX-License-Identifier: GPL-3.0-or-later

//! The connect path end to end, with no real openvpn and no real route table.
//!
//! Every collaborator is a double: the process spawner, the management
//! transport, tunnel policy and the egress publisher. What is exercised is the
//! orchestration itself — ordering, and that every failure path tears down.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use thisconnect_shared::ipc::{ConnectionState, DaemonMessage, PromptReply, Secret};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::{mpsc, oneshot};

use super::profiles::testing::MemoryProfiles;
use super::spawn::{ProcessControl, ProcessExit, ProcessSpawner, SpawnedProcess};
use super::transport::testing::{FixedFactory, ScriptedTransport, SilentTransport};
use super::tunnel::testing::{FakePolicy, RecordingPublisher};
use super::tunnel::TunnelPolicyDriver;
use super::*;
use crate::auth::store::testing::MemoryStore;

const PROFILE: &str = concat!(
    "client\n",
    "pull\n",
    "dev tun\n",
    "remote vpn.example.com 1194 udp\n",
    "auth-user-pass\n",
    "tun-mtu 1400\n",
);

// ---------------------------------------------------------------------------
// Process double
// ---------------------------------------------------------------------------

struct FakeProcess {
    terminated: AtomicUsize,
    killed: AtomicUsize,
    exit: Mutex<Option<oneshot::Sender<ProcessExit>>>,
}

impl FakeProcess {
    fn finish(&self) {
        if let Some(sender) = lock(&self.exit).take() {
            let _ = sender.send(ProcessExit {
                code: Some(0),
                signal: None,
            });
        }
    }
}

impl ProcessControl for FakeProcess {
    fn terminate(&self) {
        self.terminated.fetch_add(1, Ordering::SeqCst);
        self.finish();
    }

    fn kill(&self) {
        self.killed.fetch_add(1, Ordering::SeqCst);
        self.finish();
    }
}

struct FakeSpawner {
    process: Arc<FakeProcess>,
    exit: Mutex<Option<oneshot::Receiver<ProcessExit>>>,
    spawns: AtomicUsize,
    args: Mutex<Vec<String>>,
}

impl FakeSpawner {
    fn alive() -> Arc<Self> {
        Self::build(false)
    }

    /// openvpn that exits the moment it is started.
    fn dead() -> Arc<Self> {
        Self::build(true)
    }

    fn build(exits_now: bool) -> Arc<Self> {
        let (tx, rx) = oneshot::channel();
        let process = Arc::new(FakeProcess {
            terminated: AtomicUsize::new(0),
            killed: AtomicUsize::new(0),
            exit: Mutex::new(Some(tx)),
        });
        if exits_now {
            process.finish();
        }
        Arc::new(Self {
            process,
            exit: Mutex::new(Some(rx)),
            spawns: AtomicUsize::new(0),
            args: Mutex::new(Vec::new()),
        })
    }

    fn terminations(&self) -> usize {
        self.process.terminated.load(Ordering::SeqCst)
    }

    fn spawns(&self) -> usize {
        self.spawns.load(Ordering::SeqCst)
    }

    fn args(&self) -> Vec<String> {
        lock(&self.args).clone()
    }
}

impl ProcessSpawner for FakeSpawner {
    fn spawn(&self, _program: &Path, args: &[String]) -> Result<SpawnedProcess, SessionError> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        *lock(&self.args) = args.to_vec();
        let exit = lock(&self.exit).take().ok_or(SessionError::Spawn {
            command: "openvpn".to_owned(),
            detail: "the fake spawner allows one spawn".to_owned(),
        })?;
        Ok(SpawnedProcess {
            control: Arc::clone(&self.process) as Arc<dyn ProcessControl>,
            exit,
        })
    }
}

// ---------------------------------------------------------------------------
// openvpn's side of the management channel
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    /// Comes straight up: no credentials asked for.
    NoAuth,
    /// Asks for a username and password, then comes up.
    AsksForCredentials,
    /// Asks, then rejects what it is given.
    RejectsCredentials,
    /// Connects, replies to the handshake, and then never comes up.
    NeverConnects,
}

/// Emitted only after a short pause: the orchestrator subscribes to the event
/// feed once the handshake's `hold release` has been answered, and a `>PASSWORD`
/// that overtakes that subscription would be missed.
const SETTLE: Duration = Duration::from_millis(120);

async fn drive_openvpn(peer: DuplexStream, script: Script) {
    let (read_half, mut write) = tokio::io::split(peer);
    let mut lines = BufReader::new(read_half).lines();

    let _ = write
        .write_all(b">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info\r\n")
        .await;

    let mut handshake = 0;
    while let Ok(Some(line)) = lines.next_line().await {
        let _ = write.write_all(b"SUCCESS: ok\r\n").await;
        if line.starts_with("password ") {
            if script == Script::RejectsCredentials {
                tokio::time::sleep(SETTLE).await;
                let _ = write
                    .write_all(b">PASSWORD:Verification Failed: 'Auth' ['bad password']\r\n")
                    .await;
                continue;
            }
            tokio::time::sleep(SETTLE).await;
            let _ = write.write_all(connected_block().as_bytes()).await;
            continue;
        }
        if line.starts_with("signal ") {
            return;
        }
        handshake += 1;
        if handshake < 5 {
            continue;
        }
        tokio::time::sleep(SETTLE).await;
        match script {
            Script::NoAuth => {
                let _ = write.write_all(connected_block().as_bytes()).await;
            }
            Script::AsksForCredentials | Script::RejectsCredentials => {
                let _ = write
                    .write_all(b">PASSWORD:Need 'Auth' username/password\r\n")
                    .await;
            }
            Script::NeverConnects => {}
        }
    }
}

fn connected_block() -> String {
    concat!(
        ">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,\r\n",
        ">UPDOWN:UP\r\n",
        ">UPDOWN:ENV,BEGIN\r\n",
        ">UPDOWN:ENV,dev=utun7\r\n",
        ">UPDOWN:ENV,dev_type=tun\r\n",
        ">UPDOWN:ENV,ifconfig_local=10.8.0.2\r\n",
        ">UPDOWN:ENV,END\r\n",
    )
    .to_owned()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    manager: SessionManager,
    spawner: Arc<FakeSpawner>,
    policy: Arc<FakePolicy>,
    egress: Arc<RecordingPublisher>,
    runtime_dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime_dir);
    }
}

fn scratch(name: &str) -> PathBuf {
    // SAFETY: reading our own pid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let dir = std::env::temp_dir().join(format!("thisconnect-session-{pid}-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Options {
    script: Option<Script>,
    spawner: Arc<FakeSpawner>,
    policy: Arc<FakePolicy>,
    egress: Arc<RecordingPublisher>,
    reply: Option<PromptReply>,
}

impl Options {
    fn new() -> Self {
        Self {
            script: Some(Script::NoAuth),
            spawner: FakeSpawner::alive(),
            policy: Arc::new(FakePolicy::working()),
            egress: Arc::new(RecordingPublisher::default()),
            reply: None,
        }
    }
}

fn build(name: &str, options: Options) -> Harness {
    let runtime_dir = scratch(name);
    let mut config = SessionConfig::new(&runtime_dir, &runtime_dir);
    config.openvpn_path = Some(PathBuf::from("/bin/sh"));
    config.connect_timeout = Duration::from_secs(10);
    config.prompt_timeout = Duration::from_secs(5);

    let (outbound, inbound) = mpsc::channel(256);
    let prompts = Arc::new(PromptBroker::new(outbound.clone(), config.prompt_timeout));
    let egress = Arc::clone(&options.egress);

    let transport: Box<dyn super::transport::MgmtTransport> = match options.script {
        Some(script) => {
            let (daemon_side, openvpn_side) = tokio::io::duplex(16 * 1024);
            tokio::spawn(drive_openvpn(openvpn_side, script));
            Box::new(ScriptedTransport::new(daemon_side))
        }
        None => Box::new(SilentTransport),
    };

    let deps = SessionDeps {
        profiles: Arc::new(MemoryProfiles::new().with("work", PROFILE)),
        spawner: Arc::clone(&options.spawner) as Arc<dyn ProcessSpawner>,
        transports: Arc::new(FixedFactory::new(transport)),
        policy: Arc::clone(&options.policy) as Arc<dyn TunnelPolicyDriver>,
        egress: Arc::clone(&egress) as Arc<dyn EgressPublisher>,
        secrets: Arc::new(MemoryStore::new()),
        prompts: Arc::clone(&prompts),
    };

    let manager = SessionManager::new(config, deps, outbound);
    tokio::spawn(answer_prompts(inbound, prompts, options.reply));
    Harness {
        manager,
        spawner: options.spawner,
        policy: options.policy,
        egress,
        runtime_dir,
    }
}

/// Stands in for the GUI: drains events so the sink never blocks, and answers
/// every credential prompt the way the test asked for.
async fn answer_prompts(
    mut inbound: mpsc::Receiver<DaemonMessage>,
    prompts: Arc<PromptBroker>,
    reply: Option<PromptReply>,
) {
    while let Some(message) = inbound.recv().await {
        if let DaemonMessage::Prompt { prompt_id, .. } = message {
            let answer = reply.clone().unwrap_or(PromptReply::UsernamePassword {
                username: "alice".to_owned(),
                password: Secret::new("hunter2"),
            });
            let _ = prompts.deliver(&prompt_id, answer);
        }
    }
}

/// A manager with nothing connected, for the IPC handler's tests.
pub(crate) fn idle_manager() -> SessionManager {
    let runtime_dir = scratch("idle");
    let config = SessionConfig::new(&runtime_dir, &runtime_dir);
    let (outbound, _inbound) = mpsc::channel(16);
    let prompts = Arc::new(PromptBroker::new(outbound.clone(), config.prompt_timeout));
    let deps = SessionDeps {
        profiles: Arc::new(MemoryProfiles::new()),
        spawner: FakeSpawner::alive(),
        transports: Arc::new(FixedFactory::new(Box::new(SilentTransport))),
        policy: Arc::new(FakePolicy::working()),
        egress: Arc::new(RecordingPublisher::default()),
        secrets: Arc::new(MemoryStore::new()),
        prompts,
    };
    SessionManager::new(config, deps, outbound)
}

fn profile() -> ProfileId {
    ProfileId("work".to_owned())
}

fn session_dirs(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(root)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("session-"))
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connects_installs_policy_then_publishes_the_tunnel_identity() {
    // Arrange
    let harness = build("happy", Options::new());

    // Act
    let status = harness.manager.connect(profile()).await.expect("connect");

    // Assert
    assert_eq!(status.state, ConnectionState::Connected);
    let tunnel = status.tunnel.expect("tunnel info");
    assert_eq!(tunnel.device, "utun7");
    assert_eq!(tunnel.mtu, Some(1400));
    assert_eq!(harness.policy.installs(), 1);
    assert!(harness.egress.is_published());
}

#[tokio::test]
async fn spawns_openvpn_with_the_config_and_the_management_socket_it_created() {
    let harness = build("spawn-args", Options::new());

    harness.manager.connect(profile()).await.expect("connect");

    let args = harness.spawner.args();
    assert_eq!(args[0], "--config");
    assert!(args[1].ends_with("canonical.ovpn"));
    assert!(args.iter().any(|arg| arg.ends_with("mgmt.sock")));
    assert!(args.iter().any(|arg| arg == "--management-client"));
}

#[tokio::test]
async fn answers_a_credential_prompt_and_comes_up() {
    // Arrange
    let mut options = Options::new();
    options.script = Some(Script::AsksForCredentials);
    let harness = build("auth", options);

    // Act
    let status = harness.manager.connect(profile()).await.expect("connect");

    // Assert
    assert_eq!(status.state, ConnectionState::Connected);
}

#[tokio::test]
async fn a_cancelled_prompt_fails_the_attempt_and_tears_everything_down() {
    // Arrange
    let mut options = Options::new();
    options.script = Some(Script::AsksForCredentials);
    options.reply = Some(PromptReply::Cancel);
    let harness = build("cancelled", options);

    // Act
    let outcome = harness.manager.connect(profile()).await;

    // Assert
    assert!(matches!(outcome, Err(SessionError::Auth(_))));
    assert_eq!(harness.manager.state(), SessionState::Failed);
    assert_eq!(harness.spawner.terminations(), 1);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn rejected_credentials_are_reported_as_an_auth_failure() {
    let mut options = Options::new();
    options.script = Some(Script::RejectsCredentials);
    let harness = build("rejected", options);

    let outcome = harness.manager.connect(profile()).await;

    assert!(matches!(outcome, Err(SessionError::AuthRejected { .. })));
    assert_eq!(harness.manager.state(), SessionState::Failed);
}

#[tokio::test]
async fn openvpn_dying_mid_connect_fails_the_attempt_rather_than_hanging() {
    // Arrange
    let mut options = Options::new();
    options.script = None;
    options.spawner = FakeSpawner::dead();
    let harness = build("child-died", options);

    // Act
    let outcome = harness.manager.connect(profile()).await;

    // Assert
    assert!(matches!(outcome, Err(SessionError::OpenvpnExited { .. })));
    assert_eq!(harness.manager.state(), SessionState::Failed);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn a_policy_install_failure_stops_openvpn_and_publishes_nothing() {
    // Arrange
    let mut options = Options::new();
    options.policy = Arc::new(FakePolicy::refusing());
    let harness = build("policy-fails", options);

    // Act
    let outcome = harness.manager.connect(profile()).await;

    // Assert
    assert!(matches!(outcome, Err(SessionError::Policy(_))));
    assert!(!harness.egress.is_published());
    assert_eq!(harness.spawner.terminations(), 1);
    assert_eq!(harness.manager.state(), SessionState::Failed);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn a_publish_failure_removes_the_policy_that_was_just_installed() {
    // Arrange
    let mut options = Options::new();
    options.egress = Arc::new(RecordingPublisher::refusing());
    let harness = build("publish-fails", options);

    // Act
    let outcome = harness.manager.connect(profile()).await;

    // Assert
    assert!(matches!(outcome, Err(SessionError::Policy(_))));
    assert_eq!(harness.policy.installs(), 1);
    assert_eq!(harness.policy.teardowns(), 1);
    assert!(!harness.egress.is_published());
    assert_eq!(harness.spawner.terminations(), 1);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn a_disconnect_racing_the_final_transition_leaves_no_orphaned_tunnel() {
    // Arrange: the policy parks inside `install`, so the disconnect lands after
    // the tunnel exists but before the session can claim it.
    let (policy, mut gate) = FakePolicy::gated();
    let mut options = Options::new();
    options.policy = Arc::new(policy);
    let harness = build("late-cancel", options);
    let manager = harness.manager.clone();
    let connecting = tokio::spawn(async move { manager.connect(profile()).await });

    // Act
    gate.wait_for_install().await;
    harness.manager.disconnect().await.expect("disconnect");
    gate.release();
    let outcome = connecting.await.expect("connect task");

    // Assert
    assert!(matches!(
        outcome,
        Err(SessionError::IllegalTransition { .. })
    ));
    assert_eq!(harness.policy.installs(), 1);
    assert_eq!(harness.policy.teardowns(), 1);
    assert!(!harness.egress.is_published());
    assert_eq!(harness.spawner.terminations(), 1);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn a_second_connect_while_one_is_up_is_refused_and_starts_no_second_openvpn() {
    // Arrange
    let harness = build("double", Options::new());
    harness.manager.connect(profile()).await.expect("connect");

    // Act
    let second = harness.manager.connect(profile()).await;

    // Assert
    assert!(matches!(second, Err(SessionError::AlreadyConnected)));
    assert_eq!(harness.spawner.spawns(), 1);
    assert_eq!(harness.manager.state(), SessionState::Connected);
}

#[tokio::test]
async fn disconnect_revokes_the_identity_removes_policy_and_stops_openvpn() {
    // Arrange
    let harness = build("disconnect", Options::new());
    harness.manager.connect(profile()).await.expect("connect");

    // Act
    harness.manager.disconnect().await.expect("disconnect");

    // Assert
    assert!(!harness.egress.is_published());
    assert!(harness.egress.revocations() >= 1);
    assert_eq!(harness.policy.teardowns(), 1);
    assert_eq!(harness.spawner.terminations(), 1);
    assert_eq!(harness.manager.state(), SessionState::Disconnected);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

/// The kill-switch assertion in scripts/verify-live-tunnel.sh SIGKILLs openvpn
/// and then asks the daemon to disconnect. Whatever the supervisor has already
/// done to the session, that request must be answered promptly: a disconnect
/// that never returns leaves the GUI with a spinner and no way forward.
#[tokio::test]
async fn disconnect_answers_promptly_after_openvpn_died_on_its_own() {
    // Arrange
    let harness = build("disconnect-after-kill", Options::new());
    harness.manager.connect(profile()).await.expect("connect");

    // Act: openvpn dies without the daemon asking, as `kill -KILL` does.
    harness.spawner.process.finish();

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        harness.manager.disconnect(),
    )
    .await;

    // Assert: any answer is fine — already torn down, or torn down by us. What
    // is not fine is no answer at all.
    let answered = outcome.expect("disconnect must answer after an unexpected exit");
    match answered {
        Ok(()) | Err(SessionError::NotConnected) | Err(SessionError::Busy) => {}
        Err(other) => panic!("unexpected disconnect error: {other}"),
    }
}

#[tokio::test]
async fn disconnect_is_refused_when_nothing_is_connected() {
    let harness = build("idle-disconnect", Options::new());

    assert!(matches!(
        harness.manager.disconnect().await,
        Err(SessionError::NotConnected)
    ));
}

#[tokio::test]
async fn an_unknown_profile_never_reaches_the_spawner() {
    let harness = build("unknown-profile", Options::new());

    let outcome = harness
        .manager
        .connect(ProfileId("absent".to_owned()))
        .await;

    assert!(matches!(outcome, Err(SessionError::ProfileNotFound { .. })));
    assert_eq!(harness.spawner.spawns(), 0);
}

#[tokio::test]
async fn a_stored_profile_that_no_longer_validates_is_refused() {
    // Arrange
    let runtime_dir = scratch("bad-profile");
    let mut config = SessionConfig::new(&runtime_dir, &runtime_dir);
    config.openvpn_path = Some(PathBuf::from("/bin/sh"));
    let (outbound, _inbound) = mpsc::channel(64);
    let spawner = FakeSpawner::alive();
    let deps = SessionDeps {
        // `plugin` dlopens a library whose constructor runs before any symbol
        // check; it must never survive a round trip through storage.
        profiles: Arc::new(MemoryProfiles::new().with("work", "client\nplugin /tmp/evil.so\n")),
        spawner: Arc::clone(&spawner) as Arc<dyn ProcessSpawner>,
        transports: Arc::new(FixedFactory::new(Box::new(SilentTransport))),
        policy: Arc::new(FakePolicy::working()),
        egress: Arc::new(RecordingPublisher::default()),
        secrets: Arc::new(MemoryStore::new()),
        prompts: Arc::new(PromptBroker::new(outbound.clone(), Duration::from_secs(1))),
    };
    let manager = SessionManager::new(config, deps, outbound);

    // Act
    let outcome = manager.connect(profile()).await;

    // Assert
    assert!(matches!(outcome, Err(SessionError::Profile(_))));
    assert_eq!(spawner.spawns(), 0);
    let _ = std::fs::remove_dir_all(&runtime_dir);
}

#[tokio::test]
async fn openvpn_that_never_reports_connected_times_out_and_is_cleaned_up() {
    // Arrange
    let mut options = Options::new();
    options.script = Some(Script::NeverConnects);
    let harness = build("never-up", options);
    // The default is minutes; this test must not wait that long.
    let outcome = tokio::time::timeout(Duration::from_secs(20), harness.manager.connect(profile()))
        .await
        .expect("connect did not settle");

    // Assert
    assert!(outcome.is_err());
    assert_eq!(harness.spawner.terminations(), 1);
    assert!(session_dirs(&harness.runtime_dir).is_empty());
}

#[tokio::test]
async fn the_status_snapshot_reports_the_profile_that_is_connected() {
    let harness = build("status", Options::new());
    harness.manager.connect(profile()).await.expect("connect");

    let status = harness.manager.status();

    assert_eq!(status.profile_id, Some(profile()));
    assert!(status.connected_since_unix_secs.is_some());
}
