// SPDX-License-Identifier: GPL-3.0-or-later

//! The connect orchestrator: the piece that turns a stored profile into a
//! running, policy-verified tunnel.
//!
//! Exactly one connection exists at a time in v1 (SPEC.md §2). The state machine
//! in [`state`] is the authority on that, and every transition either completes
//! or tears down fully — there is no partial state a later step could inherit.

// The connect path is reached through `handler::SessionHandler::dispatch`, which
// speaks the `thisconnect_shared::ipc` vocabulary. The IPC server still frames the
// skeleton `ping`/`version`/`status` protocol in `ipc::proto`, so in a non-test
// build nothing calls `connect` yet. Drop this allow once the server is moved onto
// the shared vocabulary; the tests below already drive every path.
#![allow(dead_code)]

pub mod connect;
pub mod dns;
pub mod error;
pub mod handshake;
pub mod profiles;
pub mod proxy;
pub mod spawn;
pub mod state;
pub mod store;
pub mod transport;
pub mod tunnel;
#[cfg(target_os = "linux")]
pub mod watchdog;
pub mod workspace;

#[cfg(test)]
pub(crate) mod tests;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thisconnect_shared::ipc::{ConnectionStatus, DaemonMessage, Event, ProfileId, TunnelInfo};
use thisconnect_shared::ovpn;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{info, warn};

use crate::auth::prompt::{PromptBroker, DEFAULT_PROMPT_TIMEOUT};
use crate::auth::store::SecretStore;
use crate::auth::totp::TotpSettings;
use crate::auth::AuthFlow;
use crate::mgmt::TunnelState;
use crate::policy::ReconcileReport;

use connect::{establish, teardown, Attempt, SessionResources};
pub use error::SessionError;
use profiles::ProfileSource;
use spawn::ProcessSpawner;
use state::{EventSink, SessionState, StateCell};
use transport::MgmtTransportFactory;
use tunnel::{EgressPublisher, TunnelPolicyDriver};

/// Long enough for a user to fetch a phone for a TOTP prompt, and bounded so a
/// stuck attempt never holds the session slot forever.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(180);

/// Tunables. Everything with a filesystem path is overridable so the daemon can
/// run out of a scratch directory in tests and out of `/run` in production.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub runtime_dir: PathBuf,
    pub profile_dir: PathBuf,
    /// User override for the openvpn binary; resolved from `PATH` when absent.
    pub openvpn_path: Option<PathBuf>,
    pub connect_timeout: Duration,
    pub prompt_timeout: Duration,
    pub totp: TotpSettings,
    /// Queried *through the tun* when the profile carried no `dhcp-option DNS`.
    /// Never the system resolver (SPEC.md §5.4 D4).
    pub fallback_dns: Vec<IpAddr>,
}

impl SessionConfig {
    pub fn new(runtime_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            runtime_dir: runtime_dir.into(),
            profile_dir: profiles::default_profile_dir(&state_dir),
            openvpn_path: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            prompt_timeout: DEFAULT_PROMPT_TIMEOUT,
            totp: TotpSettings::default(),
            fallback_dns: vec![
                "9.9.9.9"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(9, 9, 9, 9))),
                "1.1.1.1"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))),
            ],
        }
    }
}

/// The injectable collaborators. Every one of them has a test double, which is
/// how the connect path is exercised without a real openvpn or a real route table.
pub struct SessionDeps {
    pub profiles: Arc<dyn ProfileSource>,
    pub spawner: Arc<dyn ProcessSpawner>,
    pub transports: Arc<dyn MgmtTransportFactory>,
    pub policy: Arc<dyn TunnelPolicyDriver>,
    pub egress: Arc<dyn EgressPublisher>,
    pub secrets: Arc<dyn SecretStore>,
    pub prompts: Arc<PromptBroker>,
}

#[derive(Clone, Debug, Default)]
struct StatusSnapshot {
    profile_id: Option<ProfileId>,
    since: Option<u64>,
    bytes_in: u64,
    bytes_out: u64,
    tunnel: Option<TunnelInfo>,
    last_error: Option<String>,
}

struct Active {
    resources: SessionResources,
}

struct Inner {
    config: SessionConfig,
    deps: SessionDeps,
    state: StateCell,
    events: EventSink,
    active: tokio::sync::Mutex<Option<Active>>,
    cancel: Mutex<watch::Sender<bool>>,
    status: Mutex<StatusSnapshot>,
}

/// The daemon's single connection.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Inner>,
}

impl SessionManager {
    pub fn new(
        config: SessionConfig,
        deps: SessionDeps,
        outbound: mpsc::Sender<DaemonMessage>,
    ) -> Self {
        let events = EventSink::new(outbound);
        let (cancel, _) = watch::channel(false);
        Self {
            inner: Arc::new(Inner {
                config,
                deps,
                state: StateCell::new(events.clone()),
                events,
                active: tokio::sync::Mutex::new(None),
                cancel: Mutex::new(cancel),
                status: Mutex::new(StatusSnapshot::default()),
            }),
        }
    }

    pub fn prompts(&self) -> Arc<PromptBroker> {
        Arc::clone(&self.inner.deps.prompts)
    }

    pub fn state(&self) -> SessionState {
        self.inner.state.current()
    }

    /// Removes tunnel policy a crashed run left behind. Must run before the
    /// first connect of a daemon's life (SPEC.md §5.2).
    pub async fn reconcile(&self) -> Result<ReconcileReport, SessionError> {
        let policy = Arc::clone(&self.inner.deps.policy);
        tokio::task::spawn_blocking(move || policy.reconcile())
            .await
            .map_err(|error| SessionError::Internal {
                detail: format!("reconciliation task failed: {error}"),
            })?
            .map_err(SessionError::Policy)
    }

    pub fn status(&self) -> ConnectionStatus {
        let snapshot = lock(&self.inner.status).clone();
        let state = self.inner.state.current();
        ConnectionStatus {
            state: state.to_ipc(),
            profile_id: snapshot.profile_id,
            connected_since_unix_secs: snapshot.since,
            bytes_in: snapshot.bytes_in,
            bytes_out: snapshot.bytes_out,
            tunnel: snapshot.tunnel,
            last_error: snapshot.last_error,
        }
    }

    pub async fn connect(&self, profile_id: ProfileId) -> Result<ConnectionStatus, SessionError> {
        self.inner.state.begin_connect()?;
        match self.run_connect(profile_id).await {
            Ok(status) => Ok(status),
            Err(error) => {
                self.record_failure(&error);
                Err(error)
            }
        }
    }

    async fn run_connect(&self, profile_id: ProfileId) -> Result<ConnectionStatus, SessionError> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        *lock(&self.inner.cancel) = cancel_tx;

        let flow = AuthFlow::new(
            profile_id.clone(),
            Arc::clone(&self.inner.deps.secrets),
            Arc::clone(&self.inner.deps.prompts),
            self.inner.config.totp,
        );
        let established = establish(Attempt {
            profile_id: &profile_id,
            config: &self.inner.config,
            deps: &self.inner.deps,
            state: &self.inner.state,
            events: &self.inner.events,
            flow: &flow,
            cancel: cancel_rx,
        })
        .await?;

        let tunnel_rx = established.resources.tunnel_state();
        let events_rx = established.resources.mgmt_events();
        // The transition is the commit point. A concurrent `disconnect` can have
        // moved the session on while the tunnel was coming up, and a refused
        // transition means nothing will ever own these resources: they are torn
        // down here rather than published into a slot no one can reach.
        if let Err(error) = self.inner.state.advance(SessionState::Connected) {
            teardown(established.resources, &self.inner.deps).await;
            return Err(error);
        }
        *lock(&self.inner.status) = StatusSnapshot {
            profile_id: Some(profile_id),
            since: Some(now_unix()),
            tunnel: Some(established.tunnel.clone()),
            ..StatusSnapshot::default()
        };
        *self.inner.active.lock().await = Some(Active {
            resources: established.resources,
        });
        self.inner.events.emit(Event::TunnelUp {
            tunnel: established.tunnel,
        });
        info!("tunnel up");

        if let (Some(tunnel_rx), Some(events_rx)) = (tunnel_rx, events_rx) {
            let weak = Arc::downgrade(&self.inner);
            tokio::spawn(supervise(weak, tunnel_rx, events_rx));
        }
        Ok(self.status())
    }

    pub async fn disconnect(&self) -> Result<(), SessionError> {
        let previous = self.inner.state.begin_disconnect()?;
        let _ = lock(&self.inner.cancel).send(true);

        if matches!(
            previous,
            SessionState::Connecting | SessionState::Authenticating
        ) {
            // The in-flight attempt owns its own resources and tears them down
            // on the cancellation it just saw; taking them here would race it.
            return Ok(());
        }

        let active = self.inner.active.lock().await.take();
        if let Some(active) = active {
            teardown(active.resources, &self.inner.deps).await;
        }
        self.finish_disconnect("disconnect requested");
        Ok(())
    }

    fn finish_disconnect(&self, reason: &str) {
        *lock(&self.inner.status) = StatusSnapshot::default();
        self.inner.state.force(SessionState::Disconnected, None);
        self.inner.events.emit(Event::TunnelDown {
            reason: reason.to_owned(),
        });
    }

    fn record_failure(&self, error: &SessionError) {
        let detail = error.user_facing();
        let mut snapshot = lock(&self.inner.status);
        *snapshot = StatusSnapshot {
            last_error: Some(detail.clone()),
            ..StatusSnapshot::default()
        };
        drop(snapshot);
        // A cancelled attempt is a user decision, not a failure to report as one.
        let next = if matches!(error, SessionError::Cancelled) {
            SessionState::Disconnected
        } else {
            SessionState::Failed
        };
        self.inner.state.force(next, Some(detail));
    }
}

/// Watches the live session. The tunnel `watch` is the authoritative feed: it is
/// never lossy, and the management actor publishes "disconnected" on every exit
/// path, so a dead openvpn arrives here too.
async fn supervise(
    inner: Weak<Inner>,
    mut tunnel_rx: watch::Receiver<TunnelState>,
    mut events_rx: broadcast::Receiver<crate::mgmt::Event>,
) {
    let generation = tunnel_rx.borrow().generation;
    let reason = loop {
        tokio::select! {
            changed = tunnel_rx.changed() => {
                if changed.is_err() {
                    break "the management channel closed";
                }
                let state = tunnel_rx.borrow_and_update().clone();
                if !state.connected {
                    break "the tunnel went down";
                }
                if state.generation != generation {
                    break "the tunnel reconnected under a new identity";
                }
            }
            event = events_rx.recv() => match event {
                Ok(crate::mgmt::Event::ByteCount { bytes_in, bytes_out }) => {
                    if let Some(inner) = inner.upgrade() {
                        record_bytes(&inner, bytes_in, bytes_out);
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break "the management channel closed",
            },
        }
    };

    let Some(inner) = inner.upgrade() else {
        return;
    };
    warn!(reason, "tearing the session down");
    handle_loss(&inner, reason).await;
}

fn record_bytes(inner: &Inner, bytes_in: u64, bytes_out: u64) {
    let mut snapshot = lock(&inner.status);
    *snapshot = StatusSnapshot {
        bytes_in,
        bytes_out,
        ..snapshot.clone()
    };
    drop(snapshot);
    inner.events.emit(Event::ByteCount {
        bytes_in,
        bytes_out,
    });
}

async fn handle_loss(inner: &Arc<Inner>, reason: &str) {
    inner
        .state
        .force(SessionState::Disconnecting, Some(reason.to_owned()));
    let active = inner.active.lock().await.take();
    if let Some(active) = active {
        teardown(active.resources, &inner.deps).await;
    }
    *lock(&inner.status) = StatusSnapshot {
        last_error: Some(reason.to_owned()),
        ..StatusSnapshot::default()
    };
    inner
        .state
        .force(SessionState::Failed, Some(reason.to_owned()));
    inner.events.emit(Event::TunnelDown {
        reason: reason.to_owned(),
    });
}

/// The default dependency set: real openvpn, real sockets, real routing, and the
/// proxy listener attached to the tunnel's lifetime.
///
/// The publisher is passed in rather than built here because the IPC handler
/// answers `ProxyInfo`/`ProxyStats` from the same value. Its DNS capture is wired
/// into the management transport, which is the only place the tunnel's pushed
/// resolver can be observed: it arrives in a `>LOG:` line before anything the
/// orchestrator owns exists (SPEC.md §5.4 D1).
pub fn system_deps(
    config: &SessionConfig,
    policy: Arc<dyn TunnelPolicyDriver>,
    secrets: Arc<dyn SecretStore>,
    outbound: mpsc::Sender<DaemonMessage>,
    egress: Arc<proxy::ProxyPublisher>,
) -> SessionDeps {
    let transports = proxy::TappedTransportFactory::new(
        Arc::new(transport::UnixTransportFactory),
        egress.capture(),
    );
    SessionDeps {
        profiles: Arc::new(profiles::FileProfileStore::new(&config.profile_dir)),
        spawner: Arc::new(spawn::SystemSpawner),
        transports: Arc::new(transports),
        policy,
        egress,
        secrets,
        prompts: Arc::new(PromptBroker::new(outbound, config.prompt_timeout)),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|delta| delta.as_secs())
        .unwrap_or_default()
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Re-exported so callers do not have to reach into `thisconnect_shared` for the
/// one constant that bounds a stored profile.
pub const MAX_PROFILE_BYTES: usize = ovpn::MAX_FILE_BYTES;
