// SPDX-License-Identifier: GPL-3.0-or-later

//! The connect path: profile to running tunnel, and the teardown that every
//! failure on it runs.
//!
//! The order is fixed by SPEC.md and is not an implementation detail:
//! re-validate the stored profile, write the canonical config 0600 into a 0700
//! directory, create the management socket *before* spawning openvpn, accept its
//! reverse connection, answer credentials, and only once `>STATE:...,CONNECTED`
//! has arrived together with a `>UPDOWN` block carrying `dev=` install and verify
//! tunnel policy — after which, and only after which, the tunnel identity is
//! published to the proxy.
//!
//! Nothing partial survives. Every early return goes through [`teardown`], and
//! the files are additionally owned by a `Drop` guard so a panic cannot leave a
//! config full of key material behind.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use thisconnect_shared::ipc::{DnsSource, ProfileId, TunnelInfo};
use thisconnect_shared::ovpn::{parse_profile, Profile};
use tokio::sync::{broadcast, oneshot, watch};
use tracing::{debug, info, warn};

use crate::auth::AuthFlow;
use crate::mgmt::challenge::StaticChallengeFormat;
use crate::mgmt::client::Connected;
use crate::mgmt::{Event as MgmtEvent, MgmtClient, TunnelIdentity};

use super::spawn::{ProcessControl, ProcessExit};
use super::state::{EventSink, SessionState, StateCell};
use super::transport::ACCEPT_TIMEOUT;
use super::tunnel::{spec_from_identity, TunnelBinding, DEFAULT_TUNNEL_MTU};
use super::workspace::SessionWorkspace;
use super::{SessionConfig, SessionDeps, SessionError};

/// How long openvpn gets to stop politely before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Ceiling on a whole teardown. Every step inside is individually bounded, but
/// they talk to subprocesses, a management socket whose peer may already be
/// gone, and the routing table — so the sum is bounded too. Disconnect is a
/// user-visible action: an unbounded teardown is a GUI that spins forever with
/// no way forward, which is worse than a teardown that gives up and says so.
const TEARDOWN_BUDGET: Duration = Duration::from_secs(30);

/// Everything one attempt owns. Dropping it removes the config, the socket and
/// their directory, and kills the child.
pub(crate) struct SessionResources {
    workspace: SessionWorkspace,
    control: Arc<dyn ProcessControl>,
    pub(super) exit: oneshot::Receiver<ProcessExit>,
    pub(super) mgmt: Option<Connected>,
    binding: Option<TunnelBinding>,
}

impl SessionResources {
    pub(crate) fn binding(&self) -> Option<&TunnelBinding> {
        self.binding.as_ref()
    }

    /// The authoritative tunnel-state feed the supervisor watches for a
    /// transition away from `CONNECTED`.
    pub(crate) fn tunnel_state(&self) -> Option<watch::Receiver<crate::mgmt::TunnelState>> {
        self.mgmt.as_ref().map(|mgmt| mgmt.client.tunnel_state())
    }

    /// A fresh subscription to the management event feed, for the supervisor's
    /// byte-count accounting.
    pub(crate) fn mgmt_events(&self) -> Option<broadcast::Receiver<MgmtEvent>> {
        self.mgmt.as_ref().map(|mgmt| mgmt.client.subscribe())
    }
}

pub(crate) struct Established {
    pub resources: SessionResources,
    pub tunnel: TunnelInfo,
}

pub(crate) struct Attempt<'a> {
    pub profile_id: &'a ProfileId,
    pub config: &'a SessionConfig,
    pub deps: &'a SessionDeps,
    pub state: &'a StateCell,
    pub events: &'a EventSink,
    pub flow: &'a AuthFlow,
    pub cancel: watch::Receiver<bool>,
}

/// Runs the whole attempt. On any failure the machine is left exactly as it was
/// found: openvpn stopped, policy removed, identity revoked, files gone.
pub(crate) async fn establish(attempt: Attempt<'_>) -> Result<Established, SessionError> {
    let raw = attempt.deps.profiles.load(attempt.profile_id)?;
    // Stored state is re-validated on every connect; it is never trusted because
    // this daemon wrote it once.
    let profile = parse_profile(&raw).map_err(SessionError::Profile)?;

    let mut resources = start_openvpn(&profile, attempt.config, attempt.deps).await?;

    match bring_up(&mut resources, &profile, &attempt).await {
        Ok(tunnel) => Ok(Established { resources, tunnel }),
        Err(error) => {
            teardown(resources, attempt.deps).await;
            Err(error)
        }
    }
}

/// Config file, then socket, then process — in that order, because openvpn
/// connects back the moment it starts.
async fn start_openvpn(
    profile: &Profile,
    config: &SessionConfig,
    deps: &SessionDeps,
) -> Result<SessionResources, SessionError> {
    let program = super::spawn::resolve_openvpn(config.openvpn_path.as_deref())?;
    let workspace = SessionWorkspace::create(&config.runtime_dir)?;
    workspace.write_config(&profile.to_canonical_config())?;

    let transport = deps.transports.bind(workspace.socket_path())?;
    let capabilities = super::spawn::detect_capabilities(&program);
    let args = super::spawn::build_args(
        workspace.config_path(),
        workspace.socket_path(),
        capabilities,
    )?;
    let spawned = deps.spawner.spawn(&program, &args)?;

    info!(binary = %program.display(), "spawned openvpn");
    let mut resources = SessionResources {
        workspace,
        control: spawned.control,
        exit: spawned.exit,
        mgmt: None,
        binding: None,
    };

    let stream = tokio::select! {
        // A child that is already gone is reported as such: an accept error on a
        // socket nothing will ever connect to is the symptom, not the cause.
        biased;
        exit = &mut resources.exit => return Err(exited(exit)),
        accepted = transport.accept(ACCEPT_TIMEOUT) => accepted?,
    };
    let connected = MgmtClient::connect(stream)
        .await
        .map_err(SessionError::Mgmt)?;
    debug!(version = connected.version, "management interface up");
    resources.mgmt = Some(connected);
    Ok(resources)
}

async fn bring_up(
    resources: &mut SessionResources,
    profile: &Profile,
    attempt: &Attempt<'_>,
) -> Result<TunnelInfo, SessionError> {
    attempt.state.advance(SessionState::Authenticating)?;
    let identity = super::handshake::authenticate(resources, profile, attempt).await?;
    install_policy(resources, profile, attempt, &identity).await
}

/// Installs and verifies tunnel policy, then — and only then — publishes the
/// tunnel identity the proxy pins its sockets to.
async fn install_policy(
    resources: &mut SessionResources,
    profile: &Profile,
    attempt: &Attempt<'_>,
    identity: &TunnelIdentity,
) -> Result<TunnelInfo, SessionError> {
    let local_v4 = identity
        .ifconfig_local
        .clone()
        .ok_or(SessionError::MissingTunnelAddress)?;
    let mtu = profile_mtu(profile);
    let spec = spec_from_identity(
        &identity.dev,
        &local_v4,
        identity.ifconfig_ipv6_local.as_deref(),
        mtu,
    )
    .map_err(SessionError::Policy)?;

    let policy = Arc::clone(&attempt.deps.policy);
    // `CommandRunner` is synchronous std::process, so it must not run on a
    // runtime worker thread.
    let binding = tokio::task::spawn_blocking(move || policy.install(spec, mtu))
        .await
        .map_err(|error| SessionError::Internal {
            detail: format!("tunnel policy task failed: {error}"),
        })?
        .map_err(SessionError::Policy)?;

    // The routes, the rule and the floor now exist on the machine, and this
    // binding is the only value able to remove them. It is handed to the
    // resources before anything else may fail, so that every later error still
    // reaches `teardown` with something to undo.
    let binding = resources.binding.insert(binding);

    attempt
        .deps
        .egress
        .publish(binding)
        .map_err(SessionError::Policy)?;

    Ok(describe_tunnel(binding, profile, attempt.config))
}

fn describe_tunnel(
    binding: &TunnelBinding,
    profile: &Profile,
    config: &SessionConfig,
) -> TunnelInfo {
    let pushed: Vec<IpAddr> = profile
        .dhcp_dns_servers()
        .into_iter()
        .filter_map(|raw| raw.parse().ok())
        .collect();
    let (dns_servers, dns_source) = if pushed.is_empty() {
        (config.fallback_dns.clone(), DnsSource::TunnelFallback)
    } else {
        (pushed, DnsSource::Pushed)
    };
    TunnelInfo {
        device: binding.device.clone(),
        ipv4: Some(binding.ipv4),
        ipv6: binding.ipv6,
        mtu: Some(binding.mtu),
        tunnel_has_v6: binding.tunnel_has_v6,
        dns_servers,
        dns_source,
        search_domains: Vec::new(),
    }
}

/// SPEC.md §4.3 point 6 gives no MTU in the `>UPDOWN` block, so the profile's own
/// `tun-mtu` is the only thing to go on.
fn profile_mtu(profile: &Profile) -> u32 {
    profile
        .directives()
        .iter()
        .find(|directive| directive.name == "tun-mtu")
        .and_then(|directive| directive.args.first())
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_TUNNEL_MTU)
}

pub(crate) fn challenge_format(profile: &Profile) -> StaticChallengeFormat {
    match profile.static_challenge().and_then(|sc| sc.format_flags) {
        Some(1) => StaticChallengeFormat::Concat,
        _ => StaticChallengeFormat::Scrv1,
    }
}

pub(crate) fn exited(exit: Result<ProcessExit, oneshot::error::RecvError>) -> SessionError {
    match exit {
        Ok(status) => SessionError::OpenvpnExited {
            code: status.code,
            signal: status.signal,
        },
        Err(_) => SessionError::OpenvpnExited {
            code: None,
            signal: None,
        },
    }
}

/// The single teardown path, run on every failure and on every disconnect.
///
/// The tunnel identity is revoked first and unconditionally: until it is, the
/// proxy could still hand out a socket pinned to a tunnel that is already going
/// away (SPEC.md §5.3).
pub(crate) async fn teardown(resources: SessionResources, deps: &SessionDeps) {
    if tokio::time::timeout(TEARDOWN_BUDGET, teardown_inner(resources, deps))
        .await
        .is_err()
    {
        // The tunnel identity was revoked first, so nothing can still be
        // pinning sockets to it even if a later step is wedged.
        warn!(
            "teardown did not finish within {}s; the session is reported as gone anyway",
            TEARDOWN_BUDGET.as_secs()
        );
    }
}

async fn teardown_inner(mut resources: SessionResources, deps: &SessionDeps) {
    deps.egress.revoke();

    if let Some(binding) = resources.binding.take() {
        let policy = Arc::clone(&deps.policy);
        let outcome = tokio::task::spawn_blocking(move || policy.teardown(&binding)).await;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "tunnel policy teardown failed"),
            Err(error) => warn!(%error, "tunnel policy teardown task failed"),
        }
    }

    if let Some(mgmt) = resources.mgmt.take() {
        // Closing the management socket makes openvpn SIGTERM itself; asking
        // first is politer and works even if the child ignores the signal.
        // Bounded on its own: the peer may already be gone (the tunnel died, or
        // something killed openvpn), and politely asking a corpse to exit must
        // not be what delays a disconnect. Closing the socket below achieves the
        // same thing regardless.
        match tokio::time::timeout(STOP_GRACE, mgmt.client.signal("SIGTERM")).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(%error, "could not ask openvpn to stop over the management channel")
            }
            Err(_) => debug!("openvpn did not acknowledge SIGTERM over the management channel"),
        }
        drop(mgmt.client);
        mgmt.task.abort();
    }

    resources.control.terminate();
    if tokio::time::timeout(STOP_GRACE, &mut resources.exit)
        .await
        .is_err()
    {
        warn!("openvpn did not exit within the grace period; killing it");
        resources.control.kill();
        let _ = tokio::time::timeout(STOP_GRACE, &mut resources.exit).await;
    }

    deps.prompts.withdraw_all().await;
    // Dropping the workspace removes the canonical config, the management socket
    // and their directory.
}
