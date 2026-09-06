// SPDX-License-Identifier: GPL-3.0-or-later

//! Tunnel policy (SPEC.md §5.2): the privileged routing state that makes pinned egress work,
//! installed and removed without ever touching the system default route.
//!
//! The two platforms differ in what has to be installed — macOS scopes a default route to the
//! utun and gets its fail-closed floor from the kernel's refusal to fall back to `en0`, while
//! Linux needs a `unreachable` floor, a source-address rule and a route in a private table — but
//! both are expressed as an ordered list of verified, reversible steps behind [`TunnelPolicy`],
//! so the orchestrator never branches on the platform.
//!
//! The order is a security property, not bookkeeping: on Linux the floor is installed first and
//! removed last, and only after the rule is *observed* gone. The daemon may not publish the tun
//! address to the proxy until everything is installed and read back, which is why the tun address
//! is reachable only through an [`InstalledPolicy`] that `install` returns after verification.

// Nothing consumes tunnel policy until the connect orchestrator lands; the module is complete and
// tested on its own, so the unused-code warnings are silenced here rather than at the crate root.
#![allow(dead_code, unused_imports)]

mod command;
mod linux;
mod macos;
#[cfg(target_os = "linux")]
mod netlink;
mod plan;
mod reconcile;
#[cfg(target_os = "macos")]
mod route_socket;
mod types;
mod watch;

use std::net::IpAddr;

pub use command::{Command, CommandOutput, CommandRunner, SystemRunner};
pub use linux::LinuxPolicy;
pub use macos::MacosPolicy;
#[cfg(target_os = "linux")]
pub use netlink::{PolicyWatch, WatchError};
pub use plan::{Check, Plan, Reassertion, Step, StepKind};
pub use reconcile::ReconcileReport;
#[cfg(target_os = "macos")]
pub use route_socket::{PolicyWatch, WatchError};
pub use types::{
    DeviceName, Family, Mtu, RawTunnel, Topology, TunnelEndpoint, TunnelSpec, POLICY_TABLE,
    RULE_PRIORITY,
};
pub use watch::Trigger;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("refusing {value:?} as an interface name: {reason}")]
    InvalidDevice { reason: &'static str, value: String },

    #[error("refusing {value:?} as a tunnel address: {reason}")]
    InvalidAddress { reason: &'static str, value: String },

    #[error("refusing an MTU of {0}")]
    InvalidMtu(u32),

    #[error("refusing {value:?} as a command argument: {reason}")]
    UnsafeArgument { reason: &'static str, value: String },

    #[error("tunnel policy steps are out of order: {detail}")]
    Ordering { detail: &'static str },

    #[error("could not run {command}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to install the {what} with {command}: {stderr}")]
    CommandFailed {
        what: &'static str,
        command: String,
        stderr: String,
    },

    #[error("{probe} did not confirm the policy: {detail}")]
    Verification { probe: String, detail: String },

    /// Both halves are carried because they mean different things to the caller: `cause` is why
    /// the install stopped, `rollback` is why the machine is still holding privileged state.
    #[error("tunnel policy install failed ({cause}) and the rollback failed too ({rollback}); privileged routing state is still installed")]
    RollbackFailed {
        cause: Box<PolicyError>,
        rollback: Box<PolicyError>,
    },

    #[error("stale tunnel policy survived {passes} teardown passes")]
    ResidueRemains { passes: usize },

    #[error("tunnel policy is not implemented for this platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
pub(crate) use command::testing;

/// One platform's tunnel policy, expressed as commands and read-back assertions.
pub trait TunnelPolicy: Send + Sync {
    /// The ordered, reversible steps that make egress work for this tunnel.
    fn plan(&self, spec: &TunnelSpec) -> Result<Plan, PolicyError>;

    /// State a previous session may have left on the exact device we are about to use. Applied
    /// best effort before the plan, because a recycled interface can still carry a dead session's
    /// route and `route add` would otherwise fail with `File exists` forever.
    fn pre_install_cleanup(&self, spec: &TunnelSpec) -> Result<Vec<Command>, PolicyError>;

    /// Leftovers found anywhere on the machine, for startup reconciliation. Returning an empty
    /// vector means "the machine is clean"; reconciliation calls this again after acting on it.
    fn stale_cleanup(&self, runner: &dyn CommandRunner) -> Result<Vec<Command>, PolicyError>;
}

/// Proof that a tunnel's policy is installed *and was read back*. The tun address the proxy pins
/// its sockets to is only reachable through this value, so it cannot be published early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPolicy {
    spec: TunnelSpec,
    plan: Plan,
}

impl InstalledPolicy {
    pub fn device(&self) -> &DeviceName {
        self.spec.device()
    }

    /// The address the unprivileged proxy binds outbound sockets to (SPEC.md §5.3).
    pub fn egress_v4(&self) -> IpAddr {
        self.spec.v4().local()
    }

    pub fn egress_v6(&self) -> Option<IpAddr> {
        self.spec.v6().map(TunnelEndpoint::local)
    }

    /// §5.5: a v4-only tunnel on a v6-capable host is a leak vector, so the proxy must know.
    pub fn tunnel_has_v6(&self) -> bool {
        self.spec.v6().is_some()
    }

    pub fn spec(&self) -> &TunnelSpec {
        &self.spec
    }
}

/// Platform-agnostic front door: reconcile, install, tear down.
pub struct PolicyManager<R: CommandRunner> {
    backend: Box<dyn TunnelPolicy>,
    runner: R,
    /// Whether a policy this manager installed is still standing. Reconciliation removes *any*
    /// policy state it finds, including the live session's own rule and table, so the precondition
    /// "reconcile before the first install" has to be enforced rather than documented.
    installed: std::sync::atomic::AtomicBool,
}

impl<R: CommandRunner> PolicyManager<R> {
    pub fn new(backend: Box<dyn TunnelPolicy>, runner: R) -> Self {
        Self {
            backend,
            runner,
            installed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn for_platform(runner: R) -> Result<Self, PolicyError> {
        Ok(Self::new(platform_backend()?, runner))
    }

    /// Startup reconciliation. Refuses to run while a policy is installed: it would tear the live
    /// session's rule and table down out from under a proxy that is still pinning sockets to the
    /// egress address, which is a leak, not a cleanup.
    pub fn reconcile(&self) -> Result<ReconcileReport, PolicyError> {
        if self.installed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(PolicyError::Ordering {
                detail: "reconciliation may not run while a tunnel policy is installed",
            });
        }
        reconcile::reconcile(self.backend.as_ref(), &self.runner)
    }

    /// Installs and verifies. On any failure the partial state is torn down before returning; if
    /// that teardown also fails the caller gets [`PolicyError::RollbackFailed`], so a caller
    /// holding any other error holds a clean machine.
    pub fn install(&self, spec: TunnelSpec) -> Result<InstalledPolicy, PolicyError> {
        let plan = self.backend.plan(&spec)?;
        let cleanup = self.backend.pre_install_cleanup(&spec)?;
        reconcile::run_best_effort(&cleanup, &self.runner)?;
        plan::install(&plan, &self.runner)?;
        self.installed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(InstalledPolicy { spec, plan })
    }

    /// Restores whatever has been deleted out from under a live session. Distinct from
    /// [`Self::reconcile`], which removes state a *dead* session left behind: this one puts back
    /// state a live session still depends on, and the two must never be confused.
    pub fn reassert(&self, installed: &InstalledPolicy) -> plan::Reassertion {
        plan::reassert(&installed.plan, &self.runner)
    }

    /// Idempotent, and safe to call on a machine where the state is already gone.
    pub fn teardown(&self, installed: &InstalledPolicy) -> Result<(), PolicyError> {
        plan::teardown(&installed.plan, &self.runner)?;
        self.installed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn platform_backend() -> Result<Box<dyn TunnelPolicy>, PolicyError> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacosPolicy::default()))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxPolicy::system()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(PolicyError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::command::testing::{ok, ScriptedRunner};
    use super::*;

    fn spec() -> TunnelSpec {
        TunnelSpec::parse(RawTunnel {
            device: "tun0",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            local_v6: Some("fd00::2"),
            gateway_v6: None,
            mtu: 1400,
        })
        .expect("valid spec")
    }

    fn linux_manager<F>(reply: F) -> PolicyManager<ScriptedRunner<F>>
    where
        F: Fn(&Command) -> CommandOutput + Send + Sync,
    {
        PolicyManager::new(
            Box::new(LinuxPolicy::with_ip_binary("/usr/sbin/ip")),
            ScriptedRunner::new(reply),
        )
    }

    fn everything_installed(command: &Command) -> CommandOutput {
        let rendered = command.to_string();
        if rendered.ends_with("route show table 218") {
            ok("unreachable default metric 4000\ndefault dev tun0 src 10.8.0.2 metric 100 mtu 1400\n")
        } else if rendered.ends_with("rule show") {
            ok(
                "18500:\tfrom 10.8.0.2 unreachable\n18500:\tfrom fd00::2 unreachable\n\
                18000:\tfrom 10.8.0.2 lookup 218\n18000:\tfrom fd00::2 lookup 218\n",
            )
        } else {
            ok("")
        }
    }

    #[test]
    fn install_publishes_the_egress_address_only_after_every_step_verified() {
        let manager = linux_manager(everything_installed);

        let installed = manager.install(spec()).expect("installed");

        assert_eq!(installed.egress_v4().to_string(), "10.8.0.2");
        assert_eq!(
            installed.egress_v6().map(|address| address.to_string()),
            Some("fd00::2".to_owned())
        );
        assert!(installed.tunnel_has_v6());
        assert_eq!(installed.device().as_str(), "tun0");
    }

    #[test]
    fn install_clears_a_dead_sessions_state_before_building_on_it() {
        let manager = linux_manager(everything_installed);

        manager.install(spec()).expect("installed");

        let log = manager.runner.log();
        let flush_at = log
            .iter()
            .position(|line| line.ends_with("route flush table 218"))
            .expect("cleanup ran");
        let first_install_at = log
            .iter()
            .position(|line| line.contains("rule add from 10.8.0.2/32 type unreachable"))
            .expect("backstop installed");
        assert!(
            flush_at < first_install_at,
            "cleanup must precede the first install"
        );
    }

    #[test]
    fn a_failed_install_yields_no_installed_policy_and_leaves_nothing_behind() {
        // The backstop and the floor read back, our policy rule never does, so verification of the
        // rule fails. Each stops reading back once deleted, which is how the rollback proves the
        // machine is clean.
        let floor_removed = std::sync::atomic::AtomicBool::new(false);
        let backstop_removed = std::sync::atomic::AtomicBool::new(false);
        let manager = linux_manager(move |command| {
            let rendered = command.to_string();
            if rendered.contains("route del unreachable") {
                floor_removed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if rendered.contains("rule del from 10.8.0.2/32 type unreachable") {
                backstop_removed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if rendered.ends_with("route show table 218")
                && !floor_removed.load(std::sync::atomic::Ordering::SeqCst)
            {
                ok("unreachable default metric 4000\n")
            } else if rendered.ends_with("rule show")
                && !backstop_removed.load(std::sync::atomic::Ordering::SeqCst)
            {
                ok("18500:\tfrom 10.8.0.2 unreachable\n")
            } else {
                ok("")
            }
        });

        let outcome = manager.install(spec());

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
        let log = manager.runner.log();
        assert!(log
            .iter()
            .any(|line| line.contains("rule del from 10.8.0.2/32")));
        assert!(log
            .iter()
            .any(|line| line.contains("route del unreachable")));
        assert!(log
            .iter()
            .any(|line| line.contains("rule del from 10.8.0.2/32 type unreachable")));
    }

    #[test]
    fn teardown_of_a_verified_install_removes_every_step_in_reverse() {
        let manager = linux_manager(|command| {
            let rendered = command.to_string();
            if rendered.contains("show") {
                // Present while installing is verified by the install test; here everything reads
                // back empty, which is what teardown must see.
                ok("")
            } else {
                ok("")
            }
        });
        let installed = InstalledPolicy {
            plan: LinuxPolicy::with_ip_binary("/usr/sbin/ip")
                .plan(&spec())
                .expect("plan"),
            spec: spec(),
        };

        manager.teardown(&installed).expect("torn down");

        let removals: Vec<String> = manager
            .runner
            .log()
            .into_iter()
            .filter(|line| line.contains(" del "))
            .collect();
        assert_eq!(removals.len(), 8);
        assert!(removals[0].contains("route del default dev tun0 src fd00::2"));
        assert!(removals[6].contains("-4 route del unreachable"));
        assert!(removals[7].contains("-4 rule del from 10.8.0.2/32 type unreachable"));
    }

    #[test]
    fn reconcile_refuses_to_run_while_a_policy_is_installed() {
        // Reports the policy present until the first teardown command is issued, then empty.
        let tearing_down = std::sync::atomic::AtomicBool::new(false);
        let manager = linux_manager(move |command| {
            let rendered = command.to_string();
            if rendered.contains("route del default dev") {
                tearing_down.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if tearing_down.load(std::sync::atomic::Ordering::SeqCst) {
                ok("")
            } else {
                everything_installed(command)
            }
        });
        let installed = manager.install(spec()).expect("installed");

        let outcome = manager.reconcile();

        assert!(matches!(outcome, Err(PolicyError::Ordering { .. })));
        // And it becomes available again once the live session's policy is gone.
        manager.teardown(&installed).expect("torn down");
        assert!(manager.reconcile().is_ok());
    }

    #[test]
    fn reconcile_runs_before_the_first_install() {
        let manager = linux_manager(|_| ok(""));

        assert!(manager.reconcile().is_ok());
    }

    #[test]
    fn the_macos_backend_installs_a_scoped_route_and_no_floor_or_rule() {
        let manager = PolicyManager::new(
            Box::new(MacosPolicy::default()),
            ScriptedRunner::new(|command| {
                if command.args().contains(&"get".to_owned()) {
                    ok("   route to: default\n  interface: utun4\n    gateway: 10.8.0.1\n")
                } else {
                    ok("")
                }
            }),
        );
        let macos_spec = TunnelSpec::parse(RawTunnel {
            device: "utun4",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            mtu: 1400,
            ..RawTunnel::default()
        })
        .expect("valid spec");

        let installed = manager.install(macos_spec).expect("installed");

        assert_eq!(installed.egress_v4().to_string(), "10.8.0.2");
        assert!(!installed.tunnel_has_v6());
        assert!(manager
            .runner
            .log()
            .iter()
            .any(|line| line == "/sbin/route -n add -inet -ifscope utun4 default 10.8.0.1"));
    }
}
