// SPDX-License-Identifier: GPL-3.0-or-later

//! The seam between the connect orchestrator, tunnel policy, and the proxy's
//! egress dialer.
//!
//! Two orderings here are security properties, not bookkeeping. The tunnel
//! address reaches the proxy only from a [`TunnelBinding`], which exists only
//! after `PolicyManager::install` has installed *and read back* the floor, the
//! rule and the route (SPEC.md §5.6 L6). And on the way down the identity is
//! revoked before anything else, so no new pinned socket can be created against
//! a tunnel that is already going away (SPEC.md §5.3).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use tracing::warn;

use crate::policy::{
    CommandRunner, InstalledPolicy, PolicyError, PolicyManager, RawTunnel, Reassertion,
    ReconcileReport, TunnelSpec,
};

/// The `>UPDOWN:ENV` block carries no MTU, so the profile's `tun-mtu` is used
/// when it has one and this otherwise. It only sizes the tunnel route's `mtu`
/// argument on Linux; the kernel still owns path MTU on the utun itself.
pub const DEFAULT_TUNNEL_MTU: u32 = 1500;

/// Everything the unprivileged proxy needs to pin a socket, and nothing else.
///
/// Field-for-field the shape of `thisconnect_proxy::egress::TunnelConfig`; the
/// daemon does not depend on the proxy crate, so the conversion happens in
/// whichever process ends up owning the listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelBinding {
    pub device: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: u32,
}

impl TunnelBinding {
    /// §5.5. Not a stored flag: a binding that claimed v6 while carrying no v6 address would
    /// make the proxy offer AAAA and advertise `ATYP=0x04`, then refuse every connection that
    /// came back — a v4-only tunnel that looks dual-stack from the outside. Deriving it from
    /// the address makes that state unrepresentable rather than merely unreached.
    pub fn tunnel_has_v6(&self) -> bool {
        self.ipv6.is_some()
    }

    fn from_installed(installed: &InstalledPolicy, mtu: u32) -> Result<Self, PolicyError> {
        let ipv4 = match installed.egress_v4() {
            IpAddr::V4(address) => address,
            IpAddr::V6(address) => {
                return Err(PolicyError::InvalidAddress {
                    reason: "the tunnel's v4 endpoint is a v6 address",
                    value: address.to_string(),
                })
            }
        };
        let ipv6 = match installed.egress_v6() {
            Some(IpAddr::V6(address)) => Some(address),
            None => None,
            Some(IpAddr::V4(address)) => {
                return Err(PolicyError::InvalidAddress {
                    reason: "the tunnel's v6 endpoint is a v4 address",
                    value: address.to_string(),
                })
            }
        };
        Ok(Self {
            device: installed.device().as_str().to_owned(),
            ipv4,
            ipv6,
            mtu,
        })
    }
}

/// Installing and removing the privileged routing state. Injectable so the
/// connect path can be tested against a policy that refuses to install.
pub trait TunnelPolicyDriver: Send + Sync {
    fn reconcile(&self) -> Result<ReconcileReport, PolicyError>;

    /// Returns only after the policy has been installed and verified.
    fn install(&self, spec: TunnelSpec, mtu: u32) -> Result<TunnelBinding, PolicyError>;

    fn teardown(&self, binding: &TunnelBinding) -> Result<(), PolicyError>;

    /// Re-installs any policy step that has been removed since `install`. A no-op when nothing
    /// is installed, which is what makes it safe to call from a watchdog that outlives any one
    /// session.
    fn reassert(&self) -> Reassertion;
}

/// The real driver. It keeps the [`InstalledPolicy`] proof that `install`
/// returned, because only that value knows the plan to undo. One slot is enough:
/// v1 allows exactly one connection.
pub struct ManagedPolicy<R: CommandRunner> {
    manager: PolicyManager<R>,
    installed: Mutex<Option<InstalledPolicy>>,
}

impl<R: CommandRunner> ManagedPolicy<R> {
    pub fn new(manager: PolicyManager<R>) -> Self {
        Self {
            manager,
            installed: Mutex::new(None),
        }
    }
}

impl<R: CommandRunner> TunnelPolicyDriver for ManagedPolicy<R> {
    fn reconcile(&self) -> Result<ReconcileReport, PolicyError> {
        self.manager.reconcile()
    }

    fn install(&self, spec: TunnelSpec, mtu: u32) -> Result<TunnelBinding, PolicyError> {
        let installed = self.manager.install(spec)?;
        let binding = TunnelBinding::from_installed(&installed, mtu)?;
        *lock(&self.installed) = Some(installed);
        Ok(binding)
    }

    fn teardown(&self, binding: &TunnelBinding) -> Result<(), PolicyError> {
        // The guard is held across the whole teardown, not just the take(). It is the only thing
        // serialising this against a re-assertion from the watchdog, which would otherwise start
        // re-adding rules half way through their removal. Holding it also means "this session is
        // going away" is expressed as the absence of the proof value rather than as a second flag
        // that could disagree with it.
        let mut guard = lock(&self.installed);
        let Some(installed) = guard.take() else {
            // Already removed, or this daemon never installed it. Teardown is
            // idempotent by contract, so this is not an error.
            return Ok(());
        };
        if installed.device().as_str() != binding.device {
            warn!(
                installed = %installed.device(),
                requested = %binding.device,
                "tearing down the policy that is actually installed"
            );
        }
        self.manager.teardown(&installed)
    }

    fn reassert(&self) -> Reassertion {
        let installed = lock(&self.installed);
        installed
            .as_ref()
            .map(|installed| self.manager.reassert(installed))
            .unwrap_or_default()
    }
}

/// Where the tunnel identity is published for the proxy to pin sockets to.
///
/// [`super::proxy::ProxyPublisher`] is the implementation the daemon installs:
/// `publish` maps onto `thisconnect_proxy::egress::EgressState::tunnel_up` plus
/// the tunnel-pinned resolver and the listener, and `revoke` onto `tunnel_down`,
/// whose generation bump strands every socket handle issued against the old
/// tunnel.
pub trait EgressPublisher: Send + Sync {
    fn publish(&self, binding: &TunnelBinding) -> Result<(), PolicyError>;

    /// Must be called before any other teardown step.
    fn revoke(&self);
}

/// A publisher that admits it is not one. Kept for tests that need an egress
/// seam and do not care about the proxy; the daemon installs
/// [`super::proxy::ProxyPublisher`] instead, because a tunnel that comes up with
/// nothing able to egress through it must not look like success.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnwiredPublisher;

impl EgressPublisher for UnwiredPublisher {
    fn publish(&self, binding: &TunnelBinding) -> Result<(), PolicyError> {
        warn!(
            device = %binding.device,
            "no proxy worker is attached; the tunnel is up but nothing can egress through it"
        );
        Ok(())
    }

    fn revoke(&self) {}
}

/// Builds the validated spec from the untrusted strings openvpn reported.
pub fn spec_from_identity(
    device: &str,
    local_v4: &str,
    local_v6: Option<&str>,
    mtu: u32,
) -> Result<TunnelSpec, PolicyError> {
    TunnelSpec::parse(RawTunnel {
        device,
        local_v4,
        // openvpn's `>UPDOWN:ENV` block does not carry the tunnel peer, so the
        // interface-scoped variant of the route is used. It is the p2p/net30
        // form SPEC.md §5.2 lists and was verified working on macOS.
        gateway_v4: None,
        local_v6,
        gateway_v6: None,
        mtu,
    })
}

fn lock<T>(cell: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    cell.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::policy::TunnelEndpoint;

    use super::*;

    /// Lets a test hold `install` open, so it can drive the orchestrator into
    /// the window where the policy is on the machine but nothing owns it yet.
    pub(crate) struct InstallGate {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    /// The test's end of an [`InstallGate`].
    pub(crate) struct GateHandle {
        entered: tokio::sync::oneshot::Receiver<()>,
        release: std::sync::mpsc::Sender<()>,
    }

    impl GateHandle {
        /// Resolves once `install` has been entered and parked.
        pub(crate) async fn wait_for_install(&mut self) {
            let _ = (&mut self.entered).await;
        }

        pub(crate) fn release(&self) {
            let _ = self.release.send(());
        }
    }

    /// Records what the orchestrator asked for, and can be told to refuse.
    pub(crate) struct FakePolicy {
        fail_install: bool,
        gate: Option<InstallGate>,
        installs: AtomicUsize,
        teardowns: AtomicUsize,
    }

    impl FakePolicy {
        pub(crate) fn working() -> Self {
            Self {
                fail_install: false,
                gate: None,
                installs: AtomicUsize::new(0),
                teardowns: AtomicUsize::new(0),
            }
        }

        pub(crate) fn refusing() -> Self {
            Self {
                fail_install: true,
                ..Self::working()
            }
        }

        /// A policy whose `install` parks until the returned handle releases it.
        pub(crate) fn gated() -> (Self, GateHandle) {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let policy = Self {
                gate: Some(InstallGate {
                    entered: Mutex::new(Some(entered_tx)),
                    release: Mutex::new(Some(release_rx)),
                }),
                ..Self::working()
            };
            let handle = GateHandle {
                entered: entered_rx,
                release: release_tx,
            };
            (policy, handle)
        }

        pub(crate) fn teardowns(&self) -> usize {
            self.teardowns.load(Ordering::SeqCst)
        }

        pub(crate) fn installs(&self) -> usize {
            self.installs.load(Ordering::SeqCst)
        }
    }

    impl TunnelPolicyDriver for FakePolicy {
        fn reconcile(&self) -> Result<ReconcileReport, PolicyError> {
            Ok(ReconcileReport {
                passes: 0,
                removed: Vec::new(),
            })
        }

        fn install(&self, spec: TunnelSpec, mtu: u32) -> Result<TunnelBinding, PolicyError> {
            self.installs.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                if let Some(entered) = lock(&gate.entered).take() {
                    let _ = entered.send(());
                }
                // The receiver is taken out of the lock first: parking while
                // holding it would deadlock a second caller.
                let waiter = lock(&gate.release).take();
                if let Some(waiter) = waiter {
                    let _ = waiter.recv();
                }
            }
            if self.fail_install {
                return Err(PolicyError::Verification {
                    probe: "netstat -rn".to_owned(),
                    detail: "the scoped default route is not present".to_owned(),
                });
            }
            let ipv4 = match spec.v4().local() {
                IpAddr::V4(address) => address,
                IpAddr::V6(_) => unreachable!("v4 endpoint is v4 by construction"),
            };
            let ipv6 = match spec.v6().map(TunnelEndpoint::local) {
                Some(IpAddr::V6(address)) => Some(address),
                _ => None,
            };
            Ok(TunnelBinding {
                device: spec.device().as_str().to_owned(),
                ipv4,
                ipv6,
                mtu,
            })
        }

        fn teardown(&self, _binding: &TunnelBinding) -> Result<(), PolicyError> {
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn reassert(&self) -> Reassertion {
            Reassertion::default()
        }
    }

    #[derive(Default)]
    pub(crate) struct RecordingPublisher {
        fail_publish: bool,
        published: AtomicBool,
        revoked: AtomicUsize,
    }

    impl RecordingPublisher {
        /// Stands in for an `EgressState` that refuses the identity, which
        /// happens after the policy is already on the machine.
        pub(crate) fn refusing() -> Self {
            Self {
                fail_publish: true,
                ..Self::default()
            }
        }

        pub(crate) fn is_published(&self) -> bool {
            self.published.load(Ordering::SeqCst)
        }

        pub(crate) fn revocations(&self) -> usize {
            self.revoked.load(Ordering::SeqCst)
        }
    }

    impl EgressPublisher for RecordingPublisher {
        fn publish(&self, _binding: &TunnelBinding) -> Result<(), PolicyError> {
            if self.fail_publish {
                return Err(PolicyError::Verification {
                    probe: "egress publish".to_owned(),
                    detail: "the proxy refused the tunnel identity".to_owned(),
                });
            }
            self.published.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn revoke(&self) {
            self.published.store(false, Ordering::SeqCst);
            self.revoked.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use crate::policy::testing::ScriptedRunner;
    use crate::policy::{Command, CommandOutput, LinuxPolicy, RawTunnel};

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

    fn everything_installed(command: &Command) -> CommandOutput {
        let rendered = command.to_string();
        if rendered.ends_with("route show table 218") {
            crate::policy::testing::ok(
                "unreachable default metric 4000\ndefault dev tun0 src 10.8.0.2 metric 100 mtu 1400\n",
            )
        } else if rendered.ends_with("rule show") {
            crate::policy::testing::ok(
                "18500:\tfrom 10.8.0.2 unreachable\n18500:\tfrom fd00::2 unreachable\n\
                18000:\tfrom 10.8.0.2 lookup 218\n18000:\tfrom fd00::2 lookup 218\n",
            )
        } else {
            crate::policy::testing::ok("")
        }
    }

    fn managed_driver<F>(reply: F) -> ManagedPolicy<ScriptedRunner<F>>
    where
        F: Fn(&Command) -> CommandOutput + Send + Sync,
    {
        ManagedPolicy::new(PolicyManager::new(
            Box::new(LinuxPolicy::with_ip_binary("/usr/sbin/ip")),
            ScriptedRunner::new(reply),
        ))
    }

    #[test]
    fn reassert_does_nothing_before_an_install_and_after_a_teardown() {
        // The liveness signal is the InstalledPolicy itself. A watchdog that ran against a
        // torn-down session would re-install the rule and the table the proxy no longer pins
        // sockets to — reconciliation's job, done at the worst possible moment.
        use std::sync::atomic::{AtomicBool, Ordering};

        // `everything_installed` alone cannot answer a real teardown: it always reports the
        // policy present, which fails every after-undo check. Once the first removal command
        // runs, later read-backs must report the policy gone, exactly as a real `ip` would.
        let tearing_down = AtomicBool::new(false);
        let driver = managed_driver(move |command: &Command| {
            if command.to_string().contains("route del default dev") {
                tearing_down.store(true, Ordering::SeqCst);
            }
            if tearing_down.load(Ordering::SeqCst) {
                crate::policy::testing::ok("")
            } else {
                everything_installed(command)
            }
        });

        assert!(driver.reassert().is_quiet());

        let binding = driver.install(spec(), 1400).expect("installed");
        driver.teardown(&binding).expect("torn down");

        assert!(driver.reassert().is_quiet());
    }

    #[test]
    fn teardown_holds_the_guard_so_a_concurrent_reassert_cannot_interleave() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // Set once the racing thread's reassert() returns.
        let reassert_returned = Arc::new(AtomicBool::new(false));
        // Set while the runner is parked inside the first teardown command.
        let inside_teardown = Arc::new(AtomicBool::new(false));

        let driver = {
            let inside = Arc::clone(&inside_teardown);
            Arc::new(managed_driver(move |command: &Command| {
                let rendered = command.to_string();
                // Park inside teardown's first removal, holding the guard open for as long
                // as a correct implementation would hold it: the whole teardown.
                if rendered.contains("route del default dev") {
                    inside.store(true, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
                // Once torn down is under way, every read-back must report the policy gone —
                // otherwise teardown's own after-undo verification fails before it can finish.
                if inside.load(Ordering::SeqCst) {
                    crate::policy::testing::ok("")
                } else {
                    everything_installed(command)
                }
            }))
        };

        let binding = driver.install(spec(), 1400).expect("installed");

        // Teardown runs on its own thread: the runner parks inside it for 300ms, and the main
        // thread needs to observe that window from the outside rather than being the one blocked
        // inside `teardown` itself.
        let teardown_thread = {
            let driver = Arc::clone(&driver);
            let binding = binding.clone();
            std::thread::spawn(move || driver.teardown(&binding))
        };

        let racer = {
            let driver = Arc::clone(&driver);
            let returned = Arc::clone(&reassert_returned);
            let inside = Arc::clone(&inside_teardown);
            std::thread::spawn(move || {
                // Only start racing once teardown is demonstrably in flight.
                while !inside.load(Ordering::SeqCst) {
                    std::thread::yield_now();
                }
                driver.reassert();
                returned.store(true, Ordering::SeqCst);
            })
        };

        // Wait until the runner is parked, then check the racer is still blocked on the guard.
        while !inside_teardown.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        let returned_mid_teardown = reassert_returned.load(Ordering::SeqCst);

        teardown_thread
            .join()
            .expect("teardown thread")
            .expect("torn down");
        racer.join().expect("racer");

        assert!(
            !returned_mid_teardown,
            "a reassert completed while teardown was mid-flight: the guard is not held across \
             teardown, so re-assertion can re-add rules that teardown is in the middle of removing"
        );
    }

    #[test]
    fn builds_a_spec_from_the_strings_openvpn_reported() {
        let spec = spec_from_identity("utun4", "10.8.0.2", None, 1400).expect("spec");

        assert_eq!(spec.device().as_str(), "utun4");
        assert_eq!(spec.mtu().as_u32(), 1400);
        assert!(spec.v6().is_none());
    }

    #[test]
    fn a_binding_without_a_v6_address_never_claims_v6() {
        let binding = TunnelBinding {
            device: "tun0".to_owned(),
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            ipv6: None,
            mtu: 1400,
        };

        assert!(!binding.tunnel_has_v6());
    }

    #[test]
    fn a_binding_with_a_v6_address_claims_v6() {
        let binding = TunnelBinding {
            device: "tun0".to_owned(),
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            ipv6: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            mtu: 1400,
        };

        assert!(binding.tunnel_has_v6());
    }

    #[test]
    fn rejects_a_device_name_that_could_carry_a_shell_payload() {
        let outcome = spec_from_identity("utun0; rm -rf /", "10.8.0.2", None, 1400);

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }

    #[test]
    fn rejects_a_tunnel_address_that_is_not_an_address() {
        let outcome = spec_from_identity("utun0", "not-an-ip", None, 1400);

        assert!(matches!(outcome, Err(PolicyError::InvalidAddress { .. })));
    }

    #[test]
    fn carries_the_v6_endpoint_when_the_tunnel_has_one() {
        let spec = spec_from_identity("utun0", "10.8.0.2", Some("fd00::2"), 1400).expect("spec");

        assert!(spec.v6().is_some());
    }
}
