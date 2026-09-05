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
    CommandRunner, InstalledPolicy, PolicyError, PolicyManager, RawTunnel, ReconcileReport,
    TunnelSpec,
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
    pub tunnel_has_v6: bool,
}

impl TunnelBinding {
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
            Some(IpAddr::V4(_)) | None => None,
        };
        Ok(Self {
            device: installed.device().as_str().to_owned(),
            ipv4,
            ipv6,
            mtu,
            tunnel_has_v6: installed.tunnel_has_v6(),
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
        let Some(installed) = lock(&self.installed).take() else {
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
            Ok(TunnelBinding {
                device: spec.device().as_str().to_owned(),
                ipv4,
                ipv6: None,
                mtu,
                tunnel_has_v6: spec.v6().is_some(),
            })
        }

        fn teardown(&self, _binding: &TunnelBinding) -> Result<(), PolicyError> {
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
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

    use super::*;

    #[test]
    fn builds_a_spec_from_the_strings_openvpn_reported() {
        let spec = spec_from_identity("utun4", "10.8.0.2", None, 1400).expect("spec");

        assert_eq!(spec.device().as_str(), "utun4");
        assert_eq!(spec.mtu().as_u32(), 1400);
        assert!(spec.v6().is_none());
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
