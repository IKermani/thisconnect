// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-assertion of live tunnel policy (SPEC.md §5.2).
//!
//! `PolicyManager::reconcile` removes what a *dead* session left behind, once, at startup. This
//! is the other half: putting back what something removed from a session that is still running.
//! NetworkManager, systemd-networkd and other VPN clients rewrite policy routing on connectivity
//! changes, and deleting both rules was *observed* to fall through to table `main` and leave over
//! the physical link. Without this the re-assertion latency is the time until the daemon restarts.
//!
//! The watchdog outlives any one session on purpose. `TunnelPolicyDriver::reassert` is a no-op
//! while nothing is installed, so there is no start/abort lifecycle to race against teardown —
//! the `InstalledPolicy` guard is the only liveness signal, and it is already exclusive.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::policy::{PolicyWatch, Reassertion, Trigger};
use crate::session::tunnel::TunnelPolicyDriver;

/// Floor on the gap between re-assertions. The first event of a burst is acted on immediately;
/// this bounds what the rest cost. It also stops a socket that has gone permanently unreadable
/// from spinning a root process — `Desynchronised` arrives as fast as the loop asks for it.
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Covers an edge missed for any reason the trigger does not name — a group we did not join, a
/// kernel that coalesced something, a rule replaced rather than deleted.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Depth is irrelevant to correctness: every trigger means the same thing, so a full channel
/// dropping one changes nothing. It exists only to decouple the socket read from the blocking
/// `ip` invocations.
const TRIGGER_QUEUE: usize = 64;

pub async fn run(
    watch: PolicyWatch,
    driver: Arc<dyn TunnelPolicyDriver>,
    shutdown: watch::Receiver<bool>,
) {
    let (tx, rx) = mpsc::channel(TRIGGER_QUEUE);
    let reader = tokio::spawn(async move {
        loop {
            let trigger = watch.next().await;
            if tx.send(trigger).await.is_err() {
                return;
            }
        }
    });
    drive_bounded(rx, driver, shutdown).await;
    reader.abort();
}

async fn drive_bounded(
    mut triggers: mpsc::Receiver<Trigger>,
    driver: Arc<dyn TunnelPolicyDriver>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    sweep.tick().await; // the first tick is immediate; skip it.
    loop {
        let reason = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            trigger = triggers.recv() => match trigger {
                Some(trigger) => trigger,
                None => return,
            },
            _ = sweep.tick() => Trigger::Deletion,
        };
        if *shutdown.borrow() {
            return;
        }
        if matches!(reason, Trigger::Desynchronised) {
            warn!("netlink reported dropped messages; re-asserting tunnel policy unconditionally");
        }
        report(reassert(&driver).await);
        // Coalesce whatever arrived while the probes were running, then hold the floor.
        tokio::time::sleep(MIN_INTERVAL).await;
        while triggers.try_recv().is_ok() {}
    }
}

async fn reassert(driver: &Arc<dyn TunnelPolicyDriver>) -> Reassertion {
    let driver = Arc::clone(driver);
    // The probes shell out to `ip`, which blocks. Running them on the async worker would stall
    // the IPC server behind a routing change.
    tokio::task::spawn_blocking(move || driver.reassert())
        .await
        .unwrap_or_default()
}

fn report(outcome: Reassertion) {
    if outcome.is_quiet() {
        return;
    }
    if !outcome.restored.is_empty() {
        info!(
            restored = ?outcome.restored,
            "tunnel policy was removed by something else and has been re-asserted"
        );
    }
    if !outcome.failed.is_empty() {
        warn!(
            failed = ?outcome.failed,
            "tunnel policy could not be fully re-asserted; egress stays fail-closed on the layers that remain"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::policy::{PolicyError, ReconcileReport, TunnelSpec};
    use crate::session::tunnel::TunnelBinding;

    /// Counts re-assertions and reports how many it has seen.
    #[derive(Default)]
    struct CountingDriver {
        calls: AtomicUsize,
    }

    impl TunnelPolicyDriver for CountingDriver {
        fn reconcile(&self) -> Result<ReconcileReport, PolicyError> {
            Ok(ReconcileReport::default())
        }

        fn install(&self, _spec: TunnelSpec, _mtu: u32) -> Result<TunnelBinding, PolicyError> {
            Err(PolicyError::UnsupportedPlatform)
        }

        fn teardown(&self, _binding: &TunnelBinding) -> Result<(), PolicyError> {
            Ok(())
        }

        fn reassert(&self) -> Reassertion {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Reassertion::default()
        }
    }

    async fn drive(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<Trigger>,
        driver: Arc<dyn TunnelPolicyDriver>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let (tx, bounded) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(trigger) = rx.recv().await {
                if tx.send(trigger).await.is_err() {
                    return;
                }
            }
        });
        super::drive_bounded(bounded, driver, shutdown).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_trigger_causes_exactly_one_reassertion() {
        let driver = Arc::new(CountingDriver::default());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tx.send(Trigger::Deletion).expect("queued");
        drop(tx);

        drive(
            rx,
            Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>,
            shutdown_rx,
        )
        .await;

        assert_eq!(driver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_triggers_coalesces_into_fewer_reassertions_than_events() {
        // NetworkManager rewriting policy routing produces a burst, not one deletion. Re-running
        // four `ip show` probes per message would turn a routing change into a stampede.
        let driver = Arc::new(CountingDriver::default());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        for _ in 0..50 {
            tx.send(Trigger::Deletion).expect("queued");
        }
        drop(tx);

        drive(
            rx,
            Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>,
            shutdown_rx,
        )
        .await;

        let calls = driver.calls.load(Ordering::SeqCst);
        assert!(
            calls >= 1,
            "a burst must still produce at least one re-assertion"
        );
        assert!(
            calls < 50,
            "50 events produced {calls} re-assertions; nothing coalesced"
        );
    }

    #[tokio::test]
    async fn shutdown_stops_the_loop_even_with_triggers_pending() {
        let driver = Arc::new(CountingDriver::default());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).expect("signalled");
        for _ in 0..10 {
            tx.send(Trigger::Deletion).expect("queued");
        }

        // Completing at all is the assertion: a loop that ignored shutdown would hang here.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            drive(
                rx,
                Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>,
                shutdown_rx,
            ),
        )
        .await
        .expect("the watchdog must stop when shutdown is signalled");
    }

    /// The end-to-end proof needs `ip`, a tun and a private network namespace, none of
    /// which exist on macOS. The rest of this module is platform-neutral and runs on both.
    #[cfg(target_os = "linux")]
    mod netns {
        use super::*;

        use crate::policy::{LinuxPolicy, PolicyManager, RawTunnel, SystemRunner};
        use crate::session::tunnel::ManagedPolicy;

        const TEST_TUN: &str = "tc-watch0";
        const TEST_ESCAPE: &str = "tc-watch-esc";
        const TEST_TUN_IP: &str = "10.255.254.2";
        const TEST_ESCAPE_IP: &str = "10.255.253.1";
        const TEST_DST: &str = "1.1.1.1";

        fn ip(args: &[&str]) -> std::process::Output {
            std::process::Command::new("ip")
                .args(args)
                .output()
                .expect("ip(8) must be present")
        }

        fn must_ip(args: &[&str]) {
            let output = ip(args);
            assert!(
                output.status.success(),
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// Which device the kernel picks for a packet sourced from the tun address. Empty when the
        /// lookup fails, which is the fail-closed answer.
        fn selected_device() -> String {
            let output = ip(&["route", "get", TEST_DST, "from", TEST_TUN_IP]);
            let text = String::from_utf8_lossy(&output.stdout);
            let mut fields = text.split_whitespace();
            while let Some(field) = fields.next() {
                if field == "dev" {
                    return fields.next().unwrap_or_default().to_owned();
                }
            }
            String::new()
        }

        fn rules_present() -> bool {
            let text = String::from_utf8_lossy(&ip(&["rule", "show"]).stdout).into_owned();
            text.contains(&format!("from {TEST_TUN_IP} lookup 218"))
                && text.contains(&format!("from {TEST_TUN_IP} unreachable"))
        }

        fn delete_both_rules() {
            must_ip(&["rule", "del", "priority", "18000"]);
            must_ip(&["rule", "del", "priority", "18500"]);
        }

        /// Removes the throwaway devices even when an assertion unwinds. Without this a failed run
        /// leaves a tun behind and every later run refuses to start.
        struct Devices;

        impl Drop for Devices {
            fn drop(&mut self) {
                let _ = ip(&["link", "del", TEST_ESCAPE]);
                let _ = ip(&["link", "del", TEST_TUN]);
            }
        }

        /// Needs CAP_NET_ADMIN in a private network namespace; run by
        /// `scripts/verify-egress-linux.sh --watcher`.
        #[tokio::test]
        #[ignore = "needs CAP_NET_ADMIN in a private netns"]
        async fn the_watcher_restores_rules_deleted_under_a_live_session() {
            must_ip(&["link", "set", "lo", "up"]);
            let _devices = Devices;

            // The tun the policy is keyed on.
            must_ip(&["tuntap", "add", "dev", TEST_TUN, "mode", "tun"]);
            must_ip(&["addr", "add", &format!("{TEST_TUN_IP}/24"), "dev", TEST_TUN]);
            must_ip(&["link", "set", "dev", TEST_TUN, "mtu", "1400", "up"]);

            // The escape path: what table main offers once our rules are gone. On a real host this
            // is the physical link; manufacturing it here is what makes the control conclusive.
            must_ip(&["link", "add", TEST_ESCAPE, "type", "dummy"]);
            must_ip(&[
                "addr",
                "add",
                &format!("{TEST_ESCAPE_IP}/24"),
                "dev",
                TEST_ESCAPE,
            ]);
            must_ip(&["link", "set", "dev", TEST_ESCAPE, "up"]);
            must_ip(&[
                "route",
                "add",
                "default",
                "dev",
                TEST_ESCAPE,
                "metric",
                "500",
            ]);

            let driver = Arc::new(ManagedPolicy::new(PolicyManager::new(
                Box::new(LinuxPolicy::system()),
                SystemRunner,
            )));
            let spec = crate::policy::TunnelSpec::parse(RawTunnel {
                device: TEST_TUN,
                local_v4: TEST_TUN_IP,
                gateway_v4: None,
                mtu: 1400,
                ..RawTunnel::default()
            })
            .expect("valid spec");
            let binding = driver.install(spec, 1400).expect("policy installed");
            assert!(rules_present(), "the install did not read back");
            assert_eq!(
                selected_device(),
                TEST_TUN,
                "with the policy installed the lookup must select the tun"
            );

            // ---- Control: no watcher. The deletion must be seen to cause a leak. ----
            delete_both_rules();
            let escaped = selected_device();
            assert!(
                !escaped.is_empty() && escaped != TEST_TUN,
                "INCONCLUSIVE: with both rules deleted and no watcher running, the address selected \
                 '{escaped}' rather than escaping via '{TEST_ESCAPE}'. This environment cannot \
                 demonstrate the leak, so restoring the rules below would prove nothing."
            );
            assert!(
                !rules_present(),
                "the control's deletion did not take effect"
            );

            // Put the policy back by hand so the watched half starts from the same state.
            assert_eq!(
                driver.reassert().restored.len(),
                2,
                "re-assertion must restore exactly the two rules the control deleted"
            );
            assert!(rules_present());

            // ---- The assertion: same deletion, watcher running. ----
            let watch = crate::policy::PolicyWatch::open().expect("netlink socket");
            let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let watchdog = tokio::spawn(run(
                watch,
                Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>,
                shutdown_rx,
            ));

            delete_both_rules();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !rules_present() && std::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            assert!(
                rules_present(),
                "the watcher did not restore both rules within 10s of their deletion"
            );
            assert_eq!(
                selected_device(),
                TEST_TUN,
                "the rules came back but the lookup still leaves via another device"
            );

            watchdog.abort();
            driver.teardown(&binding).expect("torn down");
        }
    }
}
