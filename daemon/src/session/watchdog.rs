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
}
