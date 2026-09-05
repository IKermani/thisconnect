// SPDX-License-Identifier: GPL-3.0-or-later

//! Startup reconciliation (SPEC.md §5.2, §7.1).
//!
//! A crash leaves policy behind: a scoped route pointing at a utun that has since been recycled,
//! or a rule sending the next session's source address into a table whose contents nobody owns.
//! Both are correctness *and* security hazards, so leftovers are enumerated and torn down before
//! any new state is installed — and if they survive, that is an error, not a warning.

use super::command::{Command, CommandRunner};
use super::{PolicyError, TunnelPolicy};

/// Deleting a rule removes one instance, so a session that crashed mid-install can leave several.
/// The bound turns "kept finding more" into a loud failure instead of a spin.
const MAX_PASSES: usize = 4;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub passes: usize,
    /// The command lines issued, for the daemon log. They contain no secrets.
    pub removed: Vec<String>,
}

impl ReconcileReport {
    pub fn found_nothing(&self) -> bool {
        self.removed.is_empty()
    }
}

pub fn reconcile(
    backend: &dyn TunnelPolicy,
    runner: &dyn CommandRunner,
) -> Result<ReconcileReport, PolicyError> {
    let mut report = ReconcileReport::default();
    for pass in 0..MAX_PASSES {
        let leftovers = backend.stale_cleanup(runner)?;
        if leftovers.is_empty() {
            report.passes = pass;
            return Ok(report);
        }
        report.removed.extend(run_best_effort(&leftovers, runner)?);
    }
    if backend.stale_cleanup(runner)?.is_empty() {
        report.passes = MAX_PASSES;
        return Ok(report);
    }
    Err(PolicyError::ResidueRemains { passes: MAX_PASSES })
}

/// Runs removal commands, tolerating a non-zero exit. "Already gone" is the expected outcome for
/// most of these and is indistinguishable from a real failure by exit status alone; what actually
/// decides whether the state is clean is the read-back that follows.
pub fn run_best_effort(
    commands: &[Command],
    runner: &dyn CommandRunner,
) -> Result<Vec<String>, PolicyError> {
    commands
        .iter()
        .map(|command| {
            let output = runner.run(command)?;
            if !output.succeeded() {
                tracing::debug!(command = %command, "policy cleanup command reported no change");
            }
            Ok(command.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;

    use super::super::command::flag;
    use super::super::command::testing::{ok, ScriptedRunner};
    use super::super::plan::Plan;
    use super::super::types::TunnelSpec;
    use super::*;

    /// A backend whose leftovers shrink by one on every pass, or never at all.
    struct FakeBackend {
        remaining: Mutex<usize>,
        shrinks: bool,
    }

    impl FakeBackend {
        fn new(remaining: usize, shrinks: bool) -> Self {
            Self {
                remaining: Mutex::new(remaining),
                shrinks,
            }
        }
    }

    impl TunnelPolicy for FakeBackend {
        fn plan(&self, _spec: &TunnelSpec) -> Result<Plan, PolicyError> {
            Ok(Plan::default())
        }

        fn pre_install_cleanup(&self, _spec: &TunnelSpec) -> Result<Vec<Command>, PolicyError> {
            Ok(Vec::new())
        }

        fn stale_cleanup(&self, _runner: &dyn CommandRunner) -> Result<Vec<Command>, PolicyError> {
            let mut remaining = self.remaining.lock().expect("remaining");
            if *remaining == 0 {
                return Ok(Vec::new());
            }
            if self.shrinks {
                *remaining -= 1;
            }
            Ok(vec![Command::build(
                std::path::Path::new("/bin/clean"),
                vec![flag("one")],
            )?])
        }
    }

    #[test]
    fn reports_nothing_when_the_machine_is_already_clean() {
        let runner = ScriptedRunner::new(|_| ok(""));

        let report = reconcile(&FakeBackend::new(0, true), &runner).expect("reconciled");

        assert!(report.found_nothing());
        assert_eq!(report.passes, 0);
        assert!(runner.log().is_empty());
    }

    #[test]
    fn keeps_tearing_down_until_nothing_is_left() {
        let runner = ScriptedRunner::new(|_| ok(""));

        let report = reconcile(&FakeBackend::new(2, true), &runner).expect("reconciled");

        assert_eq!(report.removed.len(), 2);
        assert_eq!(report.passes, 2);
    }

    #[test]
    fn fails_rather_than_starting_on_top_of_state_it_could_not_remove() {
        let runner = ScriptedRunner::new(|_| ok(""));

        let outcome = reconcile(&FakeBackend::new(1, false), &runner);

        assert!(matches!(outcome, Err(PolicyError::ResidueRemains { .. })));
    }

    #[test]
    fn best_effort_removal_tolerates_a_command_that_had_nothing_to_do() {
        let runner =
            ScriptedRunner::new(|_| super::super::command::testing::failed("No such process"));
        let command =
            Command::build(std::path::Path::new("/bin/clean"), vec![flag("one")]).expect("valid");

        let issued = run_best_effort(std::slice::from_ref(&command), &runner).expect("ran");

        assert_eq!(issued, vec!["/bin/clean one".to_owned()]);
    }
}
