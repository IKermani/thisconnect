// SPDX-License-Identifier: GPL-3.0-or-later

//! Ordered installation and teardown of tunnel policy, platform-independent.
//!
//! The order is the security property, not an implementation detail. Installing the fail-closed
//! floor before the rule means there is no instant in which a packet sourced from the tun address
//! can be looked up in `main` and leave over the untouched default route; removing the floor last,
//! and only once the rule is *observed* gone, means the same on the way down. Every step is
//! verified by reading the state back, because assuming a zero exit status meant the kernel now
//! holds what we asked for was a real defect in the macOS verification script.

use super::command::{Command, CommandRunner};
use super::types::Family;
use super::PolicyError;

/// Ordering rank within one address family. Install ascends, teardown descends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StepKind {
    Backstop,
    Floor,
    Rule,
    TunnelRoute,
}

impl StepKind {
    fn label(self) -> &'static str {
        match self {
            Self::Backstop => "fail-closed backstop rule",
            Self::Floor => "fail-closed floor route",
            Self::Rule => "policy rule",
            Self::TunnelRoute => "tunnel route",
        }
    }
}

/// A read-back assertion over the output of `probe`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub probe: Command,
    pub required: Vec<String>,
    pub forbidden: Vec<String>,
    /// Whether a non-zero exit from `probe` is itself proof that the subject is gone. True only
    /// for probes whose contract *is* "non-zero means no such object" — macOS `route -n get`.
    /// For `ip rule show` and `ip route show` a non-zero exit means the state could not be read
    /// (netlink busy, EPERM, a missing binary), which is not the same as confirmed absence, and
    /// treating it as such would let the floor be removed while the rule still stands.
    pub probe_failure_proves_absence: bool,
}

impl Check {
    pub fn present(probe: Command, required: Vec<String>) -> Self {
        Self {
            probe,
            required,
            forbidden: Vec::new(),
            probe_failure_proves_absence: false,
        }
    }

    /// Strict absence: the state must be readable and must not contain `forbidden`.
    pub fn absent(probe: Command, forbidden: Vec<String>) -> Self {
        Self {
            probe,
            required: Vec::new(),
            forbidden,
            probe_failure_proves_absence: false,
        }
    }

    /// Absence for a probe that reports "no such object" by exiting non-zero.
    pub fn absent_or_probe_fails(probe: Command, forbidden: Vec<String>) -> Self {
        Self {
            probe_failure_proves_absence: true,
            ..Self::absent(probe, forbidden)
        }
    }

    fn evaluate(&self, runner: &dyn CommandRunner) -> Result<(), PolicyError> {
        let output = runner.run(&self.probe)?;
        let fail = |detail: String| {
            Err(PolicyError::Verification {
                probe: self.probe.to_string(),
                detail,
            })
        };
        if !output.succeeded() {
            // A failing probe can never prove presence, and only proves absence where the probe
            // itself defines a non-zero exit as "no such object".
            return if self.probe_failure_proves_absence && self.required.is_empty() {
                Ok(())
            } else {
                fail(format!(
                    "probe exited with {:?}; the state could not be read back",
                    self.status_label(output.status),
                ))
            };
        }
        if let Some(missing) = self
            .required
            .iter()
            .find(|needle| !output.stdout.contains(needle.as_str()))
        {
            return fail(format!("expected {missing:?} in the state read back"));
        }
        if let Some(present) = self
            .forbidden
            .iter()
            .find(|needle| output.stdout.contains(needle.as_str()))
        {
            return fail(format!("{present:?} is still installed"));
        }
        Ok(())
    }

    fn status_label(&self, status: Option<i32>) -> String {
        status.map_or_else(|| "signal".to_owned(), |code| code.to_string())
    }
}

/// One reversible piece of policy: how to install it, how to remove it, and how to prove both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub family: Family,
    pub kind: StepKind,
    pub apply: Command,
    pub undo: Command,
    pub after_apply: Option<Check>,
    pub after_undo: Option<Check>,
}

/// An ordering-validated sequence of steps.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Plan {
    steps: Vec<Step>,
}

impl Plan {
    /// Rejects any sequence that would install the backstop after the floor, the floor after the
    /// rule, or the rule after the route, within an address family. Encoding the invariant here
    /// means a platform backend cannot regress it silently. Because teardown walks this order in
    /// reverse, ranking the backstop first is also what makes it the last thing removed.
    pub fn new(steps: Vec<Step>) -> Result<Self, PolicyError> {
        for family in [Family::V4, Family::V6] {
            let ranks: Vec<StepKind> = steps
                .iter()
                .filter(|step| step.family == family)
                .map(|step| step.kind)
                .collect();
            if ranks.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(PolicyError::Ordering {
                    detail:
                        "policy steps must ascend backstop -> floor -> rule -> route within a family",
                });
            }
        }
        Ok(Self { steps })
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The install command lines in order — the shape the unit tests assert on.
    pub fn install_commands(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|step| step.apply.to_string())
            .collect()
    }
}

/// Installs every step in order, verifying each before moving on. Any failure tears down what was
/// already installed before returning: a half-installed policy is a leak, so the failure path is
/// the teardown path. A rollback that itself fails is reported as [`PolicyError::RollbackFailed`]
/// rather than hidden behind the original error.
pub fn install(plan: &Plan, runner: &dyn CommandRunner) -> Result<(), PolicyError> {
    for (index, step) in plan.steps().iter().enumerate() {
        match install_step(step, runner) {
            Ok(()) => continue,
            Err(error) => {
                let installed = Plan {
                    steps: plan.steps()[..=index].to_vec(),
                };
                return match teardown(&installed, runner) {
                    Ok(()) => Err(error),
                    // The caller must be able to tell "failed, machine clean" from "failed,
                    // privileged state still installed"; collapsing the two would let an
                    // orchestrator abandon a floor route and a source rule it does not know about.
                    Err(rollback) => Err(PolicyError::RollbackFailed {
                        cause: Box::new(error),
                        rollback: Box::new(rollback),
                    }),
                };
            }
        }
    }
    Ok(())
}

fn install_step(step: &Step, runner: &dyn CommandRunner) -> Result<(), PolicyError> {
    let output = runner.run(&step.apply)?;
    if !output.succeeded() {
        return Err(PolicyError::CommandFailed {
            what: step.kind.label(),
            command: step.apply.to_string(),
            stderr: first_line(&output.stderr),
        });
    }
    match &step.after_apply {
        Some(check) => check.evaluate(runner),
        None => Ok(()),
    }
}

/// Removes every step in reverse. Idempotent: a removal command that fails because the state was
/// already gone is not an error, only a failed *verification* is. Verification failure aborts
/// immediately, which is what keeps the floor installed while a rule that should have gone is
/// still standing.
pub fn teardown(plan: &Plan, runner: &dyn CommandRunner) -> Result<(), PolicyError> {
    for step in plan.steps().iter().rev() {
        let _ = runner.run(&step.undo)?;
        if let Some(check) = &step.after_undo {
            check.evaluate(runner)?;
        }
    }
    Ok(())
}

/// What one re-assertion pass changed. `failed` is not an error: the floor and the backstop do
/// not depend on the tun device, so a step that cannot come back leaves the address more
/// refused, never less.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reassertion {
    pub restored: Vec<StepKind>,
    pub failed: Vec<StepKind>,
}

impl Reassertion {
    /// Nothing was missing. The overwhelmingly common outcome, and the one that must not log.
    pub fn is_quiet(&self) -> bool {
        self.restored.is_empty() && self.failed.is_empty()
    }
}

/// Restores whatever has been deleted out from under a live session, in install order.
///
/// Walking `plan.steps()` forward is the same ordering invariant `Plan::new` enforces and
/// `teardown` reverses, applied a third time: the backstop and the floor come back *before* the
/// rule that routes the address into the table they protect. Restoring the rule first would
/// reopen, however briefly, the fall-through to table `main` that this whole mechanism exists
/// to prevent.
///
/// Every step is checked before it is touched, because `ip rule add` appends a duplicate rather
/// than refusing — a blanket re-run of the plan would multiply rules, not restore them.
pub fn reassert(plan: &Plan, runner: &dyn CommandRunner) -> Reassertion {
    let mut outcome = Reassertion::default();
    for step in plan.steps() {
        let still_standing = step
            .after_apply
            .as_ref()
            .is_some_and(|check| check.evaluate(runner).is_ok());
        if still_standing {
            continue;
        }
        match install_step(step, runner) {
            Ok(()) => outcome.restored.push(step.kind),
            Err(error) => {
                tracing::warn!(
                    %error,
                    kind = ?step.kind,
                    family = ?step.family,
                    "could not re-assert tunnel policy; the fail-closed layers below it still stand"
                );
                outcome.failed.push(step.kind);
            }
        }
    }
    outcome
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use std::path::Path;

    use super::super::command::testing::{failed, ok, ScriptedRunner};
    use super::super::command::{flag, value};
    use super::*;

    fn cmd(name: &str) -> Command {
        Command::build(Path::new("/bin/policy"), vec![flag("do"), value(name)]).expect("valid")
    }

    fn step(kind: StepKind, name: &str) -> Step {
        Step {
            family: Family::V4,
            kind,
            apply: cmd(name),
            undo: cmd(&format!("un{name}")),
            after_apply: Some(Check::present(
                cmd(&format!("show{name}")),
                vec![name.to_owned()],
            )),
            after_undo: Some(Check::absent(
                cmd(&format!("show{name}")),
                vec![name.to_owned()],
            )),
        }
    }

    fn full_plan() -> Plan {
        Plan::new(vec![
            step(StepKind::Floor, "floor"),
            step(StepKind::Rule, "rule"),
            step(StepKind::TunnelRoute, "route"),
        ])
        .expect("ordered")
    }

    #[test]
    fn rejects_a_plan_that_installs_the_rule_before_the_floor() {
        let outcome = Plan::new(vec![
            step(StepKind::Rule, "rule"),
            step(StepKind::Floor, "floor"),
        ]);

        assert!(matches!(outcome, Err(PolicyError::Ordering { .. })));
    }

    #[test]
    fn rejects_a_plan_repeating_a_step_within_one_family() {
        let outcome = Plan::new(vec![
            step(StepKind::Floor, "floor"),
            step(StepKind::Floor, "floor2"),
        ]);

        assert!(matches!(outcome, Err(PolicyError::Ordering { .. })));
    }

    #[test]
    fn installs_floor_then_rule_then_route_and_verifies_each() {
        let plan = full_plan();
        // Every probe reports its own subject present.
        let runner = ScriptedRunner::new(|command| ok(&command.args().join(" ")));

        install(&plan, &runner).expect("installed");

        assert_eq!(
            runner.log(),
            vec![
                "/bin/policy do floor",
                "/bin/policy do showfloor",
                "/bin/policy do rule",
                "/bin/policy do showrule",
                "/bin/policy do route",
                "/bin/policy do showroute",
            ]
        );
    }

    #[test]
    fn a_failed_step_tears_down_everything_already_installed_in_reverse() {
        let plan = full_plan();
        // A fixture that actually models the kernel: probes report what is installed, so the
        // rollback is proven by absence rather than by the order of the log alone.
        let installed = std::sync::Mutex::new(Vec::<String>::new());
        let runner = ScriptedRunner::new(move |command| {
            let subject = command.args()[1].clone();
            let mut state = installed.lock().expect("state");
            if let Some(name) = subject.strip_prefix("show") {
                let present = state.iter().any(|held| held == name);
                return ok(if present { name } else { "" });
            }
            if let Some(name) = subject.strip_prefix("un") {
                state.retain(|held| held != name);
                return ok("");
            }
            if subject == "route" {
                return failed("RTNETLINK answers: File exists");
            }
            state.push(subject);
            ok("")
        });

        let outcome = install(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::CommandFailed { .. })));
        assert_eq!(
            runner.log(),
            vec![
                "/bin/policy do floor",
                "/bin/policy do showfloor",
                "/bin/policy do rule",
                "/bin/policy do showrule",
                "/bin/policy do route",
                "/bin/policy do unroute",
                "/bin/policy do showroute",
                "/bin/policy do unrule",
                "/bin/policy do showrule",
                "/bin/policy do unfloor",
                "/bin/policy do showfloor",
            ]
        );
    }

    #[test]
    fn a_step_that_reports_success_but_did_not_take_effect_fails_verification() {
        let plan = Plan::new(vec![step(StepKind::Floor, "floor")]).expect("ordered");
        let runner = ScriptedRunner::new(|_| ok(""));

        let outcome = install(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    }

    #[test]
    fn teardown_removes_the_route_then_the_rule_then_the_floor() {
        let plan = full_plan();
        let runner = ScriptedRunner::new(|_| ok(""));

        teardown(&plan, &runner).expect("torn down");

        assert_eq!(
            runner.log(),
            vec![
                "/bin/policy do unroute",
                "/bin/policy do showroute",
                "/bin/policy do unrule",
                "/bin/policy do showrule",
                "/bin/policy do unfloor",
                "/bin/policy do showfloor",
            ]
        );
    }

    #[test]
    fn teardown_is_idempotent_when_the_state_is_already_gone() {
        let plan = full_plan();
        // The removals report "nothing to do"; the probes read back cleanly and see nothing.
        let runner = ScriptedRunner::new(|command| {
            if command.args().join(" ").starts_with("do show") {
                ok("")
            } else {
                failed("RTNETLINK answers: No such process")
            }
        });

        teardown(&plan, &runner).expect("already absent is not an error");
    }

    #[test]
    fn a_probe_that_cannot_be_read_never_counts_as_proof_of_absence() {
        let plan = full_plan();
        // `ip rule show` degrading — netlink busy, EPERM, a missing binary — must not be read as
        // "the rule is gone", or the floor would come out from under a surviving rule.
        let runner = ScriptedRunner::new(|command| {
            if command.args().join(" ").starts_with("do show") {
                failed("Cannot open netlink socket")
            } else {
                ok("")
            }
        });

        let outcome = teardown(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
        assert!(
            !runner.log().contains(&"/bin/policy do unfloor".to_owned()),
            "the floor must not be removed on an unreadable probe"
        );
    }

    #[test]
    fn a_probe_whose_failure_means_no_such_object_still_proves_absence() {
        let step = Step {
            after_undo: Some(Check::absent_or_probe_fails(
                cmd("showroute"),
                vec!["route".to_owned()],
            )),
            ..step(StepKind::TunnelRoute, "route")
        };
        let plan = Plan::new(vec![step]).expect("ordered");
        let runner =
            ScriptedRunner::new(|_| failed("route: writing to routing socket: not in table"));

        teardown(&plan, &runner).expect("a route(8) probe that fails means the route is gone");
    }

    #[test]
    fn a_failed_rollback_is_reported_alongside_the_cause_rather_than_swallowed() {
        // The route step fails, and the rollback's rule probe then refuses to read back, so the
        // caller must learn that privileged state is still installed.
        let plan = full_plan();
        let rule_probes = std::sync::atomic::AtomicUsize::new(0);
        let runner = ScriptedRunner::new(move |command| {
            let subject = command.args()[1].clone();
            if subject == "route" {
                return failed("RTNETLINK answers: File exists");
            }
            if subject == "showroute" {
                // The route never landed, so it reads back absent throughout.
                return ok("");
            }
            if subject == "showrule"
                && rule_probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
            {
                // Readable while installing, unreadable by the time the rollback asks again.
                return failed("Cannot open netlink socket");
            }
            match subject.strip_prefix("show") {
                Some(name) => ok(name),
                None => ok(""),
            }
        });

        let outcome = install(&plan, &runner);

        let Err(PolicyError::RollbackFailed { cause, rollback }) = outcome else {
            panic!("expected the rollback failure to reach the caller");
        };
        assert!(matches!(*cause, PolicyError::CommandFailed { .. }));
        assert!(matches!(*rollback, PolicyError::Verification { .. }));
    }

    #[test]
    fn the_floor_survives_a_rule_that_refuses_to_go_away() {
        let plan = full_plan();
        let runner = ScriptedRunner::new(|command| {
            let rendered = command.args().join(" ");
            if rendered == "do showrule" {
                ok("rule")
            } else {
                ok("")
            }
        });

        let outcome = teardown(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
        assert!(
            !runner.log().contains(&"/bin/policy do unfloor".to_owned()),
            "the floor must not be removed while the rule is still installed"
        );
    }

    #[test]
    fn reassert_is_quiet_when_every_step_still_reads_back() {
        let plan = full_plan();
        // Every probe reports its own subject present, exactly as after a good install.
        let runner = ScriptedRunner::new(|command| {
            let rendered = command.to_string();
            if rendered.contains("showfloor") {
                ok("floor")
            } else if rendered.contains("showrule") {
                ok("rule")
            } else if rendered.contains("showroute") {
                ok("route")
            } else {
                ok("")
            }
        });

        let outcome = reassert(&plan, &runner);

        assert!(outcome.is_quiet());
        // Only the three probes ran: a policy that is still standing must not be re-applied,
        // because `ip rule add` appends a duplicate rather than refusing.
        assert_eq!(runner.log().len(), 3);
        assert!(!runner
            .log()
            .iter()
            .any(|line| line == "/bin/policy do rule"));
    }

    #[test]
    fn reassert_restores_a_deleted_step_and_leaves_the_others_alone() {
        let plan = full_plan();
        // The rule is gone; the floor and the route are not. Once re-applied it reads back.
        let rule_restored = std::sync::atomic::AtomicBool::new(false);
        let runner = ScriptedRunner::new(move |command| {
            let rendered = command.to_string();
            if rendered == "/bin/policy do rule" {
                rule_restored.store(true, std::sync::atomic::Ordering::SeqCst);
                return ok("");
            }
            if rendered.contains("showrule") {
                return if rule_restored.load(std::sync::atomic::Ordering::SeqCst) {
                    ok("rule")
                } else {
                    ok("")
                };
            }
            if rendered.contains("showfloor") {
                ok("floor")
            } else if rendered.contains("showroute") {
                ok("route")
            } else {
                ok("")
            }
        });

        let outcome = reassert(&plan, &runner);

        assert_eq!(outcome.restored, vec![StepKind::Rule]);
        assert!(outcome.failed.is_empty());
        assert!(runner
            .log()
            .iter()
            .any(|line| line == "/bin/policy do rule"));
        assert!(!runner
            .log()
            .iter()
            .any(|line| line == "/bin/policy do floor"));
    }

    #[test]
    fn reassert_restores_the_floor_before_the_rule_when_both_are_gone() {
        // The window this whole change exists to close: with both gone, restoring the rule
        // first would route the tun source address through a table that has no floor in it.
        let plan = full_plan();
        // Nothing ever reads back, so every step is treated as missing and re-applied.
        let runner = ScriptedRunner::new(|_command| ok(""));

        let outcome = reassert(&plan, &runner);

        let log = runner.log();
        let floor_at = log
            .iter()
            .position(|line| line == "/bin/policy do floor")
            .expect("floor re-applied");
        let rule_at = log
            .iter()
            .position(|line| line == "/bin/policy do rule")
            .expect("rule re-applied");
        let route_at = log
            .iter()
            .position(|line| line == "/bin/policy do route")
            .expect("route re-applied");
        assert!(
            floor_at < rule_at,
            "the floor must be restored before the rule"
        );
        assert!(
            rule_at < route_at,
            "the rule must be restored before the route"
        );
        // Re-applied but never read back, so none of them count as restored.
        assert_eq!(outcome.restored, Vec::<StepKind>::new());
        assert_eq!(
            outcome.failed,
            vec![StepKind::Floor, StepKind::Rule, StepKind::TunnelRoute]
        );
    }

    #[test]
    fn reassert_keeps_going_after_a_step_it_cannot_restore() {
        // The rule sits in the middle of the plan and can never be restored, but the tunnel
        // route after it still is: a failure partway through must not abandon the steps that
        // follow. (The route step is last in `full_plan()`, so this is the only shape that can
        // prove "keeps going" — a fail on the last step looks identical to an abort-on-error.)
        let plan = full_plan();
        let route_applied = std::sync::atomic::AtomicBool::new(false);
        let runner = ScriptedRunner::new(move |command| {
            let rendered = command.to_string();
            if rendered == "/bin/policy do rule" {
                return failed("Cannot find device \"tun0\"");
            }
            if rendered.contains("showfloor") {
                // Still standing: must be skipped, never re-applied.
                return ok("floor");
            }
            if rendered.contains("showrule") {
                // Absent both before and after the failed re-apply attempt.
                return ok("");
            }
            if rendered == "/bin/policy do route" {
                route_applied.store(true, std::sync::atomic::Ordering::SeqCst);
                return ok("");
            }
            if rendered.contains("showroute") {
                return if route_applied.load(std::sync::atomic::Ordering::SeqCst) {
                    ok("route")
                } else {
                    ok("")
                };
            }
            ok("")
        });

        let outcome = reassert(&plan, &runner);

        assert_eq!(outcome.failed, vec![StepKind::Rule]);
        // Pins "keeps going": a loop that aborts on the first error would leave this empty.
        assert_eq!(outcome.restored, vec![StepKind::TunnelRoute]);
        assert!(runner
            .log()
            .iter()
            .any(|line| line == "/bin/policy do route"));
        assert!(!runner
            .log()
            .iter()
            .any(|line| line == "/bin/policy do floor"));
    }
}
