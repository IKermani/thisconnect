// SPDX-License-Identifier: GPL-3.0-or-later

//! Linux tunnel policy: a source-address rule into a private table (SPEC.md §5.2).
//!
//! Exercised on Ubuntu 24.04 / iproute2 6.1.0 by `scripts/verify-egress-linux.sh`. Not yet run on
//! Debian stable or Fedora.
//!
//! Three details are load-bearing and must not be "simplified":
//!
//! * `unreachable`, never `blackhole`. `fib_props[]` maps `RTN_BLACKHOLE` to `-EINVAL` and
//!   `RTN_UNREACHABLE` to `-EHOSTUNREACH`; `EINVAL` out of `connect()` is indistinguishable from
//!   a caller bug and has no SOCKS5 reply code, while `EHOSTUNREACH` maps cleanly to REP `0x04`.
//!   Observed: the floor answers `EHOSTUNREACH(113)` with the tun address still present, and a
//!   matched `unreachable` route terminates the lookup rather than falling through to the next
//!   rule — which is the property the whole fail-closed story rests on.
//! * The backstop rule is not redundant with the floor. The floor lives *inside* table 218 and is
//!   therefore unreachable once the policy rule is gone; deleting that rule was observed to fall
//!   straight through to table `main` and out of the physical interface. The backstop is a second
//!   rule at a lower priority that catches the same source address. Note the errno differs by
//!   layer: `FR_ACT_UNREACHABLE` on a *rule* yields `ENETUNREACH` (REP `0x03`), where
//!   `RTN_UNREACHABLE` on a *route* yields `EHOSTUNREACH` (REP `0x04`). Both are mapped.
//! * No `rp_filter` sysctl is set. `__fib_validate_source()` performs the reverse lookup with the
//!   tun IP as source, so it re-fires our rule and lands back in this table; strict RPF is already
//!   survived. Because the effective value is `max(all, iface)`, writing the sysctl can only ever
//!   enable loose RPF on a host that had none.

use std::path::{Path, PathBuf};

use super::command::{flag, value, Command, CommandRunner};
use super::plan::{Check, Plan, Step, StepKind};
use super::types::{
    DeviceName, Family, TunnelEndpoint, TunnelSpec, BACKSTOP_PRIORITY, FLOOR_METRIC, POLICY_TABLE,
    ROUTE_METRIC, RULE_PRIORITY,
};
use super::{PolicyError, TunnelPolicy};

/// `ip(8)` moves between `/sbin` and `/usr/sbin` across distributions, so it is resolved once at
/// construction rather than looked up through an inherited `PATH` at every call.
const IP_CANDIDATES: [&str; 4] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];

#[derive(Clone, Debug)]
pub struct LinuxPolicy {
    ip: PathBuf,
}

impl LinuxPolicy {
    pub fn with_ip_binary(ip: impl Into<PathBuf>) -> Self {
        Self { ip: ip.into() }
    }

    pub fn system() -> Self {
        let ip = IP_CANDIDATES
            .iter()
            .map(Path::new)
            .find(|candidate| candidate.exists())
            .map_or_else(|| PathBuf::from(IP_CANDIDATES[0]), Path::to_path_buf);
        Self { ip }
    }
}

impl TunnelPolicy for LinuxPolicy {
    fn plan(&self, spec: &TunnelSpec) -> Result<Plan, PolicyError> {
        let steps = spec
            .endpoints()
            .map(|endpoint| self.family_steps(spec, endpoint))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        Plan::new(steps)
    }

    fn pre_install_cleanup(&self, spec: &TunnelSpec) -> Result<Vec<Command>, PolicyError> {
        // The table and priority are ours exclusively, so anything left in them belongs to a dead
        // session and is removed wholesale before a new one is built on top of it.
        spec.endpoints()
            .flat_map(|endpoint| {
                let family = endpoint.family();
                [
                    self.backstop_flush(family),
                    self.rule_flush(family),
                    self.table_flush(family),
                ]
            })
            .collect()
    }

    fn stale_cleanup(&self, runner: &dyn CommandRunner) -> Result<Vec<Command>, PolicyError> {
        [Family::V4, Family::V6]
            .into_iter()
            .map(|family| self.stale_for_family(runner, family))
            .collect::<Result<Vec<_>, _>>()
            .map(|per_family| per_family.into_iter().flatten().collect())
    }
}

impl LinuxPolicy {
    fn family_steps(
        &self,
        spec: &TunnelSpec,
        endpoint: &TunnelEndpoint,
    ) -> Result<Vec<Step>, PolicyError> {
        Ok(vec![
            self.backstop_step(endpoint)?,
            self.floor_step(endpoint.family())?,
            self.rule_step(endpoint)?,
            self.route_step(spec.device(), endpoint, spec.mtu().to_string())?,
        ])
    }

    /// Catches the tun source address if the policy rule is ever removed out from under us, which
    /// NetworkManager, systemd-networkd and other VPN clients all do on connectivity changes. It is
    /// installed before anything else and removed after everything else, so no window exists in
    /// which the address is routable but unprotected.
    fn backstop_step(&self, endpoint: &TunnelEndpoint) -> Result<Step, PolicyError> {
        let family = endpoint.family();
        let selector = endpoint.local_host_cidr();
        let spec = |verb: &'static str| {
            Command::build(
                &self.ip,
                vec![
                    flag(family.ip_flag()),
                    flag("rule"),
                    flag(verb),
                    flag("from"),
                    value(&selector),
                    flag("type"),
                    flag("unreachable"),
                    flag("priority"),
                    value(BACKSTOP_PRIORITY),
                ],
            )
        };
        let probe = self.rule_show(family)?;
        // `ip rule show` drops the prefix length for a host selector and renders the action bare.
        let rendered = format!("from {} unreachable", endpoint.local());
        Ok(Step {
            family,
            kind: StepKind::Backstop,
            apply: spec("add")?,
            undo: spec("del")?,
            after_apply: Some(Check::present(probe.clone(), vec![rendered.clone()])),
            after_undo: Some(Check::absent(probe, vec![rendered])),
        })
    }

    fn floor_step(&self, family: Family) -> Result<Step, PolicyError> {
        let spec = |verb: &'static str| {
            Command::build(
                &self.ip,
                vec![
                    flag(family.ip_flag()),
                    flag("route"),
                    flag(verb),
                    flag("unreachable"),
                    flag("default"),
                    flag("table"),
                    value(POLICY_TABLE),
                    flag("metric"),
                    value(FLOOR_METRIC),
                ],
            )
        };
        let probe = self.table_show(family)?;
        Ok(Step {
            family,
            kind: StepKind::Floor,
            apply: spec("add")?,
            undo: spec("del")?,
            after_apply: Some(Check::present(
                probe.clone(),
                vec!["unreachable default".to_owned()],
            )),
            after_undo: Some(Check::absent(probe, vec!["unreachable default".to_owned()])),
        })
    }

    fn rule_step(&self, endpoint: &TunnelEndpoint) -> Result<Step, PolicyError> {
        let family = endpoint.family();
        let selector = endpoint.local_host_cidr();
        let spec = |verb: &'static str| {
            Command::build(
                &self.ip,
                vec![
                    flag(family.ip_flag()),
                    flag("rule"),
                    flag(verb),
                    flag("from"),
                    value(&selector),
                    flag("lookup"),
                    value(POLICY_TABLE),
                    flag("priority"),
                    value(RULE_PRIORITY),
                ],
            )
        };
        let probe = self.rule_show(family)?;
        let rendered = format!("from {} lookup {POLICY_TABLE}", endpoint.local());
        Ok(Step {
            family,
            kind: StepKind::Rule,
            apply: spec("add")?,
            undo: spec("del")?,
            after_apply: Some(Check::present(probe.clone(), vec![rendered.clone()])),
            after_undo: Some(Check::absent(probe, vec![rendered])),
        })
    }

    fn route_step(
        &self,
        device: &DeviceName,
        endpoint: &TunnelEndpoint,
        mtu: String,
    ) -> Result<Step, PolicyError> {
        let family = endpoint.family();
        let local = endpoint.local().to_string();
        let spec = |verb: &'static str| {
            Command::build(
                &self.ip,
                vec![
                    flag(family.ip_flag()),
                    flag("route"),
                    flag(verb),
                    flag("default"),
                    flag("dev"),
                    value(device),
                    flag("src"),
                    value(&local),
                    flag("table"),
                    value(POLICY_TABLE),
                    flag("metric"),
                    value(ROUTE_METRIC),
                    flag("mtu"),
                    value(&mtu),
                ],
            )
        };
        let probe = self.table_show(family)?;
        let rendered = format!("default dev {device}");
        Ok(Step {
            family,
            kind: StepKind::TunnelRoute,
            apply: spec("add")?,
            undo: spec("del")?,
            after_apply: Some(Check::present(probe.clone(), vec![rendered.clone()])),
            after_undo: Some(Check::absent(probe, vec![rendered])),
        })
    }

    fn table_show(&self, family: Family) -> Result<Command, PolicyError> {
        Command::build(
            &self.ip,
            vec![
                flag(family.ip_flag()),
                flag("route"),
                flag("show"),
                flag("table"),
                value(POLICY_TABLE),
            ],
        )
    }

    fn rule_show(&self, family: Family) -> Result<Command, PolicyError> {
        Command::build(
            &self.ip,
            vec![flag(family.ip_flag()), flag("rule"), flag("show")],
        )
    }

    /// Deleting by selector rather than by priority removes a rule left by a session that used a
    /// different priority, which a bare `del priority` would leave behind forever.
    fn rule_flush(&self, family: Family) -> Result<Command, PolicyError> {
        Command::build(
            &self.ip,
            vec![
                flag(family.ip_flag()),
                flag("rule"),
                flag("del"),
                flag("lookup"),
                value(POLICY_TABLE),
            ],
        )
    }

    /// The backstop carries no `lookup` selector to key on, and deleting by action alone would
    /// take an unrelated `unreachable` rule with it, so this deletes by the priority we own.
    fn backstop_flush(&self, family: Family) -> Result<Command, PolicyError> {
        Command::build(
            &self.ip,
            vec![
                flag(family.ip_flag()),
                flag("rule"),
                flag("del"),
                flag("priority"),
                value(BACKSTOP_PRIORITY),
            ],
        )
    }

    fn table_flush(&self, family: Family) -> Result<Command, PolicyError> {
        Command::build(
            &self.ip,
            vec![
                flag(family.ip_flag()),
                flag("route"),
                flag("flush"),
                flag("table"),
                value(POLICY_TABLE),
            ],
        )
    }

    fn stale_for_family(
        &self,
        runner: &dyn CommandRunner,
        family: Family,
    ) -> Result<Vec<Command>, PolicyError> {
        let lookup = format!("lookup {POLICY_TABLE}");
        // `ip rule show` prefixes every line with the priority, which is the only marker a stale
        // backstop carries; its source address belongs to a tun that no longer exists.
        let backstop = format!("{BACKSTOP_PRIORITY}:");
        let rules = self.read(runner, self.rule_show(family)?)?;
        let table = self.read(runner, self.table_show(family)?)?;
        let mut cleanup = Vec::new();
        if rules.contains(&backstop) {
            cleanup.push(self.backstop_flush(family)?);
        }
        if rules.contains(&lookup) {
            cleanup.push(self.rule_flush(family)?);
        }
        if !table.trim().is_empty() {
            cleanup.push(self.table_flush(family)?);
        }
        Ok(cleanup)
    }

    /// A failed enumeration is fatal: assuming "nothing is there" would let a stale rule survive
    /// into a session that believes it built its policy from nothing.
    fn read(&self, runner: &dyn CommandRunner, command: Command) -> Result<String, PolicyError> {
        let output = runner.run(&command)?;
        if !output.succeeded() {
            return Err(PolicyError::CommandFailed {
                what: "policy state enumeration",
                command: command.to_string(),
                stderr: output.stderr.lines().next().unwrap_or_default().to_owned(),
            });
        }
        Ok(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::super::command::testing::{failed, ok, ScriptedRunner};
    use super::super::plan::StepKind;
    use super::super::types::RawTunnel;
    use super::*;

    fn policy() -> LinuxPolicy {
        LinuxPolicy::with_ip_binary("/usr/sbin/ip")
    }

    fn tunnel() -> TunnelSpec {
        TunnelSpec::parse(RawTunnel {
            device: "tun0",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            mtu: 1400,
            ..RawTunnel::default()
        })
        .expect("valid spec")
    }

    #[test]
    fn installs_the_backstop_then_the_floor_then_the_rule_then_the_tunnel_route() {
        let plan = policy().plan(&tunnel()).expect("plan");

        assert_eq!(
            plan.install_commands(),
            vec![
                "/usr/sbin/ip -4 rule add from 10.8.0.2/32 type unreachable priority 18500",
                "/usr/sbin/ip -4 route add unreachable default table 218 metric 4000",
                "/usr/sbin/ip -4 rule add from 10.8.0.2/32 lookup 218 priority 18000",
                "/usr/sbin/ip -4 route add default dev tun0 src 10.8.0.2 table 218 metric 100 mtu 1400",
            ]
        );
        assert_eq!(
            plan.steps().iter().map(|s| s.kind).collect::<Vec<_>>(),
            vec![
                StepKind::Backstop,
                StepKind::Floor,
                StepKind::Rule,
                StepKind::TunnelRoute
            ]
        );
    }

    #[test]
    fn the_floor_is_unreachable_and_never_blackhole() {
        let plan = policy().plan(&tunnel()).expect("plan");

        let floor = plan.install_commands()[1].clone();
        assert!(floor.contains("route add unreachable default"));
        assert!(!plan.install_commands().join(" ").contains("blackhole"));
    }

    #[test]
    fn sets_no_sysctl_at_all() {
        let plan = policy().plan(&tunnel()).expect("plan");

        let everything = plan
            .steps()
            .iter()
            .map(|step| format!("{} {}", step.apply, step.undo))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!everything.contains("sysctl"));
        assert!(!everything.contains("rp_filter"));
    }

    #[test]
    fn mirrors_the_whole_triple_for_v6_when_an_address_was_assigned() {
        let dual = TunnelSpec::parse(RawTunnel {
            device: "tun0",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            local_v6: Some("fd00::2"),
            gateway_v6: Some("fd00::1"),
            mtu: 1400,
        })
        .expect("valid spec");

        let plan = policy().plan(&dual).expect("plan");

        assert_eq!(
            plan.install_commands(),
            vec![
                "/usr/sbin/ip -4 rule add from 10.8.0.2/32 type unreachable priority 18500",
                "/usr/sbin/ip -4 route add unreachable default table 218 metric 4000",
                "/usr/sbin/ip -4 rule add from 10.8.0.2/32 lookup 218 priority 18000",
                "/usr/sbin/ip -4 route add default dev tun0 src 10.8.0.2 table 218 metric 100 mtu 1400",
                "/usr/sbin/ip -6 rule add from fd00::2/128 type unreachable priority 18500",
                "/usr/sbin/ip -6 route add unreachable default table 218 metric 4000",
                "/usr/sbin/ip -6 rule add from fd00::2/128 lookup 218 priority 18000",
                "/usr/sbin/ip -6 route add default dev tun0 src fd00::2 table 218 metric 100 mtu 1400",
            ]
        );
    }

    #[test]
    fn teardown_removes_the_route_then_the_rule_then_the_floor_then_the_backstop() {
        let plan = policy().plan(&tunnel()).expect("plan");
        let runner = ScriptedRunner::new(|_| ok(""));

        super::super::plan::teardown(&plan, &runner).expect("torn down");

        let issued: Vec<String> = runner
            .log()
            .into_iter()
            .filter(|line| !line.contains("show"))
            .collect();
        assert_eq!(
            issued,
            vec![
                "/usr/sbin/ip -4 route del default dev tun0 src 10.8.0.2 table 218 metric 100 mtu 1400",
                "/usr/sbin/ip -4 rule del from 10.8.0.2/32 lookup 218 priority 18000",
                "/usr/sbin/ip -4 route del unreachable default table 218 metric 4000",
                "/usr/sbin/ip -4 rule del from 10.8.0.2/32 type unreachable priority 18500",
            ]
        );
    }

    #[test]
    fn a_rule_that_survives_its_deletion_keeps_the_floor_installed() {
        let plan = policy().plan(&tunnel()).expect("plan");
        let runner = ScriptedRunner::new(|command| {
            if command.args().contains(&"rule".to_owned())
                && command.args().contains(&"show".to_owned())
            {
                ok("18000:\tfrom 10.8.0.2 lookup 218\n")
            } else {
                ok("")
            }
        });

        let outcome = super::super::plan::teardown(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
        assert!(!runner
            .log()
            .iter()
            .any(|line| line.contains("route del unreachable")));
    }

    #[test]
    fn install_verifies_the_rule_by_reading_the_rule_table_back() {
        let plan = policy().plan(&tunnel()).expect("plan");
        let floor_removed = std::sync::atomic::AtomicBool::new(false);
        let runner = ScriptedRunner::new(move |command| {
            let rendered = command.to_string();
            if rendered.contains("route del unreachable") {
                floor_removed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if rendered.ends_with("route show table 218") {
                if floor_removed.load(std::sync::atomic::Ordering::SeqCst) {
                    ok("")
                } else {
                    ok("unreachable default metric 4000\ndefault dev tun0 src 10.8.0.2 metric 100 mtu 1400\n")
                }
            } else if rendered.ends_with("rule show") {
                // The rule silently failed to land; `ip` still exited zero.
                ok("0:\tfrom all lookup local\n")
            } else {
                ok("")
            }
        });

        let outcome = super::super::plan::install(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
    }

    #[test]
    fn pre_install_cleanup_flushes_the_backstop_the_rule_and_the_table() {
        let commands = policy().pre_install_cleanup(&tunnel()).expect("cleanup");

        assert_eq!(
            commands.iter().map(Command::to_string).collect::<Vec<_>>(),
            vec![
                "/usr/sbin/ip -4 rule del priority 18500",
                "/usr/sbin/ip -4 rule del lookup 218",
                "/usr/sbin/ip -4 route flush table 218",
            ]
        );
    }

    #[test]
    fn stale_cleanup_reports_nothing_when_the_table_and_rules_are_clean() {
        let runner = ScriptedRunner::new(|command| {
            if command.to_string().ends_with("rule show") {
                ok("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n")
            } else {
                ok("")
            }
        });

        let commands = policy().stale_cleanup(&runner).expect("cleanup");

        assert!(commands.is_empty());
    }

    #[test]
    fn stale_cleanup_removes_a_leftover_rule_and_table_from_a_crashed_session() {
        let runner = ScriptedRunner::new(|command| {
            if command.to_string().ends_with("rule show") {
                ok("18000:\tfrom 10.8.0.2 lookup 218\n")
            } else {
                ok("unreachable default metric 4000\n")
            }
        });

        let commands = policy().stale_cleanup(&runner).expect("cleanup");

        assert_eq!(
            commands.iter().map(Command::to_string).collect::<Vec<_>>(),
            vec![
                "/usr/sbin/ip -4 rule del lookup 218",
                "/usr/sbin/ip -4 route flush table 218",
                "/usr/sbin/ip -6 rule del lookup 218",
                "/usr/sbin/ip -6 route flush table 218",
            ]
        );
    }

    #[test]
    fn stale_cleanup_fails_loudly_when_the_state_cannot_be_read() {
        let runner = ScriptedRunner::new(|_| failed("Cannot open netlink socket"));

        let outcome = policy().stale_cleanup(&runner);

        assert!(matches!(outcome, Err(PolicyError::CommandFailed { .. })));
    }

    #[test]
    fn rejects_a_device_name_that_would_smuggle_an_option_onto_the_command_line() {
        let outcome = TunnelSpec::parse(RawTunnel {
            device: "tun0 dev eth0",
            local_v4: "10.8.0.2",
            mtu: 1400,
            ..RawTunnel::default()
        });

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }
}
