// SPDX-License-Identifier: GPL-3.0-or-later

//! macOS tunnel policy: interface-scoped default routes (SPEC.md §5.2).
//!
//! Empirically verified by `scripts/verify-ifscope-macos.sh --confirm` under sudo on macOS 26.6:
//! a socket pinned with `IP_BOUND_IF` and no scoped route gets `ENETUNREACH(51)`, either scoped
//! route variant makes the same connect proceed, and the unscoped default route is byte-for-byte
//! unchanged throughout. The kernel's refusal to fall back to `en0` *is* the fail-closed floor,
//! which is why this platform installs no floor route and no rule — there is nothing to install.

use std::net::IpAddr;
use std::path::PathBuf;

use super::command::{flag, value, Arg, Command, CommandRunner};
use super::plan::{Check, Plan, Step, StepKind};
use super::types::{DeviceName, Family, Topology, TunnelEndpoint, TunnelSpec};
use super::{PolicyError, TunnelPolicy};

/// System binaries on macOS live at fixed absolute paths; resolving them through `PATH` in a root
/// daemon would be a lever, not a convenience.
const ROUTE: &str = "/sbin/route";
const NETSTAT: &str = "/usr/sbin/netstat";
const IFCONFIG: &str = "/sbin/ifconfig";

#[derive(Clone, Debug)]
pub struct MacosPolicy {
    route: PathBuf,
    netstat: PathBuf,
    ifconfig: PathBuf,
}

impl Default for MacosPolicy {
    fn default() -> Self {
        Self {
            route: PathBuf::from(ROUTE),
            netstat: PathBuf::from(NETSTAT),
            ifconfig: PathBuf::from(IFCONFIG),
        }
    }
}

impl TunnelPolicy for MacosPolicy {
    fn plan(&self, spec: &TunnelSpec) -> Result<Plan, PolicyError> {
        // Re-validated here, at the last point before an argument becomes a root command line.
        spec.device().require_utun()?;
        let steps = spec
            .endpoints()
            .map(|endpoint| self.route_step(spec.device(), endpoint))
            .collect::<Result<Vec<_>, _>>()?;
        Plan::new(steps)
    }

    fn pre_install_cleanup(&self, spec: &TunnelSpec) -> Result<Vec<Command>, PolicyError> {
        spec.device().require_utun()?;
        // A recycled utun can still carry a scoped default from a crashed session. Both variants
        // are attempted because we cannot know which one the dead session chose.
        spec.endpoints()
            .flat_map(|endpoint| {
                let family = endpoint.family();
                // The interface variant is always attempted: a crashed session may have chosen
                // it even where this one has a gateway to route via.
                let interface_variant = self.delete_command(spec.device(), family, None);
                match endpoint.topology() {
                    Topology::Gateway(address) => vec![
                        interface_variant,
                        self.delete_command(spec.device(), family, Some(*address)),
                    ],
                    Topology::Interface => vec![interface_variant],
                }
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn stale_cleanup(&self, runner: &dyn CommandRunner) -> Result<Vec<Command>, PolicyError> {
        let live = self.live_interfaces(runner)?;
        [Family::V4, Family::V6]
            .into_iter()
            .map(|family| {
                self.scoped_defaults(runner, family)
                    .map(move |r| (family, r))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flat_map(|(family, routes)| {
                routes
                    .into_iter()
                    .filter(|route| !live.iter().any(|name| *name == route.device.as_str()))
                    .map(move |route| self.delete_command(&route.device, family, route.gateway))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// A `default` row from `netstat -rn`, already re-validated.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScopedDefault {
    device: DeviceName,
    gateway: Option<IpAddr>,
}

impl MacosPolicy {
    fn route_step(
        &self,
        device: &DeviceName,
        endpoint: &TunnelEndpoint,
    ) -> Result<Step, PolicyError> {
        let family = endpoint.family();
        let gateway = match endpoint.topology() {
            Topology::Gateway(address) => Some(*address),
            Topology::Interface => None,
        };
        let probe = Command::build(
            &self.route,
            vec![
                flag("-n"),
                flag("get"),
                flag(family.route_flag()),
                flag("-ifscope"),
                value(device),
                flag("default"),
            ],
        )?;
        let mut required = vec![format!("interface: {device}")];
        if let Some(address) = gateway {
            required.push(format!("gateway: {address}"));
        }
        Ok(Step {
            family,
            kind: StepKind::TunnelRoute,
            apply: self.mutate_command(device, family, gateway, "add")?,
            undo: self.mutate_command(device, family, gateway, "delete")?,
            after_apply: Some(Check::present(probe.clone(), required)),
            // `route -n get` exits non-zero precisely when there is no such route, so here — and
            // only here — a failing probe is the confirmation of absence.
            after_undo: Some(Check::absent_or_probe_fails(
                probe,
                vec![format!("interface: {device}")],
            )),
        })
    }

    fn delete_command(
        &self,
        device: &DeviceName,
        family: Family,
        gateway: Option<IpAddr>,
    ) -> Result<Command, PolicyError> {
        self.mutate_command(device, family, gateway, "delete")
    }

    fn mutate_command(
        &self,
        device: &DeviceName,
        family: Family,
        gateway: Option<IpAddr>,
        verb: &'static str,
    ) -> Result<Command, PolicyError> {
        let head = vec![
            flag("-n"),
            flag(verb),
            flag(family.route_flag()),
            flag("-ifscope"),
            value(device),
            flag("default"),
        ];
        let tail: Vec<Arg> = match gateway {
            Some(address) => vec![value(address)],
            None => vec![flag("-interface"), value(device)],
        };
        Command::build(&self.route, head.into_iter().chain(tail).collect())
    }

    fn live_interfaces(&self, runner: &dyn CommandRunner) -> Result<Vec<String>, PolicyError> {
        let command = Command::build(&self.ifconfig, vec![flag("-l")])?;
        let output = runner.run(&command)?;
        if !output.succeeded() {
            return Err(PolicyError::CommandFailed {
                what: "interface enumeration",
                command: command.to_string(),
                stderr: output.stderr.lines().next().unwrap_or_default().to_owned(),
            });
        }
        Ok(output
            .stdout
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    }

    fn scoped_defaults(
        &self,
        runner: &dyn CommandRunner,
        family: Family,
    ) -> Result<Vec<ScopedDefault>, PolicyError> {
        let command = Command::build(
            &self.netstat,
            vec![flag("-rn"), flag("-f"), flag(netstat_family(family))],
        )?;
        let output = runner.run(&command)?;
        if !output.succeeded() {
            return Err(PolicyError::CommandFailed {
                what: "route table enumeration",
                command: command.to_string(),
                stderr: output.stderr.lines().next().unwrap_or_default().to_owned(),
            });
        }
        Ok(parse_default_routes(&output.stdout))
    }
}

fn netstat_family(family: Family) -> &'static str {
    match family {
        Family::V4 => "inet",
        Family::V6 => "inet6",
    }
}

/// Extracts the `default` rows that are scoped to a utun. The column layout of `netstat -rn` is
/// not fixed across releases — older Darwin carries `Refs`/`Use` columns — so the header is read
/// rather than assumed, and any row whose device is not a utun is ignored outright: the unscoped
/// system default lives in this same table and must never be touched.
fn parse_default_routes(stdout: &str) -> Vec<ScopedDefault> {
    let mut columns: Option<(usize, usize)> = None;
    let mut found = Vec::new();
    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let (Some(gateway), Some(netif)) = (
            fields.iter().position(|f| *f == "Gateway"),
            fields.iter().position(|f| *f == "Netif"),
        ) {
            columns = Some((gateway, netif));
            continue;
        }
        let Some((gateway_at, netif_at)) = columns else {
            continue;
        };
        if fields.first() != Some(&"default") || fields.len() <= netif_at {
            continue;
        }
        let Ok(device) = DeviceName::parse(fields[netif_at]) else {
            continue;
        };
        if device.require_utun().is_err() {
            continue;
        }
        found.push(ScopedDefault {
            device,
            // A `-interface` route reports the device name or `link#N` here, neither of which
            // parses as an address; that is exactly how the two variants are told apart.
            gateway: fields
                .get(gateway_at)
                .and_then(|g| g.parse::<IpAddr>().ok()),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::super::command::testing::{failed, ok, ScriptedRunner};
    use super::super::types::RawTunnel;
    use super::*;

    fn spec(raw: RawTunnel<'_>) -> TunnelSpec {
        TunnelSpec::parse(raw).expect("valid spec")
    }

    fn gateway_tunnel() -> TunnelSpec {
        spec(RawTunnel {
            device: "utun4",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            mtu: 1400,
            ..RawTunnel::default()
        })
    }

    fn p2p_tunnel() -> TunnelSpec {
        spec(RawTunnel {
            device: "utun4",
            local_v4: "10.8.0.2",
            gateway_v4: None,
            mtu: 1400,
            ..RawTunnel::default()
        })
    }

    #[test]
    fn the_gateway_variant_matches_the_verified_script_line() {
        let plan = MacosPolicy::default()
            .plan(&gateway_tunnel())
            .expect("plan");

        assert_eq!(
            plan.install_commands(),
            vec!["/sbin/route -n add -inet -ifscope utun4 default 10.8.0.1"]
        );
    }

    #[test]
    fn the_point_to_point_variant_matches_the_verified_script_line() {
        let plan = MacosPolicy::default().plan(&p2p_tunnel()).expect("plan");

        assert_eq!(
            plan.install_commands(),
            vec!["/sbin/route -n add -inet -ifscope utun4 default -interface utun4"]
        );
    }

    #[test]
    fn mirrors_the_route_for_v6_only_when_an_address_was_assigned() {
        let dual = spec(RawTunnel {
            device: "utun4",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            local_v6: Some("fd00::2"),
            gateway_v6: Some("fd00::1"),
            mtu: 1400,
        });

        let plan = MacosPolicy::default().plan(&dual).expect("plan");

        assert_eq!(
            plan.install_commands(),
            vec![
                "/sbin/route -n add -inet -ifscope utun4 default 10.8.0.1",
                "/sbin/route -n add -inet6 -ifscope utun4 default fd00::1",
            ]
        );
        assert_eq!(
            MacosPolicy::default()
                .plan(&gateway_tunnel())
                .expect("plan")
                .steps()
                .len(),
            1
        );
    }

    #[test]
    fn refuses_to_scope_a_route_against_a_device_that_is_not_a_utun() {
        let linux_shaped = spec(RawTunnel {
            device: "tun0",
            local_v4: "10.8.0.2",
            gateway_v4: Some("10.8.0.1"),
            mtu: 1400,
            ..RawTunnel::default()
        });

        let outcome = MacosPolicy::default().plan(&linux_shaped);

        assert!(matches!(outcome, Err(PolicyError::InvalidDevice { .. })));
    }

    #[test]
    fn verifies_the_installed_route_by_reading_it_back() {
        let plan = MacosPolicy::default()
            .plan(&gateway_tunnel())
            .expect("plan");
        let check = plan.steps()[0].after_apply.clone().expect("check");

        assert_eq!(
            check.probe.to_string(),
            "/sbin/route -n get -inet -ifscope utun4 default"
        );
        assert_eq!(
            check.required,
            vec![
                "interface: utun4".to_owned(),
                "gateway: 10.8.0.1".to_owned()
            ]
        );
    }

    #[test]
    fn install_fails_when_the_route_reads_back_pointing_at_another_interface() {
        let plan = MacosPolicy::default()
            .plan(&gateway_tunnel())
            .expect("plan");
        let runner = ScriptedRunner::new(|command| {
            if command.args().contains(&"get".to_owned()) {
                // The unscoped default answering in place of a scoped route that never landed.
                ok("   route to: default\ndestination: default\n  interface: en0\n")
            } else {
                ok("")
            }
        });

        let outcome = super::super::plan::install(&plan, &runner);

        assert!(matches!(outcome, Err(PolicyError::Verification { .. })));
        assert!(runner
            .log()
            .contains(&"/sbin/route -n delete -inet -ifscope utun4 default 10.8.0.1".to_owned()));
    }

    #[test]
    fn pre_install_cleanup_clears_both_variants_on_a_recycled_utun() {
        let commands = MacosPolicy::default()
            .pre_install_cleanup(&gateway_tunnel())
            .expect("cleanup");

        assert_eq!(
            commands.iter().map(Command::to_string).collect::<Vec<_>>(),
            vec![
                "/sbin/route -n delete -inet -ifscope utun4 default -interface utun4",
                "/sbin/route -n delete -inet -ifscope utun4 default 10.8.0.1",
            ]
        );
    }

    const NETSTAT_V4: &str = "Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            10.255.255.1       UGScIg             utun90
default            utun91             UCSIg              utun91
10.8/24            utun4              USc                 utun4
";

    #[test]
    fn parses_only_scoped_utun_defaults_and_never_the_system_default() {
        let found = parse_default_routes(NETSTAT_V4);

        assert_eq!(
            found,
            vec![
                ScopedDefault {
                    device: DeviceName::parse("utun90").expect("valid"),
                    gateway: Some("10.255.255.1".parse().expect("addr")),
                },
                ScopedDefault {
                    device: DeviceName::parse("utun91").expect("valid"),
                    gateway: None,
                },
            ]
        );
    }

    #[test]
    fn parses_the_older_layout_that_carries_refs_and_use_columns() {
        let older = "Destination        Gateway            Flags   Refs      Use   Netif Expire
default            10.255.255.1       UGSc       3        0  utun90
";

        let found = parse_default_routes(older);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].device.as_str(), "utun90");
    }

    #[test]
    fn stale_cleanup_only_removes_scoped_defaults_on_interfaces_that_are_gone() {
        let runner = ScriptedRunner::new(|command| {
            if command.program().ends_with("ifconfig") {
                // utun90 survived a crash; utun91 no longer exists.
                ok("lo0 en0 utun90\n")
            } else if command.args().contains(&"inet".to_owned()) {
                ok(NETSTAT_V4)
            } else {
                ok("")
            }
        });

        let commands = MacosPolicy::default()
            .stale_cleanup(&runner)
            .expect("cleanup");

        assert_eq!(
            commands.iter().map(Command::to_string).collect::<Vec<_>>(),
            vec!["/sbin/route -n delete -inet -ifscope utun91 default -interface utun91"]
        );
    }

    #[test]
    fn stale_cleanup_reports_an_enumeration_failure_rather_than_assuming_nothing_is_stale() {
        let runner = ScriptedRunner::new(|_| failed("ifconfig: interface list failed"));

        let outcome = MacosPolicy::default().stale_cleanup(&runner);

        assert!(matches!(outcome, Err(PolicyError::CommandFailed { .. })));
    }
}
