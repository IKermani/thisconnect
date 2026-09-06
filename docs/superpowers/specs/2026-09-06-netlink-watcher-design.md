# Netlink watcher — design

Date: 2026-09-06
Status: approved, not yet implemented
Implements: `docs/SPEC.md` §5.2, "Netlink watcher — specified, NOT IMPLEMENTED [U]"

## The defect

`PolicyManager::reconcile` is the only reconciliation the daemon has. It runs once, from
`main`, before the first install, and its job is to *remove* stale state — not to re-assert
live state. Nothing watches the policy after `install` returns.

This matters because the policy is not ours alone to hold. NetworkManager, systemd-networkd
and other VPN clients rewrite policy routing on connectivity changes; Tailscale issue #2325
documents rules being discarded that way. SPEC §5.2 records the consequence as observed, not
theorised: delete both the policy rule and the backstop mid-session and the tun source address
falls through to table `main` and leaves over the physical interface. Nothing puts the rules
back until the daemon restarts, so the re-assertion latency is unbounded.

That is a leak with no upper time bound, which makes it a Linux release blocker rather than
hardening.

## Scope

Linux only. macOS keeps its `PF_ROUTE` equivalent marked `[U]` in SPEC §5.2; the interface
below is shaped so a `PF_ROUTE` backend slots in without moving the re-assertion logic. On
macOS the kernel's refusal to fall back to the physical interface is itself a floor, so the
exposure is smaller and this box cannot verify a macOS fix anyway.

## Transport: raw `AF_NETLINK` over libc

The alternative was the `rtnetlink` crate. Rejected, for one reason: **the watcher does not
need to understand netlink messages.**

The authority on whether the policy is still standing already exists and is already verified —
`Step::after_apply`, the `Check` read-backs that `install` runs and that four distributions
have exercised. So netlink is only an *edge trigger*; the decision is made by re-running
assertions that are already covered. That collapses the parser to reading `nlmsg_type` out of
a fixed 16-byte header, walked with `NLMSG_ALIGN`. No attribute parsing, no `RTA_*`, no
address decoding.

`rtnetlink` would buy precise filtering — reacting only to our own rule priority and table —
at the cost of `netlink-packet-route`, `netlink-proto`, `netlink-sys` and a `futures` stack
beside the tokio the daemon already runs on. Its licence (MIT/Apache) is GPLv3-compatible, so
licensing is not the objection; surface area is. Precision is available more cheaply by
re-verifying, and a parser we do not write cannot be wrong about a message that decides
whether traffic leaks.

`libc` 0.2.189, already in the dependency tree, exposes everything required on Linux:
`NETLINK_ROUTE`, `sockaddr_nl`, `nlmsghdr`, `NETLINK_ADD_MEMBERSHIP`, `SOL_NETLINK`,
`RTM_DELRULE`/`RTM_DELROUTE`/`RTM_DELADDR`, and all six `RTNLGRP_*` groups. **No new
dependency is added.**

The accepted cost: we re-verify on unrelated route churn — a DHCP renewal, another VPN coming
up. That is two `ip … show` invocations, coalesced. It strengthens the fail-closed claim
rather than weakening it.

## Components

### 1. `daemon/src/policy/netlink.rs` — the trigger

`PolicyWatch` opens `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
NETLINK_ROUTE)`, binds a `sockaddr_nl`, and joins six multicast groups with
`setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP)`, one group per call:

| Group | Watched for |
|---|---|
| `RTNLGRP_IPV4_RULE`, `RTNLGRP_IPV6_RULE` | `RTM_DELRULE` — the policy rule *and* the backstop, both families |
| `RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE` | `RTM_DELROUTE` — the floor and the tunnel route |
| `RTNLGRP_IPV4_IFADDR`, `RTNLGRP_IPV6_IFADDR` | `RTM_DELADDR` — the tun address the whole policy is keyed on |

`NETLINK_ADD_MEMBERSHIP` is used rather than a `nl_groups` bitmask in `bind`. Every group
needed today has a number below 32 and would fit the bitmask, but the bitmask cannot express a
group above 32, and the setsockopt form is the one that keeps working if that ever changes.

The fd is wrapped in `tokio::io::unix::AsyncFd`. Tokio is already the daemon's runtime; no
second async idiom is introduced.

All raw syscalls live in this one module, behind a safe API, with `// SAFETY:` comments — the
exception CLAUDE.md already carves out for `setsockopt`-shaped code, kept in one place rather
than inline.

The watch yields:

```rust
enum Trigger {
    /// An RTM_DEL* in a group we watch. Re-assert.
    Deletion,
    /// recv returned ENOBUFS: the kernel dropped messages and we cannot know
    /// which. Re-assert unconditionally.
    Desynchronised,
}
```

`Desynchronised` is the case that would otherwise be a silent hole. A netlink socket whose
receive buffer overflows drops messages and reports `ENOBUFS` once; treating that as a
transient read error would lose exactly the deletion burst we exist to catch. It gets both a
large `SO_RCVBUF` and the pessimistic path.

### 2. `plan::reassert` — the response

```rust
pub fn reassert(plan: &Plan, runner: &dyn CommandRunner) -> Reassertion;
```

Walks `plan.steps()` in **plan order, ascending**. For each step: evaluate `after_apply`; if
it fails, re-run `apply` and re-verify. Returns the kinds it restored.

Ascending order is not incidental. `Plan::new` already enforces `Backstop → Floor → Rule →
TunnelRoute` within a family, and `teardown` walks it in reverse; re-assertion walking it
forward is the same invariant applied a third time. It is what makes the backstop come back
*before* the rule — the same direction `install` closes the window in. Re-adding the rule
first would open, however briefly, precisely the fall-through to table `main` that SPEC §5.2
records as observed.

`ip rule add` is not idempotent — it appends a duplicate rather than refusing — which is why
re-assertion is check-then-apply per step and never a blanket re-run of the plan.

A step that cannot be restored is logged at `warn` and the walk continues. It does not abort
the remaining steps and it does not tear anything down.

### 3. Failure posture: report only, stay fail-closed

When re-assertion cannot restore a step — the common case being the tunnel route, because the
tun device itself disappeared — the daemon logs at `warn` and changes nothing else.

Logging is the whole of the reporting in this change. Surfacing it to the GUI over the
existing event channel is deferred: `ManagedPolicy` is constructed without an event sender,
and threading one in is coupling this change does not need in order to close the leak.

This is safe because the backstop and the floor do not depend on the device. With the tunnel
route gone, the floor answers `EHOSTUNREACH`; with the rule gone too, the backstop answers
`ENETUNREACH`. Both are already mapped by the egress dialer. The posture degrades toward
*more* refusal, never toward escape.

The two rejected alternatives, recorded so they are not re-proposed without a reason:

- *Revoke the egress identity* (`EgressPublisher::revoke`) on unrecoverable failure. Strictly
  stronger, but it couples the watcher to the session orchestrator and adds a teardown path
  driven from a background task.
- *Escalate to full teardown.* A transient netlink hiccup would then kill a live session, and
  teardown from a watcher thread is the hardest race here to get right.

Neither is needed to close the leak, so neither is in scope.

### 4. Race with teardown: no new lock

`ManagedPolicy` already holds `Mutex<Option<InstalledPolicy>>` — the proof value that install
returns and teardown consumes. Today `teardown` `take()`s it and drops the guard *before*
calling `manager.teardown`.

The change: hold that guard across the whole teardown. Re-assertion acquires the same guard
and, finding `None`, does nothing.

Teardown and re-assertion then cannot interleave, and "this session is going away" is
expressed as the absence of the proof value rather than as a second flag that could disagree
with it. That is the same fix shape as `TunnelBinding::tunnel_has_v6`: make the contradictory
state unrepresentable instead of merely unreached.

### 5. Wiring

A `PolicyWatchdog` task runs for the daemon's whole lifetime, not per-session. `reassert` is a
no-op while nothing is installed, which removes the start/abort race against `install` and
`teardown` rather than managing it. It re-asserts on:

- any `Trigger::Deletion`, after draining whatever else is already queued so a burst
  coalesces into one pass;
- `Trigger::Desynchronised`;
- a periodic sweep every 30s, which covers an edge missed for any reason the two cases above
  do not name.

Blocking `ip` invocations run off the async worker.

## What is deliberately not built

- Parsing *which* rule or route was deleted. The read-backs decide; the message only wakes us.
- Reacting to `RTM_NEW*`. A rule appearing is not evidence ours is gone, and the sweep covers
  a competing rule inserted at a higher priority.
- Any change to `reconcile`. Removing stale state at startup and re-asserting live state
  mid-session stay distinct jobs.

## Verification

Unit tests do not settle anything platform-specific here, and an assertion that would read the
same with the watcher absent settles less than nothing — that was the vacuous-backstop finding
of the previous session.

`daemon/Cargo.toml` declares only a `[[bin]]`, no `lib.rs`, so an integration test under
`daemon/tests/` would have no crate to import. The `#[ignore]`d test that requires
`CAP_NET_ADMIN` therefore lives in `daemon/src/session/watchdog.rs` and runs via
`cargo test -p thisconnect-daemon --bin thisconnectd -- --ignored`.
`scripts/verify-egress-linux.sh --watcher` runs it inside `unshare --user --map-root-user
--net`, which grants `CAP_NET_ADMIN` without root and touches no host networking.

The test deletes **both** rules out from under a live watcher and requires:

1. both rules present again afterwards, read back through the same `Check` probes; and
2. the tun source address still unable to escape.

**Paired control, on the same path, with the watcher disabled:** the same deletion must be
seen to let the address escape over the dummy device. If the control does not observe that
escape, the environment cannot demonstrate a leak, the main assertion proves nothing, and the
run reports `INCONCLUSIVE` rather than `PASS`.

A v6 tun address in the harness must be added `nodad`, or it stays `tentative` and `bind()`
fails `EADDRNOTAVAIL` — a run whose `bind()` failed proves nothing about routing.

## Documentation

On landing, SPEC §5.2's "Netlink watcher — specified, NOT IMPLEMENTED [U]" becomes `[V]` for
Linux, citing the verification run, and keeps the macOS `PF_ROUTE` half at `[U]`.
