# Netlink Watcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-assert the Linux tunnel policy within milliseconds of anything deleting it, closing the unbounded leak window SPEC §5.2 records as observed.

**Architecture:** A netlink multicast socket is an *edge trigger* only — it reports that something in one of six `RTNLGRP_*` groups was deleted and nothing more. The decision is made by re-running the `Check` read-backs that already verify every install, walking the `Plan` forward so the backstop is restored before the rule. Failure to restore a step is logged and nothing else; the floor and backstop do not depend on the tun device, so the posture degrades toward more refusal, never toward escape.

**Tech Stack:** Rust, `libc` 0.2.189 (already a dependency — no new crate), `tokio` `AsyncFd`.

**Spec:** `docs/superpowers/specs/2026-09-06-netlink-watcher-design.md`

## Global Constraints

- SPDX header on every source file: `// SPDX-License-Identifier: GPL-3.0-or-later`
- **No `unwrap()` / `expect()` / `panic!()` anywhere in `daemon/` outside test modules.** Workspace clippy lints `unwrap_used`, `expect_used`, `panic` are `warn`; CI runs `-D warnings`. Every `#[cfg(test)] mod tests` in this crate opens with `#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]` — follow that pattern.
- **No new dependency.** `libc` and `tokio` are already in `daemon/Cargo.toml`. Adding `rtnetlink` or any netlink crate contradicts the spec's transport decision.
- No `unsafe` without a `// SAFETY:` comment stating the invariant. All raw syscalls in this change live in exactly one file, `daemon/src/policy/netlink.rs`.
- Errors: `thiserror` in library code, never `anyhow` outside the binary top level.
- Files stay under ~400 lines; functions under ~50 lines.
- Comments explain *why*, never *what*. No task or PR references in comments.
- Conventional commits. Stage files **by name** — never `git add -A`.
- Every task ends green on: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`.

## Two corrections to the spec, made while mapping files

Both are recorded here and applied to the spec in Task 8. An implementer following the spec literally would hit both.

1. **`daemon/tests/netlink_watcher.rs` cannot exist.** `daemon/Cargo.toml` declares only `[[bin]]` — there is no `lib.rs`, so an integration test in `daemon/tests/` has no crate to import. The `#[ignore]`d end-to-end test therefore lives in a `#[cfg(test)]` module inside `daemon/src/session/watchdog.rs`, and runs via `cargo test -p thisconnect-daemon --bin thisconnectd -- --ignored`.
2. **The watchdog runs for the daemon's whole life, not per-session.** The spec says "starts after `install`, aborted at `teardown`". Starting it once at startup and letting `reassert` be a no-op while nothing is installed removes the start/abort race entirely rather than managing it — the `Option<InstalledPolicy>` the guard already protects is the only liveness signal needed. Cost is one idle socket and a no-op sweep.

## File Structure

| File | Responsibility |
|---|---|
| `daemon/src/policy/netlink.rs` *(new)* | The only file with raw syscalls. Opens the `AF_NETLINK` socket, joins the six groups, yields `Trigger`. Knows nothing about policy. |
| `daemon/src/policy/plan.rs` *(modify)* | Gains `reassert` + `Reassertion`. Sits beside `install`/`teardown` because it is the third walk of the same ordering invariant. |
| `daemon/src/policy/mod.rs` *(modify)* | Declares `netlink`, re-exports, adds `PolicyManager::reassert`. |
| `daemon/src/session/tunnel.rs` *(modify)* | `TunnelPolicyDriver::reassert`; `teardown` holds the guard across itself. |
| `daemon/src/session/watchdog.rs` *(new)* | The loop joining `Trigger` to the driver. Owns the `#[ignore]`d namespace test. |
| `daemon/src/session/mod.rs` *(modify)* | `pub mod watchdog;` |
| `daemon/src/main.rs` *(modify)* | Spawns the watchdog after startup reconciliation. |
| `scripts/verify-egress-linux.sh` *(modify)* | `--watcher` mode. |
| `docs/SPEC.md`, `daemon/src/policy/linux.rs` *(modify)* | Record the result; the linux.rs header currently says nothing re-asserts, which stops being true. |

---

### Task 1: `plan::reassert` — check each step, restore what is missing, in install order

**Files:**
- Modify: `daemon/src/policy/plan.rs`

**Interfaces:**
- Consumes: `Plan`, `Step`, `StepKind`, `Check::evaluate`, `install_step` — all already private-in-module in `plan.rs`.
- Produces:
  ```rust
  pub struct Reassertion { pub restored: Vec<StepKind>, pub failed: Vec<StepKind> }
  impl Reassertion { pub fn is_quiet(&self) -> bool }
  pub fn reassert(plan: &Plan, runner: &dyn CommandRunner) -> Reassertion
  ```
  Note the return type is **not** `Result`, unlike the spec's sketch: there is no error to return. A step that cannot be restored is a `failed` entry and a `warn` log, per the report-only posture.

- [ ] **Step 1: Write the failing tests**

Add to the existing `mod tests` at the bottom of `daemon/src/policy/plan.rs`. `full_plan()`, `step()`, `cmd()`, `ok`, `failed` and `ScriptedRunner` already exist there — reuse them, do not redefine them.

```rust
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
        assert!(!runner.log().iter().any(|line| line == "/bin/policy do rule"));
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
        assert!(runner.log().iter().any(|line| line == "/bin/policy do rule"));
        assert!(!runner.log().iter().any(|line| line == "/bin/policy do floor"));
    }

    #[test]
    fn reassert_restores_the_floor_before_the_rule_when_both_are_gone() {
        // The window this whole change exists to close: with both gone, restoring the rule
        // first would route the tun source address through a table that has no floor in it.
        let plan = full_plan();
        let runner = ScriptedRunner::new(|command| {
            let rendered = command.to_string();
            // Nothing ever reads back, so every step is treated as missing and re-applied.
            if rendered.contains("show") {
                ok("")
            } else {
                ok("")
            }
        });

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
        assert!(floor_at < rule_at, "the floor must be restored before the rule");
        assert!(rule_at < route_at, "the rule must be restored before the route");
        // Re-applied but never read back, so none of them count as restored.
        assert_eq!(outcome.restored, Vec::<StepKind>::new());
        assert_eq!(
            outcome.failed,
            vec![StepKind::Floor, StepKind::Rule, StepKind::TunnelRoute]
        );
    }

    #[test]
    fn reassert_keeps_going_after_a_step_it_cannot_restore() {
        // The tun device is gone, so the route can never come back. The floor and the rule
        // still can, and must: they are what keeps the address fail-closed without it.
        let plan = full_plan();
        let runner = ScriptedRunner::new(|command| {
            let rendered = command.to_string();
            if rendered == "/bin/policy do route" {
                return failed("Cannot find device \"tun0\"");
            }
            if rendered.contains("showroute") {
                return ok("");
            }
            if rendered.contains("show") {
                // Absent on the first look, present after the re-apply this test does not
                // gate on; returning the subject makes the restore succeed.
                let subject = if rendered.contains("showfloor") { "floor" } else { "rule" };
                return ok(subject);
            }
            ok("")
        });

        let outcome = reassert(&plan, &runner);

        assert_eq!(outcome.failed, vec![StepKind::TunnelRoute]);
        assert!(runner.log().iter().any(|line| line == "/bin/policy do route"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p thisconnect-daemon --bin thisconnectd reassert 2>&1 | tail -20
```

Expected: FAIL — `cannot find function 'reassert' in this scope`.

- [ ] **Step 3: Implement**

Insert into `daemon/src/policy/plan.rs`, directly after the `teardown` function and before `fn first_line`:

```rust
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
```

A step with no `after_apply` check is treated as missing and re-applied — `is_some_and` returns false. Every step the Linux backend builds has one, so this is the conservative reading of a case that does not arise.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p thisconnect-daemon --bin thisconnectd reassert 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
```

Expected: 4 passed; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add daemon/src/policy/plan.rs
git commit -m "feat: restore deleted policy steps in install order

reassert walks the plan forward, so the backstop and the floor come back
before the rule that routes into the table they protect. Restoring the rule
first would reopen the fall-through to table main.

Each step is checked before it is touched: ip rule add appends a duplicate
rather than refusing, so re-running the plan wholesale would multiply rules
instead of restoring them."
```

---

### Task 2: The netlink trigger

**Files:**
- Create: `daemon/src/policy/netlink.rs`
- Modify: `daemon/src/policy/mod.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  ```rust
  pub enum Trigger { Deletion, Desynchronised }
  pub struct PolicyWatch;
  impl PolicyWatch {
      pub fn open() -> Result<Self, WatchError>;
      pub async fn next(&self) -> Trigger;
  }
  #[derive(Debug, thiserror::Error)] pub enum WatchError { Socket(std::io::Error), Register { group: u32, source: std::io::Error } }
  ```

- [ ] **Step 1: Write the failing tests for the message walker**

Create `daemon/src/policy/netlink.rs` containing **only** the SPDX header, the module doc, the constants, `nlmsg_align`, `mentions_deletion`, and this test module. The socket comes in Step 3.

```rust
// SPDX-License-Identifier: GPL-3.0-or-later

//! The netlink edge trigger for tunnel policy re-assertion (SPEC.md §5.2).
//!
//! This module deliberately does not understand netlink. It reads `nlmsg_type` out of the fixed
//! 16-byte header and nothing else: no attributes, no addresses, no rule priorities. What decides
//! whether the policy still stands is [`super::plan::reassert`], which re-runs the same read-back
//! `Check`s that verified the install — assertions four distributions have already exercised. A
//! parser we do not write cannot be wrong about a message that decides whether traffic leaks,
//! which is why there is no netlink crate here.
//!
//! Every raw syscall in this change lives in this file.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

/// `sizeof(struct nlmsghdr)`: u32 len, u16 type, u16 flags, u32 seq, u32 pid.
const NLMSG_HDRLEN: usize = 16;

/// Big enough that a burst of rule deletions arrives in one read. Undersizing this does not lose
/// messages — the kernel reports `ENOBUFS` and we re-assert pessimistically — but it makes the
/// common case take several wakeups.
const READ_BUFFER: usize = 8192;

/// The kernel drops messages rather than blocking when a listener falls behind, so the receive
/// buffer is the real defence against `ENOBUFS`; the pessimistic path is the backstop.
const RECV_BUFFER_BYTES: libc::c_int = 1 << 20;

/// Deletions in any of these mean our policy may no longer be installed. Rules cover both the
/// policy rule and the backstop; routes cover the floor and the tunnel route; addresses cover
/// the tun address the whole policy is keyed on. Both families throughout.
const GROUPS: [libc::c_uint; 6] = [
    libc::RTNLGRP_IPV4_RULE,
    libc::RTNLGRP_IPV6_RULE,
    libc::RTNLGRP_IPV4_ROUTE,
    libc::RTNLGRP_IPV6_ROUTE,
    libc::RTNLGRP_IPV4_IFADDR,
    libc::RTNLGRP_IPV6_IFADDR,
];

/// Why the watchdog woke up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// An `RTM_DEL*` arrived in a group we watch.
    Deletion,
    /// The kernel dropped messages (`ENOBUFS`) or the socket errored. We cannot know what was
    /// missed, so the only safe reading is that it was the deletion we exist to catch.
    Desynchronised,
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Walks a netlink read buffer looking only for a deletion we care about.
///
/// A malformed or truncated header stops the walk rather than being skipped: an attacker cannot
/// reach this socket, so a bad length means a bug, and continuing past one would mean reading
/// `nlmsg_type` out of arbitrary offsets.
fn mentions_deletion(buffer: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + NLMSG_HDRLEN <= buffer.len() {
        let Some(header) = buffer.get(offset..offset + NLMSG_HDRLEN) else {
            return false;
        };
        let (len_bytes, rest) = header.split_at(4);
        let Ok(len_bytes) = <[u8; 4]>::try_from(len_bytes) else {
            return false;
        };
        let Ok(kind_bytes) = <[u8; 2]>::try_from(&rest[..2]) else {
            return false;
        };
        // Netlink is host-endian on the wire.
        let len = u32::from_ne_bytes(len_bytes) as usize;
        let kind = u16::from_ne_bytes(kind_bytes);
        if len < NLMSG_HDRLEN || offset + len > buffer.len() {
            return false;
        }
        if matches!(
            kind,
            libc::RTM_DELRULE | libc::RTM_DELROUTE | libc::RTM_DELADDR
        ) {
            return true;
        }
        offset += nlmsg_align(len);
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// One netlink message: a 16-byte header with `payload` bytes after it.
    fn message(kind: u16, payload: usize) -> Vec<u8> {
        let len = NLMSG_HDRLEN + payload;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(len as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // flags
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // seq
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // pid
        bytes.resize(nlmsg_align(len), 0);
        bytes
    }

    #[test]
    fn sees_each_deletion_we_watch_for() {
        for kind in [libc::RTM_DELRULE, libc::RTM_DELROUTE, libc::RTM_DELADDR] {
            assert!(
                mentions_deletion(&message(kind, 24)),
                "type {kind} must trigger a re-assertion"
            );
        }
    }

    #[test]
    fn ignores_messages_that_are_not_deletions() {
        for kind in [libc::RTM_NEWRULE, libc::RTM_NEWROUTE, libc::RTM_NEWADDR] {
            assert!(
                !mentions_deletion(&message(kind, 24)),
                "type {kind} must not trigger a re-assertion"
            );
        }
    }

    #[test]
    fn finds_a_deletion_behind_other_messages_in_one_read() {
        // The realistic shape: a burst arrives in a single recv, and the interesting message
        // is not the first one.
        let mut buffer = message(libc::RTM_NEWROUTE, 40);
        buffer.extend_from_slice(&message(libc::RTM_NEWADDR, 12));
        buffer.extend_from_slice(&message(libc::RTM_DELRULE, 20));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn walks_past_a_payload_that_is_not_a_multiple_of_four() {
        // NLMSG_ALIGN pads to 4; getting this wrong reads the next header at the wrong offset
        // and silently stops seeing every message after the first odd-sized one.
        let mut buffer = message(libc::RTM_NEWROUTE, 13);
        buffer.extend_from_slice(&message(libc::RTM_DELROUTE, 20));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_reading_past_a_truncated_message() {
        let mut buffer = message(libc::RTM_NEWROUTE, 64);
        buffer.truncate(20);

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_spinning_on_a_length_below_the_header() {
        // A zero length would otherwise advance the offset by nothing, forever.
        let mut buffer = vec![0u8; NLMSG_HDRLEN];
        buffer.extend_from_slice(&message(libc::RTM_DELRULE, 8));

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn treats_an_empty_read_as_nothing_to_do() {
        assert!(!mentions_deletion(&[]));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

First declare the module so it compiles at all — add `mod netlink;` to the `mod` block near the top of `daemon/src/policy/mod.rs`, alongside `mod linux;`.

```bash
cargo test -p thisconnect-daemon --bin thisconnectd netlink 2>&1 | tail -20
```

Expected: these pass immediately, because Step 1 wrote the implementation alongside them. That is intentional for a pure byte-walker whose test *is* the specification — the meaningful failure to see first is Step 4's. If any fail, fix `mentions_deletion` before continuing.

- [ ] **Step 3: Add the socket**

Append to `daemon/src/policy/netlink.rs`, before the `#[cfg(test)]` module:

```rust
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("could not open a netlink route socket")]
    Socket(#[source] io::Error),

    #[error("could not join netlink multicast group {group}")]
    Register {
        group: libc::c_uint,
        #[source]
        source: io::Error,
    },
}

/// A subscription to the deletions that could take our policy down.
pub struct PolicyWatch {
    fd: AsyncFd<OwnedFd>,
}

impl PolicyWatch {
    pub fn open() -> Result<Self, WatchError> {
        let fd = open_netlink_socket()?;
        for group in GROUPS {
            join_group(&fd, group)?;
        }
        set_receive_buffer(&fd);
        AsyncFd::new(fd)
            .map(|fd| Self { fd })
            .map_err(WatchError::Socket)
    }

    /// Resolves the moment something happened that could have removed our policy. Returns
    /// [`Trigger::Desynchronised`] rather than an error on *any* socket trouble: a watchdog that
    /// stops watching because it could not read is the failure this module exists to prevent, so
    /// every uncertain outcome resolves toward re-asserting.
    pub async fn next(&self) -> Trigger {
        let mut buffer = [0u8; READ_BUFFER];
        loop {
            let Ok(mut guard) = self.fd.readable().await else {
                return Trigger::Desynchronised;
            };
            match guard.try_io(|inner| recv(inner.get_ref(), &mut buffer)) {
                // Spurious readiness: the guard has cleared it, so wait again.
                Err(_would_block) => continue,
                Ok(Ok(read)) => match buffer.get(..read) {
                    Some(message) if mentions_deletion(message) => return Trigger::Deletion,
                    _ => continue,
                },
                Ok(Err(_)) => return Trigger::Desynchronised,
            }
        }
    }
}

fn open_netlink_socket() -> Result<OwnedFd, WatchError> {
    // SAFETY: socket(2) with constant arguments has no preconditions and returns an owned fd or
    // -1. The descriptor is handed to OwnedFd immediately, so it is closed exactly once.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(WatchError::Socket(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh descriptor this function owns and never uses again.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // nl_pid 0 asks the kernel to assign a unique port id, which is what lets more than one
    // netlink listener exist in a process. Groups are joined by setsockopt rather than through
    // nl_groups: the bitmask cannot express a group above 32, and RTNLGRP numbering has already
    // passed that once.
    let address = libc::sockaddr_nl {
        nl_family: libc::AF_NETLINK as libc::sa_family_t,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    // SAFETY: `address` is a fully initialised sockaddr_nl and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(address).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(WatchError::Socket(io::Error::last_os_error()));
    }
    Ok(fd)
}

fn join_group(fd: &OwnedFd, group: libc::c_uint) -> Result<(), WatchError> {
    // SAFETY: the option value is a single initialised c_uint and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let joined = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP,
            std::ptr::addr_of!(group).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if joined < 0 {
        return Err(WatchError::Register {
            group,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Best effort by design. A kernel that refuses the size still delivers messages; it only makes
/// `ENOBUFS` likelier, and that path is already handled pessimistically.
fn set_receive_buffer(fd: &OwnedFd) {
    let size = RECV_BUFFER_BYTES;
    // SAFETY: the option value is a single initialised c_int and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let outcome = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if outcome < 0 {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            "could not enlarge the netlink receive buffer; ENOBUFS will be handled by re-asserting"
        );
    }
}

fn recv(fd: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is a valid mutable slice and the length passed is its own length; `fd` is
    // open for the duration of the call.
    let read = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    // A non-negative ssize_t always fits usize on every target this daemon builds for.
    Ok(read.max(0) as usize)
}
```

Then add to `daemon/src/policy/mod.rs`, in the `pub use` block:

```rust
pub use netlink::{PolicyWatch, Trigger, WatchError};
```

`netlink.rs` is Linux-only. Gate both the `mod netlink;` declaration and the `pub use` with `#[cfg(target_os = "linux")]`, matching how the crate already gates `peerauth::macos`.

- [ ] **Step 4: Write and run the live-socket test**

This is the assertion that would be identical if the socket were never opened, unless it actually observes an event — so it observes one. Add to the `mod tests` in `netlink.rs`:

```rust
    /// Needs CAP_NET_ADMIN and a network namespace of its own; run by
    /// `scripts/verify-egress-linux.sh --watcher`. A unit test cannot establish anything about
    /// netlink delivery, so this one drives a real socket and a real deletion.
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN in a private netns"]
    async fn a_real_rule_deletion_wakes_the_watch() {
        let watch = PolicyWatch::open().expect("netlink socket");

        let add = std::process::Command::new("ip")
            .args(["rule", "add", "from", "10.255.255.9/32", "lookup", "219", "priority", "18999"])
            .status()
            .expect("ip rule add");
        assert!(add.success(), "could not install the rule this test deletes");

        let deleted = std::process::Command::new("ip")
            .args(["rule", "del", "priority", "18999"])
            .status()
            .expect("ip rule del");
        assert!(deleted.success(), "could not delete the rule");

        let trigger = tokio::time::timeout(std::time::Duration::from_secs(5), watch.next())
            .await
            .expect("the watch did not wake within 5s of a real rule deletion");
        assert_eq!(trigger, Trigger::Deletion);
    }
```

```bash
cargo test -p thisconnect-daemon --bin thisconnectd netlink 2>&1 | tail -20
cargo test -p thisconnect-daemon --bin thisconnectd --no-run
unshare --user --map-root-user --net -- \
  cargo test -p thisconnect-daemon --bin thisconnectd -- --ignored --nocapture a_real_rule_deletion 2>&1 | tail -20
```

Expected: the seven pure tests pass; the ignored test passes inside the namespace. If it times out, the group registration or the bind is wrong — do not proceed.

- [ ] **Step 5: Commit**

```bash
git add daemon/src/policy/netlink.rs daemon/src/policy/mod.rs
git commit -m "feat: watch netlink for the deletions that take policy down

The socket is an edge trigger and nothing more: it reads nlmsg_type out of
the fixed header and never touches a payload. What decides whether the policy
still stands is the read-back Checks that verified the install, so no netlink
crate and no attribute parser is needed.

ENOBUFS and every other socket error resolve to Desynchronised. A watchdog
that stops watching because it could not read is the failure this exists to
prevent, so uncertainty resolves toward re-asserting."
```

---

### Task 3: Close the teardown race with the guard that already exists

**Files:**
- Modify: `daemon/src/session/tunnel.rs:107-134`
- Modify: `daemon/src/policy/mod.rs`

**Interfaces:**
- Consumes: `plan::reassert`, `Reassertion` (Task 1).
- Produces:
  ```rust
  impl<R: CommandRunner> PolicyManager<R> { pub fn reassert(&self, installed: &InstalledPolicy) -> Reassertion }
  pub trait TunnelPolicyDriver { /* … existing … */ fn reassert(&self) -> Reassertion; }
  ```

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` in `daemon/src/session/tunnel.rs`. If that module has no `ScriptedRunner` import yet, mirror the one in `daemon/src/policy/mod.rs`'s test module.

```rust
    #[test]
    fn reassert_does_nothing_before_an_install_and_after_a_teardown() {
        // The liveness signal is the InstalledPolicy itself. A watchdog that ran against a
        // torn-down session would re-install the rule and the table the proxy no longer pins
        // sockets to — reconciliation's job, done at the worst possible moment.
        let driver = managed_driver(everything_installed);

        assert!(driver.reassert().is_quiet());

        let binding = driver.install(spec(), 1400).expect("installed");
        driver.teardown(&binding).expect("torn down");

        assert!(driver.reassert().is_quiet());
    }

    #[test]
    fn teardown_holds_the_guard_so_a_concurrent_reassert_cannot_interleave() {
        // The runner blocks partway through teardown while another thread calls reassert. If the
        // guard were released before teardown ran, that reassert would see an InstalledPolicy
        // and start re-adding the rules teardown is in the middle of removing.
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let observed_during_teardown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let driver = std::sync::Arc::new(managed_driver(everything_installed));
        let binding = driver.install(spec(), 1400).expect("installed");

        let racer = {
            let driver = std::sync::Arc::clone(&driver);
            let gate = std::sync::Arc::clone(&gate);
            let observed = std::sync::Arc::clone(&observed_during_teardown);
            std::thread::spawn(move || {
                gate.wait();
                // Blocks until teardown releases the guard, then observes an empty slot.
                observed.store(driver.reassert().is_quiet(), std::sync::atomic::Ordering::SeqCst);
            })
        };

        gate.wait();
        driver.teardown(&binding).expect("torn down");
        racer.join().expect("racer");

        assert!(
            observed_during_teardown.load(std::sync::atomic::Ordering::SeqCst),
            "a reassert racing teardown must find nothing installed, never a half-removed plan"
        );
    }
```

Add the two helpers this needs to the same test module, if they are not already there:

```rust
    fn managed_driver<F>(reply: F) -> ManagedPolicy<crate::policy::testing::ScriptedRunner<F>>
    where
        F: Fn(&crate::policy::Command) -> crate::policy::CommandOutput + Send + Sync,
    {
        ManagedPolicy::new(PolicyManager::new(
            Box::new(crate::policy::LinuxPolicy::with_ip_binary("/usr/sbin/ip")),
            crate::policy::testing::ScriptedRunner::new(reply),
        ))
    }
```

`command::testing` is currently `#[cfg(test)] pub(crate)` inside `policy::command` but is not re-exported from `policy`. Add to `daemon/src/policy/mod.rs`:

```rust
#[cfg(test)]
pub(crate) use command::testing;
```

and reuse `spec()` / `everything_installed()` by copying them from `daemon/src/policy/mod.rs`'s test module into `tunnel.rs`'s — they are five lines each and the two test modules are independent.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p thisconnect-daemon --bin thisconnectd tunnel:: 2>&1 | tail -20
```

Expected: FAIL — `no method named 'reassert' found`.

- [ ] **Step 3: Implement**

In `daemon/src/policy/mod.rs`, add to `impl<R: CommandRunner> PolicyManager<R>`, after `teardown`:

```rust
    /// Restores whatever has been deleted out from under a live session. Distinct from
    /// [`Self::reconcile`], which removes state a *dead* session left behind: this one puts back
    /// state a live session still depends on, and the two must never be confused.
    pub fn reassert(&self, installed: &InstalledPolicy) -> plan::Reassertion {
        plan::reassert(&installed.plan, &self.runner)
    }
```

and re-export `Reassertion` beside `Plan`:

```rust
pub use plan::{Check, Plan, Reassertion, Step, StepKind};
```

In `daemon/src/session/tunnel.rs`, add to the `TunnelPolicyDriver` trait:

```rust
    /// Re-installs any policy step that has been removed since `install`. A no-op when nothing
    /// is installed, which is what makes it safe to call from a watchdog that outlives any one
    /// session.
    fn reassert(&self) -> Reassertion;
```

Implement it on `ManagedPolicy`, and change `teardown` to hold the guard:

```rust
    fn reassert(&self) -> Reassertion {
        let installed = lock(&self.installed);
        installed
            .as_ref()
            .map(|installed| self.manager.reassert(installed))
            .unwrap_or_default()
    }

    fn teardown(&self, binding: &TunnelBinding) -> Result<(), PolicyError> {
        // The guard is held across the whole teardown, not just the take(). It is the only thing
        // serialising this against a re-assertion from the watchdog, which would otherwise start
        // re-adding rules half way through their removal. Holding it also means "this session is
        // going away" is expressed as the absence of the proof value rather than as a second flag
        // that could disagree with it.
        let mut guard = lock(&self.installed);
        let Some(installed) = guard.take() else {
            // Already removed, or this daemon never installed it. Teardown is idempotent by
            // contract, so this is not an error.
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
```

Import `Reassertion` in `tunnel.rs`'s `use crate::policy::{…}` list. Every other implementer of `TunnelPolicyDriver` — the test fakes in `daemon/src/session/tests.rs` and `daemon/src/session/connect.rs` — needs `fn reassert(&self) -> Reassertion { Reassertion::default() }`; find them with `grep -rn "impl TunnelPolicyDriver" daemon/src`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --workspace 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
```

Expected: all 717+ pass; clippy and fmt clean.

- [ ] **Step 5: Commit**

```bash
git add daemon/src/policy/mod.rs daemon/src/session/tunnel.rs daemon/src/session/tests.rs daemon/src/session/connect.rs
git commit -m "feat: expose re-assertion behind the teardown guard

teardown now holds the InstalledPolicy guard across itself rather than
dropping it after the take(), which is the whole of the serialisation
against a concurrent re-assertion. Liveness stays expressed as the presence
of the proof value, so there is no second flag that could disagree with it."
```

---

### Task 4: The watchdog loop

**Files:**
- Create: `daemon/src/session/watchdog.rs`
- Modify: `daemon/src/session/mod.rs`

**Interfaces:**
- Consumes: `PolicyWatch`, `Trigger` (Task 2); `TunnelPolicyDriver::reassert`, `Reassertion` (Tasks 1, 3).
- Produces:
  ```rust
  pub const MIN_INTERVAL: Duration;   // 1s
  pub const SWEEP_INTERVAL: Duration; // 30s
  pub async fn run(watch: PolicyWatch, driver: Arc<dyn TunnelPolicyDriver>, shutdown: watch::Receiver<bool>)
  ```

- [ ] **Step 1: Write the failing tests**

Create `daemon/src/session/watchdog.rs` with the SPDX header, the module doc, and this test module only.

```rust
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

    #[tokio::test]
    async fn a_trigger_causes_exactly_one_reassertion() {
        let driver = Arc::new(CountingDriver::default());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tx.send(Trigger::Deletion).expect("queued");
        drop(tx);

        drive(rx, Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>, shutdown_rx).await;

        assert_eq!(driver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
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

        drive(rx, Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>, shutdown_rx).await;

        let calls = driver.calls.load(Ordering::SeqCst);
        assert!(calls >= 1, "a burst must still produce at least one re-assertion");
        assert!(calls < 50, "50 events produced {calls} re-assertions; nothing coalesced");
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
            drive(rx, Arc::clone(&driver) as Arc<dyn TunnelPolicyDriver>, shutdown_rx),
        )
        .await
        .expect("the watchdog must stop when shutdown is signalled");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Add `pub mod watchdog;` to the `pub mod` block in `daemon/src/session/mod.rs`.

```bash
cargo test -p thisconnect-daemon --bin thisconnectd watchdog 2>&1 | tail -20
```

Expected: FAIL — `cannot find function 'drive' in this scope`.

- [ ] **Step 3: Implement**

The loop is split in two so the tests above can drive it from a channel rather than a real socket: `run` owns the `PolicyWatch` and feeds `drive`, which owns the policy.

```rust
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
```

`spawn_blocking(...).await.unwrap_or_default()` needs `Reassertion: Default`, which Task 1 derives. A `JoinError` here means the runtime is shutting down; a quiet default is the right reading and keeps the no-`unwrap` rule.

The tests call `drive` with an **unbounded** channel; name the function `drive_bounded` for the real path and add this thin adapter inside the test module rather than widening the production API:

```rust
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
```

The burst test would otherwise take 50 seconds of real time; add `#[tokio::test(start_paused = true)]` to it and to `a_trigger_causes_exactly_one_reassertion` so `tokio::time::sleep` is virtual. `start_paused` requires tokio's `test-util` feature — add it under `[dev-dependencies]` in `daemon/Cargo.toml`:

```toml
[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p thisconnect-daemon --bin thisconnectd watchdog 2>&1 | tail -20
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
```

Expected: 3 passed, quickly (seconds, not a minute — if the burst test takes 50s, `start_paused` is missing).

- [ ] **Step 5: Commit**

```bash
git add daemon/src/session/watchdog.rs daemon/src/session/mod.rs daemon/Cargo.toml
git commit -m "feat: re-assert tunnel policy when something deletes it

The watchdog outlives any one session: reassert is a no-op while nothing is
installed, so there is no start/abort lifecycle to race against teardown.

A one-second floor between passes coalesces the burst a routing change
produces, and stops a permanently unreadable socket from spinning a root
process on Desynchronised."
```

---

### Task 5: Start it

**Files:**
- Modify: `daemon/src/main.rs:265-300` (the `main` body, between `reconcile_startup_state` and `IpcServer::new`)

**Interfaces:**
- Consumes: `watchdog::run` (Task 4), `PolicyWatch::open` (Task 2).
- Produces: nothing.

- [ ] **Step 1: Implement**

`tunnel_policy()` currently builds the `Arc<dyn TunnelPolicyDriver>` inline inside the `system_deps` call. Bind it first so the watchdog gets the same instance — a second `ManagedPolicy` would have its own empty `installed` slot and re-assert nothing, forever, silently.

Replace:

```rust
    let deps = system_deps(
        &config,
        tunnel_policy()?,
        secrets,
        outbound.clone(),
        Arc::clone(&proxy),
    );
```

with:

```rust
    let tunnel_policy = tunnel_policy()?;
    let deps = system_deps(
        &config,
        Arc::clone(&tunnel_policy),
        secrets,
        outbound.clone(),
        Arc::clone(&proxy),
    );
```

Then, after `signals::install(shutdown_tx)…`, add:

```rust
    spawn_policy_watchdog(Arc::clone(&tunnel_policy), shutdown_rx.clone());
```

and the function itself, beside `reconcile_startup_state`:

```rust
/// Something else deleting our policy mid-session was observed to leak (SPEC.md §5.2), and
/// nothing put it back until the daemon restarted. A daemon that cannot open the netlink socket
/// still runs — the policy is installed and fail-closed either way — but it has lost its only
/// bound on how long a deletion goes unnoticed, so this is a warning, not a debug line.
#[cfg(target_os = "linux")]
fn spawn_policy_watchdog(
    policy: Arc<dyn TunnelPolicyDriver>,
    shutdown: watch::Receiver<bool>,
) {
    match policy::PolicyWatch::open() {
        Ok(watch) => {
            tokio::spawn(session::watchdog::run(watch, policy, shutdown));
            info!("watching netlink for policy deletions");
        }
        Err(error) => warn!(
            %error,
            "no netlink watch: tunnel policy deleted by something else will not be re-asserted until reconnect"
        ),
    }
}

/// macOS needs the `PF_ROUTE` equivalent (SPEC.md §5.2); until then a deletion goes unnoticed,
/// which is a smaller exposure there because a scoped route's absence makes the kernel refuse to
/// fall back to the physical interface rather than silently using it.
#[cfg(not(target_os = "linux"))]
fn spawn_policy_watchdog(_policy: Arc<dyn TunnelPolicyDriver>, _shutdown: watch::Receiver<bool>) {}
```

`shutdown_rx` is currently created and moved straight into `IpcServer::run`; `watch::Receiver` is `Clone`, so pass a clone to the watchdog and leave the original for the server.

- [ ] **Step 2: Verify it builds and starts on both targets**

```bash
cargo build --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all -- --check
```

Expected: clean. `#[cfg]` errors here mean the macOS stub's signature drifted from the Linux one.

- [ ] **Step 3: Confirm the log line appears**

```bash
THISCONNECT_LOG=thisconnectd=info \
THISCONNECT_SOCKET=/tmp/tc-watchdog.sock \
THISCONNECT_RUNTIME_DIR=/tmp/tc-rt THISCONNECT_STATE_DIR=/tmp/tc-state \
THISCONNECT_ALLOWED_UIDS=$(id -u) \
  timeout 3 cargo run -p thisconnect-daemon --features dev-insecure-ipc 2>&1 | grep -E "netlink|no netlink"
```

Expected: `watching netlink for policy deletions`. Unprivileged users can open `NETLINK_ROUTE` and join these groups, so this must succeed without root; if it logs the warning instead, the group registration is wrong.

- [ ] **Step 4: Commit**

```bash
git add daemon/src/main.rs
git commit -m "feat: start the policy watchdog at daemon startup

The driver is bound once and shared: a second ManagedPolicy would carry its
own empty installed slot and re-assert nothing, forever, without saying so.

A daemon that cannot open the socket still runs, but it has lost its only
bound on how long a deletion goes unnoticed, so that path warns."
```

---

### Task 6: Prove it, with a control that can invalidate the run

**Files:**
- Modify: `daemon/src/session/watchdog.rs` (test module)

**Interfaces:**
- Consumes: everything above.
- Produces: `#[ignore]`d test `the_watcher_restores_rules_deleted_under_a_live_session`.

A unit test settles nothing platform-specific here, and an assertion that would read the same with the watcher absent settles less than nothing. So the control runs **first**, with no watcher: the same deletion must be *seen* to let the address escape over the dummy device. If it is not, the environment cannot demonstrate a leak, the main assertion proves nothing, and the test fails as `INCONCLUSIVE` rather than passing.

- [ ] **Step 1: Write the test**

Append to the `mod tests` in `daemon/src/session/watchdog.rs`:

```rust
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
        must_ip(&["addr", "add", &format!("{TEST_ESCAPE_IP}/24"), "dev", TEST_ESCAPE]);
        must_ip(&["link", "set", "dev", TEST_ESCAPE, "up"]);
        must_ip(&["route", "add", "default", "dev", TEST_ESCAPE, "metric", "500"]);

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
        assert!(!rules_present(), "the control's deletion did not take effect");

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
```

The test is v4-only on purpose. The v6 half of the *policy* is already verified by `verify-egress-linux.sh` across four distributions; what is unproven here is netlink delivery and re-assertion, and `RTM_DELRULE` is one message type for both families over one socket. Adding v6 would double the setup — including the `nodad` requirement — to re-exercise the same code path.

- [ ] **Step 2: Run it, and confirm the control can actually fail**

```bash
cargo test -p thisconnect-daemon --bin thisconnectd --no-run
unshare --user --map-root-user --net -- \
  cargo test -p thisconnect-daemon --bin thisconnectd -- --ignored --nocapture the_watcher_restores 2>&1 | tail -30
```

Expected: PASS.

Then **verify the control is not vacuous** by making it fail on purpose — temporarily comment out the `ip route add default dev tc-watch-esc` line and re-run. Expected: the test fails with the `INCONCLUSIVE:` message, not with a later assertion. Restore the line. Do not commit the commented-out version.

- [ ] **Step 3: Commit**

```bash
git add daemon/src/session/watchdog.rs
git commit -m "test: drive the watcher over a real netlink socket, with a control

The control runs first and without a watcher: the same deletion must be seen
to let the tun source address escape over the dummy device. If it cannot, the
environment cannot demonstrate the leak and the run reports INCONCLUSIVE
rather than passing on an assertion that would read the same with the watcher
absent."
```

---

### Task 7: `--watcher` in the verification script

**Files:**
- Modify: `scripts/verify-egress-linux.sh`

**Interfaces:**
- Consumes: the `#[ignore]`d test from Task 6.
- Produces: `./scripts/verify-egress-linux.sh --confirm --watcher`.

- [ ] **Step 1: Add the flag and the mode**

Add `WATCHER="no"` beside the other defaults near the top, then in `parse_args` add, next to `--netns`:

```bash
      --watcher) WATCHER="yes" ;;
```

Add to `usage`, under `--netns`:

```
  --watcher            Prove the netlink watcher re-asserts policy deleted out from under a
                       live session (SPEC.md §5.2). Builds the daemon's ignored watcher test
                       and runs it in a private user+network namespace; needs no root. The
                       test carries its own control and reports INCONCLUSIVE if the namespace
                       cannot demonstrate the leak. Implies --netns; ignores --family.
```

Add the function beside `run_egress_test`:

```bash
# The watcher lives in the daemon, so this mode delegates to the daemon's own ignored test
# rather than re-implementing re-assertion in shell. The build happens OUTSIDE the namespace so
# a compile error is reported as a compile error, not as a namespace failure.
run_watcher_test() {
  step "Test: the netlink watcher re-asserts policy deleted mid-session"
  command -v cargo >/dev/null || die "--watcher needs cargo"
  command -v unshare >/dev/null || die "--watcher needs util-linux's unshare(1)"
  say "Building the daemon test binary (outside the namespace)"
  cargo test -p thisconnect-daemon --bin thisconnectd --no-run ||
    die "the daemon test binary does not build"
  say "Running the watcher test inside a private user+network namespace"
  if unshare --user --map-root-user --net -- \
    cargo test -p thisconnect-daemon --bin thisconnectd -- \
    --ignored --nocapture --test-threads=1 the_watcher_restores; then
    WATCHER_VERDICT="PASS the watcher restored both rules and the lookup stayed on the tun"
  else
    WATCHER_VERDICT="FAIL see the test output above; an INCONCLUSIVE control reports there too"
  fi
}
```

Declare `WATCHER_VERDICT=""` beside `EGRESS_VERDICT=""`, and add to `print_verdict`, after the egress block:

```bash
  if [ -n "$WATCHER_VERDICT" ]; then
    say "netlink watcher: $WATCHER_VERDICT"
    all="$all$WATCHER_VERDICT"
  fi
```

In `main`, handle it before `preflight` — this mode builds its own namespace and its own devices, so it must not share the outer run's:

```bash
  if [ "$WATCHER" = "yes" ]; then
    run_watcher_test
    print_verdict
    return
  fi
```

placed immediately after the `--netns` re-exec block. Also extend the FAIL guidance in `print_verdict`:

```bash
      say "A netlink watcher failure means policy deleted mid-session is not re-asserted, so"
      say "§5.2's re-assertion latency is unbounded and the Linux leak window is open again."
```

- [ ] **Step 2: Run it**

```bash
bash scripts/verify-egress-linux.sh --self-test
shellcheck scripts/verify-egress-linux.sh
./scripts/verify-egress-linux.sh --confirm --watcher 2>&1 | tail -20
./scripts/verify-egress-linux.sh --confirm --netns 2>&1 | tail -12
```

Expected: self-test passes, shellcheck silent, `--watcher` reports PASS, and the existing `--netns` run is unchanged (four PASS lines, no INCONCLUSIVE).

- [ ] **Step 3: Commit**

```bash
git add scripts/verify-egress-linux.sh
git commit -m "test: run the netlink watcher proof from the verification script

The build happens outside the namespace so a compile error is reported as a
compile error rather than as a namespace failure."
```

---

### Task 8: Record what is now verified, and fix the spec's two errors

**Files:**
- Modify: `docs/SPEC.md` (§5.2, the "Netlink watcher" bullet)
- Modify: `daemon/src/policy/linux.rs:1-30` (module doc)
- Modify: `docs/superpowers/specs/2026-09-06-netlink-watcher-design.md`

- [ ] **Step 1: Update SPEC §5.2**

Replace the `**Netlink watcher — specified, NOT IMPLEMENTED [U].**` bullet with:

```markdown
- **Netlink watcher — implemented and verified on Linux [V].** `daemon/src/policy/netlink.rs`
  joins `RTNLGRP_IPV4_RULE`, `RTNLGRP_IPV6_RULE`, `RTNLGRP_IPV4_ROUTE`, `RTNLGRP_IPV6_ROUTE`,
  `RTNLGRP_IPV4_IFADDR` and `RTNLGRP_IPV6_IFADDR` on one `AF_NETLINK` socket and reports any
  `RTM_DELRULE`/`RTM_DELROUTE`/`RTM_DELADDR` as an edge trigger. It reads `nlmsg_type` out of the
  fixed header and nothing else: what decides whether the policy still stands is
  `plan::reassert`, which re-runs the same read-back `Check`s that verified the install, walking
  the plan **forward** so the backstop and floor are restored before the rule. No netlink crate
  is used and no dependency was added.
- **The re-assertion latency is now bounded and measured [V].** With both rules deleted out from
  under a live session inside a private user+network namespace, the watcher restored them and the
  lookup for the tun source address stayed on the tun. The assertion carries a control: the same
  deletion with no watcher running must first be *seen* to send the address out over a dummy
  device, or the run reports INCONCLUSIVE rather than passing. Driven by
  `scripts/verify-egress-linux.sh --watcher`.
- **A step that cannot be restored is reported, not escalated.** If the tun device is gone the
  tunnel route can never come back; the floor and the backstop do not depend on it, so egress
  answers `EHOSTUNREACH`/`ENETUNREACH` and the posture degrades toward more refusal. The daemon
  logs and changes nothing else.
- **macOS `PF_ROUTE` — still specified, NOT IMPLEMENTED [U].** Scoped routes deleted out from
  under a live session are not re-asserted. The exposure is smaller than the Linux one was,
  because the kernel refuses to fall back to the physical interface rather than silently using
  it, but stale-route reconciliation on daemon start remains the only defence.
```

- [ ] **Step 2: Fix the `linux.rs` module doc**

It currently ends `Nothing re-asserts any of this after install — see the netlink watcher in SPEC.md §5.2, which is specified and not implemented.` Replace that sentence with:

```rust
//! `session::watchdog` re-asserts all of this whenever netlink reports a deletion, so a rule
//! removed by NetworkManager or another VPN client comes back rather than leaking until the
//! daemon restarts (SPEC.md §5.2).
```

- [ ] **Step 3: Fix the design doc's two errors**

In `docs/superpowers/specs/2026-09-06-netlink-watcher-design.md`:

- Under "Verification", replace `daemon/tests/netlink_watcher.rs` with a note that `daemon` has no `lib.rs` — only `[[bin]]` — so the `#[ignore]`d test lives in `daemon/src/session/watchdog.rs` and runs via `cargo test -p thisconnect-daemon --bin thisconnectd -- --ignored`.
- Under "Wiring", replace "starts after `install` … aborted at `teardown`" with: the watchdog runs for the daemon's lifetime and `reassert` is a no-op while nothing is installed, which removes the start/abort race instead of managing it.
- Under `plan::reassert`, correct the signature to `-> Reassertion` (not `Result<Vec<StepKind>, PolicyError>`): there is no error to return under the report-only posture.

- [ ] **Step 4: Full verification before claiming anything**

```bash
cargo test --workspace 2>&1 | tail -5
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
shellcheck scripts/verify-egress-linux.sh
./scripts/verify-egress-linux.sh --confirm --netns 2>&1 | tail -12
./scripts/verify-egress-linux.sh --confirm --watcher 2>&1 | tail -8
```

Every one must pass. Paste the actual output into the commit body — a claim without the output is not evidence.

- [ ] **Step 5: Commit**

```bash
git add docs/SPEC.md daemon/src/policy/linux.rs docs/superpowers/specs/2026-09-06-netlink-watcher-design.md
git commit -m "docs: record the netlink watcher as implemented and verified

SPEC 5.2's watcher moves from [U] to [V] for Linux, with the control that
makes the run conclusive named. macOS PF_ROUTE stays [U].

Also corrects two errors in the design doc found while implementing: daemon
has no lib target, so the ignored test cannot live in daemon/tests/, and the
watchdog runs for the daemon's lifetime rather than per-session, which removes
the start/abort race rather than managing it."
```

---

## Self-review

**Spec coverage.** Transport decision → Task 2. `PolicyWatch`/`Trigger`/six groups → Task 2. `ENOBUFS` → Task 2 (`Desynchronised`) and Task 4 (the unconditional re-assert). `plan::reassert` ascending → Task 1. Report-only posture → Task 1 (`failed`), Task 4 (`report`). Teardown guard → Task 3. Wiring, sweep, coalescing → Tasks 4 and 5. Verification with control → Tasks 6 and 7. macOS stays `[U]` → Tasks 5 and 8.

**Known deviations, all deliberate and all fixed in the spec by Task 8:** `reassert` returns `Reassertion`, not `Result`; the test lives in `daemon/src/session/watchdog.rs`, not `daemon/tests/`; the watchdog is process-lifetime, not per-session.

**Type consistency.** `Reassertion { restored, failed }` and `is_quiet()` are used identically in Tasks 1, 3, 4 and 6. `Trigger::{Deletion, Desynchronised}` in Tasks 2, 4 and 6. `PolicyWatch::open() -> Result<Self, WatchError>` in Tasks 2, 5 and 6. `TunnelPolicyDriver::reassert(&self) -> Reassertion` in Tasks 3, 4 and 6. `watchdog::run(watch, driver, shutdown)` in Tasks 4, 5 and 6.
