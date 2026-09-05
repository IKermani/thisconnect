<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Verification scripts

These are not unit tests. They are the two experiments that decide whether the egress design in
`docs/SPEC.md` §5.2 actually holds on a real kernel. Both modify system networking, both require
root, and both refuse to do anything without `--confirm`.

| Script | Platform | Proves |
|---|---|---|
| `verify-ifscope-macos.sh` | macOS | §10 test 1 — the one **[U]** claim in the whole design |
| `verify-egress-linux.sh` | Linux | §10 tests 2 and 3 — the fail-closed floor and the rule |

## Safety conventions

Both scripts follow the same rules:

- `--confirm` is mandatory. Without it they print the exact set of changes they would make and
  exit. Read that output before granting root.
- Every mutation is echoed as `+ <command>` before it runs, and every undo as `- <command>`.
- `trap cleanup EXIT INT TERM` removes every route, rule and interface they created, including on
  failure and on Ctrl-C.
- They abort rather than touch anything that already exists: an existing `tc-verify0`, an existing
  `ip rule` at priority 18000, or a utun outside the throwaway 90–99 range.
- Neither writes to `resolv.conf`, table `main`, or the system default route.
- `--self-test` runs the pure decision logic (verdict rules, log parsing, errno labels) with no
  root and no system access. CI runs it on every push.

## macOS — the critical experiment

`docs/SPEC.md` §5.2 claims that an interface-scoped default route makes a socket pinned with
`IP_BOUND_IF` reachable, while leaving the unscoped default lookup untouched. Nobody has run it.
Everything macOS depends on it.

```sh
sudo ./scripts/verify-ifscope-macos.sh --confirm                       # synthetic utun, no server
sudo ./scripts/verify-ifscope-macos.sh --confirm --profile ~/x.ovpn    # real openvpn
```

The script asserts four things, in order:

1. **Negative case first.** A socket pinned to the utun with no scoped route must fail with
   `ENETUNREACH` (51). A test that only checks the positive case says nothing about fail-closed.
2. **Positive case, both variants.** `route -n add -inet -ifscope <utunN> default <peer>` (topology
   subnet) and `... default -interface <utunN>` (p2p/net30) are installed and measured separately.
   The result is reported per variant, because the daemon must know which one to use.
3. **The system default route is byte-for-byte unchanged.** `route -n get -inet default` is captured
   three times: before any change, **while each scoped route is installed**, and after teardown.
   The middle snapshot is the one that matters — the leak §5.2 rules out is only observable while
   a scoped route exists, so a before/after pair taken either side of a torn-down state would
   report PASS on a real leak. The after-teardown comparison remains as a residue check. This is
   the product's core promise; a diff at either point fails the run regardless of everything else.
4. **Everything is torn down.** Teardown is a fixed sequence of `route`/`ifconfig` calls guarded by
   booleans, never strings passed to `eval`: the tun device and peer address in `--profile` mode
   are scraped from a log that carries the server's pushed options verbatim at `--verb 3`, so they
   are untrusted input. They are rejected unless the device matches `utun<digits>` and the peer is
   a dotted quad, before anything runs them as root.

### Synthetic mode and the utun

There is no `utun` interface cloner on Darwin (`ifconfig -C` does not list one), so
`ifconfig utunN create` cannot work. A utun exists only while some process holds the
`PF_SYSTEM` / `com.apple.net.utun_control` socket it was created from. Synthetic mode therefore
compiles a second small helper alongside the probe, which opens that socket, prints the interface
name and blocks; killing it is the destroy. `--compile-check` builds both helpers and exits,
needing no root — CI runs it on macOS.

### `--profile` mode limits

This script has no management client. `docs/SPEC.md` §4.1 records **[V]** that without
`--management-query-passwords` openvpn dies before auth (`neither stdin nor stderr are a tty
device`), so a profile with a bare `auth-user-pass` is refused up front with that explanation
rather than timing out. Use a profile with `auth-user-pass <file>` or an inline
`<auth-user-pass>` block. Driving credentials over the management socket is the daemon's job.

### Reading the verdict

Synthetic mode creates a utun with an address and no peer, so no handshake can complete. The pass
criterion there is the errno moving **off** `ENETUNREACH` — that is exactly the claim under test
(does the scoped route enter the pinned lookup?), and nothing more is claimed. `--profile` mode
demands a completed TCP connection.

`FAIL` means §5.2's macOS half does not work. Interface-scoped routing cannot be the egress
mechanism, and macOS needs a redesign — a userspace TCP/IP stack over the utun, or full-tunnel-only
on macOS — before more macOS code is written. Record the output under `docs/SPEC.md` §13 item 1
either way, and flip the **[U]** in §5.2 to **[V]** on a pass.

## Linux — floor route and rule

```sh
sudo ./scripts/verify-egress-linux.sh --confirm
sudo ./scripts/verify-egress-linux.sh --confirm \
     --egress-check 10.8.0.2 --echo-url https://api.ipify.org
```

Default run builds the §5.2 policy on a throwaway tun (floor route first, then rule, then the real
route) and then:

- **Test 3, the floor.** Deletes the tunnel route from table 218 **with the tun address still
  present** and asserts `EHOSTUNREACH` (113). The address must still be there: with it gone the
  test degrades into "`bind()` returns `EADDRNOTAVAIL`", which passes with no rule and no floor
  installed and therefore proves nothing. The script checks this explicitly before measuring.
- **Test 3, the rule.** Deletes the `ip rule` and asserts the lookup does not fall through to table
  `main`. Both the probe errno and `ip route get <dst> from <tunip>` are inspected; a selected
  device that is not the tun is a `FAIL`, because packets bearing the tun source address would
  leave over the physical link. If this fails, the netlink watcher in §5.2 is load-bearing rather
  than defence in depth, and teardown order has to be re-derived.
- **Test 2, `--egress-check`.** Needs an *already-connected* tunnel whose policy the daemon has
  installed; the script does not create one. It compares an IP-echo response bound to the tun
  source address against an unbound one and asserts they differ.

`blackhole` is deliberately not used anywhere: `RTN_BLACKHOLE` yields `EINVAL`, which maps to no
SOCKS5 reply code. `RTN_UNREACHABLE` yields `EHOSTUNREACH`, which maps to REP `0x04`.

## Probes

Each script compiles a small C probe into a temporary directory at run time and deletes it on exit.
They share one exit-code vocabulary:

| Code | Meaning |
|---|---|
| 0 | connected |
| 10 | `ENETUNREACH` |
| 11 | `EHOSTUNREACH` |
| 12 | some other `connect()` errno |
| 13 | still pending when the timeout expired |
| 20 | probe setup failure — the measurement did not happen |

The macOS probe pins with `IP_BOUND_IF`; the Linux probe binds the tun source address with
`IP_BIND_ADDRESS_NO_PORT`, mirroring the unprivileged dialer in §5.3. Neither needs root itself —
only the route setup does.
