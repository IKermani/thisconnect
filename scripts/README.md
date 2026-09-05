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

## The live run — `verify-live-tunnel.sh`

The two scripts above test *routing primitives* on synthetic interfaces. This one drives the real
daemon, built from this tree, against a real server, and is the only thing in the repository that
has ever carried a packet. It closes `docs/SPEC.md` §10 tests 2 and 3 and §13 open question 1.

```sh
sudo ./scripts/verify-live-tunnel.sh --profile ~/vpn/work.ovpn --confirm
THISCONNECT_ECHO_URL=https://ifconfig.me/ip \
  sudo -E ./scripts/verify-live-tunnel.sh --profile ~/vpn/work.ovpn --confirm
```

**What is under test is not the connection.** A VPN client that connects proves nothing. The
verdict is a table of security properties, and a connection that succeeds while any of them fails
is a worse outcome than one that never connects:

| | Property | Failure means |
|---|---|---|
| A | The system default route is byte-for-byte unchanged **while connected** | §3.1 point 5 is broken: the client modifies the system stack |
| B | A direct, non-proxied request still leaves via the normal interface with the same public IP | the machine's own connectivity was disturbed |
| C | A request **through the proxy** returns a *different* public IP | proxied traffic is not traversing the tunnel; the product does nothing |
| D | The daemon reports `local_dns_lookups == 0` for the session | names escaped the tunnel — §5.4 calls this a release blocker |
| E | With the tunnel killed, a proxy request **fails** | the proxy is fail-**open**; users browse believing they are tunnelled |
| F/G | The default route is unchanged after teardown and no route referencing the utun survives | a scoped default route pointing at a dead utun is a correctness *and* security hazard (§5.2) |

**E is the file's reason to exist.** It `kill -KILL`s the daemon's own `openvpn` child — the daemon
is not asked to disconnect — and then makes the proxy request twice: immediately, and again after a
settle period. A pass is only ever downgraded by the second look, never upgraded, because a
fail-open window that closes three seconds later is still a fail-open window. The loudest failure
in the whole script is a proxy request that succeeds and answers with the **direct** public IP:
nothing looked broken, and every byte left over the ISP link under the user's real identity.

### Measurement honesty

- The IP-echo endpoint defaults to `https://api.ipify.org` and is overridable with
  `--echo-url` or `THISCONNECT_ECHO_URL`, for networks where it is blocked.
- If the endpoint is unreachable **before** connecting, or answers with something that is not an IP
  address (a captive portal returns HTML with a 200), the run exits **2 = SKIP** and says why.
  Every assertion compares against that baseline, so a run that cannot measure must never report
  `PASS`. Exit codes are `0` PASS, `1` FAIL, `2` SKIP.
- A property that could not be measured — no proxy listener to ask, no DNS counters in the
  response, no `openvpn` child to kill — is reported as `skip` with a sentence saying what was
  *not* tested, and the headline becomes `PASS-WITH-GAPS`. It is never folded into a pass:
  **`PASS-WITH-GAPS` exits `2` (SKIP)**, so an unfinished run is never green to a caller or a CI
  job. `0` means every assertion in the table ran and held.
- Two assertions are explicitly gated on the measurement having happened at all, because their
  naive form passes on a session where nothing worked:
  - **E (fail-closed)** runs only when **C (egress)** passed. Otherwise the post-kill request
    would fail for the reason it was already failing, and a broken proxy would be printed as a
    proven fail-closed property. When C did not pass, E is `skip`.
  - **D (DNS)** reads `tunnel_dns_lookups` alongside `local_dns_lookups`. `local == 0` alone is
    indistinguishable between "every name went through the tunnel" and "no name was ever
    resolved"; D passes only on `local == 0` **and** `tunnel > 0`, and is `skip` when
    `tunnel == 0`.
- `curl` is invoked with `socks5h://`. `socks5://` resolves the hostname locally, which would pass
  assertion C while leaking every name (§5.4 D8); the script refuses a proxy URL that is not
  `socks5h://` even if the daemon offers one.

### Secrets

The profile will normally need a username and password, so the daemon sends a credential `prompt`
over IPC as a daemon-initiated message (`docs/IPC.md` §6). The script answers it from the
operator's terminal with `read -r` and `read -rs`, honouring the prompt's `echo` flag for
challenge responses. Nothing sensitive is echoed, written to disk, or logged, and nothing
sensitive is ever passed as an argument — `argv` is world-readable through `ps`. That constraint
shapes two pieces of the implementation:

- A small Python helper does the JSON encoding, reading the password (and the `.ovpn` body) from
  **stdin**. Its escaping and its single-line framing are unit-tested, because framing is
  load-bearing (`docs/IPC.md` §1).
- The proxy password reaches `curl` through `--config -` on stdin, never `-x <url>`.

The profile's contents, the CA, and any key material are never printed. On a validator rejection
the script prints the daemon's own redacted error, never the file.

### Isolation

The daemon runs against `THISCONNECT_SOCKET`, `THISCONNECT_RUNTIME_DIR` and
`THISCONNECT_STATE_DIR` inside one `mktemp -d`, removed by the `trap` on every exit path.
`/var/run` and any system install are untouched, and the script adds no route, interface or
resolver of its own — it only observes. When invoked through `sudo`, the `cargo build` is dropped
back to `$SUDO_USER` so `target/` is not left owned by root.

### What this run does *not* cover

The daemon is built `--features dev-insecure-ipc`, which reduces the macOS authenticator to a uid
check. It has to be: without it the authenticator is `UnimplementedCodeVerifier`, which denies
every peer, and a shell script cannot present the GUI's designated requirement anyway. **IPC peer
authentication (`docs/SPEC.md` §7.3) is therefore not exercised here**, and the verdict says so on
every run rather than letting a reader assume otherwise.

`--self-test` runs the pure decision functions — the verdict rules, the echo-answer validation, the
`ps` and `netstat` parsers, the JSON helper's escaping — with no root and no network. CI runs it
on every push, like the other two scripts.
