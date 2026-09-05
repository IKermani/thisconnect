# thisconnect — Product Specification

Status: **draft v1**, pre-implementation.
License: GPL-3.0-or-later.

Every claim marked **[V]** was empirically verified against `openvpn 2.7.6 aarch64-apple-darwin25.6.0`
or read directly from OpenVPN `release/2.7` source during research. Claims marked **[U]** are
unverified and must be proven by an integration test before the code that depends on them is merged.

---

## 1. What this is

A desktop OpenVPN client that can put a VPN connection behind a **local SOCKS5/HTTP proxy instead
of the system routing table**.

The user connects a profile, and gets `socks5h://127.0.0.1:1080`. Applications pointed at that
proxy egress through the VPN. Everything else on the machine is untouched — no default-route
change, no `resolv.conf` rewrite, no other application affected.

That is per-application VPN on a stock OpenVPN server, with no server-side cooperation. No
existing OpenVPN client does this. It is the reason this project exists.

### 1.1 Why it doesn't exist yet

The proxy-based VPN clients (v2rayN, Clash, sing-box, Hiddify) get this almost free: their cores
are userspace TCP/IP stacks that natively speak SOCKS. OpenVPN is L3 — it only knows how to push
packets into a kernel TUN device. Bridging L3 → SOCKS without touching system routing is the
entire technical content of this project. §5 is how.

### 1.2 Prior art, and what we are not

| Project | Platforms | License | Why it isn't this |
|---|---|---|---|
| OpenVPN GUI (official) | Windows | GPLv2 | Windows-only, no proxy mode |
| Tunnelblick | macOS | GPLv2 | macOS-only, TOTP via user shell scripts |
| Pritunl Client | Win/mac/Linux | proprietary non-commercial | Closest architecture; not free software |
| Viscosity | Win/mac | commercial | Paid, closed |
| OpenVPN Connect | all | proprietary | Closed, no proxy mode |

We are the free-software cross-platform client with proxy mode. We are **not** trying to be a
better full-tunnel client than Tunnelblick, and we are not a VPN provider.

---

## 2. Scope

### v1.0 — ships

- Import, validate, and store multiple `.ovpn` profiles.
- Connect / disconnect, live status, byte counters, log view.
- Username/password auth, including static challenge and CRV1 dynamic challenge.
- **Proxy mode** (the default): SOCKS5 + HTTP CONNECT on loopback, leak-free DNS, fail-closed.
- Opt-in TOTP autofill, seed in OS keyring.
- Linux and macOS. System tray where the platform cooperates.

### v1.1

- SOCKS5 `UDP ASSOCIATE`.
- Full-tunnel mode (the conventional behaviour, opt-in).
- Plain-HTTP absolute-URI proxying.

### Explicitly out of scope

- Windows (post-1.1; architecture must not preclude it).
- WireGuard.
- Mobile.
- Running our own VPN infrastructure.
- Mac App Store / Microsoft Store. Both forbid the privileged daemon this design requires;
  ruling them out costs nothing.

---

## 3. Architecture

```
┌────────────────────────┐
│  Tauri v2 GUI          │  unprivileged, user session
│  (Rust backend + web)  │  never touches packets, never root
└───────────┬────────────┘
            │ line-delimited JSON over AF_UNIX
            │ peer-authenticated (§7.3)
┌───────────┴────────────┐
│  thisconnectd          │  privileged: CAP_NET_ADMIN (Linux) / root (macOS)
│  ├ profile validator   │  §6 — the security boundary
│  ├ openvpn supervisor  │  §4 — management-interface client
│  ├ tunnel policy       │  §5.2 — routes/rules, privileged
│  └ IPC server          │
└───────────┬────────────┘
            │ AF_UNIX, daemon-created, mode 0600, reverse-connect
┌───────────┴────────────┐
│  openvpn 2.6+ (stock)  │  unprivileged where possible
└────────────────────────┘

┌────────────────────────┐
│  proxy worker          │  UNPRIVILEGED — see §5.3
│  SOCKS5 + HTTP + DNS   │  no capabilities, no root
└────────────────────────┘
```

### 3.1 Settled decisions

1. **Never vendor OpenVPN3 core.** C++ and AGPLv3. We drive the stock `openvpn` binary over its
   management interface. Keeps us GPLv3, Rust-only, FFI-free. The entire v2rayN/Clash/sing-box
   ecosystem converged on the same launcher pattern independently.
2. **All Rust.** Daemon, proxy, and Tauri backend. One toolchain.
3. **The proxy runs unprivileged.** This is a design constraint, not an accident — see §5.3. It is
   the single biggest security win in the architecture and it is why we chose source-address
   binding over `SO_MARK`.
4. **The GUI never sends a raw `.ovpn` to the daemon.** It sends a profile id. Profiles are
   validated and canonicalised on import. See §6.
5. **Fail closed, everywhere.** Every failure mode must break the connection, never silently
   fall back to the untunnelled path.

### 3.2 Repo layout

```
/daemon      privileged: supervisor, validator, tunnel policy, IPC server
/proxy       unprivileged: SOCKS5, HTTP CONNECT, tunnel-pinned resolver, egress dialer
/shared      IPC types, .ovpn parser + allowlist, TOTP, keyring
/ui          Tauri v2 app
/packaging   systemd unit, launchd plist, polkit, deb/rpm/AUR/pkg
/docs        this file, ARCHITECTURE.md, SECURITY.md, IPC.md
/testdata    sample profiles for parser tests — never real credentials
```

---

## 4. OpenVPN supervision

### 4.1 Spawn line

The daemon writes a **canonical sanitised config file** (mode 0600, in a 0700 daemon-owned
directory) and passes only `--config` plus daemon-owned flags. Rebuilding a long command line is
rejected: config-file form keeps the management socket path and credentials out of world-readable
`ps` output, and keeps inline `<ca>`/`<key>` material in one 0600 file instead of scattered.

Daemon-injected flags, **appended last** — `script_security_set()` is applied per occurrence in
parse order, last-wins **[V]** (`options.c:7152`):

```
--config <canonical.ovpn>
--management <sock> unix
--management-client
--management-hold
--management-query-passwords
--management-up-down
--script-security 1
--pull-filter ignore "route"
--pull-filter ignore "redirect-gateway"
--route-noexec
--dns-updown disable
--allow-compression no
--auth-retry interact
--auth-nocache
--verb 3
```

Each of these is load-bearing:

- **`--management-query-passwords` is mandatory.** Without it openvpn dies before auth with
  `neither stdin nor stderr are a tty device ... can't ask for 'Enter Auth Username'. Exiting due
  to fatal error` **[V]**.
- **`--script-security 1`, not 0.** Level 0 breaks the tunnel: `tun.c:1455` execve's `/sbin/ifconfig`
  for macOS tun bring-up with no `S_SCRIPT` flag **[V]**. Level 1 permits built-ins only.
- **`--dns-updown disable`.** The *built-in* dns-updown handler runs via `openvpn_execve_check()`
  **without** `S_SCRIPT` (`dns.c:588-597`) **[V]** — so it executes as root even at script-security 1.
  Disabling it is a security control, not a preference.
- **`--auth-retry interact`, never `nointeract`.** `nointeract` retries without re-querying
  credentials, replaying an already-consumed TOTP until the account locks **[V]**. `interact` is
  also required for CRV1 dynamic challenge to work at all.
- **`--management-client`** makes openvpn connect *out* to a socket the daemon already created at
  mode 0600. Verified working over AF_UNIX **[V]**. This avoids openvpn's own default, which
  creates the socket `srwxrwxrwx` (0777) and accepts commands with no authentication — verified
  with `nc -U`: `state`, `pid`, `version` all answered **[V]**. Under a root daemon that is a local
  privilege escalation. Closing the socket makes openvpn `SIGTERM` itself: a free deadman switch **[V]**.

### 4.2 `--route-nopull` is banned

**This is the correction that saved the product.**

`--route-nopull` suppresses pushed routes **and pushed DNS**: openvpn(8) 2.7.6 line 4623 —
"accept options pushed by server EXCEPT for routes, block-outside-dns and dhcp options like DNS
servers" **[V]**. With it, the daemon can never learn the tunnel's resolver, and §5.4 leak-free DNS
becomes impossible.

Use targeted `--pull-filter ignore` for `route` and `redirect-gateway` instead, plus
`--route-noexec`, so `dhcp-option DNS` and `--dns` still arrive.

`--pull-filter` is explicitly *not* a security boundary — openvpn(8) line 1242: "cannot be relied
upon as a security measure ... defeated by pushing options with extra spaces" **[V]**. It is
defence in depth. The real guarantees are `--route-noexec` (openvpn installs nothing) and the fact
that `OPT_P_SCRIPT` and `OPT_P_PLUGIN` are never in the pull permission mask (`init.c:2520-2533`)
**[V]**, so a malicious server cannot push script or plugin directives at all. `setenv`, `iproute`,
and `dev-node` are `OPT_P_GENERAL` **[V]** — so a server can push neither an `LD_PRELOAD`/
`DYLD_INSERT_LIBRARIES` env var nor a substitute command path.

### 4.3 Management protocol client

Wire format **[V]**: line-oriented, CRLF-terminated. Exactly three output shapes — `SUCCESS: <text>` /
`ERROR: <text>`; multiline output terminated by a bare `END`; and async notifications `>TYPE:payload`
in column 0. Greeting is `>INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info`.

Contract:

1. **Framing.** Split on `\n`, strip trailing `\r`. Lines starting with `>` are events, dispatched
   to a broadcast channel *immediately*. Everything else feeds the in-flight command's accumulator.
   Async notifications interleave freely between a command and its reply — verified: a `>LOG:` line
   arrived *before* the `SUCCESS:` for the command that produced it **[V]**.
2. **Strictly one outstanding command.** The protocol has no correlation id. One `oneshot` reply,
   10 s timeout. Pipelining makes `SUCCESS`/`ERROR`/`END` unattributable.
3. **Handshake.** Await `>INFO:`, then `version 6`, `state on`, `bytecount 5`, `log on all`,
   `hold release`. Announce version ≥ 4 always — `version <n>` for n ≤ 3 produces no reply and will
   deadlock a generic await-terminal-line helper **[V]**.
4. **Re-release hold on every `>HOLD:`.** `--management-hold` sets a *persistent* flag; every
   reconnect and every auth-failure retry re-enters hold **[V]**. Missing this is the single most
   likely "hangs forever on reconnect" bug.
5. **Connected detection is `>STATE:*,CONNECTED,*` only.** Never gate on `GET_CONFIG`, `ASSIGN_IP`,
   or `ADD_ROUTES`. `ADD_ROUTES` only fires when `rl->routes != NULL`, so under `--route-noexec` it
   may never fire **[V]**. Parse `>STATE:` defensively by index — 2.7.6 emits a trailing empty IPv6
   field **[V]**.
6. **Tunnel identity.** The tun device name is **not** in `>STATE:` **[V]**. It comes only from the
   `>UPDOWN:UP` … `>UPDOWN:ENV,END` block (`dev`, `dev_type`, `ifconfig_local`,
   `ifconfig_ipv6_local`), which is why `--management-up-down` is mandatory. `>UPDOWN` is
   undocumented in `management-notes.txt`, so it is not a stability contract — an integration test
   must assert `dev=` is present on every supported openvpn version, and a missing `dev=` is a hard
   error, not a warning: §5 egress binding has nothing to bind to without it.
7. **Credentials.** Implement all four prompt shapes: plain `Need 'Auth' username/password`;
   `SC:<flag>,<text>` static challenge (SCRV1 base64 for FORMAT=0, plain concat for FORMAT=1);
   CRV1 dynamic challenge parsed from `Verification Failed: '<type>' ['<reason>']`; and
   `>INFOMSG:CR_TEXT:` answered with `cr-response <base64>`. Parse CRV1 with `splitn(5, ':')` —
   `challenge_text` may contain `:` while `state_id` may not **[V]**.
8. **One escaping function, unit-tested.** The management channel uses the *config-file* lexer, not
   shell or JSON quoting. A password containing a quote, backslash, or leading/trailing space
   silently corrupts if unescaped — verified **[V]**.
9. **Line length limit.** The input buffer is 1024 bytes and overflow is discarded **silently** with
   no error **[V]**. Refuse to send any line > 900 bytes; use the multiline base64 password form
   above 256 bytes per parameter.
10. **Version floor.** Assert management version ≥ 5 (openvpn 2.6) at startup; refuse to run below.

### 4.4 Logging

`openvpn`'s own `>LOG:` redacts `password` as `[...]` but does **not** redact `username` **[V]**.
Raw `>LOG:` output is never persisted. Credentials never go in the username field.

---

## 5. Proxy mode — the core feature

### 5.1 The mechanism, in one sentence

Let openvpn bring up a tun with an address but install no routes; install a default route for that
tun **in a scope the system default lookup never consults**; then have the proxy pin each outbound
socket into that scope.

### 5.2 Tunnel policy (privileged, daemon, once per tunnel-up)

**Linux** — policy routing keyed on source address:

```sh
# 1. fail-closed floor FIRST, and it outlives individual connections
ip route add unreachable default table 218 metric 4000
# 2. rule
ip rule add from <tunip>/32 lookup 218 priority 18000
# 3. real route
ip route add default dev <tun> src <tunip> table 218 metric 100 mtu <tunmtu>
```

Mirrored for IPv6 when the tun has a v6 address; otherwise the proxy refuses `AF_INET6` outright (§5.5).

- **`unreachable`, not `blackhole`.** `fib_props[]` in `net/ipv4/fib_semantics.c`: `RTN_BLACKHOLE`
  → `-EINVAL`, `RTN_UNREACHABLE` → `-EHOSTUNREACH` **[V]**. `EINVAL` from `connect()` is
  indistinguishable from a caller bug and maps to no SOCKS5 reply code; `EHOSTUNREACH` maps
  cleanly to REP `0x04`.
- **No `rp_filter` sysctl.** Source-address binding provably survives strict reverse-path
  filtering: `__fib_validate_source()` sets `fl4.daddr = src; fl4.saddr = dst`, so the RPF reverse
  lookup carries the tun IP as source, re-fires the `from <tunip>` rule, and lands in table 218
  **[V]**. Setting `rp_filter=2` is a no-op at best; because the effective value is
  `max(all, iface)` it can only ever *enable* loose RPF on systems that had none.
- **Netlink watcher.** Watch `RTM_NEWRULE`, `RTM_DELRULE`, `RTM_DELROUTE`, `RTM_DELADDR` and
  re-assert. NetworkManager, systemd-networkd, and other VPN clients rewrite policy routing;
  Tailscale issue #2325 documents rules being discarded on connectivity changes.
- **Teardown order:** stop listener → kill live sessions → remove rule → remove table. The floor
  route is removed last, and only after the rule is confirmed gone.

**macOS** — interface-scoped routing:

```sh
route -n add -inet -ifscope <utunN> default <tunnel_peer_ip>   # topology subnet
route -n add -inet -ifscope <utunN> default -interface <utunN> # p2p / net30
```

Scoped routes do not affect the unscoped default lookup — verified: six such routes coexist on the
dev machine today while the unscoped lookup stays empty **[V]**. **[U]** The `route add -ifscope`
call itself could not be executed during research (no passwordless sudo). **This is the single
unverified link in the whole design and must be the first integration test written.** Expected
result: an outbound socket pinned to the utun flips from `ENETUNREACH` to a working connection.

The kernel's refusal to fall back to `en0` is a free, race-proof kill switch. `ENETUNREACH` on bind
is surfaced in the UI as "tunnel not ready", never as a generic network error.

Stale scoped routes pointing at a dead or recycled utun are a correctness *and* security hazard:
reconcile on daemon start, and watch `PF_ROUTE`.

### 5.3 Egress dialer (unprivileged, proxy worker)

**Linux** — source-address binding. No `CAP_NET_ADMIN`, no `CAP_NET_RAW`, no setuid:

```rust
let sock = TcpSocket::new_v4()?;
// SAFETY: setsockopt on an owned fd with a correctly-sized c_int.
#[cfg(target_os = "linux")]
unsafe {
    let on: libc::c_int = 1;
    // Tolerate ENOPROTOOPT on kernels < 4.2.
    libc::setsockopt(sock.as_raw_fd(), libc::IPPROTO_IP,
                     libc::IP_BIND_ADDRESS_NO_PORT,
                     &on as *const _ as *const libc::c_void, 4);
}
sock.bind(SocketAddr::new(tun_ip, 0))?;
sock.connect(dst).await
```

`IP_BIND_ADDRESS_NO_PORT` is **mandatory**, not an optimisation: a plain `bind((tun_ip, 0))` before
`connect()` forces source-port selection without knowing the destination, defeating 4-tuple
uniqueness and producing `EADDRINUSE`/`EADDRNOTAVAIL` under exactly this proxy workload. Neither
`socket2` 0.6.5 nor `tokio::net::TcpSocket` exposes it, so one `unsafe libc::setsockopt` is
unavoidable — wrapped once, in one tested helper.

Never set `IP_FREEBIND` (`socket2::set_freebind_v4`): it would let `bind()` succeed after the tun IP
vanishes, destroying fail-closed.

**macOS** — `IP_BOUND_IF` / `IPV6_BOUND_IF` via `socket2` `bind_device_by_index_v4/v6`
(features = `["all"]`), or raw `libc::setsockopt` on a tokio `TcpSocket` fd. Both verified
working **[V]**. No root, no entitlement.

`if_nametoindex()` is re-resolved on **every** tunnel up. utun names and indexes are not stable
across reconnects, and a stale ifindex silently binds to a recycled interface — a real leak vector.
All proxy sessions are force-closed on any management state transition away from `CONNECTED`;
sockets bound to a vanished tun IP otherwise hang for ~15 minutes (`tcp_retries2` = 15).

**Why source-binding, not `SO_MARK`.** `SO_MARK` requires `CAP_NET_ADMIN` (or `CAP_NET_RAW` on
≥ 5.17) in whatever process opens the socket — which would force the SOCKS5/HTTP proxy, the
component handling attacker-influenced traffic, into the root daemon. That trade is not worth it.

**The honest cost:** `ip rule from <tunip>` is *address*-based, so any local UID that binds the tun
IP gets free tunnel egress. `SO_MARK` would be an unforgeable capability token. Acceptable on a
single-user desktop; documented in `SECURITY.md` rather than papered over.

### 5.4 DNS — where this design lives or dies

Any name resolution that escapes the tunnel leaks every hostname the user visits to their ISP
resolver in cleartext, and defeats the entire feature.

**`ATYP=0x03` alone is not the answer.** It means the *client* defers resolution to the proxy — and
the proxy is on the same host. `TcpSocket::connect()` takes an already-resolved `SocketAddr`, so
resolution happens *outside* the pinned dialer via `getaddrinfo`/`resolv.conf`, over the
deliberately-untouched default route. The pinned socket is necessary and not sufficient.

Requirements:

- **D1.** The daemon captures the tunnel resolver by parsing `>LOG:` for
  `PUSH: Received control message: 'PUSH_REPLY,...'`, extracting every `dhcp-option DNS <ip>`,
  `dhcp-option DNS6 <ip6>`, `dhcp-option DOMAIN|ADOMAIN|DOMAIN-SEARCH`, and the 2.6+
  `dns server N address ...` form. This works only because §4.2 banned `--route-nopull`.
- **D2.** Resolution uses an in-daemon `hickory-resolver` with a custom `RuntimeProvider` (~60 lines)
  whose every UDP/TCP socket is created through the §5.3 pinned dialer. UDP with TCP retry on TC.
- **D3.** **No fallback to the system resolver, ever.** Not on error, not on timeout, not on empty
  capture. `getaddrinfo`, `ToSocketAddrs`, and `tokio::net::lookup_host` are **banned in the proxy
  crate** — enforced by a clippy `disallowed_methods` lint, not by convention.
- **D4.** If no DNS was captured, or a captured server is unreachable through the tunnel, use a
  user-configured `tunnel_fallback_dns` (default `9.9.9.9`, `1.1.1.1`) queried **through the tun**,
  and say plainly in the UI that queries are going to a third party rather than the VPN's resolver.
  Never the system resolver.
- **D5.** Resolver cache flushed on every tunnel up and down; TTLs honoured but capped at 300 s.
- **D6.** Destination denylist, applied after resolution and to IP literals: `127.0.0.0/8`, `::1`,
  `0.0.0.0/8`, `169.254.0.0/16`, `fe80::/10`, multicast, and `::ffff:0:0/96`-mapped forms.
  Pinning a socket to an interface does **not** stop it reaching the user's own machine or LAN —
  that is an SSRF surface. RFC1918 is *allowed* by default (corporate VPNs need it) but configurable.
- **D7.** Per-session counter of names resolved via the tunnel resolver. The GUI shows
  "0 local DNS lookups this session" as user-visible leak proof.
- **D8.** Document loudly that `socks5://` (curl `--socks5`) resolves locally and leaks; only
  `socks5h://` / `--socks5-hostname` is safe. **The GUI's copy button emits `socks5h://`.**

The `PUSH_REPLY` parse is a string dependency on a log line whose wording is not a stability
contract. Mitigation: treat "no DNS captured" as hard, visible, and fail-closed; pin a regex against
a unit-test corpus of real `PUSH_REPLY` lines; integration-test capture on every supported openvpn
version. Note `sanitize_control_message()` scrubs auth tokens, not dhcp-options **[V]**.

### 5.5 IPv6

A v4-only tunnel on a v6-capable host is a live leak vector. Determine `tunnel_has_v6` from
`PUSH_REPLY` (`ifconfig-ipv6`, or a pushed `route-ipv6`).

- If `!tunnel_has_v6`: query `A` only, never `AAAA`; discard AAAA answers; reject `ATYP=0x04` with
  REP `0x08`; reject HTTP `CONNECT` to a v6 literal with 403. **Never happy-eyeballs.**
- If `tunnel_has_v6`: RFC 8305 happy eyeballs, but *both* racing sockets pinned.
- Surface `tunnel_has_v6` in the UI. A v4-only tunnel reaching a v6-only destination is a
  legitimate hard failure, not something to silently work around.

### 5.6 Listener and protocol

- **L1.** One **mixed** listener at `127.0.0.1:1080` and `[::1]:1080`. Dispatch on first byte:
  `0x05` → SOCKS5, `0x04` → reject (SOCKS4 unsupported), ASCII uppercase → HTTP.
- **L2.** **Auth on by default, including on loopback.** Credentials randomly generated (16 bytes,
  URL-safe), stored in the OS keyring, shown in the GUI with one-click copy of the full
  `socks5h://user:pass@127.0.0.1:1080`. Loopback is a weak boundary on a multi-user machine: any
  local UID could otherwise use the tunnel under the user's identity.
- **L3.** Binding a non-loopback address **hard-refuses to start** without auth configured — a
  refusal, not a warning. Plus an `allowed_cidrs` list, default `[]`, checked on accept before the
  greeting. An open proxy relays traffic under the user's VPN identity and IP.
- **L4.** Persistent, non-dismissable UI banner whenever the listener is non-loopback, showing the
  bind address and the count of distinct remote peers seen.
- **L5.** Constant-time credential comparison (`subtle::ConstantTimeEq`). Auth failures rate-limited
  per source IP (token bucket, 5/min) and logged.
- **L6.** The listener opens only after `>STATE:...,CONNECTED` and closes, killing all sessions, on
  `EXITING`/`RECONNECTING` or management-socket EOF. The daemon does not publish the tun IP to the
  proxy until the floor route, the rule, and the tunnel route are all installed and verified.

**SOCKS5** (RFC 1928 / 1929): offer method `0x02` when auth is on, `0x00` only if the user
explicitly disabled it — never both; no acceptable method → `[0x05][0xFF]`, close. RFC 1929
sub-negotiation uses **VER=0x01**, not `0x05`. `CONNECT` supported; `BIND` → REP `0x07` permanently;
`UDP ASSOCIATE` → REP `0x07` in v1. `ATYP` `0x01` and `0x03` mandatory, `0x04` only when
`tunnel_has_v6` else REP `0x08`. Parse as a stream, never assume one `read()`. Validate
`DOMAINNAME`: length 1..=255, no NUL, no control bytes, IDNA-safe; if it parses as an IP literal,
treat it as one. `CONNECT` success replies `ATYP=0x01, BND.ADDR=0.0.0.0, BND.PORT=0` — do not
disclose the internal tun IP to a possibly-LAN client. Error mapping: NXDOMAIN → `0x04`,
`ECONNREFUSED` → `0x05`, `ENETUNREACH` → `0x03`, policy rejection → `0x02`, else `0x01`.

**HTTP**: `CONNECT host:port` → `200 Connection established`, then raw relay; **the target is never
resolved locally**. `407` + `Proxy-Authenticate: Basic realm="thisconnect", charset="UTF-8"`.
No `Via`, no `X-Forwarded-For`, no `Server` header — a deliberate, documented privacy deviation from
the RFC's SHOULD. Absolute-form plaintext proxying is v1.1 and must reject ambiguous framing
(both `Content-Length` and `Transfer-Encoding`, or conflicting `Content-Length`) with 400; being a
full HTTP intermediary carries RFC 9112 request-smuggling exposure.

**v1.1 `UDP ASSOCIATE`** needs **two** sockets: client-facing bound to `127.0.0.1:0` (its address is
what goes in the `BND.ADDR` reply) and upstream bound to `(tun_ip, 0)`. Association lifetime tied to
the TCP control connection. Accept datagrams only from the client's source IP. Drop `FRAG != 0`.
NAT table keyed on `(client_addr, target_addr)`, 60 s idle timeout, hard-capped count.

---

## 6. Profile validation — the security boundary

An imported `.ovpn` is untrusted input handed to a process with elevated privilege. It is the
highest-severity attack surface in the product.

**Allowlist, never denylist.** Denylists drift as OpenVPN adds directives — Tunnelblick documents
this as a known weakness of its own approach. We parse the profile into a typed struct, reject
anything unknown, and emit a canonical config ourselves.

`--script-security` is **not** sufficient on its own. `--plugin` `dlopen`s a library and its
constructor runs before any symbol check — reproduced on the dev machine: `openvpn --script-security 0
--plugin ./evil.dylib` wrote its payload file before failing on the missing
`openvpn_plugin_close_v1` symbol **[V]**. Code-loading directives must be rejected at parse time.

**HARD REJECT** — parse fails, profile refused, offending line named in the UI:

- *Code loading:* `plugin`, `pkcs11-providers`, `pkcs11-id`, `pkcs11-id-management`,
  `pkcs11-cert-private`, `pkcs11-private-mode`, `pkcs11-protected-authentication`,
  `pkcs11-pin-cache`, `cryptoapicert`, `engine`, `providers`
- *Script hooks:* `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `tls-verify`,
  `auth-user-pass-verify`, `client-connect`, `client-disconnect`, `learn-address`,
  `tls-export-cert`, `client-crresponse`, `tls-crypt-v2-verify`, `auth-gen-token-secret`,
  and `dns-updown` unless the value is exactly `disable`
- *File paths / root write primitives:* `log`, `log-append`, `status`, `status-version`, `writepid`,
  `tmp-dir`, `cd`, `chroot`, `client-config-dir`, `ccd-exclusive`, `iproute`, `setcon`, `askpass`,
  `capath`
- *Env and channel hijack:* `setenv`, `setenv-safe`, `management*`, `config` (no nested includes —
  we flatten), `http-proxy-user-pass`
- `dev tap` (tun/utun only in v1)

`--down-pre` is **not** a script hook — it only reorders `--down` **[V]**. Listed here historically
in other projects; we do not reject it.

**ALLOWLIST**, each with per-directive typed argument validation (name allowlisting alone is not
enough — `remote` and `dev` can still carry traversal or metacharacter payloads):

`client`, `pull`, `remote` (RFC1123 host or IP + port 1..65535 + udp/tcp), `proto`, `port`/`lport`/
`rport`, `dev tun|utun[0-9]*`, `dev-type tun`, `topology`, `resolv-retry`, `nobind`, `float`,
`remote-random`, `explicit-exit-notify`, `persist-key`, `persist-tun`, `remote-cert-tls server`,
`remote-cert-eku`, `remote-cert-ku`, `ns-cert-type`, `verify-x509-name`, `data-ciphers`,
`data-ciphers-fallback`, `auth`, `tls-client`, `tls-version-min`, `tls-cipher`, `tls-ciphersuites`,
`reneg-sec`, `keepalive`/`ping`/`ping-restart` (bounded), `mssfix`/`tun-mtu`/`tun-mtu-extra`/
`fragment` (bounded), `sndbuf`/`rcvbuf`, `route-method`, `verb` (clamped 0..4), `mute`,
`connect-retry`/`connect-retry-max`/`connect-timeout`, `auth-user-pass` (bare only),
`static-challenge`, `auth-nocache`, `key-direction` (scalar `0|1`), `peer-fingerprint`
(colon-hex on the line), `<connection>` blocks, and `http-proxy`/`socks-proxy`.

**`client` and `pull` must be allowlisted.** `--client` is equivalent to `pull` + `tls-client` **[V]**.
A fail-closed parser without them rejects essentially every real-world profile, and without `pull`
there is no pushed `--ifconfig`, so no tunnel comes up at all.

`key-direction` and `peer-fingerprint` are **scalar directives, not inline blocks** — classifying
them as inline-only rejects every `tls-auth` profile **[V]**.

`route`, `redirect-gateway`, and `dhcp-option` are **parsed and retained** for proxy-egress logic
but **never written to the canonical config**. Forwarding them buys nothing and `dhcp-option DNS`
is exactly what feeds the root `dns-updown` path.

**Inline material** — accepted **only** as `<...>` blocks, never as file paths: `ca`, `cert`, `key`,
`dh`, `tls-auth`, `tls-crypt`, `tls-crypt-v2`, `pkcs12`, `crl-verify`, `extra-certs`. Written into
the canonical 0600 config in a 0700 daemon-owned directory, at a path we choose.

**Any `<tag>` not in that set is rejected before directive classification.** OpenVPN 2.7 supports
inline forms beyond the crypto list — `<auth-user-pass>` (`options.c:7780`),
`<http-proxy-user-pass>` (`options.c:6730`), `<auth-token-secret-file>` (`options.c:7534`) **[V]** —
so "`auth-user-pass` bare, no file path" does *not* cover `<auth-user-pass>`. This is a real bypass
if the tag check is skipped.

Parser rules: reject unknown directives; reject any argument containing NUL, newline, shell
metacharacters, or `..`; cap file size and directive count; log every rejection.

---

## 7. Privileged daemon

### 7.1 Linux

Non-root user `thisconnectd` with exactly `AmbientCapabilities=CAP_NET_ADMIN` and a matching
`CapabilityBoundingSet`. Not `CAP_NET_RAW`, not `CAP_SETUID`, not `CAP_DAC_OVERRIDE`.

Socket-activated AF_UNIX at `/run/thisconnect/thisconnectd.sock`, `root:thisconnect`, mode `0660`.
Group membership is the authorisation model in v1; no polkit. polkit over a raw AF_UNIX socket
forces the deprecated racy `unix-process` subject — either stay with `SO_PEERCRED` + group, or do
the full D-Bus system-service move in v2. Do not half-implement it.

The daemon pre-creates a persistent owner-tagged tun and runs openvpn with `--ifconfig-noexec
--route-noexec`, doing all address/route/rule work itself over rtnetlink.

On startup, reconcile: enumerate `tc*` devices owned by our uid and tear down leftovers and their
table-218 routes/rules. `IFF_PERSIST` outlives the process by design, so a crash leaks the device
and the next run collides with it.

Known integration costs, budgeted rather than discovered later:
- **SELinux** (Fedora/RHEL): `TUNSETIFF` on `/dev/net/tun` from a non-`openvpn_t` domain will
  generate AVCs. Needs a small policy module before the `.rpm` ships.
- **AppArmor** (Ubuntu): the stock `/usr/sbin/openvpn` profile applies to our spawned child and may
  deny our management socket path under `/run/thisconnect`. Ship an override in the `.deb`.
- **`ProtectSystem=strict`** makes `/proc/sys` read-only. Harmless given §5.2 sets no sysctls.
- **Group-membership UX trap:** adding the user to `thisconnect` in postinst does not affect their
  running session. The GUI must detect `EACCES` *specifically* and say "log out and back in", not
  "daemon unreachable".
- **Non-systemd distros** get none of this hardening. Say so in the README rather than pretending
  portability.
- **Flatpak cannot ship the daemon.** State it plainly; a Flatpak GUI is possible only after a v2
  D-Bus migration.

### 7.2 macOS

Daemon at `/Library/PrivilegedHelperTools/net.thisconnect.daemon`, `root:wheel 0755`. Plain
launchd job at `/Library/LaunchDaemons/net.thisconnect.daemon.plist`. **No** NetworkExtension
entitlement, **no** `SMAppService`, **no** `SMJobBless` in v1.

Creating a utun via `PF_SYSTEM`/`SYSPROTO_CONTROL` needs **root and nothing else** — verified with a
zero-entitlement ad-hoc-signed binary: as uid 501 `connect()` returns `Operation not permitted`;
Homebrew's own `openvpn` 2.7.6 is ad-hoc signed with no entitlements and creates utuns as root **[V]**.
NetworkExtension is required for `NEPacketTunnelProvider`, which we do not use.

`SMAppService` is deliberately avoided: without a Developer ID you cannot iterate, and a stale
registration poisons the BTM database, recoverable only via `sfltool resetbtm` (nukes *all*
background items, requires reboot) or Safe Mode.

**Let launchd create the socket.** A `Sockets` dict plus `launch_activate_socket()` (public SDK,
macOS 10.10+, not deprecated) eliminates the `bind()` → `chmod()` TOCTOU window and stale-socket
cleanup, and allows on-demand launch instead of a resident root process:

```xml
<key>Sockets</key><dict><key>Listener</key><dict>
  <key>SockFamily</key><string>Unix</string>
  <key>SockType</key><string>Stream</string>
  <key>SockPathName</key><string>/var/run/thisconnect.sock</string>
  <key>SockPathMode</key><integer>438</integer><!-- 0666 decimal; plists are decimal -->
</dict></dict>
```

**The socket is 0666, not 0660.** Group `wheel` contains only `root` on stock macOS
(`dscl . -read /Groups/wheel GroupMembership` → `root`), and Darwin *does* enforce filesystem
permissions on `connect()` to an AF_UNIX socket — verified: 0600 → OK, 0400 → `EACCES`,
0000 → `EACCES` **[V]**. A `root:wheel 0660` socket is therefore unreachable by the GUI on every
stock Mac; the product would not work on first run. 0666 plus mandatory peer authentication is the
shipping pattern on this machine today: Docker's `vmnetd` and Tunnelblick's `tunnelblickd` are both
`srw-rw-rw-` (`SockPathMode 438`), OpenVPN Connect's is `0777` **[V]**.

Note `SockPathMode` is **decimal** — 0666 is written `438`. Writing `660` is a silent footgun.

### 7.3 IPC peer authentication

A root daemon with an unauthenticated local socket is a local privilege escalation. Authentication
is mandatory on **every connection**, before any command is processed.

**Linux:** `SO_PEERCRED` via tokio's `peer_cred()` — check uid and gid.

**macOS:** `LOCAL_PEERTOKEN` → `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` →
`SecCodeCheckValidity` against a compiled-in designated requirement, plus a check that the peer is
the current console user. Verified end to end on the dev machine: `getsockopt(SOL_LOCAL,
LOCAL_PEERTOKEN)` returns a 32-byte audit token, `SecCodeCopyPath` resolves the peer's real
executable, and `SecCodeCheckValidity` returns `errSecSuccess` for the correct identifier and
`-67050 errSecCSReqFailed` for a wrong one **[V]**.

Build the requirement with `FromStr` — **`SecRequirement::create_with_string` does not exist** in
`security-framework` 3.7.0 **[V]**:

```rust
let req: SecRequirement = "anchor apple generic \
    and identifier \"net.thisconnect.gui\" \
    and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
    and certificate leaf[subject.OU] = \"TEAMID\"".parse()?;
```

The `field.1.2.840.113635.100.6.1.13` clause is the Developer ID Application marker OID; without it
a Mac App Store or development certificate from the same team satisfies the requirement.

Fail **closed** on every non-zero status. `SecCodeCopyGuestWithAttributes` can intermittently return
`errSecCSUnsigned` or `kPOSIXErrorEPERM` (peer already exited, translocated app); log-and-continue
is not an option.

`SCDynamicStoreCopyConsoleUser` returns `loginwindow` at the login screen and NULL on a headless or
SSH-only session. Handle "no console user" as an explicit distinct case — deny in release — rather
than comparing against a garbage uid.

**Dev mode.** Release builds require the full designated requirement; ad-hoc signatures have no
stable identity, so dev builds cannot. Behind `--features dev-insecure-ipc`, verify uid == installing
user **and tighten the socket to 0600 owned by that user** (`SockPathOwner` + `SockPathMode 384`).
Loosened auth plus a 0666 socket would hand root VPN control to any process the desktop user runs,
including a compromised browser renderer or an npm postinstall script. Print a loud warning at
startup. Shipping the dev path in a release build is a straight local-privilege-escalation bug —
CI must assert the feature is off in release artifacts.

### 7.4 IPC protocol

Line-delimited JSON (`serde_json` + `tokio_util::codec::LinesCodec`). No JSON-RPC framing, no
`jsonrpsee`, no `tarpc` — a single-socket local control channel does not warrant them. Full
reference in `docs/IPC.md`.

The GUI sends a **profile id**, never a raw config.

---

## 8. TOTP autofill

Opt-in, off by default.

**The tradeoff, stated plainly in the UI and README:** storing the TOTP seed next to the password in
the same application collapses two factors into one. Anything that compromises the machine gets
both. Every existing OpenVPN client deliberately pushes TOTP to an external tool (`oathtool`,
`client-crresponse`, before-connect scripts) for exactly this reason. We offer it because a local
convenience tradeoff is the user's to make — but the default is to prompt, and the UI says why.

- Seed in the OS keyring via `keyring` 4.2 (`v1` facade). On Linux this needs a running Secret
  Service provider; on headless or minimal setups there is none, so ship an explicit fallback and a
  clear error rather than a runtime panic.
- Generation via `totp-rs` 6.0 (`otpauth`, `zeroize`). Try `build()`, fall back to
  `build_noncompliant()` **with a visible UI warning** — `build()` rejects sub-128-bit seeds, and
  real VPN deployments commonly issue 80-bit (16-char base32) seeds. Silently rejecting them would
  break working accounts; silently accepting them would hide a weak secret.
- Feeds the §4.3 static-challenge and CRV1 flows. Requires `--auth-retry interact` and
  `--auth-nocache`.
- Seeds and generated codes are `zeroize`d after use and **never** logged, never in the username
  field, never persisted from `>LOG:` output.

---

## 9. Dependencies

All verified GPLv3-compatible, versions checked against crates.io during research.

| Purpose | Crate | Version | Note |
|---|---|---|---|
| Runtime, process, unix sockets | `tokio` | 1.53 | `process`, `net` |
| Codecs | `tokio-util` | 0.7 | `LinesCodec` |
| Socket pinning | `socket2` | 0.6 | `features=["all"]` |
| libc | `libc` | 0.2 | **not** the 1.0 alpha |
| Peer creds | `nix` | 0.31 | `getpeereid` / `SO_PEERCRED` |
| DNS | `hickory-resolver` | 0.26 | custom `RuntimeProvider`, §5.4 |
| SOCKS5 | `fast-socks5` | 1.0 | **low-level `Socks5ServerProtocol` only** |
| TOTP | `totp-rs` | 6.0 | `otpauth`, `zeroize` |
| Keyring | `keyring` | 4.2 | `v1` facade |
| Zeroization | `zeroize` | 1.9 | skip `secrecy` — dormant 2 years |
| Serialization | `serde` / `serde_json` | 1.0 | |
| Constant-time compare | `subtle` | 2.6 | §5.6 L5 |
| GUI | `tauri` | 2.11 | `tray-icon` feature |

**Banned in the `proxy` crate**, enforced by clippy `disallowed_methods`:
`fast_socks5::run_tcp_proxy`, `fast_socks5::DnsResolveHelper::resolve_dns`,
`std::net::ToSocketAddrs`, `tokio::net::lookup_host`, `socket2::Socket::set_freebind_v4`.
Each one silently reintroduces a system-resolver DNS leak or breaks fail-closed.

**Hand-rolled, deliberately:** the `.ovpn` parser (`ovpnfile` is dead since 2017, and §6 needs
allowlist semantics no generic parser provides) and the HTTP `CONNECT` handler (~100 lines).

**Vendored:** `openvpn-mgmt-codec` 0.8 (MIT OR Apache-2.0) — ~197 downloads, one maintainer, and
load-bearing for both supervision and TOTP. Vendor it into the repo and pin exactly rather than
depending on crates.io. Its `Hold` variant does not split out the hold-seconds field; parse that
ourselves.

**Not a sidecar.** `tauri-plugin-shell`'s sidecar mechanism is the wrong tool for the daemon —
sidecars inherit the GUI's unprivileged identity. The daemon is installed and started by
launchd/systemd; the GUI only connects to its socket.

**Linux tray is the weakest cross-platform link:** deprecated `libayatana-appindicator3` with open
bugs on KDE Plasma 6/Wayland and Flatpak. The app must be fully usable with no tray at all — never
make the tray the only path to connect, disconnect, or the challenge prompt.

---

## 10. Test requirements

Three integration tests define the product's security property. Without them the feature is a
claim, not a guarantee.

1. **`ifscope` route works (macOS).** **[U]** The one unverified link in the design. On a
   sudo-capable Mac, install the scoped default route and assert a pinned socket flips from
   `ENETUNREACH` to a working connection. **Write this first.** If it fails, §5.2's macOS half needs
   redesign before anything else is built.
2. **Egress is real.** With the tunnel up and full policy installed, an IP-echo request through the
   proxy returns the exit node's IP, not the ISP's.
3. **Fail-closed floor.** With the tun IP **still present**, delete the tunnel route from table 218
   and assert `connect()` returns `EHOSTUNREACH` from the floor route. This is the only test that
   exercises the floor. Separately, delete the `ip rule` and assert failure rather than fall-through
   to `main`.

A tun-flap test is worth keeping but must be labelled honestly: it tests `bind()` returning
`EADDRNOTAVAIL`, **not** the routing policy. It passes with no rule and no floor installed, which is
exactly why it cannot stand in for test 3.

Also required:
- `PUSH_REPLY` DNS-capture parser against a corpus of real lines from several server types.
- Management-interface escaping matrix (quotes, backslashes, leading/trailing spaces).
- `>UPDOWN:ENV` contains `dev=` on every supported openvpn version.
- Profile-validator corpus: every hard-reject directive, every inline-tag bypass, real-world
  profiles from common providers that must *pass*.
- CI asserts `dev-insecure-ipc` is off in release artifacts.

---

## 11. Distribution

| | Cost | Friction without it |
|---|---|---|
| Linux `.deb`/`.rpm`/AUR | none | none |
| macOS, built from source | none | none — no quarantine, self-signed daemon fine |
| macOS, unsigned download | none | Gatekeeper; macOS 15+ requires System Settings → Privacy & Security → Open Anyway |
| macOS, signed + notarized | $99/yr | none |

Ship source-first and unsigned from day one. Add signing when there are users who are not compiling
it themselves; Sponsors or a fiscal host can cover it by then.

Two certificates are needed, not one: **Developer ID Application** to codesign the daemon and the
`.app`, and **Developer ID Installer** to `productsign` the `.pkg` before `notarytool submit`.
The install script must strip `com.apple.quarantine` from the daemon binary — it survives
zip/dmg download. On macOS 13+ the launchd job appears under System Settings → General → Login Items
& Extensions with a "Background Items Added" notification, and the user can disable it there; the
GUI must detect an unreachable daemon and say so actionably rather than hanging on `connect()`.

**A VPN client running a root daemon is the worst software to train users to click past Gatekeeper
for.** Publish reproducible builds and checksums early so "verify it yourself" is a real option.

---

## 12. Project governance

- Repo lives under an organisation, not a personal account. More than one release-key holder.
- Nekoray, a popular client in the adjacent space, was archived when its maintainer stepped away.
  Bus factor is a design concern, not an afterthought.
- Signing keys held by a fiscal host (SFC, Open Collective) rather than one person, once funded —
  a solo key holder can never step away.

---

## 13. Open questions

1. **[U] macOS `route add -ifscope` behaviour.** Test 1 in §10. Everything on macOS depends on it.
2. Linux distro matrix for §5.2 — every routing, teardown, and RPF claim needs verification on at
   least Debian stable and Fedora. No Linux machine was available during research.
3. Whether to ship full-tunnel mode in v1.0 after all. It is what most users expect, and the daemon
   already has the privilege to do it.
4. MTU handling. The observed utun MTU is 1240; tunnels commonly run 1300–1420. TCP relaying lets
   the kernel handle MSS on the utun path, but IPv6 PMTUD blackholes and oversized v1.1 UDP
   datagrams need a decision.
5. Whether `allowed_cidrs` should default to the local subnet rather than empty when a user
   explicitly opts into LAN binding.
