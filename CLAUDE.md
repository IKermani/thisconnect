# thisconnect

Open-source (GPLv3) cross-platform desktop OpenVPN client with a leak-free local SOCKS5/HTTP
proxy mode and opt-in TOTP autofill.

> Product requirements live in `docs/SPEC.md`. Read it before implementing anything.

## Non-negotiables

These are settled decisions. Do not relitigate them in code review or propose alternatives
without a written reason in an issue.

1. **Never vendor or link OpenVPN3 core.** It is C++ and AGPLv3. We spawn the stock `openvpn`
   2.x binary and drive it over its `--management` interface. This keeps us GPLv3, Rust-only,
   and FFI-free.
2. **All Rust.** The daemon and the Tauri backend are both Rust. No Go, no C++, no FFI.
   One toolchain for contributors.
3. **The GUI never runs as root and never touches packets.** Unprivileged Tauri GUI talks to a
   privileged daemon over a local unix socket. All privileged work happens in the daemon.
4. **The proxy runs unprivileged.** No `CAP_NET_ADMIN`, no root. This is why we bind outbound
   sockets to the tun source address instead of using `SO_MARK` — `SO_MARK` would force the
   component handling attacker-influenced traffic into the root daemon.
5. **The system networking stack is not modified by default.** No default-route change, no
   `resolv.conf` rewrite. Proxy mode is the default posture; full-tunnel mode is opt-in.
6. **License is GPLv3.** Every new source file gets the SPDX header (below). Do not add
   dependencies that are not GPLv3-compatible.

## Traps that already cost us a design round

Each of these was found by empirically testing against `openvpn` 2.7.6. Do not "simplify" them back.

- **Never use `--route-nopull`.** It suppresses pushed *DNS* as well as routes, which makes
  leak-free proxy DNS impossible. Use `--pull-filter ignore "route"`, `--pull-filter ignore
  "redirect-gateway"`, and `--route-noexec` instead.
- **`--management-query-passwords` is mandatory.** Without it openvpn exits fatally before auth
  with `can't ask for 'Enter Auth Username'`.
- **`--script-security 1`, never 0.** Level 0 breaks macOS tun bring-up — `tun.c` execve's
  `/sbin/ifconfig` with no `S_SCRIPT` flag.
- **`--dns-updown disable` is a security control.** The built-in dns-updown handler runs as root
  even at script-security 1.
- **`--auth-retry interact`, never `nointeract`.** `nointeract` replays a consumed TOTP forever.
- **`client` and `pull` must be in the profile allowlist**, or every real-world profile is rejected.
- **On macOS the IPC socket is 0666, not 0660.** Group `wheel` contains only root, and Darwin
  enforces permissions on AF_UNIX `connect()`. 0660 means the GUI can never connect. Security comes
  from mandatory peer authentication, not the mode bits. `SockPathMode` in a plist is **decimal**.
- **Use `unreachable`, not `blackhole`, for the Linux floor route.** `blackhole` yields `EINVAL`,
  which maps to no SOCKS5 reply code and reads as a caller bug.
- **`ATYP=0x03` does not by itself prevent DNS leaks.** The proxy is on the same host; resolution
  still escapes via `getaddrinfo` unless it goes through the tunnel-pinned resolver.

## Repo layout

```
/daemon      Rust. Privileged. openvpn supervision, management-interface client,
             tun/route/rule policy, IPC server, profile validator.
/proxy       Rust. UNPRIVILEGED. SOCKS5 + HTTP CONNECT, tunnel-pinned resolver,
             egress dialer. Must never require a capability.
/shared      Rust. IPC protocol types (serde), .ovpn parsing + validation, TOTP, keyring.
/ui          Tauri v2 app. Rust backend (IPC client only) + web frontend.
/packaging   systemd units, launchd plists, polkit policy, deb/rpm/AUR/pkg recipes.
/docs        SPEC.md, ARCHITECTURE.md, SECURITY.md, IPC protocol reference.
/testdata    Sample .ovpn profiles for parser tests. Never real credentials.
```

## Environment gotchas

- **Stale `GOROOT`**: this machine exports `GOROOT=/usr/local/go`, which does not exist. Go is
  at `/opt/homebrew/bin/go`. Irrelevant to this project (we are Rust-only) but it breaks any
  `go` invocation — use `env -u GOROOT go ...` if you ever need it.
- Dev machine is macOS arm64. Linux behaviour must be verified in a VM or container, never
  assumed. Mark untested-on-Linux code paths explicitly.
- `openvpn` 2.7.6 is installed locally via Homebrew. Do not hardcode `/usr/sbin/openvpn`;
  resolve the binary at runtime and let the user override the path.

## Build and test

```bash
cargo build --workspace            # all Rust crates
cargo test  --workspace            # unit + integration tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cd ui && npm install && npm run tauri dev
```

Every PR must pass `clippy -D warnings` and `fmt --check`. CI enforces both.

## Coding conventions

- **SPDX header on every source file:**
  ```rust
  // SPDX-License-Identifier: GPL-3.0-or-later
  ```
- No `unwrap()` / `expect()` / `panic!()` in `daemon/` outside of tests and startup
  invariant checks. The daemon runs privileged; a panic is a denial of service. Return
  `Result` and handle it.
- Errors: `thiserror` for library crates, `anyhow` only at binary top level.
- No `unsafe` without a `// SAFETY:` comment explaining the invariant. Raw `setsockopt` calls
  are the expected exception — wrap them in a safe, tested helper in one place, not inline.
- Immutable by default. Build new values rather than mutating in place.
- Files stay under ~400 lines. Split by responsibility, not by type.
- Functions stay under ~50 lines.
- Comments explain *why*, never *what*. No task or PR references in comments.
- Never log secrets. Not credentials, not TOTP seeds, not generated codes, not the contents of
  `<key>` blocks. Auth-flow logging is opt-in, redacted, and off by default.
- Secrets in memory use `secrecy` / `zeroize`. Never let a seed or password reach a plain
  `String` that outlives its use.

## Security rules for contributors

Read `docs/SECURITY.md` in full before touching the daemon. Summary of the tripwires:

- **`.ovpn` validation is allowlist-based, never denylist.** An imported profile is untrusted
  input that we hand to a privileged process. Unknown directives are rejected, not passed through.
  The GUI sends a profile id, never a raw config.
- **`--script-security` does not save you from `--plugin`.** `dlopen` runs a constructor before any
  symbol check — reproduced on the dev machine at `--script-security 0`. Code-loading directives
  must be rejected at parse time.
- **Reject unknown `<tag>` inline blocks before directive classification.** `<auth-user-pass>`,
  `<http-proxy-user-pass>`, and `<auth-token-secret-file>` are real inline forms and a real bypass.
- **Authenticate the IPC peer on every connection.** Linux `SO_PEERCRED`; macOS `LOCAL_PEERTOKEN`
  → `SecCodeCheckValidity` against a compiled-in designated requirement. Fail closed on any
  non-zero status. A root daemon with an unauthenticated local socket is a privilege escalation.
- **The proxy binds `127.0.0.1` by default.** Binding to any other address requires credentials
  to be configured first; the daemon refuses to start the listener otherwise. An open proxy
  relays traffic under the user's VPN identity.
- **DNS must resolve through the tunnel.** Any name resolution that escapes the tunnel is a
  leak and a release blocker, not a bug.

## Git conventions

- Conventional commits: `feat|fix|refactor|docs|test|chore|perf|ci: <description>`.
- Branch off `main`; never commit directly to `main`.
- Stage files by name. Never `git add -A`.
- Never commit a real `.ovpn`, key, or certificate. `.gitignore` blocks them; do not override it.
