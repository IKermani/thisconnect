# thisconnect

**Per-application VPN on a stock OpenVPN server.**

thisconnect connects an OpenVPN profile and hands you a local proxy:

```
socks5h://127.0.0.1:1080
```

Applications pointed at that proxy egress through the VPN. Everything else on the machine is
untouched — no default-route change, no `resolv.conf` rewrite, no other application affected. Your
browser can be on the VPN while your terminal, your backups, and your video calls are not.

No server-side cooperation is required. It works against any OpenVPN server you already have.

GPL-3.0-or-later.

---

## Status: alpha

Honest summary, because this is a VPN client and overclaiming is the wrong failure mode:

| | |
|---|---|
| **macOS** | Implemented and **verified end to end against a real commercial OpenVPN server.** |
| **Linux** | Implemented and **never executed.** Not one command of its routing path has run. |
| **Windows** | Not started. The architecture does not preclude it. |
| **GUI** | Does not exist. There is a daemon and an IPC socket; see [Using it](#using-it). |
| **Packaging** | Install scripts for macOS. No signed release, no `.deb`, no `.rpm`, no Homebrew. |

There is no release yet. Build from source.

---

## Why this doesn't already exist

The proxy-based VPN clients — v2rayN, Clash, sing-box, Hiddify — get this almost for free: their
cores are userspace TCP/IP stacks that natively speak SOCKS. OpenVPN is L3. It only knows how to
push packets into a kernel TUN device.

Bridging L3 to SOCKS *without touching system routing* is the entire technical content of this
project. Every other OpenVPN client — Tunnelblick, Viscosity, Pritunl, OpenVPN Connect, the official
GUI — captures the whole machine or nothing.

| Project | Platforms | License | Why it isn't this |
|---|---|---|---|
| OpenVPN GUI (official) | Windows | GPLv2 | Windows-only, no proxy mode |
| Tunnelblick | macOS | GPLv2 | macOS-only, TOTP via user shell scripts |
| Pritunl Client | Win/mac/Linux | proprietary, non-commercial | Closest architecture; not free software |
| Viscosity | Win/mac | commercial | Paid, closed |
| OpenVPN Connect | all | proprietary | Closed, no proxy mode |

---

## How it works

```
  your app  ──socks5h──▶  proxy (unprivileged)  ──pinned socket──▶  utun  ──▶  VPN
                              │
  GUI/CLI  ──unix socket──▶  thisconnectd (privileged)  ──manages──▶  openvpn
```

- **The stock `openvpn` binary does the protocol.** We drive it over its management interface. No
  vendored OpenVPN3 core, no C++, no FFI.
- **openvpn brings up a tun but installs no routes.** The daemon then adds a default route *in a
  scope the system's own route lookup never consults* — an interface-scoped route on macOS, a
  policy-routing table on Linux.
- **The proxy pins every outbound socket into that scope** (`IP_BOUND_IF` on macOS,
  source-address binding on Linux) and refuses to create one it cannot pin.
- **The proxy runs unprivileged.** It needs no capabilities and no root. That is why sockets are
  pinned by source address rather than `SO_MARK`: `SO_MARK` would have forced the component
  handling attacker-influenced traffic into the root daemon.

Full design, including the parts that were empirically verified and the parts that were not:
[`docs/SPEC.md`](docs/SPEC.md).

---

## Security properties

These are the claims. Each is asserted by `scripts/verify-live-tunnel.sh` against a live server,
not merely unit-tested:

- **The system routing table is never modified.** Verified byte-for-byte before, during, and after.
- **Proxied traffic leaves via the tunnel.** Verified by comparing public IPs.
- **Names resolve only through the tunnel.** A custom resolver builds every socket through the
  pinned dialer, so it is *structurally* unable to query anything else. `getaddrinfo`,
  `ToSocketAddrs`, `lookup_host`, and every socket constructor that accepts a string host are
  banned in the proxy crate and CI enforces it.
- **Fail-closed.** Kill the tunnel and proxied requests fail. They never fall back to your ISP.
- **No residue.** No route survives teardown.

Two more that the live harness cannot cover, and which have their own tests:

- **Imported profiles are validated against an allowlist, not a denylist.** An unknown directive is
  a hard rejection. `--plugin` runs attacker code through a `dlopen` constructor regardless of
  `--script-security`, so code-loading directives are refused at parse time rather than defended
  against later.
- **The IPC socket authenticates every peer.** A root daemon with an unauthenticated local socket
  is a local privilege escalation.

### What is *not* protected

- **Storing a TOTP seed next to the password collapses two factors into one.** The feature exists
  because that tradeoff is the user's to make, but it is **off by default** and the UI says why.
- **`ip rule from <tunip>` on Linux is address-based**, so any local uid that binds the tunnel
  address gets tunnel egress. Acceptable on a single-user desktop; stated rather than hidden.
- **A proxy bound to a non-loopback address is an open relay** under your VPN identity. It refuses
  to start without credentials, and `allowed_cidrs` defaults to loopback-only.

---

## Building

Requires Rust 1.85+ and `openvpn` 2.6+ on `PATH`.

```sh
cargo build --workspace
cargo test  --workspace
```

## Using it

**There is no GUI and no CLI client yet.** The daemon speaks line-delimited JSON over a unix
socket ([`docs/IPC.md`](docs/IPC.md)). Today the practical ways to drive it are the verification
harness, or your own IPC client.

To run a daemon locally without installing it system-wide:

```sh
cargo build -p thisconnect-daemon --features dev-insecure-ipc

sudo env \
  THISCONNECT_SOCKET=/tmp/tc/daemon.sock \
  THISCONNECT_RUNTIME_DIR=/tmp/tc/run \
  THISCONNECT_STATE_DIR=/tmp/tc/state \
  THISCONNECT_ALLOWED_UIDS=$(id -u) \
  ./target/debug/thisconnectd
```

> `dev-insecure-ipc` reduces peer authentication to a uid check. It is for development only, CI
> asserts it is absent from release builds, and the daemon prints a warning on every start.

For a real macOS install (launchd daemon, socket in `/var/run`):

```sh
sudo ./scripts/install-daemon-macos.sh --confirm
sudo ./scripts/uninstall-daemon-macos.sh --confirm
```

## Verifying it yourself

Do not take the claims above on trust. Every script refuses to touch anything without `--confirm`,
cleans up on failure, and has a `--self-test` mode that runs as any user.

```sh
# macOS: prove interface-scoped routing works and fails closed. No VPN needed.
sudo ./scripts/verify-ifscope-macos.sh --confirm

# macOS: the full end-to-end run. Needs a real profile; prompts for credentials.
sudo ./scripts/verify-live-tunnel.sh --profile ~/path/to/profile.ovpn --confirm

# Linux: the routing and fail-closed assertions. NEVER YET RUN — expect breakage.
sudo ./scripts/verify-egress-linux.sh --confirm
```

Credentials are read with `read -rs`: never in `argv`, never written to disk, never logged.

---

## Contributing

Read [`CLAUDE.md`](CLAUDE.md) first. It lists the settled decisions and, more usefully, the traps
that already cost a design round — several are non-obvious and were found only by testing against a
real openvpn:

- `--route-nopull` suppresses pushed *DNS* as well as routes, which makes leak-free resolution
  impossible.
- `log on all` answers `SUCCESS` *then* dumps history *then* `END`, desyncing every later reply.
- On macOS the IPC socket must be `0666`, not `0660` — group `wheel` contains only root.

The most valuable contribution right now is **running the Linux harness on real hardware** and
reporting what breaks. The Linux routing path is transcribed from kernel source and covered only by
argument-vector tests. When macOS was in that state it had a guaranteed panic, a deadlock, and a
dropped event — all invisible to a passing test suite.

CI runs `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, the test suite on Linux and
macOS, and `shellcheck` on the scripts.

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE).

Not affiliated with OpenVPN Inc. "OpenVPN" is their trademark.
