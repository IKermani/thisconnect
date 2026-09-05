<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Packaging

Init-system integration for `thisconnectd`. Everything here exists to make the
daemon's two hard requirements true on a real machine: it holds privilege, and
the socket it listens on is reachable by the GUI and by nobody else who matters.

```
linux/thisconnectd.socket     socket activation, /run/thisconnect/thisconnectd.sock
linux/thisconnectd.service    the daemon unit: CAP_NET_ADMIN and hardening
linux/thisconnectd.sysusers   -> /usr/lib/sysusers.d/thisconnectd.conf
linux/thisconnectd.tmpfiles   -> /usr/lib/tmpfiles.d/thisconnectd.conf
macos/net.thisconnect.daemon.plist  -> /Library/LaunchDaemons/
```

## Linux

Install paths:

| File | Destination |
|---|---|
| `thisconnectd` binary | `/usr/libexec/thisconnect/thisconnectd`, `root:root 0755` |
| `thisconnectd.service` | `/usr/lib/systemd/system/` |
| `thisconnectd.socket` | `/usr/lib/systemd/system/` |
| `thisconnectd.sysusers` | `/usr/lib/sysusers.d/thisconnectd.conf` |
| `thisconnectd.tmpfiles` | `/usr/lib/tmpfiles.d/thisconnectd.conf` |

```sh
systemd-sysusers
systemd-tmpfiles --create
systemctl enable --now thisconnectd.socket
usermod -aG thisconnect "$SUDO_USER"
```

The daemon runs as the non-root user `thisconnectd` with exactly
`CAP_NET_ADMIN`, ambient and bounding. The socket is created by systemd as
`root:thisconnect 0660`; the daemon adopts it as fd 3 and never binds it itself.
Group membership is the authorisation model in v1 — no polkit, because polkit
over a raw `AF_UNIX` socket forces the deprecated racy `unix-process` subject.

**Group-membership UX trap.** Adding the user to `thisconnect` in `postinst` does
not affect their already-running desktop session. The GUI must detect `EACCES`
*specifically* and tell the user to log out and back in, not "daemon
unreachable".

Two hardening directives are deliberately absent, and turning either on without
the stated prerequisite will break the product:

- `ProtectKernelModules=yes` blocks autoloading the `tun` module on hosts where
  it is not already loaded. Ship a `modules-load.d` snippet first.
- `MemoryDenyWriteExecute=yes` breaks the spawned `openvpn`, which `dlopen()`s
  OpenSSL providers. Unit settings apply to child processes too.

`ProtectSystem=strict` is on. Its only real effect here is a read-only
`/proc/sys`, which is harmless: the tunnel policy sets no sysctls by design.

Still owed before the packages ship:

- **SELinux** (Fedora/RHEL): `TUNSETIFF` on `/dev/net/tun` from a non-`openvpn_t`
  domain generates AVCs. Needs a small policy module in the `.rpm`.
- **AppArmor** (Ubuntu): the stock `/usr/sbin/openvpn` profile applies to our
  spawned child and may deny the management socket under `/run/thisconnect`.
  Ship an override in the `.deb`.
- **Non-systemd distros** get none of this hardening. Say so plainly.
- **Flatpak cannot ship the daemon.** A Flatpak GUI is possible only after a v2
  D-Bus migration.

## macOS

| File | Destination |
|---|---|
| daemon binary | `/Library/PrivilegedHelperTools/net.thisconnect.daemon`, `root:wheel 0755` |
| `net.thisconnect.daemon.plist` | `/Library/LaunchDaemons/`, `root:wheel 0644` |

A plain launchd job. No NetworkExtension entitlement, no `SMAppService`, no
`SMJobBless`: creating a utun via `PF_SYSTEM`/`SYSPROTO_CONTROL` needs root and
nothing else. The installer must replace `__INSTALLING_UID__` in the plist with
the uid of the user who installed the app, and strip
`com.apple.quarantine` from the daemon binary — it survives zip/dmg download.

### Why the socket is 0666 and not 0660

`SockPathMode` is **decimal**: `438` is `0666`. Writing `660` there means `01224`
and is a silent footgun.

The mode is 0666 on purpose:

- Group `wheel` contains only `root` on a stock Mac
  (`dscl . -read /Groups/wheel GroupMembership` → `root`), so there is no group
  the GUI could be a member of.
- Darwin **does** enforce filesystem permissions on `connect()` to an `AF_UNIX`
  socket — verified: 0600 connects, 0400 and 0000 return `EACCES`.

A `root:wheel 0660` socket is therefore unreachable by the GUI on every stock
Mac: the product would not work on first run. Security comes from mandatory peer
authentication on every connection, not from the mode bits. This is the shipping
pattern on macOS today — Docker's `vmnetd` and Tunnelblick's `tunnelblickd` are
both `srw-rw-rw-` (`SockPathMode 438`); OpenVPN Connect's is `0777`.

The Linux socket is 0660 for the opposite reason: there, a real group exists and
`connect()` honours it, so the mode bits are a working first control.

### Peer authentication status on macOS

The daemon retrieves the peer's 32-byte audit token with
`getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` and checks the uid from it. The
`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` half of SPEC.md 7.3 is
**not implemented** — it needs the `security-framework` crate, which is not yet a
dependency. The seam is `peerauth::macos::CodeVerifier`, and the shipped
implementation **denies every peer** rather than waving them through. macOS is
therefore dev-only until that lands.

## Development

`--features dev-insecure-ipc` relaxes peer authentication to a uid-only check and
tightens the socket to `0600` owned by that uid. Both halves are required:
loosened authentication behind a 0666 socket would hand root VPN control to any
process the desktop user runs, including a compromised browser renderer or an
`npm postinstall` script. The build prints a loud warning at startup, and
`cargo build --release --features dev-insecure-ipc` fails to compile.
