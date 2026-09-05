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
nothing else. The installer replaces `__INSTALLING_UID__` in the plist with the
uid of the user who installed the app, and strips `com.apple.quarantine` from
the daemon binary — it survives zip/dmg download.

### Installing

```sh
cargo build --release -p thisconnect-daemon
./scripts/install-daemon-macos.sh                  # prints the plan, changes nothing
sudo ./scripts/install-daemon-macos.sh --confirm   # does it
sudo ./scripts/uninstall-daemon-macos.sh --confirm # reverses it
```

Both scripts refuse to act without `--confirm`, print exactly what they would
change first, and take `--self-test` to run their own unit tests as any user
with nothing installed. The installer boots out an existing job before
bootstrapping, so re-running it is the supported upgrade path, and it verifies
afterwards — job loaded, socket present, socket mode and owner as expected —
rather than trusting `launchctl bootstrap`'s exit status.

It also refuses to install the wrong kind of build. The two peer-authenticator
`describe()` strings in `daemon/src/peerauth*` are feature-gated, so exactly one
of them is present in any binary; the installer greps for both and refuses when
it finds neither or both. A `dev-insecure-ipc` binary is rejected in the default
mode, and a release binary is rejected under `--dev` — a release verifier behind
a 0600 dev socket denies every peer, which would look like a successful install
of a product that cannot connect.

`launchctl enable system/net.thisconnect.daemon` runs before every bootstrap
because a user who switched the job off (see below) leaves a disable override
that survives removing the job.

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
`SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` half of SPEC.md §7.3 is
the seam at `peerauth::macos::CodeVerifier`; `security-framework` and
`core-foundation` are dependencies of the daemon on macOS. Whatever verifier is
compiled in **denies rather than waves through** on any failure — check
`daemon/src/peerauth/macos.rs` for what is actually wired up before assuming a
release install can connect. A release daemon whose verifier is still the
deny-everything stub installs fine and authenticates nobody, which is why `--dev`
exists.

### No NetworkExtension entitlement

The daemon needs **root and nothing else** to create a utun. Verified on this
machine: Homebrew's `openvpn` 2.7.6 is ad-hoc signed (`Signature=adhoc`,
`TeamIdentifier=not set`) with an empty entitlement set, and it creates utuns as
root. NetworkExtension is required for `NEPacketTunnelProvider`, which this
design does not use. Do not add the entitlement "to be safe": it needs a
provisioning profile and Apple approval, and it buys nothing here.

### Signing and notarisation

**Untested — nobody on the project holds a Developer ID yet.** SPEC.md §11 ships
source-first and unsigned. What a signed build needs:

- **Developer ID Application** — `codesign` the daemon binary and the `.app`.
- **Developer ID Installer** — `productsign` the `.pkg`. This is a *second*
  certificate; the Application one cannot sign an installer package, which is
  the usual first-time surprise.
- **Hardened runtime** — `codesign --options runtime`, required by
  `notarytool`. We know of no entitlement the daemon needs on top of it; that
  is an expectation, not a verified fact.
- `xcrun notarytool submit --wait` then `xcrun stapler staple` the `.pkg`.

The designated requirement the daemon checks the GUI against pins
`certificate leaf[field.1.2.840.113635.100.6.1.13]` (the Developer ID
Application marker OID) as well as the team OU — without the marker, a Mac App
Store or development certificate from the same team satisfies it. Signing the
GUI with the wrong certificate type therefore breaks IPC rather than merely
looking untidy.

### The user can switch the daemon off

On macOS 13+ the job appears in **System Settings → General → Login Items &
Extensions**, announced by a "Background Items Added" notification, and the user
can toggle it off. The job is then disabled: `launchctl bootstrap` will not
bring it back until `launchctl enable` clears the override, which the installer
does.

Because a user can do this at any time, an unreachable socket is a *normal*
state, not an internal error. The GUI must connect with a timeout, distinguish
"socket missing" and `ECONNREFUSED` from a protocol failure, and say something
actionable — "the thisconnect background item is turned off in System Settings →
General → Login Items & Extensions" — instead of hanging on `connect()`.

## Development

`--features dev-insecure-ipc` relaxes peer authentication to a uid-only check and
tightens the socket to `0600` owned by that uid. Both halves are required:
loosened authentication behind a 0666 socket would hand root VPN control to any
process the desktop user runs, including a compromised browser renderer or an
`npm postinstall` script. The build prints a loud warning at startup, and
`cargo build --release --features dev-insecure-ipc` fails to compile.

On macOS, `install-daemon-macos.sh --dev` installs that build with the matching
socket policy (`SockPathMode 384` = 0600, plus `SockPathOwner`), prints its own
warning, and refuses to touch a release binary.

```sh
cargo build -p thisconnect-daemon --features dev-insecure-ipc
sudo ./scripts/install-daemon-macos.sh --confirm --dev
```
