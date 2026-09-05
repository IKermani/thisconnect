#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# docs/SPEC.md §10 tests 2 and 3, and §13 open question 1 — the live end-to-end run.
#
# Everything else in this product is unit-tested. Nothing has carried a real packet. This
# script drives the real daemon, from this tree, against a real server, and then asserts the
# things the product actually promises:
#
#   A. the system default route never moves                        (§3.1 point 5)
#   B. the machine's own connectivity is untouched                 (§3.1 point 5)
#   C. egress through the proxy leaves from a DIFFERENT public IP  (§10 test 2, §13 q1)
#   D. zero local DNS lookups for the session                      (§5.4 D7)
#   E. with the tunnel killed, the proxy FAILS rather than falling back to the direct route
#                                                                  (§5.2, §10 test 3)
#
# E is the point of the file. A connection that succeeds proves nothing on its own; a proxy
# that keeps working after the tunnel dies is the failure this whole design exists to prevent.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = SKIP (the run could not measure, and says so instead of
# claiming success).

set -euo pipefail

readonly DEFAULT_ECHO_URL="https://api.ipify.org"
readonly DAEMON_START_TIMEOUT_S=20
readonly CONNECT_TIMEOUT_S=180
readonly DISCONNECT_TIMEOUT_S=45
readonly IPC_REPLY_TIMEOUT_S=15
readonly HTTP_TIMEOUT_S=25
readonly POLL_S=0.2
readonly POLLS_PER_S=5
# Time given to the daemon to notice a dead openvpn. The kill-switch assertion is made
# IMMEDIATELY as well as after this settle, because a fail-open window is still a fail-open.
readonly KILLSWITCH_SETTLE_S=3

readonly EXIT_PASS=0
readonly EXIT_FAIL=1
readonly EXIT_SKIP=2

PROFILE=""
PROFILE_NAME="live-harness"
ECHO_URL="${THISCONNECT_ECHO_URL:-$DEFAULT_ECHO_URL}"
CONFIRMED="no"
SELF_TEST="no"

WORK_DIR=""
PY=""
JSON_HELPER=""
IPC_IN=""
IPC_OUT=""
NC_PID=""
DAEMON_PID=""
DAEMON_BIN="${THISCONNECT_DAEMON_BIN:-}"
SOCKET_PATH=""
ID_FILE=""
ANSWERED_PROMPTS=" "
REPORTED_STATES=" "
IPC_OPEN="no"

TUNNEL_DEV=""
DIRECT_IP=""
PROXY_IP=""
PROXY_URL=""
DEFAULT_ROUTE_BEFORE=""

# Per-assertion results: pass | fail | skip.
R_ROUTE_DURING="skip"
R_DIRECT_STABLE="skip"
R_EGRESS="skip"
R_DNS="skip"
R_KILLSWITCH="skip"
R_ROUTE_AFTER="skip"
R_RESIDUE="skip"
D_ROUTE_DURING="not reached"
D_DIRECT_STABLE="not reached"
D_EGRESS="not reached"
D_DNS="not reached"
D_KILLSWITCH="not reached"
D_ROUTE_AFTER="not reached"
D_RESIDUE="not reached"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit "$EXIT_FAIL"
}
skip_out() {
  printf '\nSKIP: %s\n' "$*" >&2
  printf 'A run that cannot measure must not report PASS.\n' >&2
  exit "$EXIT_SKIP"
}

usage() {
  cat <<'EOF'
verify-live-tunnel.sh — the live end-to-end run (docs/SPEC.md §10 tests 2 and 3, §13 q1).

  sudo ./scripts/verify-live-tunnel.sh --profile ~/vpn/work.ovpn --confirm

What it proves is NOT that the VPN connects. It is that, with the VPN connected:
  - the system default route is byte-for-byte unchanged,
  - the machine's own (non-proxied) connectivity is untouched,
  - a request through the proxy exits from a different public IP,
  - the daemon counted zero local DNS lookups,
  - and killing the tunnel makes the proxy FAIL rather than fall back to the direct route.

Options:
  --profile PATH   The .ovpn to import. Required. Its contents are never printed.
  --confirm        Required. Without it the plan is printed and nothing runs.
  --echo-url URL   IP-echo endpoint (default https://api.ipify.org, env THISCONNECT_ECHO_URL).
                   Must answer with a bare IP address. If it is unreachable directly, the run
                   SKIPs rather than reporting a false PASS.
  --name NAME      Profile name used for the import (default live-harness).
  --self-test      Run the pure decision functions and exit. No root, touches nothing.
  -h, --help       This text.

Credentials: the profile is expected to need a username and password. The daemon sends a
credential prompt over IPC; this script reads the answers from your terminal with `read -r`
and `read -rs`. They are never echoed, never placed in argv, never written to disk, and never
logged. Neither is the profile, the CA, or any key material.

The daemon is built from this tree and run against a throwaway socket, runtime directory and
state directory under a temp dir, all removed on exit. /var/run and any system install are
untouched.

Exit codes: 0 PASS, 1 FAIL, 2 SKIP.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --self-test) SELF_TEST="yes" ;;
      --profile)
        [ "$#" -ge 2 ] || die "--profile needs a path"
        PROFILE="$2"
        shift
        ;;
      --echo-url)
        [ "$#" -ge 2 ] || die "--echo-url needs a URL"
        ECHO_URL="$2"
        shift
        ;;
      --name)
        [ "$#" -ge 2 ] || die "--name needs a value"
        PROFILE_NAME="$2"
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
}

# ---------------------------------------------------------------------------
# Pure decision logic. Covered by --self-test; no side effects, no system calls.
# ---------------------------------------------------------------------------

# An echo endpoint behind a captive portal answers 200 with HTML. Treating that as an address
# would make assertion C compare two pieces of junk and call them different.
is_ip_literal() {
  local value="$1"
  case "$value" in
    *[!0-9a-fA-F.:]* | "") return 1 ;;
  esac
  if [[ "$value" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local octet
    for octet in "${BASH_REMATCH[@]:1}"; do
      [ "$octet" -le 255 ] || return 1
    done
    return 0
  fi
  # Loose IPv6 acceptance: the shape check above already excluded everything that is not
  # hex, dots and colons, and this value is only ever compared, never executed.
  case "$value" in
    *:*) return 0 ;;
  esac
  return 1
}

is_valid_utun_name() {
  [[ "$1" =~ ^utun[0-9]{1,3}$ ]]
}

# stdin: `ps -axo pid=,ppid=,comm=` output. $1: the daemon pid. Prints its openvpn child.
pick_openvpn_child() {
  awk -v parent="$1" '$2 == parent && $3 ~ /openvpn/ { print $1; exit }'
}

# stdin: `netstat -rn` output. Prints every line still referencing the device.
routes_mentioning_device() {
  local dev="$1"
  [ -n "$dev" ] || return 0
  awk -v dev="$dev" '$0 ~ ("(^|[^a-zA-Z0-9])" dev "([^0-9]|$)")'
}

# egress_verdict <direct-ip> <proxy-ip> -> "<status> <detail>"
# Equal addresses are the interesting failure: the request succeeded, so nothing looked broken,
# and every byte still left over the ISP link under the user's real identity.
egress_verdict() {
  local direct="$1" proxied="$2"
  if [ -z "$proxied" ]; then
    echo "fail the proxy returned no address — egress through the tunnel does not work"
    return 0
  fi
  if ! is_ip_literal "$proxied"; then
    echo "skip the proxy answer was not an IP address; the echo endpoint cannot measure this"
    return 0
  fi
  if [ "$direct" = "$proxied" ]; then
    echo "fail proxied egress used the SAME public IP as the direct route — traffic is not traversing the tunnel"
    return 0
  fi
  echo "pass proxied egress left from a different public IP than the direct route"
}

# killswitch_verdict <curl-rc> <body> <direct-ip> -> "<status> <detail>"
killswitch_verdict() {
  local rc="$1" body="$2" direct="$3"
  if [ "$rc" != "0" ]; then
    echo "pass the proxy request failed with the tunnel gone (curl rc=$rc) — fail-closed"
    return 0
  fi
  if [ "$body" = "$direct" ]; then
    echo "fail FAIL-OPEN: with the tunnel dead the proxy answered from the DIRECT public IP. Every proxied byte would leave over the ISP link under the user's real identity, silently."
    return 0
  fi
  echo "fail the proxy still served a request after the tunnel was killed; egress is not pinned to the tunnel's lifetime"
}

# dns_verdict <local-count-or-empty> <tunnel-count-or-empty> -> "<status> <detail>"
# A local counter of 0 proves nothing on its own: it reads identically whether every name was
# resolved through the tunnel or no name was ever resolved at all. The tunnel counter is the
# only thing that separates leak-freedom from an idle session.
dns_verdict() {
  local count="$1" tunnel="$2"
  if [ -z "$count" ]; then
    echo "skip the daemon did not report a local-DNS counter for this session; DNS leakage was NOT checked by this run"
    return 0
  fi
  if [ "$count" != "0" ]; then
    echo "fail the daemon counted $count local DNS lookups — names escaped the tunnel (SPEC.md §5.4 D7 calls any non-zero value a bug)"
    return 0
  fi
  if [ -z "$tunnel" ] || [ "$tunnel" = "0" ]; then
    echo "skip 0 local DNS lookups, but 0 through the tunnel as well — no name was resolved this session, so leak-freedom was never exercised"
    return 0
  fi
  echo "pass the daemon counted 0 local DNS lookups against $tunnel names resolved through the tunnel"
}

# direct_stability_verdict <before> <after> <tunnel_exit> -> "<status> <detail>"
#
# The property is that the machine's own traffic does NOT enter the tunnel. It is
# deliberately NOT "the direct IP equals the baseline": plenty of connections
# rotate their public address on their own (CGNAT, DHCP lease churn, a carrier
# reassigning), and failing the run for that measures the ISP rather than this
# client. Equality with the baseline is reported as the strongest result;
# equality with the TUNNEL exit is the actual failure.
direct_stability_verdict() {
  local before="$1" after="$2" tunnel_exit="${3:-}"
  if [ -z "$after" ]; then
    echo "fail the machine lost direct connectivity while the tunnel was up — the client is supposed to leave the system alone"
    return 0
  fi
  if [ -n "$tunnel_exit" ] && [ "$after" = "$tunnel_exit" ]; then
    echo "fail direct (non-proxied) traffic left from the tunnel exit — the system stack WAS captured"
    return 0
  fi
  if [ "$before" != "$after" ]; then
    echo "pass direct traffic did not enter the tunnel (its public IP moved on its own, which upstream networks do; it is not the tunnel exit)"
    return 0
  fi
  echo "pass the direct route still exits via the normal interface, unchanged"
}

# route_verdict <changed:yes|no> <context> -> "<status> <detail>"
route_verdict() {
  local changed="$1" context="$2"
  if [ "$changed" = "no" ]; then
    echo "pass system default route byte-for-byte unchanged ($context)"
    return 0
  fi
  echo "fail the system default route changed ($context) — SPEC.md §3.1 point 5 is broken regardless of everything else"
}

# residue_verdict <leftover-lines> <device> -> "<status> <detail>"
residue_verdict() {
  local leftovers="$1" dev="$2"
  if [ -z "$leftovers" ]; then
    echo "pass no route referencing $dev survived teardown (macOS has no ip rules; a scoped route is the only residue possible)"
    return 0
  fi
  echo "fail routes referencing $dev survived teardown — a scoped default route pointing at a dead utun is a correctness and security hazard (SPEC.md §5.2)"
}

# overall_verdict <status>... -> "PASS" | "PASS-WITH-GAPS" | "FAIL"
overall_verdict() {
  local status seen_skip="no"
  for status in "$@"; do
    [ "$status" != "fail" ] || {
      echo "FAIL"
      return 0
    }
    [ "$status" != "skip" ] || seen_skip="yes"
  done
  [ "$seen_skip" = "no" ] && echo "PASS" || echo "PASS-WITH-GAPS"
}

# The kill switch outranks everything: a run where egress worked but the proxy kept serving
# after the tunnel died is worse than one that never connected.
verdict_headline() {
  local overall="$1" killswitch="$2"
  if [ "$killswitch" = "fail" ]; then
    echo "FAIL — the fail-closed property does not hold"
    return 0
  fi
  case "$overall" in
    PASS) echo "PASS — every security property asserted here held" ;;
    PASS-WITH-GAPS) echo "PASS-WITH-GAPS — nothing failed, but at least one property could not be measured" ;;
    *) echo "FAIL — at least one security property does not hold" ;;
  esac
}

# verdict_exit_code <overall> -> the process exit status for that verdict.
# A gap is a SKIP, never a pass. A run where the kill switch could not be exercised has not
# demonstrated the one property this file exists to demonstrate, and must not look green to CI.
verdict_exit_code() {
  case "$1" in
    PASS) printf '%s' "$EXIT_PASS" ;;
    PASS-WITH-GAPS) printf '%s' "$EXIT_SKIP" ;;
    *) printf '%s' "$EXIT_FAIL" ;;
  esac
}

# ---------------------------------------------------------------------------
# Runtime plumbing
# ---------------------------------------------------------------------------

# Ids must stay unique across calls, and every caller reads them through a command
# substitution — a subshell, whose variable increments are discarded. The counter therefore
# lives in a file. Reusing an id would silently correlate a reply with the wrong request.
next_id() {
  local n=0
  [ ! -r "$ID_FILE" ] || n="$(cat "$ID_FILE")"
  n=$((n + 1))
  printf '%s' "$n" >"$ID_FILE"
  printf 'req-%s' "$n"
}

write_json_helper() {
  JSON_HELPER="$WORK_DIR/ipcjson.py"
  ID_FILE="$WORK_DIR/idseq"
  cat >"$JSON_HELPER" <<'PY_EOF'
# SPDX-License-Identifier: GPL-3.0-or-later
"""JSON plumbing for verify-live-tunnel.sh.

Secrets (the profile body, the account password, a one-time code) are read from stdin and
written to stdout. They are never accepted as arguments, because argv is world-readable
through ps.
"""
import json
import sys


def dig(obj, path):
    for part in path.split("."):
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            if part not in obj:
                return None
            obj = obj[part]
        else:
            return None
    return obj


def scalar(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    return json.dumps(value, separators=(",", ":"))


def matches(obj, criteria):
    for item in criteria:
        key, _, want = item.partition("=")
        if scalar(dig(obj, key)) != want:
            return False
    return True


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")


def cmd_get(args):
    try:
        obj = json.loads(sys.stdin.read())
    except ValueError:
        return 1
    value = scalar(dig(obj, args[0]))
    if value is None:
        return 1
    sys.stdout.write(value + "\n")
    return 0


def scan(path, criteria, all_matches):
    found = 0
    try:
        handle = open(path, "r")
    except IOError:
        return 1
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if matches(obj, criteria):
                emit(obj)
                found += 1
                if not all_matches:
                    return 0
    return 0 if found else 1


def cmd_find(args):
    return scan(args[0], args[1:], False)


def cmd_findall(args):
    return scan(args[0], args[1:], True)


def cmd_hello(args):
    emit({"type": "hello", "id": args[0], "protocol_version": int(args[1]),
          "client_name": "verify-live-tunnel"})
    return 0


def cmd_request(args):
    body = {"type": args[1]}
    for item in args[2:]:
        key, _, value = item.partition("=")
        body[key] = value
    emit({"type": "request", "id": args[0], "request": body})
    return 0


def cmd_import(args):
    emit({"type": "request", "id": args[0], "request": {
        "type": "profile_import", "name": args[1], "config": sys.stdin.read()}})
    return 0


def cmd_reply(args):
    ident, prompt_id, kind = args[0], args[1], args[2]
    lines = sys.stdin.read().split("\n")
    if kind == "username_password":
        reply = {"type": "username_password", "username": lines[0],
                 "password": lines[1] if len(lines) > 1 else ""}
    elif kind == "challenge_response":
        reply = {"type": "challenge_response", "response": lines[0]}
    else:
        reply = {"type": "cancel"}
    emit({"type": "prompt_reply", "id": ident, "prompt_id": prompt_id, "reply": reply})
    return 0


COMMANDS = {"get": cmd_get, "find": cmd_find, "findall": cmd_findall, "hello": cmd_hello,
            "request": cmd_request, "import": cmd_import, "reply": cmd_reply}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        sys.stderr.write("usage: ipcjson.py <%s> ...\n" % "|".join(sorted(COMMANDS)))
        return 2
    return COMMANDS[argv[1]](argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY_EOF
}

json_get() { "$PY" "$JSON_HELPER" get "$1"; }

# ipc_wait <timeout-seconds> <path=value>... -> prints the first matching line
ipc_wait() {
  local timeout="$1"
  shift
  local iters=$((timeout * POLLS_PER_S)) i=0 line=""
  while [ "$i" -lt "$iters" ]; do
    line="$("$PY" "$JSON_HELPER" find "$IPC_OUT" "$@" 2>/dev/null || true)"
    if [ -n "$line" ]; then
      printf '%s\n' "$line"
      return 0
    fi
    ipc_is_alive || return 1
    sleep "$POLL_S"
    i=$((i + 1))
  done
  return 1
}

ipc_is_alive() {
  [ -n "$NC_PID" ] && kill -0 "$NC_PID" 2>/dev/null
}

ipc_send_stdin() { cat >&3; }

ipc_open() {
  IPC_IN="$WORK_DIR/ipc.in"
  IPC_OUT="$WORK_DIR/ipc.out"
  mkfifo "$IPC_IN"
  : >"$IPC_OUT"
  nc -U "$SOCKET_PATH" <"$IPC_IN" >"$IPC_OUT" 2>"$WORK_DIR/nc.err" &
  NC_PID=$!
  # Holding the write end open keeps nc from seeing EOF between requests.
  exec 3>"$IPC_IN"
  IPC_OPEN="yes"
}

ipc_close() {
  [ "$IPC_OPEN" = "yes" ] || return 0
  exec 3>&-
  IPC_OPEN="no"
  if [ -n "$NC_PID" ] && kill -0 "$NC_PID" 2>/dev/null; then
    kill -TERM "$NC_PID" 2>/dev/null || true
    wait "$NC_PID" 2>/dev/null || true
  fi
  NC_PID=""
}

handshake() {
  local id line
  id="$(next_id)"
  "$PY" "$JSON_HELPER" hello "$id" 1 | ipc_send_stdin
  line="$(ipc_wait "$IPC_REPLY_TIMEOUT_S" "id=$id")" ||
    die "no handshake reply from the daemon. If it denied the peer, the socket was authenticated
against a code signature this script cannot satisfy — see the note about dev-insecure-ipc below."
  case "$(printf '%s' "$line" | json_get type)" in
    hello) say "handshake ok (daemon protocol $(printf '%s' "$line" | json_get protocol_version))" ;;
    *) die "handshake refused: $(printf '%s' "$line" | json_get error.code)" ;;
  esac
}

# Sends a request built entirely from non-secret arguments.
ipc_request() {
  local id
  id="$(next_id)"
  "$PY" "$JSON_HELPER" request "$id" "$@" | ipc_send_stdin
  printf '%s' "$id"
}

ipc_reply_for() {
  local id="$1" timeout="${2:-$IPC_REPLY_TIMEOUT_S}"
  ipc_wait "$timeout" "id=$id"
}

# ---------------------------------------------------------------------------
# Daemon lifecycle
# ---------------------------------------------------------------------------

resolve_cargo() {
  local candidate
  candidate="$(command -v cargo || true)"
  if [ -z "$candidate" ] && [ -n "${SUDO_USER:-}" ]; then
    candidate="/Users/${SUDO_USER}/.cargo/bin/cargo"
    [ -x "$candidate" ] || candidate=""
  fi
  printf '%s' "$candidate"
}

# The daemon is built with `dev-insecure-ipc` on purpose: without it the macOS authenticator is
# `UnimplementedCodeVerifier`, which denies every peer, and no shell script can present a valid
# GUI code signature anyway. That means THIS RUN DOES NOT EXERCISE PEER AUTHENTICATION, and the
# verdict says so rather than letting a reader assume otherwise.
build_daemon() {
  local cargo
  if [ -n "$DAEMON_BIN" ]; then
    [ -x "$DAEMON_BIN" ] || die "THISCONNECT_DAEMON_BIN is not executable: $DAEMON_BIN"
    say "using the daemon binary from THISCONNECT_DAEMON_BIN"
    return 0
  fi
  cargo="$(resolve_cargo)"
  [ -n "$cargo" ] || die "cargo not found. Build the daemon yourself and pass it in
THISCONNECT_DAEMON_BIN=target/debug/thisconnectd."
  step "Building thisconnectd from this tree (debug, --features dev-insecure-ipc)"
  # Built as the invoking user so sudo does not leave root-owned artefacts in target/.
  if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" "$cargo" build -p thisconnect-daemon --features dev-insecure-ipc ||
      die "daemon build failed"
  else
    "$cargo" build -p thisconnect-daemon --features dev-insecure-ipc || die "daemon build failed"
  fi
  DAEMON_BIN="$REPO_ROOT/target/debug/thisconnectd"
  [ -x "$DAEMON_BIN" ] || die "built, but $DAEMON_BIN is missing"
}

start_daemon() {
  local waited=0
  SOCKET_PATH="$WORK_DIR/thisconnectd.sock"
  mkdir -p "$WORK_DIR/run" "$WORK_DIR/state"
  step "Starting the daemon on a throwaway socket (nothing in /var/run is touched)"
  say "  + $DAEMON_BIN   socket=$SOCKET_PATH"
  THISCONNECT_SOCKET="$SOCKET_PATH" \
    THISCONNECT_RUNTIME_DIR="$WORK_DIR/run" \
    THISCONNECT_STATE_DIR="$WORK_DIR/state" \
    THISCONNECT_ALLOWED_UIDS=0 \
    THISCONNECT_OPENVPN="$OPENVPN_BIN" \
    THISCONNECT_LOG="${THISCONNECT_LOG:-thisconnectd=info,warn}" \
    "$DAEMON_BIN" >"$WORK_DIR/daemon.log" 2>&1 </dev/null &
  DAEMON_PID=$!
  while [ "$waited" -lt $((DAEMON_START_TIMEOUT_S * POLLS_PER_S)) ]; do
    [ ! -S "$SOCKET_PATH" ] || return 0
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep "$POLL_S"
    waited=$((waited + 1))
  done
  dump_daemon_log
  die "the daemon did not create its socket within ${DAEMON_START_TIMEOUT_S}s"
}

# Daemon-authored output only: SPEC.md §4.4 forbids forwarding raw openvpn >LOG: lines, which
# redact `password` but not `username`.
dump_daemon_log() {
  [ -r "$WORK_DIR/daemon.log" ] || return 0
  say "--- last 20 lines of the daemon log (daemon-authored, redacted) ---"
  tail -n 20 "$WORK_DIR/daemon.log" || true
  say "--- end ---"
}

stop_daemon() {
  [ -n "$DAEMON_PID" ] || return 0
  if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  DAEMON_PID=""
}

kill_stray_openvpn() {
  local pid
  [ -n "$DAEMON_PID" ] || return 0
  pid="$(ps -axo pid=,ppid=,comm= | pick_openvpn_child "$DAEMON_PID" || true)"
  [ -n "$pid" ] || return 0
  warn "killing an openvpn process left behind by the daemon (pid $pid)"
  kill -TERM "$pid" 2>/dev/null || true
}

cleanup() {
  local rc=$?
  set +e
  ipc_close
  kill_stray_openvpn
  stop_daemon
  [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
  exit "$rc"
}

# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------

snapshot_default_route() { route -n get -inet default 2>&1 || true; }

# Prints "no" when the route is byte-for-byte identical, "yes" otherwise, and shows the diff.
default_route_changed() {
  local after
  after="$(snapshot_default_route)"
  if [ "$DEFAULT_ROUTE_BEFORE" = "$after" ]; then
    printf 'no'
    return 0
  fi
  diff <(printf '%s\n' "$DEFAULT_ROUTE_BEFORE") <(printf '%s\n' "$after") >&2 || true
  printf 'yes'
}

curl_direct() {
  curl --noproxy '*' -sS --max-time "$HTTP_TIMEOUT_S" "$ECHO_URL" 2>/dev/null | tr -d '\r\n'
}

# The proxy URL carries the daemon's generated proxy password, so it goes to curl through a
# config file on stdin. `-x <url>` would publish it in argv for every user on the machine.
# socks5h:// is mandatory: socks5:// resolves the name locally and would pass this test while
# leaking every hostname (SPEC.md §5.4 D8).
curl_proxied() {
  printf 'proxy = %s\n' "$PROXY_URL" |
    curl --config - -sS --max-time "$HTTP_TIMEOUT_S" "$ECHO_URL" 2>/dev/null | tr -d '\r\n'
}

# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

preflight() {
  [ "$(uname -s)" = "Darwin" ] || die "this harness is macOS-only; the Linux half is verify-egress-linux.sh"
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --profile <path> --confirm)"
  [ -n "$PROFILE" ] || die "--profile is required"
  [ -r "$PROFILE" ] || die "profile not readable: $PROFILE"
  PY="$(command -v python3 || true)"
  [ -n "$PY" ] || die "python3 is required for JSON framing (install the Xcode command line tools)"
  command -v nc >/dev/null || die "nc is required to speak to the unix socket"
  command -v curl >/dev/null || die "curl is required"
  OPENVPN_BIN="$(command -v openvpn || true)"
  [ -n "$OPENVPN_BIN" ] || die "openvpn not found in PATH"
  # A proxy inherited from the environment would make every measurement below a lie.
  unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
}

import_profile() {
  local id line kind
  step "Importing the profile over IPC (its contents are never printed)"
  id="$(next_id)"
  "$PY" "$JSON_HELPER" import "$id" "$PROFILE_NAME" <"$PROFILE" | ipc_send_stdin
  line="$(ipc_reply_for "$id")" || die "no reply to profile_import"
  kind="$(printf '%s' "$line" | json_get type)"
  if [ "$kind" = "error" ]; then
    say "validator verdict: REJECTED"
    say "  code:      $(printf '%s' "$line" | json_get error.code)"
    # `validation` is optional on the wire (docs/IPC.md §5.2) and the message is the
    # daemon-authored, redacted text the GUI would show. Print both, and neither the config.
    say "  reason:    $(printf '%s' "$line" | json_get error.validation.reason || echo '<not reported>')"
    say "  line:      $(printf '%s' "$line" | json_get error.validation.line || echo '<not reported>')"
    say "  directive: $(printf '%s' "$line" | json_get error.validation.directive || echo '<not reported>')"
    say "  message:   $(printf '%s' "$line" | json_get error.message || true)"
    die "the profile did not pass validation; nothing further can be measured"
  fi
  PROFILE_ID="$(printf '%s' "$line" | json_get response.profile.id)" ||
    die "import succeeded but carried no profile id"
  say "validator verdict: ACCEPTED"
  say "  profile id:                $PROFILE_ID"
  say "  requires username/password: $(printf '%s' "$line" | json_get response.profile.requires_username_password || true)"
  say "  static challenge:           $(printf '%s' "$line" | json_get response.profile.static_challenge.text >/dev/null 2>&1 && echo yes || echo no)"
}

# Reads one credential from the operator. Never echoes a masked field, never returns it through
# a file or an argument — the caller pipes it straight into the JSON encoder.
prompt_operator() {
  local label="$1" masked="$2" value=""
  printf '%s: ' "$label" >/dev/tty
  if [ "$masked" = "yes" ]; then
    read -rs value </dev/tty
    printf '\n' >/dev/tty
  else
    read -r value </dev/tty
  fi
  printf '%s' "$value"
}

answer_prompt() {
  local line="$1" prompt_id kind echo_flag username password challenge reply_id
  prompt_id="$(printf '%s' "$line" | json_get prompt_id)"
  case "$ANSWERED_PROMPTS" in
    *" $prompt_id "*) return 0 ;;
  esac
  ANSWERED_PROMPTS="$ANSWERED_PROMPTS$prompt_id "
  kind="$(printf '%s' "$line" | json_get prompt.type)"
  reply_id="$(next_id)"
  case "$kind" in
    username_password)
      say ""
      say "the daemon is asking for the account credentials (they stay in this process)"
      username="$(prompt_operator "username" no)"
      password="$(prompt_operator "password" yes)"
      printf '%s\n%s' "$username" "$password" |
        "$PY" "$JSON_HELPER" reply "$reply_id" "$prompt_id" username_password | ipc_send_stdin
      ;;
    static_challenge | dynamic_challenge)
      echo_flag="$(printf '%s' "$line" | json_get prompt.echo || echo false)"
      say ""
      say "the daemon is asking for a challenge response ($(printf '%s' "$line" | json_get prompt.challenge_text || echo 'no text'))"
      if [ "$echo_flag" = "true" ]; then
        challenge="$(prompt_operator "response" no)"
      else
        challenge="$(prompt_operator "response" yes)"
      fi
      printf '%s' "$challenge" |
        "$PY" "$JSON_HELPER" reply "$reply_id" "$prompt_id" challenge_response | ipc_send_stdin
      ;;
    *)
      warn "unknown prompt type $kind; cancelling it"
      printf '' | "$PY" "$JSON_HELPER" reply "$reply_id" "$prompt_id" cancel | ipc_send_stdin
      ;;
  esac
}

# The daemon does not answer `connect` until the tunnel is up or the attempt has failed, and a
# profile needing credentials produces a daemon-initiated prompt FIRST. Blocking on the connect
# reply before servicing prompts is therefore a deadlock: the daemon waits for credentials that
# the harness will not send until it has a reply it will never get. Everything is watched in one
# loop instead, and the connect reply is just one of the things that can end it.
connect_and_authenticate() {
  local id i=0 iters line
  step "Connecting"
  id="$(ipc_request connect "profile_id=$PROFILE_ID")"
  iters=$((CONNECT_TIMEOUT_S * POLLS_PER_S))
  while [ "$i" -lt "$iters" ]; do
    line="$("$PY" "$JSON_HELPER" find "$IPC_OUT" "id=$id" type=error 2>/dev/null || true)"
    if [ -n "$line" ]; then
      dump_daemon_log
      die "connect was refused: $(printf '%s' "$line" | json_get error.code) — $(printf '%s' "$line" | json_get error.message || true)"
    fi
    line="$("$PY" "$JSON_HELPER" findall "$IPC_OUT" type=prompt 2>/dev/null || true)"
    if [ -n "$line" ]; then
      while IFS= read -r one; do
        [ -z "$one" ] || answer_prompt "$one"
      done <<EOF_PROMPTS
$line
EOF_PROMPTS
    fi
    # Report each new state as it lands. Without this the run is silent for up
    # to CONNECT_TIMEOUT_S after the password, which reads as a hang.
    for known in connecting authenticating connected disconnecting failed; do
      case "$REPORTED_STATES" in
        *" $known "*) continue ;;
      esac
      if "$PY" "$JSON_HELPER" find "$IPC_OUT" type=event event.type=state "event.state=$known" >/dev/null 2>&1; then
        REPORTED_STATES="$REPORTED_STATES$known "
        say "state: $known"
      fi
    done
    if "$PY" "$JSON_HELPER" find "$IPC_OUT" type=event event.type=tunnel_up >/dev/null 2>&1; then
      case "$REPORTED_STATES" in
        *" tunnel_up "*) : ;;
        *)
          REPORTED_STATES="$REPORTED_STATES""tunnel_up "
          say "tunnel is up; installing routing policy and starting the proxy"
          ;;
      esac
    fi
    if "$PY" "$JSON_HELPER" find "$IPC_OUT" type=event event.type=state event.state=connected >/dev/null 2>&1; then
      return 0
    fi
    if "$PY" "$JSON_HELPER" find "$IPC_OUT" type=event event.type=state event.state=failed >/dev/null 2>&1; then
      dump_daemon_log
      die "the daemon reported state=failed. Nothing about the security properties can be
concluded from a run that never connected."
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || {
      dump_daemon_log
      die "the daemon exited during connect"
    }
    sleep "$POLL_S"
    i=$((i + 1))
  done
  dump_daemon_log
  die "no connected state within ${CONNECT_TIMEOUT_S}s"
}

capture_tunnel_device() {
  local line dev
  line="$(ipc_wait 10 type=event event.type=tunnel_up)" || {
    warn "no tunnel_up event seen; the residue check has no device to look for"
    return 0
  }
  dev="$(printf '%s' "$line" | json_get event.tunnel.device || true)"
  if is_valid_utun_name "$dev"; then
    TUNNEL_DEV="$dev"
    say "tunnel device: $TUNNEL_DEV"
  else
    warn "refusing an implausible tunnel device name from the daemon; residue check degraded"
  fi
}

fetch_proxy_url() {
  local id line kind
  id="$(ipc_request proxy_info)"
  line="$(ipc_reply_for "$id")" || die "no reply to proxy_info"
  kind="$(printf '%s' "$line" | json_get type)"
  if [ "$kind" = "error" ]; then
    skip_out "the daemon has no proxy listener to report ($(printf '%s' "$line" | json_get error.code)).
Assertions C, D and E measure the proxy; without one there is nothing to measure. If this build
links no proxy worker, that is the gap, not a passing test."
  fi
  PROXY_URL="$(printf '%s' "$line" | json_get response.proxy.socks5h_url)" ||
    skip_out "the daemon reported no socks5h URL for the proxy"
  case "$PROXY_URL" in
    socks5h://*) ;;
    *) die "the daemon reported a proxy URL that is not socks5h://. socks5:// resolves names
locally and leaks every hostname (SPEC.md §5.4 D8); this harness refuses to use it." ;;
  esac
  say "proxy listener: $(printf '%s' "$line" | json_get response.proxy.listen_addrs || true) (credentials not shown)"
}

assert_egress() {
  local verdict
  step "C. Egress actually traverses the tunnel"
  verdict="$(egress_verdict "$DIRECT_IP" "$PROXY_IP")"
  R_EGRESS="${verdict%% *}"
  D_EGRESS="${verdict#* }"
  say "direct public IP:  $DIRECT_IP"
  say "proxied public IP: ${PROXY_IP:-<none>}"
  say "$R_EGRESS: $D_EGRESS"
}

assert_dns() {
  local id line count="" tunnel="" verdict
  step "D. Local DNS lookups for the session"
  id="$(ipc_request proxy_stats)"
  line="$(ipc_reply_for "$id")" || line=""
  if [ -n "$line" ] && [ "$(printf '%s' "$line" | json_get type)" = "response" ]; then
    count="$(printf '%s' "$line" | json_get response.stats.local_dns_lookups || true)"
    tunnel="$(printf '%s' "$line" | json_get response.stats.tunnel_dns_lookups || true)"
  fi
  verdict="$(dns_verdict "$count" "$tunnel")"
  R_DNS="${verdict%% *}"
  D_DNS="${verdict#* }"
  say "$R_DNS: $D_DNS"
}

# The whole product is this assertion. Everything above can pass on a client that merely works.
assert_killswitch() {
  local pid body rc=0 verdict
  step "E. Fail-closed: kill the tunnel, the proxy must FAIL rather than fall back"
  # A request that fails after the kill only proves fail-closed if the same request worked
  # before it. Without assertion C, the post-kill failure has a pre-existing explanation.
  if [ "$R_EGRESS" != "pass" ]; then
    R_KILLSWITCH="skip"
    D_KILLSWITCH="the proxy was never observed working (assertion C is [${R_EGRESS:-unrun}]), so a request failing after the tunnel is killed proves nothing; the fail-closed property was NOT tested"
    say "$R_KILLSWITCH: $D_KILLSWITCH"
    return 0
  fi
  pid="$(ps -axo pid=,ppid=,comm= | pick_openvpn_child "$DAEMON_PID" || true)"
  if [ -z "$pid" ]; then
    R_KILLSWITCH="skip"
    D_KILLSWITCH="could not find the daemon's openvpn child, so the tunnel could not be killed; the fail-closed property was NOT tested"
    say "$R_KILLSWITCH: $D_KILLSWITCH"
    return 0
  fi
  say "  + kill -KILL $pid   (the tunnel dies without the daemon being asked)"
  kill -KILL "$pid" 2>/dev/null || true

  body="$(curl_proxied)" || rc=$?
  verdict="$(killswitch_verdict "$rc" "$body" "$DIRECT_IP")"
  R_KILLSWITCH="${verdict%% *}"
  D_KILLSWITCH="${verdict#* }"
  say "immediately after the kill: $R_KILLSWITCH: $D_KILLSWITCH"

  # A second look after the daemon has had time to react. A window that closes eventually is
  # still a window, so a failure above is never upgraded here — only a pass can be revoked.
  sleep "$KILLSWITCH_SETTLE_S"
  rc=0
  body="$(curl_proxied)" || rc=$?
  verdict="$(killswitch_verdict "$rc" "$body" "$DIRECT_IP")"
  say "after ${KILLSWITCH_SETTLE_S}s: ${verdict%% *}: ${verdict#* }"
  if [ "${verdict%% *}" = "fail" ] && [ "$R_KILLSWITCH" = "pass" ]; then
    R_KILLSWITCH="fail"
    D_KILLSWITCH="${verdict#* }"
  fi
}

teardown_and_assert_clean() {
  local id leftovers changed verdict
  step "Disconnecting and checking for residue"
  id="$(ipc_request disconnect)"
  say "asked the daemon to disconnect; waiting up to ${DISCONNECT_TIMEOUT_S}s"
  if ! ipc_reply_for "$id" "$DISCONNECT_TIMEOUT_S" >/dev/null; then
    warn "no reply to disconnect within ${DISCONNECT_TIMEOUT_S}s — the daemon log follows, since a
teardown that never answers is a bug worth naming rather than tolerating"
    dump_daemon_log
  fi
  # The kill-switch assertion killed openvpn, so the session may already have
  # torn itself down and reported `failed`. Either terminal state means there is
  # nothing left running, which is what the residue check is about.
  if ipc_wait "$DISCONNECT_TIMEOUT_S" type=event event.type=state event.state=disconnected >/dev/null; then
    say "state: disconnected"
  elif "$PY" "$JSON_HELPER" find "$IPC_OUT" type=event event.type=state event.state=failed >/dev/null 2>&1; then
    say "state: failed (expected: the kill-switch assertion killed the tunnel)"
  else
    warn "no terminal state event; checking the system anyway"
  fi
  ipc_close
  stop_daemon

  changed="$(default_route_changed)"
  verdict="$(route_verdict "$changed" "after teardown")"
  R_ROUTE_AFTER="${verdict%% *}"
  D_ROUTE_AFTER="${verdict#* }"
  say "$R_ROUTE_AFTER: $D_ROUTE_AFTER"

  if [ -z "$TUNNEL_DEV" ]; then
    R_RESIDUE="skip"
    D_RESIDUE="no tunnel device was captured, so leftover scoped routes could not be checked"
  else
    leftovers="$(netstat -rn 2>/dev/null | routes_mentioning_device "$TUNNEL_DEV" || true)"
    verdict="$(residue_verdict "$leftovers" "$TUNNEL_DEV")"
    R_RESIDUE="${verdict%% *}"
    D_RESIDUE="${verdict#* }"
    [ -z "$leftovers" ] || printf '%s\n' "$leftovers"
  fi
  say "$R_RESIDUE: $D_RESIDUE"
}

print_plan() {
  cat <<EOF
This run will, as root:
  - build thisconnectd from this tree (debug, --features dev-insecure-ipc)
  - start it against a throwaway socket, runtime dir and state dir under a temp directory,
    all removed on exit. /var/run and any system install are untouched.
  - import $PROFILE over IPC and print the validator's verdict (never the file's contents)
  - connect, asking you for the username and password at the terminal when the daemon prompts
  - measure, with the tunnel up:
      A. the system default route, byte-for-byte against the pre-connection snapshot
      B. the direct (non-proxied) public IP, against the pre-connection value
      C. the public IP seen through the proxy over socks5h://, which must DIFFER from B
      D. the daemon's DNS counters: 0 local lookups against a non-zero tunnel count
      E. kill -KILL the daemon's openvpn child and assert a proxy request FAILS
  - disconnect, stop the daemon, and re-check the default route and for leftover routes

It sends two HTTPS requests per measurement to $ECHO_URL, one direct and one through the proxy.
It changes no route, no interface and no resolver of its own.

Re-run with --confirm to execute.
EOF
}

print_verdict() {
  local overall headline code
  overall="$(overall_verdict "$R_ROUTE_DURING" "$R_DIRECT_STABLE" "$R_EGRESS" "$R_DNS" \
    "$R_KILLSWITCH" "$R_ROUTE_AFTER" "$R_RESIDUE")"
  headline="$(verdict_headline "$overall" "$R_KILLSWITCH")"
  code="$(verdict_exit_code "$overall")"

  step "VERDICT"
  say "A. default route unchanged while connected  [$R_ROUTE_DURING] $D_ROUTE_DURING"
  say "B. direct connectivity untouched            [$R_DIRECT_STABLE] $D_DIRECT_STABLE"
  say "C. proxied egress uses the tunnel           [$R_EGRESS] $D_EGRESS"
  say "D. zero local DNS lookups                   [$R_DNS] $D_DNS"
  say "E. fail-closed when the tunnel dies         [$R_KILLSWITCH] $D_KILLSWITCH"
  say "F. default route unchanged after teardown   [$R_ROUTE_AFTER] $D_ROUTE_AFTER"
  say "G. no route residue                         [$R_RESIDUE] $D_RESIDUE"
  say ""
  say "$headline"
  say ""
  say "Not covered by this run: IPC peer authentication. The daemon was built with"
  say "dev-insecure-ipc, which reduces the macOS authenticator to a uid check, because a shell"
  say "script cannot present the GUI's code signature. SPEC.md §7.3 is verified elsewhere."
  if [ "$code" = "$EXIT_SKIP" ]; then
    say ""
    say "This run exits $EXIT_SKIP (SKIP), not $EXIT_PASS: at least one property above is [skip] and was"
    say "never measured. Treat it as an unfinished run, not as evidence."
  fi
  [ "$code" = "$EXIT_FAIL" ] || return "$code"
  say ""
  say "What a FAIL means:"
  say "  A/B/F/G — the client is modifying or leaving residue in the system networking stack."
  say "            SPEC.md §3.1 point 5 says it must not. Fix teardown and policy scope before"
  say "            anything ships."
  say "  C       — proxied traffic is not leaving through the tunnel. The product's entire"
  say "            purpose is unimplemented, whatever the connection state says."
  say "  D       — names are resolved outside the tunnel. SPEC.md §5.4 calls this a release"
  say "            blocker, not a bug."
  say "  E       — the proxy is fail-OPEN. Users would keep browsing, believing they are"
  say "            tunnelled, while every packet leaves under their real identity. Do not ship"
  say "            a build that fails this; re-derive the floor route and teardown order first."
  return "$EXIT_FAIL"
}

main() {
  parse_args "$@"

  if [ "$SELF_TEST" = "yes" ]; then
    run_self_test
    return
  fi
  if [ "$CONFIRMED" != "yes" ]; then
    print_plan
    return
  fi

  local verdict
  preflight
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  build_daemon

  trap cleanup EXIT INT TERM
  WORK_DIR="$(mktemp -d)"
  write_json_helper

  step "Recording the system default route BEFORE anything runs"
  DEFAULT_ROUTE_BEFORE="$(snapshot_default_route)"
  printf '%s\n' "$DEFAULT_ROUTE_BEFORE"

  step "Baseline: the public IP this machine has right now, with no VPN"
  DIRECT_IP="$(curl_direct || true)"
  is_ip_literal "$DIRECT_IP" ||
    skip_out "the echo endpoint $ECHO_URL did not return an IP address before connecting.
Every assertion below compares against it, so nothing here can be measured on this network.
Point --echo-url (or THISCONNECT_ECHO_URL) at an endpoint that answers with a bare IP."
  say "direct public IP: $DIRECT_IP"

  start_daemon
  ipc_open
  handshake
  import_profile
  connect_and_authenticate
  capture_tunnel_device
  fetch_proxy_url

  # Measured before assertion B, which needs to know the tunnel's exit address in
  # order to tell "the upstream network moved our address" apart from "our own
  # traffic was captured by the tunnel". Reported under C, where it belongs.
  PROXY_IP="$(curl_proxied || true)"

  step "A. System default route, WHILE the tunnel is up"
  verdict="$(route_verdict "$(default_route_changed)" "while connected")"
  R_ROUTE_DURING="${verdict%% *}"
  D_ROUTE_DURING="${verdict#* }"
  say "$R_ROUTE_DURING: $D_ROUTE_DURING"

  step "B. The machine's own connectivity, WHILE the tunnel is up"
  verdict="$(direct_stability_verdict "$DIRECT_IP" "$(curl_direct || true)" "${PROXY_IP:-}")"
  R_DIRECT_STABLE="${verdict%% *}"
  D_DIRECT_STABLE="${verdict#* }"
  say "$R_DIRECT_STABLE: $D_DIRECT_STABLE"

  assert_egress
  assert_dns
  assert_killswitch
  teardown_and_assert_clean
  print_verdict
}

# ---------------------------------------------------------------------------
# Unit tests for the pure decision functions. Safe anywhere, as any user.
# ---------------------------------------------------------------------------

TESTS_RUN=0
TESTS_FAILED=0

check_eq() {
  local name="$1" expected="$2" actual="$3"
  TESTS_RUN=$((TESTS_RUN + 1))
  if [ "$expected" = "$actual" ]; then
    say "ok   $name"
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    say "FAIL $name"
    say "     expected: $expected"
    say "     actual:   $actual"
  fi
}

check_prefix() {
  local name="$1" prefix="$2" actual="$3"
  TESTS_RUN=$((TESTS_RUN + 1))
  case "$actual" in
    "$prefix"*) say "ok   $name" ;;
    *)
      TESTS_FAILED=$((TESTS_FAILED + 1))
      say "FAIL $name"
      say "     expected prefix: $prefix"
      say "     actual:          $actual"
      ;;
  esac
}

check_accepts() {
  local name="$1" fn="$2" value="$3" rc=0
  "$fn" "$value" || rc=$?
  check_eq "$name" "0" "$rc"
}

check_rejects() {
  local name="$1" fn="$2" value="$3" rc=0
  "$fn" "$value" || rc=$?
  check_eq "$name" "1" "$rc"
}

test_accepts_ipv4_and_ipv6_echo_answers() {
  check_accepts "accepts_dotted_quad_echo_answer" is_ip_literal "203.0.113.7"
  check_accepts "accepts_ipv6_echo_answer" is_ip_literal "2001:db8::1"
}

test_rejects_a_captive_portal_page_as_an_address() {
  check_rejects "rejects_html_echo_answer" is_ip_literal "<html><body>login</body></html>"
  check_rejects "rejects_empty_echo_answer" is_ip_literal ""
  check_rejects "rejects_out_of_range_octet" is_ip_literal "203.0.113.999"
  check_rejects "rejects_hostname_echo_answer" is_ip_literal "portal.example.net"
}

test_finds_the_daemons_openvpn_child() {
  local sample result
  sample=$'  501     1 launchd\n  900   777 openvpn\n  901   777 curl'
  result="$(printf '%s\n' "$sample" | pick_openvpn_child 777)"
  check_eq "finds_the_daemons_openvpn_child" "900" "$result"
}

test_ignores_an_unrelated_openvpn_process() {
  local sample result
  sample=$'  900   111 openvpn\n  901   777 curl'
  result="$(printf '%s\n' "$sample" | pick_openvpn_child 777)"
  check_eq "ignores_an_unrelated_openvpn_process" "" "$result"
}

test_spots_a_leftover_scoped_route() {
  local sample result
  sample=$'default            10.8.0.1           UGScg          utun7\n192.168.1.0/24     link#4             UCS            en0'
  result="$(printf '%s\n' "$sample" | routes_mentioning_device utun7 | wc -l | tr -d ' ')"
  check_eq "spots_a_leftover_scoped_route" "1" "$result"
}

test_does_not_confuse_utun7_with_utun70() {
  local sample result
  sample=$'default            10.8.0.1           UGScg          utun70'
  result="$(printf '%s\n' "$sample" | routes_mentioning_device utun7)"
  check_eq "does_not_confuse_utun7_with_utun70" "" "$result"
}

test_egress_fails_when_the_proxy_shares_the_direct_ip() {
  check_prefix "egress_fails_when_the_proxy_shares_the_direct_ip" "fail proxied egress used the SAME" \
    "$(egress_verdict "203.0.113.7" "203.0.113.7")"
}

test_egress_fails_when_the_proxy_returns_nothing() {
  check_prefix "egress_fails_when_the_proxy_returns_nothing" "fail the proxy returned no address" \
    "$(egress_verdict "203.0.113.7" "")"
}

test_egress_skips_when_the_proxy_answer_is_not_an_address() {
  check_prefix "egress_skips_when_the_proxy_answer_is_not_an_address" "skip" \
    "$(egress_verdict "203.0.113.7" "<html>")"
}

test_egress_passes_on_a_different_exit_address() {
  check_prefix "egress_passes_on_a_different_exit_address" "pass" \
    "$(egress_verdict "203.0.113.7" "198.51.100.4")"
}

test_killswitch_passes_only_when_the_request_fails() {
  check_prefix "killswitch_passes_only_when_the_request_fails" "pass" \
    "$(killswitch_verdict 7 "" "203.0.113.7")"
}

test_killswitch_reports_a_direct_ip_answer_as_fail_open() {
  check_prefix "killswitch_reports_a_direct_ip_answer_as_fail_open" "fail FAIL-OPEN" \
    "$(killswitch_verdict 0 "203.0.113.7" "203.0.113.7")"
}

test_killswitch_fails_even_when_the_answer_is_still_the_exit_ip() {
  check_prefix "killswitch_fails_even_when_the_answer_is_still_the_exit_ip" "fail the proxy still served" \
    "$(killswitch_verdict 0 "198.51.100.4" "203.0.113.7")"
}

test_dns_verdict_skips_when_no_counter_is_reported() {
  check_prefix "dns_verdict_skips_when_no_counter_is_reported" "skip" "$(dns_verdict "" "4")"
}

test_dns_verdict_fails_on_any_local_lookup() {
  check_prefix "dns_verdict_fails_on_any_local_lookup" "fail" "$(dns_verdict "1" "4")"
  check_prefix "dns_verdict_fails_on_a_local_lookup_even_with_no_tunnel_lookups" "fail" \
    "$(dns_verdict "1" "0")"
}

test_dns_verdict_passes_only_on_zero() {
  check_prefix "dns_verdict_passes_only_on_zero" "pass" "$(dns_verdict "0" "4")"
}

# The regression: 0 local lookups in a session that resolved nothing is an unrun measurement,
# not proof of leak-freedom.
test_dns_verdict_skips_when_no_name_was_resolved_at_all() {
  check_prefix "dns_verdict_skips_when_the_tunnel_resolved_nothing" "skip" "$(dns_verdict "0" "0")"
  check_prefix "dns_verdict_skips_when_no_tunnel_counter_is_reported" "skip" "$(dns_verdict "0" "")"
}

test_direct_stability_fails_when_connectivity_is_lost() {
  check_prefix "direct_stability_fails_when_connectivity_is_lost" "fail the machine lost direct" \
    "$(direct_stability_verdict "203.0.113.7" "")"
}

# A moved public address is NOT a failure on its own: upstream networks rotate
# addresses (CGNAT, DHCP churn, carrier reassignment), and failing for that
# measures the ISP rather than this client. What must fail is direct traffic
# leaving from the tunnel's own exit.
test_direct_stability_fails_when_direct_traffic_uses_the_tunnel_exit() {
  check_prefix "direct_stability_fails_when_direct_traffic_uses_the_tunnel_exit" "fail direct" \
    "$(direct_stability_verdict "203.0.113.7" "192.0.2.9" "192.0.2.9")"
}

test_direct_stability_passes_when_unchanged() {
  check_prefix "direct_stability_passes_when_unchanged" "pass" \
    "$(direct_stability_verdict "203.0.113.7" "203.0.113.7")"
  check_eq direct_stability_tolerates_an_upstream_address_change \
    "pass direct traffic did not enter the tunnel (its public IP moved on its own, which upstream networks do; it is not the tunnel exit)" \
    "$(direct_stability_verdict "203.0.113.7" "198.51.100.4" "192.0.2.9")"
  check_eq direct_stability_fails_when_direct_traffic_uses_the_tunnel_exit \
    "fail direct (non-proxied) traffic left from the tunnel exit — the system stack WAS captured" \
    "$(direct_stability_verdict "203.0.113.7" "192.0.2.9" "192.0.2.9")"
}

test_route_verdict_fails_on_any_change() {
  check_prefix "route_verdict_fails_on_any_change" "fail" "$(route_verdict yes "while connected")"
  check_prefix "route_verdict_passes_when_unchanged" "pass" "$(route_verdict no "while connected")"
}

test_residue_verdict_fails_on_leftover_routes() {
  check_prefix "residue_verdict_fails_on_leftover_routes" "fail" \
    "$(residue_verdict "default 10.8.0.1 utun7" utun7)"
  check_prefix "residue_verdict_passes_when_clean" "pass" "$(residue_verdict "" utun7)"
}

test_overall_verdict_is_dominated_by_a_single_failure() {
  check_eq "overall_verdict_is_dominated_by_a_single_failure" "FAIL" \
    "$(overall_verdict pass pass fail pass skip)"
}

test_overall_verdict_reports_gaps_rather_than_a_clean_pass() {
  check_eq "overall_verdict_reports_gaps_rather_than_a_clean_pass" "PASS-WITH-GAPS" \
    "$(overall_verdict pass skip pass)"
}

test_overall_verdict_passes_only_when_everything_passed() {
  check_eq "overall_verdict_passes_only_when_everything_passed" "PASS" \
    "$(overall_verdict pass pass pass)"
}

test_headline_leads_with_the_killswitch_failure() {
  check_prefix "headline_leads_with_the_killswitch_failure" "FAIL — the fail-closed property" \
    "$(verdict_headline PASS fail)"
}

test_headline_marks_an_unmeasured_property() {
  check_prefix "headline_marks_an_unmeasured_property" "PASS-WITH-GAPS" \
    "$(verdict_headline PASS-WITH-GAPS pass)"
}

# The regression that matters most: a gap must never reach a caller as exit 0.
test_a_gap_exits_skip_rather_than_pass() {
  check_eq "pass_with_gaps_exits_skip" "$EXIT_SKIP" "$(verdict_exit_code PASS-WITH-GAPS)"
  check_eq "a_clean_run_exits_pass" "$EXIT_PASS" "$(verdict_exit_code PASS)"
  check_eq "a_failed_run_exits_fail" "$EXIT_FAIL" "$(verdict_exit_code FAIL)"
}

# assert_killswitch is driven only by its guard here; the kill itself needs a live daemon.
test_killswitch_is_skipped_when_egress_never_worked() {
  local R_EGRESS="fail" R_KILLSWITCH="" D_KILLSWITCH="" DAEMON_PID=""
  assert_killswitch >/dev/null
  check_eq "killswitch_is_skipped_when_egress_never_worked" "skip" "$R_KILLSWITCH"
  check_prefix "killswitch_skip_says_the_proxy_was_never_seen_working" \
    "the proxy was never observed working" "$D_KILLSWITCH"
}

test_utun_name_validation() {
  check_accepts "accepts_plain_utun_name" is_valid_utun_name "utun7"
  check_rejects "rejects_utun_name_with_metacharacters" is_valid_utun_name 'utun7;id'
  check_rejects "rejects_non_utun_device" is_valid_utun_name "en0"
}

# The JSON helper is what keeps secrets off argv and out of the log, so its escaping is tested
# rather than assumed. Skipped, loudly, when python3 is unavailable.
test_request_ids_are_unique_across_command_substitutions() {
  local dir first second
  dir="$(mktemp -d)"
  ID_FILE="$dir/idseq"
  first="$(next_id)"
  second="$(next_id)"
  check_eq "request_ids_are_unique_across_command_substitutions" "req-1 req-2" "$first $second"
  rm -rf "$dir"
  ID_FILE=""
}

test_json_helper_round_trips_a_password_from_stdin() {
  local dir line
  if ! command -v python3 >/dev/null; then
    say "skip json helper tests: python3 not available"
    return 0
  fi
  PY="$(command -v python3)"
  dir="$(mktemp -d)"
  WORK_DIR="$dir"
  write_json_helper

  line="$(printf '%s\n%s' 'alice' 'pa"ss\word
with-newline' | "$PY" "$JSON_HELPER" reply r1 prompt-1 username_password)"
  check_eq "json_helper_escapes_a_hostile_password" 'pa"ss\word' \
    "$(printf '%s' "$line" | "$PY" "$JSON_HELPER" get reply.password)"
  # Framing is load-bearing: an embedded newline in an encoded secret would split one message
  # into two and the daemon would reject the pair (docs/IPC.md §1).
  check_eq "json_helper_never_emits_an_embedded_newline" "0" \
    "$(printf '%s' "$line" | wc -l | tr -d ' ')"

  printf '%s\n' '{"type":"event","event":{"type":"state","state":"connected"}}' >"$dir/lines"
  printf '%s\n' '{"type":"response","id":"req-1","response":{"type":"proxy"}}' >>"$dir/lines"
  check_eq "json_helper_finds_a_line_by_nested_criteria" \
    '{"type":"event","event":{"type":"state","state":"connected"}}' \
    "$("$PY" "$JSON_HELPER" find "$dir/lines" type=event event.state=connected)"
  local rc=0
  "$PY" "$JSON_HELPER" find "$dir/lines" type=event event.state=failed >/dev/null 2>&1 || rc=$?
  check_eq "json_helper_reports_no_match" "1" "$rc"

  rm -rf "$dir"
  WORK_DIR=""
}

run_self_test() {
  test_accepts_ipv4_and_ipv6_echo_answers
  test_rejects_a_captive_portal_page_as_an_address
  test_finds_the_daemons_openvpn_child
  test_ignores_an_unrelated_openvpn_process
  test_spots_a_leftover_scoped_route
  test_does_not_confuse_utun7_with_utun70
  test_egress_fails_when_the_proxy_shares_the_direct_ip
  test_egress_fails_when_the_proxy_returns_nothing
  test_egress_skips_when_the_proxy_answer_is_not_an_address
  test_egress_passes_on_a_different_exit_address
  test_killswitch_passes_only_when_the_request_fails
  test_killswitch_reports_a_direct_ip_answer_as_fail_open
  test_killswitch_fails_even_when_the_answer_is_still_the_exit_ip
  test_dns_verdict_skips_when_no_counter_is_reported
  test_dns_verdict_fails_on_any_local_lookup
  test_dns_verdict_passes_only_on_zero
  test_dns_verdict_skips_when_no_name_was_resolved_at_all
  test_direct_stability_fails_when_connectivity_is_lost
  test_direct_stability_fails_when_direct_traffic_uses_the_tunnel_exit
  test_direct_stability_passes_when_unchanged
  test_route_verdict_fails_on_any_change
  test_residue_verdict_fails_on_leftover_routes
  test_overall_verdict_is_dominated_by_a_single_failure
  test_overall_verdict_reports_gaps_rather_than_a_clean_pass
  test_overall_verdict_passes_only_when_everything_passed
  test_headline_leads_with_the_killswitch_failure
  test_headline_marks_an_unmeasured_property
  test_a_gap_exits_skip_rather_than_pass
  test_killswitch_is_skipped_when_egress_never_worked
  test_utun_name_validation
  test_request_ids_are_unique_across_command_substitutions
  test_json_helper_round_trips_a_password_from_stdin
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
