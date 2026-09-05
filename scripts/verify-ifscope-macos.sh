#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# docs/SPEC.md §10 test 1 — the one [U] claim the whole macOS half of the design rests on.
#
# Claim under test: an interface-scoped default route
#     route -n add -inet -ifscope <utunN> default <peer|-interface utunN>
# makes an outbound TCP socket pinned with IP_BOUND_IF to <utunN> flip from ENETUNREACH
# to a usable connection, WITHOUT altering the unscoped system default route.
#
# Both halves are asserted. The negative case (no scoped route => ENETUNREACH) is what
# proves the design is fail-closed; a positive-only test proves nothing.

set -euo pipefail

readonly UTUN_UNIT_MIN=90
readonly UTUN_UNIT_MAX=99
readonly SYNTHETIC_LOCAL="10.255.255.2"
readonly SYNTHETIC_PEER="10.255.255.1"
readonly OPENVPN_READY_TIMEOUT_S=90
readonly UTUN_HELPER_TRIES=25
readonly UTUN_HELPER_POLL_S=0.2

# Probe exit codes. Shared vocabulary with verify-egress-linux.sh.
readonly RC_CONNECTED=0
readonly RC_ENETUNREACH=10
readonly RC_EHOSTUNREACH=11
readonly RC_OTHER_ERRNO=12
readonly RC_PENDING=13
readonly RC_SETUP=20

DST_IP="1.1.1.1"
DST_PORT="443"
PROBE_TIMEOUT_MS="4000"
PROFILE=""
CONFIRMED="no"
SELF_TEST="no"
COMPILE_CHECK="no"

WORK_DIR=""
PROBE_BIN=""
UTUN_HELPER_BIN=""
UTUN_HELPER_PID=""
OPENVPN_PID=""
TUNNEL_DEV=""
TUNNEL_PEER=""
DEFAULT_ROUTE_BEFORE=""
GATEWAY_ROUTE_INSTALLED="no"
INTERFACE_ROUTE_INSTALLED="no"
SCOPED_LEAK="no"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
verify-ifscope-macos.sh — prove or disprove docs/SPEC.md §10 test 1.

  sudo ./scripts/verify-ifscope-macos.sh --confirm
  sudo ./scripts/verify-ifscope-macos.sh --confirm --profile ~/vpn/example.ovpn

Modes:
  synthetic (default)  Creates a throwaway utun and drives the test with no VPN server at all.
                       Fully reproducible on any Mac. Because nothing is listening on the far
                       side, the pass criterion is the errno moving OFF ENETUNREACH (route
                       lookup succeeded), not a completed handshake.
  openvpn (--profile)  Drives the real openvpn binary with the §4.1 flags that matter here
                       (--route-noexec, pull-filter ignore route/redirect-gateway,
                       --script-security 1, --dns-updown disable). Pass criterion is a
                       completed TCP connection through the tunnel. This script has no
                       management client, so the profile must not need interactive
                       credentials: a bare `auth-user-pass` with no file and no inline block
                       is refused up front (docs/SPEC.md §4.1).

Options:
  --confirm            Required. Without it nothing is changed; the plan is printed instead.
  --profile PATH       Use a real .ovpn profile instead of a synthetic utun.
  --dst IPV4           Probe destination (default 1.1.1.1).
  --port N             Probe destination port (default 443).
  --timeout MS         Probe connect timeout (default 4000).
  --self-test          Run the pure-function unit tests and exit. Touches nothing, needs no root.
  --compile-check      Compile the embedded C helpers into a temp dir and exit. macOS only,
                       needs no root, changes nothing. For CI.
  -h, --help           This text.

Every route and interface created here is removed on exit, including on failure.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --self-test) SELF_TEST="yes" ;;
      --compile-check) COMPILE_CHECK="yes" ;;
      --profile)
        [ "$#" -ge 2 ] || die "--profile needs a path"
        PROFILE="$2"
        shift
        ;;
      --dst)
        [ "$#" -ge 2 ] || die "--dst needs an address"
        DST_IP="$2"
        shift
        ;;
      --port)
        [ "$#" -ge 2 ] || die "--port needs a number"
        DST_PORT="$2"
        shift
        ;;
      --timeout)
        [ "$#" -ge 2 ] || die "--timeout needs milliseconds"
        PROBE_TIMEOUT_MS="$2"
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
# Pure helpers. Covered by --self-test; no side effects, no system calls.
# ---------------------------------------------------------------------------

errno_label() {
  case "$1" in
    "$RC_CONNECTED") echo "CONNECTED" ;;
    "$RC_ENETUNREACH") echo "ENETUNREACH(51)" ;;
    "$RC_EHOSTUNREACH") echo "EHOSTUNREACH(65)" ;;
    "$RC_OTHER_ERRNO") echo "other-errno" ;;
    "$RC_PENDING") echo "PENDING(no-error-before-timeout)" ;;
    "$RC_SETUP") echo "probe-setup-failure" ;;
    *) echo "unexpected-rc-$1" ;;
  esac
}

# The tunnel identity is scraped out of a log that carries verbatim, server-controlled text
# (`PUSH: Received control message: 'PUSH_REPLY,...'` at --verb 3; docs/SPEC.md §4.2 records
# that sanitize_control_message() scrubs auth tokens only). Everything derived from that log
# is passed to root `route`/`ifconfig` calls, so it is untrusted input and is validated to a
# closed shape before any use.
is_valid_utun_name() {
  [[ "$1" =~ ^utun[0-9]{1,3}$ ]]
}

is_valid_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local octet
  # bash's `[` reads integers base 10, so a zero-padded octet needs no special handling.
  for octet in "${BASH_REMATCH[@]:1}"; do
    [ "$octet" -le 255 ] || return 1
  done
  return 0
}

# stdin: interface names, one per line. Prints the first free utun unit in range.
pick_free_utun_unit() {
  local taken unit
  taken="$(cat)"
  for unit in $(seq "$UTUN_UNIT_MIN" "$UTUN_UNIT_MAX"); do
    if ! printf '%s\n' "$taken" | grep -qx "utun${unit}"; then
      printf '%s\n' "$unit"
      return 0
    fi
  done
  return 1
}

# stdin: openvpn log. Prints "<dev> <local> <peer>" from the macOS tun bring-up line.
parse_openvpn_tunnel() {
  awk '
    /\/sbin\/ifconfig[[:space:]]+utun[0-9]+[[:space:]]/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^utun[0-9]+$/) { print $i, $(i + 1), $(i + 2); exit }
      }
    }
  '
}

# stdin: an .ovpn profile. Prints none | file | inline | interactive.
# "interactive" means openvpn will prompt for a username/password, which needs
# --management-query-passwords (docs/SPEC.md §4.1 [V]) that this script does not implement.
profile_auth_mode() {
  awk '
    { sub(/\r$/, "") }
    /^[[:space:]]*<auth-user-pass>[[:space:]]*$/ { mode = "inline"; next }
    /^[[:space:]]*auth-user-pass[[:space:]]*$/ { mode = "interactive"; next }
    /^[[:space:]]*auth-user-pass[[:space:]]+[^[:space:]]/ { mode = "file"; next }
    END { print (mode == "" ? "none" : mode) }
  '
}

# evaluate_verdict <mode> <neg_rc> <gw_rc> <iface_rc> -> "PASS <detail>" | "FAIL <detail>"
evaluate_verdict() {
  local mode="$1" neg="$2" gw="$3" iface="$4"

  if [ "$neg" != "$RC_ENETUNREACH" ]; then
    echo "FAIL negative case did not fail closed: expected ENETUNREACH without a scoped route, got $(errno_label "$neg")"
    return 0
  fi

  local ok_gw="no" ok_iface="no"
  scoped_route_worked "$mode" "$gw" && ok_gw="yes"
  scoped_route_worked "$mode" "$iface" && ok_iface="yes"

  if [ "$ok_gw" = "no" ] && [ "$ok_iface" = "no" ]; then
    echo "FAIL scoped route did not change the pinned lookup: gateway=$(errno_label "$gw") interface=$(errno_label "$iface")"
    return 0
  fi
  echo "PASS negative=ENETUNREACH gateway-variant=$(errno_label "$gw")[$ok_gw] interface-variant=$(errno_label "$iface")[$ok_iface]"
}

# final_verdict <mode> <neg> <gw> <iface> <route_ok> <scoped_leak>
# A default-route change outranks the errno result: leaking into the unscoped lookup breaks the
# product's core promise even if the pinned socket behaved exactly as hoped.
final_verdict() {
  local mode="$1" neg="$2" gw="$3" iface="$4" route_ok="$5" scoped_leak="$6"
  if [ "$scoped_leak" != "no" ]; then
    echo "FAIL the unscoped default route changed WHILE a scoped route was installed — SPEC §5.2's macOS premise does not hold"
    return 0
  fi
  if [ "$route_ok" != "yes" ]; then
    echo "FAIL system default route was modified — the product's core promise is broken regardless of the scoped-route result"
    return 0
  fi
  evaluate_verdict "$mode" "$neg" "$gw" "$iface"
}

# In synthetic mode nothing answers, so "route was accepted" is the strongest honest signal.
scoped_route_worked() {
  local mode="$1" rc="$2"
  if [ "$mode" = "openvpn" ]; then
    [ "$rc" = "$RC_CONNECTED" ]
    return
  fi
  [ "$rc" = "$RC_CONNECTED" ] || [ "$rc" = "$RC_PENDING" ]
}

# ---------------------------------------------------------------------------
# Teardown. Fixed steps guarded by booleans — never strings fed to eval, because
# TUNNEL_DEV/TUNNEL_PEER can originate in a hostile server's pushed options.
# ---------------------------------------------------------------------------

undo_gateway_route() {
  [ "$GATEWAY_ROUTE_INSTALLED" = "yes" ] || return 0
  say "  - route -n delete -inet -ifscope $TUNNEL_DEV default $TUNNEL_PEER"
  route -n delete -inet -ifscope "$TUNNEL_DEV" default "$TUNNEL_PEER" >/dev/null 2>&1 ||
    warn "could not remove the gateway-variant scoped route (may already be gone)"
  GATEWAY_ROUTE_INSTALLED="no"
}

undo_interface_route() {
  [ "$INTERFACE_ROUTE_INSTALLED" = "yes" ] || return 0
  say "  - route -n delete -inet -ifscope $TUNNEL_DEV default -interface $TUNNEL_DEV"
  route -n delete -inet -ifscope "$TUNNEL_DEV" default -interface "$TUNNEL_DEV" >/dev/null 2>&1 ||
    warn "could not remove the interface-variant scoped route (may already be gone)"
  INTERFACE_ROUTE_INSTALLED="no"
}

# A Darwin utun's lifetime is its PF_SYSTEM control-socket fd, held by the helper process.
# There is no `ifconfig utunN destroy`; killing the holder is the destroy.
destroy_utun() {
  [ -n "$UTUN_HELPER_PID" ] || return 0
  if kill -0 "$UTUN_HELPER_PID" 2>/dev/null; then
    say "cleanup: closing the utun control socket (pid $UTUN_HELPER_PID)"
    kill -TERM "$UTUN_HELPER_PID" 2>/dev/null || true
    wait "$UTUN_HELPER_PID" 2>/dev/null || true
  fi
  UTUN_HELPER_PID=""
}

cleanup() {
  local rc=$?
  set +e
  if [ -n "$OPENVPN_PID" ] && kill -0 "$OPENVPN_PID" 2>/dev/null; then
    say "cleanup: terminating openvpn pid $OPENVPN_PID"
    kill -TERM "$OPENVPN_PID" 2>/dev/null
    wait "$OPENVPN_PID" 2>/dev/null
  fi
  # Routes before the interface that carries them.
  undo_interface_route
  undo_gateway_route
  destroy_utun
  [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
  exit "$rc"
}

mutate() {
  say "  + $*"
  "$@"
}

# ---------------------------------------------------------------------------
# Compiled helpers
# ---------------------------------------------------------------------------

write_probe_source() {
  cat >"$WORK_DIR/probe.c" <<'PROBE_C'
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Pins a socket to an interface with IP_BOUND_IF and reports the connect() errno. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RC_CONNECTED 0
#define RC_ENETUNREACH 10
#define RC_EHOSTUNREACH 11
#define RC_OTHER_ERRNO 12
#define RC_PENDING 13
#define RC_SETUP 20

static int report(const char *phase, int err) {
  printf("PROBE phase=%s errno=%d name=%s\n", phase, err,
         err == 0 ? "none" : strerror(err));
  if (err == 0) return RC_CONNECTED;
  if (err == ENETUNREACH) return RC_ENETUNREACH;
  if (err == EHOSTUNREACH) return RC_EHOSTUNREACH;
  return RC_OTHER_ERRNO;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: probe <ifname> <dst-ipv4> <port> <timeout-ms>\n");
    return RC_SETUP;
  }
  unsigned int idx = if_nametoindex(argv[1]);
  if (idx == 0) {
    fprintf(stderr, "probe: if_nametoindex(%s): %s\n", argv[1], strerror(errno));
    return RC_SETUP;
  }
  struct sockaddr_in dst;
  memset(&dst, 0, sizeof dst);
  dst.sin_len = sizeof dst;
  dst.sin_family = AF_INET;
  dst.sin_port = htons((unsigned short)atoi(argv[3]));
  if (inet_pton(AF_INET, argv[2], &dst.sin_addr) != 1) {
    fprintf(stderr, "probe: bad destination %s\n", argv[2]);
    return RC_SETUP;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "probe: socket: %s\n", strerror(errno));
    return RC_SETUP;
  }
  fprintf(stderr, "probe: binding to %s (ifindex %u)\n", argv[1], idx);
  if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof idx) < 0) {
    fprintf(stderr, "probe: setsockopt(IP_BOUND_IF): %s\n", strerror(errno));
    close(fd);
    return RC_SETUP;
  }
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    fprintf(stderr, "probe: fcntl: %s\n", strerror(errno));
    close(fd);
    return RC_SETUP;
  }
  int rc = connect(fd, (struct sockaddr *)&dst, sizeof dst);
  if (rc == 0) {
    close(fd);
    return report("immediate", 0);
  }
  if (errno != EINPROGRESS) {
    int saved = errno;
    close(fd);
    return report("immediate", saved);
  }
  struct pollfd pfd = {.fd = fd, .events = POLLOUT};
  int pr = poll(&pfd, 1, atoi(argv[4]));
  if (pr < 0) {
    int saved = errno;
    close(fd);
    fprintf(stderr, "probe: poll: %s\n", strerror(saved));
    return RC_SETUP;
  }
  if (pr == 0) {
    close(fd);
    printf("PROBE phase=deferred errno=0 name=timeout-still-pending\n");
    return RC_PENDING;
  }
  int soerr = 0;
  socklen_t len = sizeof soerr;
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0) {
    int saved = errno;
    close(fd);
    fprintf(stderr, "probe: getsockopt(SO_ERROR): %s\n", strerror(saved));
    return RC_SETUP;
  }
  close(fd);
  return report("deferred", soerr);
}
PROBE_C
}

write_mkutun_source() {
  cat >"$WORK_DIR/mkutun.c" <<'MKUTUN_C'
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Creates a Darwin utun and holds it open.
 *
 * `ifconfig utunN create` cannot work here: utun is not an interface cloner (it is absent from
 * `ifconfig -C`), and a utun exists only for as long as some process holds the PF_SYSTEM /
 * com.apple.net.utun_control socket it was created from. So this process prints the interface
 * name and then blocks; the interface disappears when it is killed. */
#include <errno.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#define RC_SETUP 20

static int fail(const char *what) {
  fprintf(stderr, "mkutun: %s: %s\n", what, strerror(errno));
  return RC_SETUP;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: mkutun <unit>\n");
    return RC_SETUP;
  }
  long unit = strtol(argv[1], NULL, 10);
  if (unit < 0 || unit > 65534) {
    fprintf(stderr, "mkutun: unit out of range: %s\n", argv[1]);
    return RC_SETUP;
  }
  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd < 0) return fail("socket(PF_SYSTEM)");

  struct ctl_info info;
  memset(&info, 0, sizeof info);
  strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof info.ctl_name - 1);
  if (ioctl(fd, CTLIOCGINFO, &info) < 0) return fail("ioctl(CTLIOCGINFO)");

  struct sockaddr_ctl addr;
  memset(&addr, 0, sizeof addr);
  addr.sc_len = sizeof addr;
  addr.sc_family = AF_SYSTEM;
  addr.ss_sysaddr = AF_SYS_CONTROL;
  addr.sc_id = info.ctl_id;
  /* sc_unit N+1 yields utunN; 0 would let the kernel pick, which we do not want here. */
  addr.sc_unit = (u_int32_t)(unit + 1);
  if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) return fail("connect(utun)");

  char name[IFNAMSIZ];
  memset(name, 0, sizeof name);
  socklen_t len = sizeof name;
  if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) < 0)
    return fail("getsockopt(UTUN_OPT_IFNAME)");

  printf("%s\n", name);
  fflush(stdout);
  for (;;) pause();
}
MKUTUN_C
}

build_helpers() {
  local compiler
  compiler="$(command -v clang || command -v cc || true)"
  [ -n "$compiler" ] || die "no C compiler found; install the Xcode command line tools"
  WORK_DIR="$(mktemp -d)"
  write_probe_source
  write_mkutun_source
  "$compiler" -Wall -Wextra -O1 -o "$WORK_DIR/probe" "$WORK_DIR/probe.c" ||
    die "failed to compile the probe"
  "$compiler" -Wall -Wextra -O1 -o "$WORK_DIR/mkutun" "$WORK_DIR/mkutun.c" ||
    die "failed to compile the utun helper"
  PROBE_BIN="$WORK_DIR/probe"
  UTUN_HELPER_BIN="$WORK_DIR/mkutun"
}

run_probe() {
  local ifname="$1" rc=0
  "$PROBE_BIN" "$ifname" "$DST_IP" "$DST_PORT" "$PROBE_TIMEOUT_MS" || rc=$?
  return "$rc"
}

snapshot_default_route() {
  route -n get -inet default 2>&1 || true
}

assert_default_route_unchanged() {
  local before="$1" after="$2" context="$3"
  if [ "$before" = "$after" ]; then
    say "system default route is byte-for-byte unchanged ($context)."
    return 0
  fi
  say "SYSTEM DEFAULT ROUTE CHANGED ($context) — this alone fails the run:"
  diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") || true
  return 1
}

# ---------------------------------------------------------------------------
# Tunnel bring-up
# ---------------------------------------------------------------------------

bring_up_synthetic_utun() {
  local unit dev="" tries=0
  unit="$(ifconfig -l | tr ' ' '\n' | pick_free_utun_unit)" ||
    die "no free utun unit in ${UTUN_UNIT_MIN}..${UTUN_UNIT_MAX}"
  step "Creating throwaway interface utun${unit} ($SYNTHETIC_LOCAL -> $SYNTHETIC_PEER)"
  say "  + mkutun ${unit}   (opens com.apple.net.utun_control and holds the fd)"

  "$UTUN_HELPER_BIN" "$unit" >"$WORK_DIR/utun.name" 2>"$WORK_DIR/utun.err" </dev/null &
  UTUN_HELPER_PID=$!
  while [ "$tries" -lt "$UTUN_HELPER_TRIES" ]; do
    dev="$(head -n 1 "$WORK_DIR/utun.name")"
    [ -z "$dev" ] || break
    kill -0 "$UTUN_HELPER_PID" 2>/dev/null || break
    sleep "$UTUN_HELPER_POLL_S"
    tries=$((tries + 1))
  done
  dev="$(head -n 1 "$WORK_DIR/utun.name")"
  is_valid_utun_name "$dev" ||
    die "could not create a utun: $(cat "$WORK_DIR/utun.err" 2>/dev/null)"
  [ "$dev" = "utun${unit}" ] || die "utun helper returned $dev, expected utun${unit}"

  mutate ifconfig "$dev" inet "$SYNTHETIC_LOCAL" "$SYNTHETIC_PEER" netmask 255.255.255.255 up
  TUNNEL_DEV="$dev"
  TUNNEL_PEER="$SYNTHETIC_PEER"
}

assert_profile_is_noninteractive() {
  local auth_mode
  auth_mode="$(profile_auth_mode <"$PROFILE")"
  [ "$auth_mode" = "interactive" ] || return 0
  die "profile uses a bare 'auth-user-pass' (interactive credentials). docs/SPEC.md §4.1 [V]:
without --management-query-passwords openvpn dies before auth with 'neither stdin nor stderr
are a tty device ... can't ask for Enter Auth Username'. This script has no management client.
Point --profile at a profile carrying 'auth-user-pass <file>' or an inline <auth-user-pass>
block, or use the default synthetic mode."
}

bring_up_openvpn() {
  local log parsed waited=0
  command -v openvpn >/dev/null || die "openvpn not found in PATH"
  assert_profile_is_noninteractive
  log="$WORK_DIR/openvpn.log"
  step "Starting openvpn with --route-noexec (it will install no routes of its own)"
  say "  + openvpn --config $PROFILE --route-noexec --pull-filter ignore route ..."
  openvpn --config "$PROFILE" \
    --route-noexec \
    --pull-filter ignore "route" \
    --pull-filter ignore "redirect-gateway" \
    --script-security 1 \
    --dns-updown disable \
    --allow-compression no \
    --auth-retry interact \
    --auth-nocache \
    --verb 3 >"$log" 2>&1 </dev/null &
  OPENVPN_PID=$!

  while [ "$waited" -lt "$OPENVPN_READY_TIMEOUT_S" ]; do
    kill -0 "$OPENVPN_PID" 2>/dev/null || die "openvpn exited early; see $log"
    if grep -q "Initialization Sequence Completed" "$log"; then break; fi
    sleep 1
    waited=$((waited + 1))
  done
  grep -q "Initialization Sequence Completed" "$log" ||
    die "openvpn did not connect within ${OPENVPN_READY_TIMEOUT_S}s; see $log"

  parsed="$(parse_openvpn_tunnel <"$log")"
  [ -n "$parsed" ] || die "could not parse the utun bring-up line from the openvpn log"
  # shellcheck disable=SC2086 # deliberate word split of "<dev> <local> <peer>"
  set -- $parsed
  [ "$#" -eq 3 ] || die "malformed tun bring-up line in the openvpn log"
  # At --verb 3 the log also contains the server's pushed options verbatim, so a hostile server
  # can plant a line that this parser matches first. Nothing downstream runs until it is a name
  # and an address and nothing else.
  is_valid_utun_name "$1" || die "refusing suspicious tun device name from the openvpn log: $1"
  is_valid_ipv4 "$3" || die "refusing suspicious tunnel peer address from the openvpn log: $3"
  TUNNEL_DEV="$1"
  TUNNEL_PEER="$3"
  say "openvpn brought up $TUNNEL_DEV local=$2 peer=$TUNNEL_PEER"
}

# ---------------------------------------------------------------------------
# The experiment
# ---------------------------------------------------------------------------

measure_with_scoped_route() {
  local variant="$1" rc=0
  step "Positive case, $variant variant"
  case "$variant" in
    gateway)
      mutate route -n add -inet -ifscope "$TUNNEL_DEV" default "$TUNNEL_PEER"
      GATEWAY_ROUTE_INSTALLED="yes"
      ;;
    interface)
      mutate route -n add -inet -ifscope "$TUNNEL_DEV" default -interface "$TUNNEL_DEV"
      INTERFACE_ROUTE_INSTALLED="yes"
      ;;
    *) die "unknown variant $variant" ;;
  esac

  # The leak §5.2 rules out is only observable WHILE the scoped route exists. Comparing two
  # snapshots taken after teardown cannot see it and would report PASS on a real leak.
  assert_default_route_unchanged "$DEFAULT_ROUTE_BEFORE" "$(snapshot_default_route)" \
    "with the $variant scoped route installed" || SCOPED_LEAK="yes"

  run_probe "$TUNNEL_DEV" || rc=$?
  say "result: $(errno_label "$rc")"

  case "$variant" in
    gateway) undo_gateway_route ;;
    interface) undo_interface_route ;;
  esac
  return "$rc"
}

print_plan() {
  cat <<EOF
This run will, as root:
  - create a throwaway utun by opening its kernel control socket (synthetic mode) or start
    openvpn from a profile (--profile mode)
  - assign it $SYNTHETIC_LOCAL -> $SYNTHETIC_PEER (synthetic mode only)
  - add and then remove:
      route -n add -inet -ifscope <utunN> default <peer>
      route -n add -inet -ifscope <utunN> default -interface <utunN>
  - open TCP connections to ${DST_IP}:${DST_PORT} pinned to that interface
  - compare the unscoped default route before, while each scoped route is installed, and after
  - destroy everything it created, including on failure

It will NOT touch the system default route, resolv.conf, or any existing interface.
Re-run with --confirm to execute.
EOF
}

main() {
  parse_args "$@"

  if [ "$SELF_TEST" = "yes" ]; then
    run_self_test
    return
  fi

  [ "$(uname -s)" = "Darwin" ] || die "this test is macOS-only; see verify-egress-linux.sh"
  if [ "$COMPILE_CHECK" = "yes" ]; then
    trap cleanup EXIT INT TERM
    build_helpers
    say "probe and utun helper compiled cleanly"
    return
  fi
  if [ "$CONFIRMED" != "yes" ]; then
    print_plan
    return
  fi
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --confirm)"
  [ -z "$PROFILE" ] || [ -r "$PROFILE" ] || die "profile not readable: $PROFILE"

  local mode="synthetic"
  [ -z "$PROFILE" ] || mode="openvpn"

  trap cleanup EXIT INT TERM
  build_helpers

  step "Recording the system default route BEFORE any change"
  DEFAULT_ROUTE_BEFORE="$(snapshot_default_route)"
  printf '%s\n' "$DEFAULT_ROUTE_BEFORE"

  if [ "$mode" = "openvpn" ]; then bring_up_openvpn; else bring_up_synthetic_utun; fi

  step "Negative case: pinned socket with NO scoped route (must be ENETUNREACH)"
  local neg=0
  run_probe "$TUNNEL_DEV" || neg=$?
  say "result: $(errno_label "$neg")"

  local gw=0 iface=0
  measure_with_scoped_route gateway || gw=$?
  measure_with_scoped_route interface || iface=$?

  step "Recording the system default route AFTER teardown"
  local after route_ok="yes"
  after="$(snapshot_default_route)"
  printf '%s\n' "$after"
  assert_default_route_unchanged "$DEFAULT_ROUTE_BEFORE" "$after" "after teardown" || route_ok="no"

  print_verdict "$mode" "$neg" "$gw" "$iface" "$route_ok" "$SCOPED_LEAK"
}

print_verdict() {
  local mode="$1" verdict
  verdict="$(final_verdict "$@")"

  step "VERDICT (mode: $mode)"
  say "$verdict"
  if [ "$mode" = "synthetic" ]; then
    say ""
    say "Synthetic mode proves the ROUTE LOOKUP, not end-to-end data flow: nothing answers on"
    say "$SYNTHETIC_PEER, so a pending connect is the expected success shape. Re-run with"
    say "--profile against a real server to prove a completed handshake."
  fi
  case "$verdict" in
    PASS*) return 0 ;;
    *)
      say ""
      say "What a FAIL means: docs/SPEC.md §5.2's macOS half does not hold. Interface-scoped"
      say "routing cannot be the egress mechanism, and macOS needs a redesign — most likely a"
      say "userspace TCP/IP stack over the utun, or full-tunnel-only on macOS — BEFORE any"
      say "further macOS code is written. Record the output here in docs/SPEC.md §13 item 1."
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Unit tests for the pure helpers. Safe to run anywhere, as any user.
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

check_rejects() {
  local name="$1" fn="$2" value="$3" rc=0
  "$fn" "$value" || rc=$?
  check_eq "$name" "1" "$rc"
}

check_accepts() {
  local name="$1" fn="$2" value="$3" rc=0
  "$fn" "$value" || rc=$?
  check_eq "$name" "0" "$rc"
}

test_picks_lowest_free_utun_unit() {
  local taken result
  taken=$'en0\nutun90\nutun91\nutun93'
  result="$(printf '%s\n' "$taken" | pick_free_utun_unit)"
  check_eq "picks_lowest_free_utun_unit" "92" "$result"
}

test_reports_no_free_utun_unit_when_range_exhausted() {
  local taken rc=0
  taken="$(seq "$UTUN_UNIT_MIN" "$UTUN_UNIT_MAX" | sed 's/^/utun/')"
  printf '%s\n' "$taken" | pick_free_utun_unit >/dev/null || rc=$?
  check_eq "reports_no_free_utun_unit_when_range_exhausted" "1" "$rc"
}

test_parses_tunnel_from_openvpn_log() {
  local log result
  log=$'Wed Sep  3 TUN/TAP device utun4 opened\nWed Sep  3 /sbin/ifconfig utun4 10.8.0.2 10.8.0.1 netmask 255.255.255.255 mtu 1500 up'
  result="$(printf '%s\n' "$log" | parse_openvpn_tunnel)"
  check_eq "parses_tunnel_from_openvpn_log" "utun4 10.8.0.2 10.8.0.1" "$result"
}

test_parses_nothing_when_log_has_no_bringup() {
  local result
  result="$(printf 'Initialization Sequence Completed\n' | parse_openvpn_tunnel)"
  check_eq "parses_nothing_when_log_has_no_bringup" "" "$result"
}

# A server that pushes a crafted option gets it echoed verbatim into the log at --verb 3, and
# the parser takes the FIRST match. Validation, not the parser, is what has to stop it.
test_parser_is_fooled_by_a_pushed_control_message() {
  local log result
  log=$'PUSH: Received control message: \'PUSH_REPLY,echo /sbin/ifconfig utun9 x 1.1.1.1;touch /tmp/pwned\'\n/sbin/ifconfig utun4 10.8.0.2 10.8.0.1 netmask 255.255.255.255 mtu 1500 up'
  result="$(printf '%s\n' "$log" | parse_openvpn_tunnel | awk '{print $3}')"
  check_eq "parser_is_fooled_by_a_pushed_control_message" "1.1.1.1;touch" "$result"
}

test_rejects_command_injection_in_peer_address() {
  check_rejects "rejects_command_injection_in_peer_address" is_valid_ipv4 '1.1.1.1;touch/tmp/pwned'
}

test_rejects_shell_metacharacters_in_device_name() {
  check_rejects "rejects_shell_metacharacters_in_device_name" is_valid_utun_name 'utun9;id'
  # shellcheck disable=SC2016 # the literal characters are the point of the test
  check_rejects "rejects_command_substitution_in_device_name" is_valid_utun_name 'utun$(id)'
  check_rejects "rejects_non_utun_device_name" is_valid_utun_name 'en0'
  check_rejects "rejects_bare_utun_prefix" is_valid_utun_name 'utun'
}

test_accepts_plain_utun_device_name() {
  check_accepts "accepts_plain_utun_device_name" is_valid_utun_name 'utun4'
}

test_rejects_out_of_range_and_malformed_ipv4() {
  check_rejects "rejects_out_of_range_octet" is_valid_ipv4 '10.8.0.256'
  check_rejects "rejects_three_octet_address" is_valid_ipv4 '10.8.0'
  check_rejects "rejects_space_separated_address" is_valid_ipv4 '10.8.0.1 2.2.2.2'
  check_rejects "rejects_empty_peer_address" is_valid_ipv4 ''
}

test_accepts_dotted_quad_peer_address() {
  check_accepts "accepts_dotted_quad_peer_address" is_valid_ipv4 '10.8.0.1'
  check_accepts "accepts_zero_padded_dotted_quad" is_valid_ipv4 '010.008.000.001'
}

test_flags_bare_auth_user_pass_as_interactive() {
  local profile result
  profile=$'client\ndev tun\nauth-user-pass\nremote vpn.example 1194'
  result="$(printf '%s\n' "$profile" | profile_auth_mode)"
  check_eq "flags_bare_auth_user_pass_as_interactive" "interactive" "$result"
}

test_flags_crlf_bare_auth_user_pass_as_interactive() {
  local result
  result="$(printf 'client\r\nauth-user-pass\r\n' | profile_auth_mode)"
  check_eq "flags_crlf_bare_auth_user_pass_as_interactive" "interactive" "$result"
}

test_accepts_auth_user_pass_with_credentials_file() {
  local result
  result="$(printf 'client\nauth-user-pass /etc/openvpn/creds\n' | profile_auth_mode)"
  check_eq "accepts_auth_user_pass_with_credentials_file" "file" "$result"
}

test_accepts_inline_auth_user_pass_block() {
  local result
  result="$(printf 'client\n<auth-user-pass>\nuser\npass\n</auth-user-pass>\n' | profile_auth_mode)"
  check_eq "accepts_inline_auth_user_pass_block" "inline" "$result"
}

test_reports_none_for_certificate_only_profile() {
  local result
  result="$(printf 'client\ndev tun\nremote vpn.example 1194\n' | profile_auth_mode)"
  check_eq "reports_none_for_certificate_only_profile" "none" "$result"
}

test_ignores_commented_auth_user_pass() {
  local result
  result="$(printf 'client\n;auth-user-pass\n#auth-user-pass\n' | profile_auth_mode)"
  check_eq "ignores_commented_auth_user_pass" "none" "$result"
}

test_fails_when_negative_case_did_not_fail_closed() {
  check_prefix "fails_when_negative_case_did_not_fail_closed" "FAIL negative case" \
    "$(evaluate_verdict synthetic "$RC_CONNECTED" "$RC_CONNECTED" "$RC_CONNECTED")"
}

test_fails_when_scoped_route_leaves_enetunreach() {
  check_prefix "fails_when_scoped_route_leaves_enetunreach" "FAIL scoped route" \
    "$(evaluate_verdict synthetic "$RC_ENETUNREACH" "$RC_ENETUNREACH" "$RC_ENETUNREACH")"
}

test_passes_synthetic_when_pending_after_scoped_route() {
  check_prefix "passes_synthetic_when_pending_after_scoped_route" "PASS" \
    "$(evaluate_verdict synthetic "$RC_ENETUNREACH" "$RC_PENDING" "$RC_ENETUNREACH")"
}

test_rejects_pending_as_success_in_openvpn_mode() {
  check_prefix "rejects_pending_as_success_in_openvpn_mode" "FAIL scoped route" \
    "$(evaluate_verdict openvpn "$RC_ENETUNREACH" "$RC_PENDING" "$RC_PENDING")"
}

test_passes_openvpn_only_on_completed_connection() {
  check_prefix "passes_openvpn_only_on_completed_connection" "PASS" \
    "$(evaluate_verdict openvpn "$RC_ENETUNREACH" "$RC_CONNECTED" "$RC_PENDING")"
}

test_fails_when_default_route_moved_while_scoped_route_installed() {
  check_prefix "fails_when_default_route_moved_while_scoped_route_installed" \
    "FAIL the unscoped default route changed WHILE" \
    "$(final_verdict synthetic "$RC_ENETUNREACH" "$RC_PENDING" "$RC_PENDING" yes yes)"
}

test_fails_when_default_route_left_residue_after_teardown() {
  check_prefix "fails_when_default_route_left_residue_after_teardown" \
    "FAIL system default route was modified" \
    "$(final_verdict synthetic "$RC_ENETUNREACH" "$RC_PENDING" "$RC_PENDING" no no)"
}

test_passes_only_when_both_route_checks_are_clean() {
  check_prefix "passes_only_when_both_route_checks_are_clean" "PASS" \
    "$(final_verdict synthetic "$RC_ENETUNREACH" "$RC_PENDING" "$RC_PENDING" yes no)"
}

test_labels_known_errnos() {
  check_eq "labels_known_errnos" "ENETUNREACH(51)" "$(errno_label "$RC_ENETUNREACH")"
}

run_self_test() {
  test_picks_lowest_free_utun_unit
  test_reports_no_free_utun_unit_when_range_exhausted
  test_parses_tunnel_from_openvpn_log
  test_parses_nothing_when_log_has_no_bringup
  test_parser_is_fooled_by_a_pushed_control_message
  test_rejects_command_injection_in_peer_address
  test_rejects_shell_metacharacters_in_device_name
  test_accepts_plain_utun_device_name
  test_rejects_out_of_range_and_malformed_ipv4
  test_accepts_dotted_quad_peer_address
  test_flags_bare_auth_user_pass_as_interactive
  test_flags_crlf_bare_auth_user_pass_as_interactive
  test_accepts_auth_user_pass_with_credentials_file
  test_accepts_inline_auth_user_pass_block
  test_reports_none_for_certificate_only_profile
  test_ignores_commented_auth_user_pass
  test_fails_when_negative_case_did_not_fail_closed
  test_fails_when_scoped_route_leaves_enetunreach
  test_passes_synthetic_when_pending_after_scoped_route
  test_rejects_pending_as_success_in_openvpn_mode
  test_passes_openvpn_only_on_completed_connection
  test_fails_when_default_route_moved_while_scoped_route_installed
  test_fails_when_default_route_left_residue_after_teardown
  test_passes_only_when_both_route_checks_are_clean
  test_labels_known_errnos
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
