#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# docs/SPEC.md §10 tests 2 and 3 — Linux policy routing.
#
# Test 3 (default, self-contained): builds the §5.2 policy on a throwaway tun and proves
#   a) with the full policy installed, a socket bound to the tun IP reaches table 218;
#   b) deleting the tunnel route while the tun IP is STILL PRESENT yields EHOSTUNREACH from
#      the `unreachable` floor route — the only assertion that actually exercises the floor;
#   c) deleting the `ip rule` does NOT fall through to table main, because a lower-priority
#      backstop rule catches the same source address.
#
# Test 2 (--egress-check, needs a live tunnel): an IP-echo request bound to the tun source
#   address must report the exit node's address, not the ISP's.
#
# `blackhole` is deliberately NOT used: RTN_BLACKHOLE yields EINVAL, which maps to no SOCKS5
# reply code. RTN_UNREACHABLE yields EHOSTUNREACH, which maps to REP 0x04.
#
# The floor and the backstop are not redundant. The floor lives inside table 218 and so is
# unreachable once the rule is gone; only the backstop covers rule deletion. They answer with
# different errnos because they act at different layers: FR_ACT_UNREACHABLE on a rule yields
# ENETUNREACH (REP 0x03), RTN_UNREACHABLE on a route yields EHOSTUNREACH (REP 0x04).

set -euo pipefail

readonly RC_CONNECTED=0
readonly RC_ENETUNREACH=10
readonly RC_EHOSTUNREACH=11
readonly RC_OTHER_ERRNO=12
readonly RC_PENDING=13
readonly RC_SETUP=20

TUN_DEV="tc-verify0"
TUN_IP="10.255.255.2"
TUN_PREFIX="24"
TUN_MTU="1400"
TABLE="218"
RULE_PRIORITY="18000"
BACKSTOP_PRIORITY="18500"
FLOOR_METRIC="4000"
ROUTE_METRIC="100"
DST_IP="1.1.1.1"
DST_PORT="443"
PROBE_TIMEOUT_MS="4000"
ECHO_URL=""
LIVE_TUN_IP=""
CONFIRMED="no"
SELF_TEST="no"

WORK_DIR=""
PROBE_BIN=""
CREATED_TUN=""
UNDO_COMMANDS=()

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
verify-egress-linux.sh — prove docs/SPEC.md §10 tests 2 and 3 on Linux.

  sudo ./scripts/verify-egress-linux.sh --confirm
  sudo ./scripts/verify-egress-linux.sh --confirm --egress-check 10.8.0.2 \
       --echo-url https://api.ipify.org

Options:
  --confirm            Required. Without it the plan is printed and nothing changes.
  --dev NAME           Throwaway tun name (default tc-verify0).
  --tun-ip ADDR        Address for the throwaway tun (default 10.255.255.2).
  --table N            Routing table (default 218, matching §5.2).
  --priority N         ip rule priority (default 18000).
  --dst IPV4           Probe destination (default 1.1.1.1).
  --port N             Probe destination port (default 443).
  --timeout MS         Probe connect timeout (default 4000).
  --egress-check ADDR  Test 2: source address of an ALREADY-UP tunnel whose policy the
                       daemon has installed. This script does not create it.
  --echo-url URL       IP-echo endpoint for test 2 (must return a bare address).
  --self-test          Run the pure-function unit tests and exit. Touches nothing, needs no root.
  -h, --help           This text.

The throwaway tun is created with IFF_PERSIST, so it outlives a crashed script. It is removed
on exit, including on failure; if the machine is killed mid-run, delete it with
`ip link del <NAME>` and `ip rule del priority <N>`.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --self-test) SELF_TEST="yes" ;;
      --dev)
        require_value "$@"
        TUN_DEV="$2"
        shift
        ;;
      --tun-ip)
        require_value "$@"
        TUN_IP="$2"
        shift
        ;;
      --table)
        require_value "$@"
        TABLE="$2"
        shift
        ;;
      --priority)
        require_value "$@"
        RULE_PRIORITY="$2"
        shift
        ;;
      --dst)
        require_value "$@"
        DST_IP="$2"
        shift
        ;;
      --port)
        require_value "$@"
        DST_PORT="$2"
        shift
        ;;
      --timeout)
        require_value "$@"
        PROBE_TIMEOUT_MS="$2"
        shift
        ;;
      --egress-check)
        require_value "$@"
        LIVE_TUN_IP="$2"
        shift
        ;;
      --echo-url)
        require_value "$@"
        ECHO_URL="$2"
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

require_value() {
  [ "$#" -ge 2 ] || die "$1 needs a value"
}

# ---------------------------------------------------------------------------
# Pure helpers. Covered by --self-test.
# ---------------------------------------------------------------------------

errno_label() {
  case "$1" in
    "$RC_CONNECTED") echo "CONNECTED" ;;
    "$RC_ENETUNREACH") echo "ENETUNREACH(101)" ;;
    "$RC_EHOSTUNREACH") echo "EHOSTUNREACH(113)" ;;
    "$RC_OTHER_ERRNO") echo "other-errno" ;;
    "$RC_PENDING") echo "PENDING(no-error-before-timeout)" ;;
    "$RC_SETUP") echo "probe-setup-failure" ;;
    *) echo "unexpected-rc-$1" ;;
  esac
}

# stdin: `ip route get ...` output. Prints the selected output device, or nothing.
parse_route_get_dev() {
  awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
}

# evaluate_floor_verdict <baseline_rc> <floor_rc> -> "PASS ..." | "FAIL ..."
evaluate_floor_verdict() {
  local baseline="$1" floor="$2"
  if [ "$baseline" != "$RC_PENDING" ] && [ "$baseline" != "$RC_CONNECTED" ]; then
    echo "FAIL policy did not take effect: with the full §5.2 policy installed the probe gave $(errno_label "$baseline"), so nothing after this is meaningful"
    return 0
  fi
  if [ "$floor" != "$RC_EHOSTUNREACH" ]; then
    echo "FAIL floor route did not catch the socket: expected EHOSTUNREACH after deleting the tunnel route, got $(errno_label "$floor")"
    return 0
  fi
  echo "PASS baseline=$(errno_label "$baseline") floor=$(errno_label "$floor")"
}

# evaluate_rule_verdict <tun_dev> <probe_rc> <selected_dev> -> "PASS ..." | "FAIL ..."
evaluate_rule_verdict() {
  local tun="$1" rc="$2" dev="$3"
  if [ -n "$dev" ] && [ "$dev" != "$tun" ]; then
    echo "FAIL removing the rule fell through to table main via '$dev' — traffic bearing the tun source address would leave over the physical link"
    return 0
  fi
  if [ "$rc" = "$RC_CONNECTED" ]; then
    echo "FAIL removing the rule still produced a working connection"
    return 0
  fi
  # The backstop must produce a mappable errno, not merely an absence of connectivity. A hang is
  # not fail-closed: the SOCKS5 layer has nothing to reply with and the caller waits on tcp_retries2.
  if [ "$rc" != "$RC_ENETUNREACH" ] && [ "$rc" != "$RC_EHOSTUNREACH" ]; then
    echo "FAIL removing the rule neither fell through nor refused: probe=$(errno_label "$rc"); the backstop rule did not fire"
    return 0
  fi
  echo "PASS backstop refused it (selected dev='${dev:-none}', probe=$(errno_label "$rc"))"
}

# evaluate_egress_verdict <direct_ip> <tunnel_ip> -> "PASS ..." | "FAIL ..."
evaluate_egress_verdict() {
  local direct="$1" tunnel="$2"
  if [ -z "$tunnel" ]; then
    echo "FAIL the tunnel-bound request returned nothing"
    return 0
  fi
  if [ "$direct" = "$tunnel" ]; then
    echo "FAIL egress is not tunnelled: bound and unbound requests both reported $tunnel"
    return 0
  fi
  echo "PASS exit address $tunnel differs from the direct address ${direct:-unknown}"
}

# ---------------------------------------------------------------------------
# System interaction
# ---------------------------------------------------------------------------

cleanup() {
  local rc=$? cmd
  set +e
  for ((i = ${#UNDO_COMMANDS[@]} - 1; i >= 0; i--)); do
    cmd="${UNDO_COMMANDS[$i]}"
    say "cleanup: $cmd"
    eval "$cmd" >/dev/null 2>&1 || warn "cleanup command failed (may already be gone): $cmd"
  done
  if [ -n "$CREATED_TUN" ]; then
    say "cleanup: ip link del $CREATED_TUN"
    ip link del "$CREATED_TUN" >/dev/null 2>&1 || warn "could not delete $CREATED_TUN — remove it by hand"
  fi
  [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
  exit "$rc"
}

mutate() {
  say "  + $*"
  "$@"
}

undo_last() {
  local last=$((${#UNDO_COMMANDS[@]} - 1))
  local cmd="${UNDO_COMMANDS[$last]}"
  say "  - $cmd"
  eval "$cmd" || die "could not undo: $cmd"
  unset "UNDO_COMMANDS[$last]"
}

build_probe() {
  local compiler
  compiler="$(command -v cc || command -v gcc || command -v clang || true)"
  [ -n "$compiler" ] || die "no C compiler found; install build-essential or equivalent"
  WORK_DIR="$(mktemp -d)"
  cat >"$WORK_DIR/probe.c" <<'PROBE_C'
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Binds a socket to a source address the way the unprivileged proxy dialer does and
   reports the connect() errno. IP_BIND_ADDRESS_NO_PORT mirrors docs/SPEC.md §5.3. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

static int fill_addr(struct sockaddr_in *sa, const char *ip, const char *port) {
  memset(sa, 0, sizeof *sa);
  sa->sin_family = AF_INET;
  sa->sin_port = htons((unsigned short)(port ? atoi(port) : 0));
  return inet_pton(AF_INET, ip, &sa->sin_addr) == 1 ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    fprintf(stderr, "usage: probe <src-ipv4> <dst-ipv4> <port> <timeout-ms>\n");
    return RC_SETUP;
  }
  struct sockaddr_in src, dst;
  if (fill_addr(&src, argv[1], NULL) != 0 || fill_addr(&dst, argv[2], argv[3]) != 0) {
    fprintf(stderr, "probe: bad address\n");
    return RC_SETUP;
  }
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "probe: socket: %s\n", strerror(errno));
    return RC_SETUP;
  }
#ifdef IP_BIND_ADDRESS_NO_PORT
  int on = 1;
  /* Absent before Linux 4.2; ENOPROTOOPT is tolerated, everything else is not. */
  if (setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &on, sizeof on) < 0 &&
      errno != ENOPROTOOPT) {
    fprintf(stderr, "probe: setsockopt(IP_BIND_ADDRESS_NO_PORT): %s\n", strerror(errno));
    close(fd);
    return RC_SETUP;
  }
#endif
  fprintf(stderr, "probe: binding source %s\n", argv[1]);
  if (bind(fd, (struct sockaddr *)&src, sizeof src) < 0) {
    int saved = errno;
    close(fd);
    fprintf(stderr, "probe: bind: %s\n", strerror(saved));
    return report("bind", saved);
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
  "$compiler" -Wall -Wextra -O1 -o "$WORK_DIR/probe" "$WORK_DIR/probe.c" ||
    die "failed to compile the probe"
  PROBE_BIN="$WORK_DIR/probe"
}

run_probe() {
  local src="$1" rc=0
  "$PROBE_BIN" "$src" "$DST_IP" "$DST_PORT" "$PROBE_TIMEOUT_MS" || rc=$?
  say "result: $(errno_label "$rc")"
  return "$rc"
}

install_policy() {
  step "Installing the §5.2 policy (backstop, floor, rule, then the real route)"
  mutate ip rule add from "$TUN_IP/32" type unreachable priority "$BACKSTOP_PRIORITY"
  UNDO_COMMANDS+=("ip rule del priority $BACKSTOP_PRIORITY")
  mutate ip route add unreachable default table "$TABLE" metric "$FLOOR_METRIC"
  UNDO_COMMANDS+=("ip route del unreachable default table $TABLE metric $FLOOR_METRIC")
  mutate ip rule add from "$TUN_IP/32" lookup "$TABLE" priority "$RULE_PRIORITY"
  UNDO_COMMANDS+=("ip rule del priority $RULE_PRIORITY")
  mutate ip route add default dev "$TUN_DEV" src "$TUN_IP" table "$TABLE" \
    metric "$ROUTE_METRIC" mtu "$TUN_MTU"
  UNDO_COMMANDS+=("ip route del default dev $TUN_DEV table $TABLE metric $ROUTE_METRIC")
}

bring_up_tun() {
  step "Creating throwaway tun $TUN_DEV ($TUN_IP/$TUN_PREFIX)"
  if ip link show "$TUN_DEV" >/dev/null 2>&1; then
    die "$TUN_DEV already exists; refusing to touch it"
  fi
  mutate ip tuntap add dev "$TUN_DEV" mode tun
  CREATED_TUN="$TUN_DEV"
  mutate ip addr add "$TUN_IP/$TUN_PREFIX" dev "$TUN_DEV"
  mutate ip link set dev "$TUN_DEV" mtu "$TUN_MTU" up
}

assert_tun_ip_present() {
  ip addr show dev "$TUN_DEV" | grep -q "inet $TUN_IP/" ||
    die "the tun address vanished; this run would test bind() failure, not the floor route"
  say "tun address $TUN_IP is still present — the floor route, not a missing address, is under test."
}

run_floor_test() {
  step "Baseline: full policy installed, socket bound to $TUN_IP"
  local baseline=0
  run_probe "$TUN_IP" || baseline=$?

  step "Deleting the tunnel route from table $TABLE, leaving the address in place"
  assert_tun_ip_present
  undo_last
  ip route show table "$TABLE"
  local floor=0
  run_probe "$TUN_IP" || floor=$?
  FLOOR_VERDICT="$(evaluate_floor_verdict "$baseline" "$floor")"

  step "Restoring the tunnel route"
  mutate ip route add default dev "$TUN_DEV" src "$TUN_IP" table "$TABLE" \
    metric "$ROUTE_METRIC" mtu "$TUN_MTU"
  UNDO_COMMANDS+=("ip route del default dev $TUN_DEV table $TABLE metric $ROUTE_METRIC")
}

run_rule_test() {
  step "Deleting the ip rule: the backstop must refuse it, not fall through to table main"
  local rc=0 selected route_get
  mutate ip rule del priority "$RULE_PRIORITY"
  route_get="$(ip route get "$DST_IP" from "$TUN_IP" 2>&1 || true)"
  say "ip route get $DST_IP from $TUN_IP -> $route_get"
  selected="$(printf '%s\n' "$route_get" | parse_route_get_dev)"
  run_probe "$TUN_IP" || rc=$?
  RULE_VERDICT="$(evaluate_rule_verdict "$TUN_DEV" "$rc" "$selected")"

  mutate ip rule add from "$TUN_IP/32" lookup "$TABLE" priority "$RULE_PRIORITY"
}

run_egress_test() {
  step "Test 2: egress is real (live tunnel $LIVE_TUN_IP)"
  command -v curl >/dev/null || die "curl is required for --egress-check"
  local direct tunnel
  direct="$(curl -fsS --max-time 15 "$ECHO_URL" 2>/dev/null || true)"
  tunnel="$(curl -fsS --max-time 15 --interface "$LIVE_TUN_IP" "$ECHO_URL" 2>/dev/null || true)"
  say "direct: ${direct:-<none>}"
  say "via tunnel source address: ${tunnel:-<none>}"
  EGRESS_VERDICT="$(evaluate_egress_verdict "$direct" "$tunnel")"
}

print_plan() {
  cat <<EOF
This run will, as root:
  - create a throwaway tun '$TUN_DEV' and give it $TUN_IP/$TUN_PREFIX
  - add, exercise and then remove:
      ip rule add from $TUN_IP/32 type unreachable priority $BACKSTOP_PRIORITY
      ip route add unreachable default table $TABLE metric $FLOOR_METRIC
      ip rule add from $TUN_IP/32 lookup $TABLE priority $RULE_PRIORITY
      ip route add default dev $TUN_DEV src $TUN_IP table $TABLE metric $ROUTE_METRIC mtu $TUN_MTU
  - open TCP connections to ${DST_IP}:${DST_PORT} bound to $TUN_IP
  - delete everything it created, including on failure

It will NOT touch table main, the default route, resolv.conf, or any existing interface,
rule or tun device. If '$TUN_DEV', priority $RULE_PRIORITY or priority $BACKSTOP_PRIORITY already
exists, it aborts.
Re-run with --confirm to execute.
EOF
}

preflight() {
  [ "$(uname -s)" = "Linux" ] || die "this test is Linux-only; see verify-ifscope-macos.sh"
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --confirm)"
  command -v ip >/dev/null || die "iproute2 is required"
  if ip rule show | grep -qE "^${RULE_PRIORITY}:"; then
    die "an ip rule already exists at priority $RULE_PRIORITY; refusing to disturb it"
  fi
  if ip rule show | grep -qE "^${BACKSTOP_PRIORITY}:"; then
    die "an ip rule already exists at priority $BACKSTOP_PRIORITY; refusing to disturb it"
  fi
  [ -z "$LIVE_TUN_IP" ] || [ -n "$ECHO_URL" ] || die "--egress-check also needs --echo-url"
}

FLOOR_VERDICT=""
RULE_VERDICT=""
EGRESS_VERDICT=""

print_verdict() {
  step "VERDICT"
  say "test 3 floor route: $FLOOR_VERDICT"
  say "test 3 rule removal: $RULE_VERDICT"
  [ -z "$EGRESS_VERDICT" ] || say "test 2 egress: $EGRESS_VERDICT"

  case "$FLOOR_VERDICT$RULE_VERDICT$EGRESS_VERDICT" in
    *FAIL*)
      say ""
      say "What a FAIL means: docs/SPEC.md §5.2's Linux policy is not fail-closed as specified."
      say "A floor-route failure means a dropped tunnel route lets sockets escape or return an"
      say "errno the SOCKS5 layer cannot map. A rule failure means the netlink watcher in §5.2"
      say "is load-bearing rather than defence in depth, and teardown order must be re-derived."
      return 1
      ;;
    *) return 0 ;;
  esac
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

  preflight
  trap cleanup EXIT INT TERM
  build_probe
  bring_up_tun
  install_policy
  run_floor_test
  run_rule_test
  [ -z "$LIVE_TUN_IP" ] || run_egress_test
  print_verdict
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

test_parses_selected_device_from_route_get() {
  check_eq "parses_selected_device_from_route_get" "eth0" \
    "$(printf '1.1.1.1 from 10.255.255.2 via 192.168.1.1 dev eth0 table main uid 0\n' | parse_route_get_dev)"
}

test_parses_no_device_when_route_get_errored() {
  check_eq "parses_no_device_when_route_get_errored" "" \
    "$(printf 'RTNETLINK answers: Network is unreachable\n' | parse_route_get_dev)"
}

test_floor_fails_when_policy_never_took_effect() {
  check_prefix "floor_fails_when_policy_never_took_effect" "FAIL policy did not take effect" \
    "$(evaluate_floor_verdict "$RC_ENETUNREACH" "$RC_EHOSTUNREACH")"
}

test_floor_fails_when_deleted_route_yields_enetunreach() {
  check_prefix "floor_fails_when_deleted_route_yields_enetunreach" "FAIL floor route" \
    "$(evaluate_floor_verdict "$RC_PENDING" "$RC_ENETUNREACH")"
}

test_floor_fails_when_socket_still_connects() {
  check_prefix "floor_fails_when_socket_still_connects" "FAIL floor route" \
    "$(evaluate_floor_verdict "$RC_PENDING" "$RC_CONNECTED")"
}

test_floor_passes_on_ehostunreach() {
  check_prefix "floor_passes_on_ehostunreach" "PASS" \
    "$(evaluate_floor_verdict "$RC_PENDING" "$RC_EHOSTUNREACH")"
}

test_rule_fails_on_fall_through_to_physical_device() {
  check_prefix "rule_fails_on_fall_through_to_physical_device" "FAIL removing the rule fell through" \
    "$(evaluate_rule_verdict "tc-verify0" "$RC_PENDING" "eth0")"
}

test_rule_fails_when_connection_still_succeeds() {
  check_prefix "rule_fails_when_connection_still_succeeds" "FAIL removing the rule still" \
    "$(evaluate_rule_verdict "tc-verify0" "$RC_CONNECTED" "")"
}

test_rule_passes_when_the_backstop_refuses() {
  check_prefix "rule_passes_when_the_backstop_refuses" "PASS" \
    "$(evaluate_rule_verdict "tc-verify0" "$RC_ENETUNREACH" "")"
}

test_rule_fails_when_it_only_hangs() {
  check_prefix "rule_fails_when_it_only_hangs" "FAIL removing the rule neither" \
    "$(evaluate_rule_verdict "tc-verify0" "$RC_PENDING" "")"
}

test_egress_fails_when_addresses_match() {
  check_prefix "egress_fails_when_addresses_match" "FAIL egress is not tunnelled" \
    "$(evaluate_egress_verdict "203.0.113.7" "203.0.113.7")"
}

test_egress_fails_when_tunnel_request_returned_nothing() {
  check_prefix "egress_fails_when_tunnel_request_returned_nothing" "FAIL the tunnel-bound" \
    "$(evaluate_egress_verdict "203.0.113.7" "")"
}

test_egress_passes_when_exit_address_differs() {
  check_prefix "egress_passes_when_exit_address_differs" "PASS" \
    "$(evaluate_egress_verdict "203.0.113.7" "198.51.100.4")"
}

test_labels_known_errnos() {
  check_eq "labels_known_errnos" "EHOSTUNREACH(113)" "$(errno_label "$RC_EHOSTUNREACH")"
}

run_self_test() {
  test_parses_selected_device_from_route_get
  test_parses_no_device_when_route_get_errored
  test_floor_fails_when_policy_never_took_effect
  test_floor_fails_when_deleted_route_yields_enetunreach
  test_floor_fails_when_socket_still_connects
  test_floor_passes_on_ehostunreach
  test_rule_fails_on_fall_through_to_physical_device
  test_rule_fails_when_connection_still_succeeds
  test_rule_passes_when_the_backstop_refuses
  test_rule_fails_when_it_only_hangs
  test_egress_fails_when_addresses_match
  test_egress_fails_when_tunnel_request_returned_nothing
  test_egress_passes_when_exit_address_differs
  test_labels_known_errnos
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
