#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# docs/SPEC.md §10 tests 2 and 3 — Linux policy routing, for BOTH address families.
#
# Test 3 (default, self-contained): builds the §5.2 policy on a throwaway tun and proves,
#   per family:
#   a) with the full policy installed, a socket bound to the tun IP reaches table 218;
#   b) deleting the tunnel route while the tun IP is STILL PRESENT yields EHOSTUNREACH from
#      the `unreachable` floor route — the only assertion that actually exercises the floor;
#   c) deleting the `ip rule` does NOT fall through to table main, because a lower-priority
#      backstop rule catches the same source address;
#   d) with the backstop ALSO removed, the source address really does escape over another
#      device. This is the control. Without it (c) is vacuous on a host that has no route
#      for that family at all — which is the normal state of IPv6 on most machines, and
#      would turn "nothing happened" into a green tick.
#
# Test 2 (--egress-check, needs a live tunnel): an IP-echo request bound to the tun source
#   address must report the exit node's address, not the ISP's.
#
# --netns re-executes the whole run inside a private user+network namespace, where the
# escape path for (d) is manufactured out of a dummy device. That needs no root, cannot
# touch host networking, and is the only way to get a conclusive IPv6 answer on a host
# with no IPv6 connectivity.
#
# `blackhole` is deliberately NOT used: RTN_BLACKHOLE yields EINVAL, which maps to no SOCKS5
# reply code. RTN_UNREACHABLE yields EHOSTUNREACH, which maps to REP 0x04.
#
# The floor and the backstop are not redundant. The floor lives inside table 218 and so is
# unreachable once the rule is gone; only the backstop covers rule deletion. They answer with
# different errnos because they act at different layers: FR_ACT_UNREACHABLE on a rule yields
# ENETUNREACH (REP 0x03), RTN_UNREACHABLE on a route yields EHOSTUNREACH (REP 0x04).
#
# IPv6 is not IPv4 with a different flag. `ip -6 route show table 218` reports an absent table
# as an error where `ip -4` reports success; a tun v6 address must be added `nodad` or it sits
# tentative and bind() fails; and the egress dialer has no IPv6 counterpart to
# IP_BIND_ADDRESS_NO_PORT, so the v6 probe below deliberately does not set it.

set -euo pipefail

readonly RC_CONNECTED=0
readonly RC_ENETUNREACH=10
readonly RC_EHOSTUNREACH=11
readonly RC_OTHER_ERRNO=12
readonly RC_PENDING=13
readonly RC_SETUP=20

TUN_DEV="tc-verify0"
ESCAPE_DEV="tc-escape0"
TUN_IP4="10.255.255.2"
TUN_PREFIX4="24"
TUN_IP6="fd00:7c07:1::2"
TUN_PREFIX6="64"
ESCAPE_IP4="10.254.254.1"
ESCAPE_PREFIX4="24"
ESCAPE_IP6="fd00:7c07:2::1"
ESCAPE_PREFIX6="64"
ESCAPE_METRIC="1024"
TUN_MTU="1400"
TABLE="218"
RULE_PRIORITY="18000"
BACKSTOP_PRIORITY="18500"
FLOOR_METRIC="4000"
ROUTE_METRIC="100"
DST_IP4="1.1.1.1"
DST_IP6="2606:4700:4700::1111"
DST_PORT="443"
PROBE_TIMEOUT_MS="4000"
FAMILIES="v4 v6"
ECHO_URL=""
LIVE_TUN_IP=""
CONFIRMED="no"
SELF_TEST="no"
NETNS="no"
WATCHER="no"

WORK_DIR=""
PROBE_BIN=""
CREATED_TUN=""
CREATED_ESCAPE=""
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
verify-egress-linux.sh — prove docs/SPEC.md §10 tests 2 and 3 on Linux, for both families.

  ./scripts/verify-egress-linux.sh --confirm --netns
  sudo ./scripts/verify-egress-linux.sh --confirm
  sudo ./scripts/verify-egress-linux.sh --confirm --family v4 --egress-check 10.8.0.2 \
       --echo-url https://api.ipify.org

Options:
  --confirm            Required. Without it the plan is printed and nothing changes.
  --netns              Run inside a private user+network namespace. Needs no root, touches
                       no host networking, and manufactures the escape device that makes the
                       backstop assertion conclusive. Incompatible with --egress-check.
  --watcher            Prove the netlink watcher re-asserts policy deleted out from under a
                       live session (SPEC.md §5.2). Builds the daemon's ignored watcher test
                       and runs it in a private user+network namespace; needs no root. The
                       test carries its own control and reports INCONCLUSIVE if the namespace
                       cannot demonstrate the leak. Implies --netns; ignores --family.
  --family v4|v6|both  Which families to exercise (default both).
  --dev NAME           Throwaway tun name (default tc-verify0).
  --tun-ip ADDR        IPv4 address for the throwaway tun (default 10.255.255.2).
  --tun-ip6 ADDR       IPv6 address for the throwaway tun (default fd00:7c07:1::2).
  --table N            Routing table (default 218, matching §5.2).
  --priority N         ip rule priority (default 18000).
  --dst IPV4           IPv4 probe destination (default 1.1.1.1).
  --dst6 IPV6          IPv6 probe destination (default 2606:4700:4700::1111).
  --port N             Probe destination port (default 443).
  --timeout MS         Probe connect timeout (default 4000).
  --egress-check ADDR  Test 2: source address of an ALREADY-UP tunnel whose policy the
                       daemon has installed. This script does not create it.
  --echo-url URL       IP-echo endpoint for test 2 (must return a bare address).
  --self-test          Run the pure-function unit tests and exit. Touches nothing, needs no root.
  -h, --help           This text.

The throwaway tun is created with IFF_PERSIST, so it outlives a crashed script. It is removed
on exit, including on failure; if the machine is killed mid-run, delete it with
`ip link del <NAME>`, `ip rule del priority <N>` and `ip -6 rule del priority <N>`.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --self-test) SELF_TEST="yes" ;;
      --netns) NETNS="yes" ;;
      --watcher) WATCHER="yes" ;;
      --family)
        require_value "$@"
        FAMILIES="$(parse_family "$2")" || die "unknown family: $2 (want v4, v6 or both)"
        shift
        ;;
      --dev)
        require_value "$@"
        TUN_DEV="$2"
        shift
        ;;
      --tun-ip)
        require_value "$@"
        TUN_IP4="$2"
        shift
        ;;
      --tun-ip6)
        require_value "$@"
        TUN_IP6="$2"
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
        DST_IP4="$2"
        shift
        ;;
      --dst6)
        require_value "$@"
        DST_IP6="$2"
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

# parse_family <word> -> "v4" | "v6" | "v4 v6"; non-zero on anything else.
parse_family() {
  case "$1" in
    v4 | 4 | ipv4) echo "v4" ;;
    v6 | 6 | ipv6) echo "v6" ;;
    both | all) echo "v4 v6" ;;
    *) return 1 ;;
  esac
}

fam_flag() { case "$1" in v6) echo "-6" ;; *) echo "-4" ;; esac; }
fam_host_len() { case "$1" in v6) echo "128" ;; *) echo "32" ;; esac; }
fam_tun_ip() { case "$1" in v6) echo "$TUN_IP6" ;; *) echo "$TUN_IP4" ;; esac; }
fam_tun_prefix() { case "$1" in v6) echo "$TUN_PREFIX6" ;; *) echo "$TUN_PREFIX4" ;; esac; }
fam_escape_ip() { case "$1" in v6) echo "$ESCAPE_IP6" ;; *) echo "$ESCAPE_IP4" ;; esac; }
fam_escape_prefix() { case "$1" in v6) echo "$ESCAPE_PREFIX6" ;; *) echo "$ESCAPE_PREFIX4" ;; esac; }
fam_dst() { case "$1" in v6) echo "$DST_IP6" ;; *) echo "$DST_IP4" ;; esac; }

# The kernel keeps a fresh v6 address tentative until duplicate-address detection finishes, and
# bind() on a tentative address fails EADDRNOTAVAIL. `nodad` is not a shortcut: it is the only
# way to make a synthetic point-to-point tun address immediately bindable. IPv4 has no analogue.
fam_addr_flags() { case "$1" in v6) echo "nodad" ;; *) echo "" ;; esac; }

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

# The control for the assertion above. With both rules gone the tun source address must be seen
# to escape somewhere; if it cannot, the backstop was never load-bearing in this run and its
# PASS proves nothing.
#
# evaluate_control_verdict <tun_dev> <selected_dev> -> "PASS ..." | "INCONCLUSIVE ..." | "FAIL ..."
evaluate_control_verdict() {
  local tun="$1" dev="$2"
  if [ -z "$dev" ]; then
    echo "INCONCLUSIVE with both rules removed the address still had nowhere to go, so the backstop was never the thing stopping it; re-run with --netns for a conclusive answer"
    return 0
  fi
  if [ "$dev" = "$tun" ]; then
    echo "FAIL with both rules removed the lookup still selected the tun '$tun'; the throwaway tun is reachable from table main, which invalidates the whole test"
    return 0
  fi
  echo "PASS with both rules removed the address escaped via '$dev', so the backstop above was load-bearing"
}

# Folds a rule verdict and its control into the answer that gets reported. A PASS that rests on
# an INCONCLUSIVE control is not a pass.
#
# combine_rule_verdict <rule_verdict> <control_verdict> -> verdict line
combine_rule_verdict() {
  local rule="$1" control="$2"
  case "$rule" in
    FAIL*)
      echo "$rule"
      return 0
      ;;
  esac
  case "$control" in
    PASS*) echo "$rule" ;;
    FAIL*) echo "FAIL the control invalidated this run: ${control#FAIL }" ;;
    *) echo "INCONCLUSIVE the backstop returned the right errno, but ${control#INCONCLUSIVE }" ;;
  esac
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

# A filter matching nothing exits 0 on some cargo versions, which would report PASS having
# run nothing. "0 passed" alone does not distinguish that from a genuine pass, so this also
# demands the filtered test actually ran.
#
# evaluate_watcher_verdict <rc> <output> -> "PASS ..." | "FAIL ..."
evaluate_watcher_verdict() {
  local rc="$1" output="$2"
  if [ "$rc" -ne 0 ]; then
    echo "FAIL see the test output above; an INCONCLUSIVE control reports there too"
    return 0
  fi
  if printf '%s\n' "$output" | grep -q "test result: ok" &&
    printf '%s\n' "$output" | grep -qE "running 1 test|test .*the_watcher_restores.* \.\.\. ok"; then
    echo "PASS the watcher restored both rules and the lookup stayed on the tun"
    return 0
  fi
  echo "FAIL the run reported success but the watcher test never ran (filter matched nothing); see the output above"
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
  if [ -n "$CREATED_ESCAPE" ]; then
    say "cleanup: ip link del $CREATED_ESCAPE"
    ip link del "$CREATED_ESCAPE" >/dev/null 2>&1 || warn "could not delete $CREATED_ESCAPE"
  fi
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

has_family() {
  case " $FAMILIES " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

build_probe() {
  local compiler
  compiler="$(command -v cc || command -v gcc || command -v clang || true)"
  [ -n "$compiler" ] || die "no C compiler found; install build-essential or equivalent"
  WORK_DIR="$(mktemp -d)"
  cat >"$WORK_DIR/probe.c" <<'PROBE_C'
/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Binds a socket to a source address the way the unprivileged proxy dialer does and
   reports the connect() errno. IP_BIND_ADDRESS_NO_PORT mirrors docs/SPEC.md §5.3; it is
   an IPPROTO_IP option with no IPv6 counterpart, and the dialer's pin_v6 does not set it,
   so neither does this. */
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

static socklen_t fill_addr(int family, struct sockaddr_storage *ss, const char *ip,
                           const char *port) {
  unsigned short p = (unsigned short)(port ? atoi(port) : 0);
  memset(ss, 0, sizeof *ss);
  if (family == AF_INET6) {
    struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ss;
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(p);
    return inet_pton(AF_INET6, ip, &sa->sin6_addr) == 1 ? sizeof *sa : 0;
  }
  struct sockaddr_in *sa = (struct sockaddr_in *)ss;
  sa->sin_family = AF_INET;
  sa->sin_port = htons(p);
  return inet_pton(AF_INET, ip, &sa->sin_addr) == 1 ? sizeof *sa : 0;
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: probe -4|-6 <src> <dst> <port> <timeout-ms>\n");
    return RC_SETUP;
  }
  int family = strcmp(argv[1], "-6") == 0 ? AF_INET6 : AF_INET;
  struct sockaddr_storage src, dst;
  socklen_t srclen = fill_addr(family, &src, argv[2], NULL);
  socklen_t dstlen = fill_addr(family, &dst, argv[3], argv[4]);
  if (srclen == 0 || dstlen == 0) {
    fprintf(stderr, "probe: bad address\n");
    return RC_SETUP;
  }
  int fd = socket(family, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "probe: socket: %s\n", strerror(errno));
    return RC_SETUP;
  }
#ifdef IP_BIND_ADDRESS_NO_PORT
  if (family == AF_INET) {
    int on = 1;
    /* Absent before Linux 4.2; ENOPROTOOPT is tolerated, everything else is not. */
    if (setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &on, sizeof on) < 0 &&
        errno != ENOPROTOOPT) {
      fprintf(stderr, "probe: setsockopt(IP_BIND_ADDRESS_NO_PORT): %s\n", strerror(errno));
      close(fd);
      return RC_SETUP;
    }
  }
#endif
  fprintf(stderr, "probe: binding source %s\n", argv[2]);
  if (bind(fd, (struct sockaddr *)&src, srclen) < 0) {
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
  int rc = connect(fd, (struct sockaddr *)&dst, dstlen);
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
  int pr = poll(&pfd, 1, atoi(argv[5]));
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
  local family="$1" src="$2" rc=0
  "$PROBE_BIN" "$(fam_flag "$family")" "$src" "$(fam_dst "$family")" "$DST_PORT" \
    "$PROBE_TIMEOUT_MS" || rc=$?
  say "result: $(errno_label "$rc")"
  return "$rc"
}

route_get_dev() {
  local family="$1" src="$2" out
  out="$(ip "$(fam_flag "$family")" route get "$(fam_dst "$family")" from "$src" 2>&1 || true)"
  # The transcript goes to stderr on purpose: stdout is the captured device name, and a log
  # line mixed into it becomes a bogus "fell through via ..." verdict.
  say "  ip $(fam_flag "$family") route get $(fam_dst "$family") from $src -> $out" >&2
  printf '%s\n' "$out" | parse_route_get_dev
}

add_tunnel_route() {
  local family="$1" ip
  ip="$(fam_tun_ip "$family")"
  mutate ip "$(fam_flag "$family")" route add default dev "$TUN_DEV" src "$ip" \
    table "$TABLE" metric "$ROUTE_METRIC" mtu "$TUN_MTU"
}

del_tunnel_route() {
  local family="$1"
  mutate ip "$(fam_flag "$family")" route del default dev "$TUN_DEV" \
    table "$TABLE" metric "$ROUTE_METRIC"
}

add_rule() {
  local family="$1" ip
  ip="$(fam_tun_ip "$family")"
  mutate ip "$(fam_flag "$family")" rule add from "$ip/$(fam_host_len "$family")" \
    lookup "$TABLE" priority "$RULE_PRIORITY"
}

add_backstop() {
  local family="$1" ip
  ip="$(fam_tun_ip "$family")"
  mutate ip "$(fam_flag "$family")" rule add from "$ip/$(fam_host_len "$family")" \
    type unreachable priority "$BACKSTOP_PRIORITY"
}

install_policy() {
  local family="$1"
  step "[$family] Installing the §5.2 policy (backstop, floor, rule, then the real route)"
  add_backstop "$family"
  UNDO_COMMANDS+=("ip $(fam_flag "$family") rule del priority $BACKSTOP_PRIORITY")
  mutate ip "$(fam_flag "$family")" route add unreachable default table "$TABLE" \
    metric "$FLOOR_METRIC"
  UNDO_COMMANDS+=("ip $(fam_flag "$family") route del unreachable default table $TABLE metric $FLOOR_METRIC")
  add_rule "$family"
  UNDO_COMMANDS+=("ip $(fam_flag "$family") rule del priority $RULE_PRIORITY")
  add_tunnel_route "$family"
  UNDO_COMMANDS+=("ip $(fam_flag "$family") route del default dev $TUN_DEV table $TABLE metric $ROUTE_METRIC")
}

bring_up_tun() {
  step "Creating throwaway tun $TUN_DEV"
  if ip link show "$TUN_DEV" >/dev/null 2>&1; then
    die "$TUN_DEV already exists; refusing to touch it"
  fi
  mutate ip tuntap add dev "$TUN_DEV" mode tun
  CREATED_TUN="$TUN_DEV"
  local family ip flags
  for family in $FAMILIES; do
    ip="$(fam_tun_ip "$family")"
    flags="$(fam_addr_flags "$family")"
    # shellcheck disable=SC2086 # $flags is a deliberate word list ("nodad" or empty).
    mutate ip "$(fam_flag "$family")" addr add "$ip/$(fam_tun_prefix "$family")" \
      dev "$TUN_DEV" $flags
  done
  mutate ip link set dev "$TUN_DEV" mtu "$TUN_MTU" up
}

# Only ever called inside the namespace. On a real host the escape path is whatever table main
# already holds, and manufacturing one would mean editing the operator's default route.
bring_up_escape() {
  step "Creating the namespace escape path $ESCAPE_DEV (stands in for the physical link)"
  mutate ip link add "$ESCAPE_DEV" type dummy
  CREATED_ESCAPE="$ESCAPE_DEV"
  local family ip flags
  for family in $FAMILIES; do
    ip="$(fam_escape_ip "$family")"
    flags="$(fam_addr_flags "$family")"
    # shellcheck disable=SC2086 # see bring_up_tun.
    mutate ip "$(fam_flag "$family")" addr add "$ip/$(fam_escape_prefix "$family")" \
      dev "$ESCAPE_DEV" $flags
  done
  mutate ip link set dev "$ESCAPE_DEV" up
  for family in $FAMILIES; do
    mutate ip "$(fam_flag "$family")" route add default dev "$ESCAPE_DEV" metric "$ESCAPE_METRIC"
  done
}

assert_tun_ip_present() {
  local family="$1" ip keyword
  ip="$(fam_tun_ip "$family")"
  case "$family" in
    v6) keyword="inet6" ;;
    *) keyword="inet" ;;
  esac
  ip addr show dev "$TUN_DEV" | grep -q "$keyword $ip/" ||
    die "the tun $family address vanished; this run would test bind() failure, not the floor route"
  # A v6 address that is still `tentative` is not bindable, and a run that never bound proves
  # nothing about routing.
  if [ "$family" = "v6" ] && ip -6 addr show dev "$TUN_DEV" | grep -q "tentative"; then
    die "$ip is still tentative; bind() would fail EADDRNOTAVAIL and the result would be meaningless"
  fi
  say "tun address $ip is still present and bindable — the floor route, not a missing address, is under test."
}

run_floor_test() {
  local family="$1" ip baseline=0 floor=0
  ip="$(fam_tun_ip "$family")"
  step "[$family] Baseline: full policy installed, socket bound to $ip"
  run_probe "$family" "$ip" || baseline=$?

  step "[$family] Deleting the tunnel route from table $TABLE, leaving the address in place"
  assert_tun_ip_present "$family"
  del_tunnel_route "$family"
  ip "$(fam_flag "$family")" route show table "$TABLE"
  run_probe "$family" "$ip" || floor=$?
  FLOOR_VERDICTS+=("$family $(evaluate_floor_verdict "$baseline" "$floor")")

  step "[$family] Restoring the tunnel route"
  add_tunnel_route "$family"
}

run_rule_test() {
  local family="$1" ip rc=0 selected control rule_verdict control_verdict
  ip="$(fam_tun_ip "$family")"
  step "[$family] Deleting the ip rule: the backstop must refuse it, not fall through to table main"
  mutate ip "$(fam_flag "$family")" rule del priority "$RULE_PRIORITY"
  selected="$(route_get_dev "$family" "$ip")"
  run_probe "$family" "$ip" || rc=$?
  rule_verdict="$(evaluate_rule_verdict "$TUN_DEV" "$rc" "$selected")"

  step "[$family] Control: with the backstop ALSO gone the address must be seen to escape"
  mutate ip "$(fam_flag "$family")" rule del priority "$BACKSTOP_PRIORITY"
  control="$(route_get_dev "$family" "$ip")"
  control_verdict="$(evaluate_control_verdict "$TUN_DEV" "$control")"
  say "control: $control_verdict"
  add_backstop "$family"

  RULE_VERDICTS+=("$family $(combine_rule_verdict "$rule_verdict" "$control_verdict")")
  add_rule "$family"
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

# The watcher lives in the daemon, so this mode delegates to the daemon's own ignored test
# rather than re-implementing re-assertion in shell. The build happens OUTSIDE the namespace so
# a compile error is reported as a compile error, not as a namespace failure.
run_watcher_test() {
  step "Test: the netlink watcher re-asserts policy deleted mid-session"
  command -v cargo >/dev/null || die "--watcher needs cargo"
  command -v unshare >/dev/null || die "--watcher needs util-linux's unshare(1)"
  command -v timeout >/dev/null || die "--watcher needs coreutils' timeout(1)"
  say "Building the daemon test binary (outside the namespace)"
  cargo test -p thisconnect-daemon --bin thisconnectd --no-run ||
    die "the daemon test binary does not build"
  say "Running the watcher test inside a private user+network namespace"
  # The test has a 10s internal deadline, but a cold `cargo test` build inside the namespace can
  # be slow; 300s is generous enough not to be a false FAIL but finite enough that a deadlock in
  # the code under test resolves to FAIL instead of hanging the whole verification run forever.
  local output rc=0
  output="$(timeout 300 unshare --user --map-root-user --net -- \
    cargo test -p thisconnect-daemon --bin thisconnectd -- \
    --ignored --nocapture --test-threads=1 the_watcher_restores 2>&1)" || rc=$?
  printf '%s\n' "$output"
  WATCHER_VERDICT="$(evaluate_watcher_verdict "$rc" "$output")"
}

print_plan() {
  local family
  say "This run will, as root${NETNS:+ (inside a private network namespace)}:"
  say "  - create a throwaway tun '$TUN_DEV'"
  [ "$NETNS" = "no" ] || say "  - create a dummy '$ESCAPE_DEV' and give it the namespace's default route"
  for family in $FAMILIES; do
    say "  - give the tun $(fam_tun_ip "$family")/$(fam_tun_prefix "$family"), then add, exercise and remove:"
    say "      ip $(fam_flag "$family") rule add from $(fam_tun_ip "$family")/$(fam_host_len "$family") type unreachable priority $BACKSTOP_PRIORITY"
    say "      ip $(fam_flag "$family") route add unreachable default table $TABLE metric $FLOOR_METRIC"
    say "      ip $(fam_flag "$family") rule add from $(fam_tun_ip "$family")/$(fam_host_len "$family") lookup $TABLE priority $RULE_PRIORITY"
    say "      ip $(fam_flag "$family") route add default dev $TUN_DEV src $(fam_tun_ip "$family") table $TABLE metric $ROUTE_METRIC mtu $TUN_MTU"
    say "  - open TCP connections to $(fam_dst "$family") port $DST_PORT bound to $(fam_tun_ip "$family")"
  done
  say "  - delete everything it created, including on failure"
  say ""
  if [ "$NETNS" = "yes" ]; then
    say "In --netns mode nothing outside the namespace is touched at all, and no root is needed."
  else
    say "It will NOT touch table main, the default route, resolv.conf, or any existing interface,"
    say "rule or tun device. If '$TUN_DEV', priority $RULE_PRIORITY or priority $BACKSTOP_PRIORITY"
    say "already exists, it aborts."
  fi
  say "Re-run with --confirm to execute."
}

preflight() {
  local family
  [ "$(uname -s)" = "Linux" ] || die "this test is Linux-only; see verify-ifscope-macos.sh"
  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --confirm), or pass --netns"
  command -v ip >/dev/null || die "iproute2 is required"
  for family in $FAMILIES; do
    if ip "$(fam_flag "$family")" rule show | grep -qE "^${RULE_PRIORITY}:"; then
      die "an ip $(fam_flag "$family") rule already exists at priority $RULE_PRIORITY; refusing to disturb it"
    fi
    if ip "$(fam_flag "$family")" rule show | grep -qE "^${BACKSTOP_PRIORITY}:"; then
      die "an ip $(fam_flag "$family") rule already exists at priority $BACKSTOP_PRIORITY; refusing to disturb it"
    fi
  done
  [ -z "$LIVE_TUN_IP" ] || [ -n "$ECHO_URL" ] || die "--egress-check also needs --echo-url"
}

# Re-executes this script inside a private user+network namespace. The marker variable is what
# stops the child from unsharing again; without it this recurses forever.
enter_netns() {
  command -v unshare >/dev/null || die "--netns needs util-linux's unshare(1)"
  [ -z "$LIVE_TUN_IP" ] || die "--netns and --egress-check are incompatible: a namespace has no route to the live tunnel"
  say "Re-executing inside a private user+network namespace (no root required)."
  exec env TC_VERIFY_IN_NETNS=1 unshare --user --map-root-user --net -- "$0" "$@"
}

FLOOR_VERDICTS=()
RULE_VERDICTS=()
EGRESS_VERDICT=""
WATCHER_VERDICT=""

print_verdict() {
  local line all=""
  step "VERDICT"
  for line in "${FLOOR_VERDICTS[@]}"; do
    say "test 3 floor route  [${line%% *}]: ${line#* }"
    all="$all${line#* }"
  done
  for line in "${RULE_VERDICTS[@]}"; do
    say "test 3 rule removal [${line%% *}]: ${line#* }"
    all="$all${line#* }"
  done
  if [ -n "$EGRESS_VERDICT" ]; then
    say "test 2 egress: $EGRESS_VERDICT"
    all="$all$EGRESS_VERDICT"
  fi
  if [ -n "$WATCHER_VERDICT" ]; then
    say "netlink watcher: $WATCHER_VERDICT"
    all="$all$WATCHER_VERDICT"
  fi

  case "$all" in
    *FAIL*)
      say ""
      say "What a FAIL means: docs/SPEC.md §5.2's Linux policy is not fail-closed as specified."
      say "A floor-route failure means a dropped tunnel route lets sockets escape or return an"
      say "errno the SOCKS5 layer cannot map. A rule failure means the netlink watcher in §5.2"
      say "is load-bearing rather than defence in depth, and teardown order must be re-derived."
      say "A netlink watcher failure means policy deleted mid-session is not re-asserted, so"
      say "§5.2's re-assertion latency is unbounded and the Linux leak window is open again."
      return 1
      ;;
    *INCONCLUSIVE*)
      say ""
      say "INCONCLUSIVE is not a pass. The backstop returned the right errno, but this host had"
      say "no route for that family at all, so an absent backstop would have looked identical."
      say "Re-run with --netns, which builds the escape path the assertion needs."
      [ "$NETNS" = "no" ] || return 1
      return 0
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
  if [ "$NETNS" = "yes" ] && [ -z "${TC_VERIFY_IN_NETNS:-}" ]; then
    enter_netns "$@"
  fi
  if [ "$WATCHER" = "yes" ]; then
    run_watcher_test
    print_verdict
    return
  fi

  preflight
  trap cleanup EXIT INT TERM
  build_probe
  if [ "$NETNS" = "yes" ]; then
    mutate ip link set lo up
  fi
  bring_up_tun
  [ "$NETNS" = "no" ] || bring_up_escape
  local family
  for family in $FAMILIES; do
    install_policy "$family"
  done
  for family in $FAMILIES; do
    run_floor_test "$family"
    run_rule_test "$family"
  done
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

test_parses_selected_device_from_v6_route_get() {
  check_eq "parses_selected_device_from_v6_route_get" "tc-escape0" \
    "$(printf '2606:4700:4700::1111 from fd00:7c07:1::2 dev tc-escape0 src fd00:7c07:2::1 metric 1024 pref medium\n' | parse_route_get_dev)"
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

test_control_passes_when_the_address_escapes() {
  check_prefix "control_passes_when_the_address_escapes" "PASS" \
    "$(evaluate_control_verdict "tc-verify0" "tc-escape0")"
}

test_control_is_inconclusive_without_an_escape_path() {
  check_prefix "control_is_inconclusive_without_an_escape_path" "INCONCLUSIVE" \
    "$(evaluate_control_verdict "tc-verify0" "")"
}

test_control_fails_when_table_main_reaches_the_tun() {
  check_prefix "control_fails_when_table_main_reaches_the_tun" "FAIL" \
    "$(evaluate_control_verdict "tc-verify0" "tc-verify0")"
}

test_a_pass_on_an_inconclusive_control_is_not_a_pass() {
  check_prefix "a_pass_on_an_inconclusive_control_is_not_a_pass" "INCONCLUSIVE" \
    "$(combine_rule_verdict "PASS backstop refused it" "INCONCLUSIVE nowhere to go")"
}

test_a_pass_on_a_good_control_survives() {
  check_eq "a_pass_on_a_good_control_survives" "PASS backstop refused it" \
    "$(combine_rule_verdict "PASS backstop refused it" "PASS escaped via tc-escape0")"
}

test_a_rule_failure_outranks_its_control() {
  check_prefix "a_rule_failure_outranks_its_control" "FAIL removing the rule fell through" \
    "$(combine_rule_verdict "FAIL removing the rule fell through" "INCONCLUSIVE nowhere to go")"
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

test_watcher_passes_on_a_real_run() {
  local output
  output="$(cat <<'CARGO_OUT'
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.08s
     Running unittests src/main.rs (target/debug/deps/thisconnectd-b3635e9d57920f49)

running 1 test
test session::watchdog::tests::the_watcher_restores_rules_deleted_under_a_live_session ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 412 filtered out; finished in 0.13s
CARGO_OUT
)"
  check_prefix "watcher_passes_on_a_real_run" "PASS" "$(evaluate_watcher_verdict 0 "$output")"
}

# The silent-pass case this whole helper exists to catch: a filter matching nothing exits 0 on
# some cargo versions, and "0 passed; 0 failed" alone looks superficially like success.
test_watcher_fails_when_the_filter_matched_nothing() {
  local output
  output="$(cat <<'CARGO_OUT'
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.10s
     Running unittests src/main.rs (target/debug/deps/thisconnectd-b3635e9d57920f49)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 413 filtered out; finished in 0.00s
CARGO_OUT
)"
  check_prefix "watcher_fails_when_the_filter_matched_nothing" "FAIL the run reported success but the watcher test never ran" \
    "$(evaluate_watcher_verdict 0 "$output")"
}

test_watcher_fails_on_a_nonzero_exit() {
  local output
  output="$(cat <<'CARGO_OUT'
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.09s
     Running unittests src/main.rs (target/debug/deps/thisconnectd-b3635e9d57920f49)

running 1 test
test session::watchdog::tests::the_watcher_restores_rules_deleted_under_a_live_session ... FAILED

failures:

---- session::watchdog::tests::the_watcher_restores_rules_deleted_under_a_live_session stdout ----
thread 'session::watchdog::tests::the_watcher_restores_rules_deleted_under_a_live_session' panicked at daemon/src/session/watchdog.rs:303:
INCONCLUSIVE: the namespace could not demonstrate the leak

failures:
    session::watchdog::tests::the_watcher_restores_rules_deleted_under_a_live_session

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 412 filtered out; finished in 0.14s
CARGO_OUT
)"
  check_prefix "watcher_fails_on_a_nonzero_exit" "FAIL see the test output above" \
    "$(evaluate_watcher_verdict 1 "$output")"
}

test_labels_known_errnos() {
  check_eq "labels_known_errnos" "EHOSTUNREACH(113)" "$(errno_label "$RC_EHOSTUNREACH")"
}

test_family_words_map_to_families() {
  check_eq "family_words_map_to_families" "v4 v6" "$(parse_family both)"
  check_eq "family_word_v6_maps_to_v6" "v6" "$(parse_family ipv6)"
}

test_family_selectors_differ_by_family() {
  check_eq "family_selector_v6_is_a_host_route" "128" "$(fam_host_len v6)"
  check_eq "family_selector_v4_is_a_host_route" "32" "$(fam_host_len v4)"
  check_eq "family_v6_addresses_skip_dad" "nodad" "$(fam_addr_flags v6)"
  check_eq "family_v4_addresses_have_no_dad_flag" "" "$(fam_addr_flags v4)"
}

run_self_test() {
  test_parses_selected_device_from_route_get
  test_parses_selected_device_from_v6_route_get
  test_parses_no_device_when_route_get_errored
  test_floor_fails_when_policy_never_took_effect
  test_floor_fails_when_deleted_route_yields_enetunreach
  test_floor_fails_when_socket_still_connects
  test_floor_passes_on_ehostunreach
  test_rule_fails_on_fall_through_to_physical_device
  test_rule_fails_when_connection_still_succeeds
  test_rule_passes_when_the_backstop_refuses
  test_rule_fails_when_it_only_hangs
  test_control_passes_when_the_address_escapes
  test_control_is_inconclusive_without_an_escape_path
  test_control_fails_when_table_main_reaches_the_tun
  test_a_pass_on_an_inconclusive_control_is_not_a_pass
  test_a_pass_on_a_good_control_survives
  test_a_rule_failure_outranks_its_control
  test_egress_fails_when_addresses_match
  test_egress_fails_when_tunnel_request_returned_nothing
  test_egress_passes_when_exit_address_differs
  test_watcher_passes_on_a_real_run
  test_watcher_fails_when_the_filter_matched_nothing
  test_watcher_fails_on_a_nonzero_exit
  test_labels_known_errnos
  test_family_words_map_to_families
  test_family_selectors_differ_by_family
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
