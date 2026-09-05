#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Remove the thisconnect launchd daemon installed by install-daemon-macos.sh.
# Safe to run when nothing is installed, and safe to re-run.
#
# Written for /bin/bash 3.2, which is what `sudo bash` gives you on macOS.

set -euo pipefail

readonly LABEL="net.thisconnect.daemon"
readonly HELPER_PATH="/Library/PrivilegedHelperTools/net.thisconnect.daemon"
readonly PLIST_PATH="/Library/LaunchDaemons/net.thisconnect.daemon.plist"
readonly SOCKET_PATH="/var/run/thisconnect.sock"
readonly LOG_DIR="/var/log/thisconnect"
readonly STATE_DIR="/Library/Application Support/thisconnect"

CONFIRMED="no"
SELF_TEST="no"
PURGE="no"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
uninstall-daemon-macos.sh — remove the thisconnect launchd daemon.

  sudo ./scripts/uninstall-daemon-macos.sh --confirm
  sudo ./scripts/uninstall-daemon-macos.sh --confirm --purge

Options:
  --confirm      Required. Without it nothing is changed; the plan is printed.
  --purge        Also delete the log directory and the state directory. The
                 state directory holds imported profiles: this throws them away.
  --self-test    Run the pure-function unit tests and exit. Touches nothing,
                 needs no root.
  -h, --help     This text.

Running this when nothing is installed is not an error.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --purge) PURGE="yes" ;;
      --self-test) SELF_TEST="yes" ;;
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

# A partial install is the normal case here — a failed bootstrap leaves files
# with no job — so "nothing at all" is reported distinctly from "some of it".
installation_state() {
  local job="$1" plist="$2" binary="$3" socket="$4"
  if [ "$job" = "no" ] && [ "$plist" = "no" ] && [ "$binary" = "no" ] && [ "$socket" = "no" ]; then
    echo "absent"
  elif [ "$job" = "yes" ] && [ "$plist" = "yes" ] && [ "$binary" = "yes" ]; then
    echo "installed"
  else
    echo "partial"
  fi
}

removal_verdict() {
  local job="$1" plist="$2" binary="$3" socket="$4"
  [ "$job" = "no" ] || {
    echo "FAIL job still loaded"
    return 0
  }
  [ "$plist" = "no" ] || {
    echo "FAIL $PLIST_PATH still present"
    return 0
  }
  [ "$binary" = "no" ] || {
    echo "FAIL $HELPER_PATH still present"
    return 0
  }
  [ "$socket" = "no" ] || {
    echo "FAIL $SOCKET_PATH still present"
    return 0
  }
  echo "PASS nothing of the daemon remains"
}

# ---------------------------------------------------------------------------
# System interaction.
# ---------------------------------------------------------------------------

job_loaded() {
  launchctl print "system/$LABEL" >/dev/null 2>&1
}

yes_no() {
  if "$@"; then echo "yes"; else echo "no"; fi
}

path_present() { [ -e "$1" ]; }

# The survey is four globals rather than a parsed string: bash 3.2 has no way to
# return a tuple that does not involve re-splitting it at the call site.
SEEN_JOB="no"
SEEN_PLIST="no"
SEEN_BINARY="no"
SEEN_SOCKET="no"

take_survey() {
  SEEN_JOB="$(yes_no job_loaded)"
  SEEN_PLIST="$(yes_no path_present "$PLIST_PATH")"
  SEEN_BINARY="$(yes_no path_present "$HELPER_PATH")"
  SEEN_SOCKET="$(yes_no path_present "$SOCKET_PATH")"
}

report_survey() {
  say "job     system/$LABEL loaded: $SEEN_JOB"
  say "plist   $PLIST_PATH: $SEEN_PLIST"
  say "binary  $HELPER_PATH: $SEEN_BINARY"
  say "socket  $SOCKET_PATH: $SEEN_SOCKET"
  say "state:  $(installation_state "$SEEN_JOB" "$SEEN_PLIST" "$SEEN_BINARY" "$SEEN_SOCKET")"
}

remove_job() {
  if job_loaded; then
    say "booting out system/$LABEL"
    # bootout returns non-zero for an already-gone job, which is not a failure.
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  else
    say "job was not loaded"
  fi
  if job_loaded; then
    die "system/$LABEL is still loaded after bootout; reboot and re-run"
  fi
}

remove_files() {
  rm -f "$PLIST_PATH"
  rm -f "$HELPER_PATH"
  if [ -S "$SOCKET_PATH" ]; then
    rm -f "$SOCKET_PATH"
  elif [ -e "$SOCKET_PATH" ]; then
    die "$SOCKET_PATH exists and is not a socket; refusing to remove it"
  fi
  say "removed the plist, the helper binary, and the socket"

  if [ "$PURGE" = "yes" ]; then
    rm -rf "$LOG_DIR"
    rm -rf "$STATE_DIR"
    say "purged $LOG_DIR and $STATE_DIR"
  else
    say "kept $LOG_DIR and $STATE_DIR (pass --purge to delete them)"
  fi
}

print_plan() {
  take_survey
  say "uninstall-daemon-macos.sh sees:"
  say ""
  report_survey
  cat <<EOF

It would then:

  run      launchctl bootout system/$LABEL   (if loaded)
  rm       $PLIST_PATH
  rm       $HELPER_PATH
  rm       $SOCKET_PATH   (only if it is a socket)
EOF
  if [ "$PURGE" = "yes" ]; then
    say "  rm -rf   $LOG_DIR"
    say "  rm -rf   $STATE_DIR   (DELETES IMPORTED PROFILES)"
  else
    say "  keep     $LOG_DIR and $STATE_DIR"
  fi
  say ""
  say "It will NOT touch routes, DNS, the firewall, or any other launchd job."
  say "Re-run with --confirm to execute."
}

main() {
  parse_args "$@"

  if [ "$SELF_TEST" = "yes" ]; then
    run_self_test
    return
  fi

  [ "$(uname -s)" = "Darwin" ] || die "this uninstaller is macOS-only"

  if [ "$CONFIRMED" != "yes" ]; then
    print_plan
    return
  fi

  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --confirm)"

  take_survey
  step "Before"
  report_survey
  if [ "$(installation_state "$SEEN_JOB" "$SEEN_PLIST" "$SEEN_BINARY" "$SEEN_SOCKET")" = "absent" ]; then
    say ""
    say "nothing to remove"
    return 0
  fi

  step "Unloading"
  remove_job

  step "Removing files"
  remove_files

  step "After"
  take_survey
  report_survey

  local verdict
  verdict="$(removal_verdict "$SEEN_JOB" "$SEEN_PLIST" "$SEEN_BINARY" "$SEEN_SOCKET")"
  say ""
  say "$verdict"
  case "$verdict" in
    PASS*) return 0 ;;
    *) return 1 ;;
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

test_reports_absent_when_nothing_is_installed() {
  check_eq "reports_absent_when_nothing_is_installed" "absent" \
    "$(installation_state no no no no)"
}

test_reports_installed_when_job_and_files_are_present() {
  check_eq "reports_installed_when_job_and_files_are_present" "installed" \
    "$(installation_state yes yes yes yes)"
}

test_reports_partial_when_bootstrap_never_ran() {
  check_eq "reports_partial_when_bootstrap_never_ran" "partial" \
    "$(installation_state no yes yes no)"
}

test_reports_partial_when_only_a_stale_socket_remains() {
  check_eq "reports_partial_when_only_a_stale_socket_remains" "partial" \
    "$(installation_state no no no yes)"
}

test_reports_partial_when_the_binary_was_deleted_by_hand() {
  check_eq "reports_partial_when_the_binary_was_deleted_by_hand" "partial" \
    "$(installation_state yes yes no no)"
}

test_removal_passes_when_everything_is_gone() {
  check_eq "removal_passes_when_everything_is_gone" "PASS nothing of the daemon remains" \
    "$(removal_verdict no no no no)"
}

test_removal_fails_when_job_survived() {
  check_eq "removal_fails_when_job_survived" "FAIL job still loaded" \
    "$(removal_verdict yes no no no)"
}

test_removal_fails_when_plist_survived() {
  check_eq "removal_fails_when_plist_survived" "FAIL $PLIST_PATH still present" \
    "$(removal_verdict no yes no no)"
}

test_removal_fails_when_binary_survived() {
  check_eq "removal_fails_when_binary_survived" "FAIL $HELPER_PATH still present" \
    "$(removal_verdict no no yes no)"
}

test_removal_fails_when_socket_survived() {
  check_eq "removal_fails_when_socket_survived" "FAIL $SOCKET_PATH still present" \
    "$(removal_verdict no no no yes)"
}

test_yes_no_maps_a_missing_path_to_no() {
  check_eq "yes_no_maps_a_missing_path_to_no" "no" \
    "$(yes_no path_present /nonexistent/thisconnect/probe)"
}

test_yes_no_maps_an_existing_path_to_yes() {
  check_eq "yes_no_maps_an_existing_path_to_yes" "yes" "$(yes_no path_present /)"
}

run_self_test() {
  test_reports_absent_when_nothing_is_installed
  test_reports_installed_when_job_and_files_are_present
  test_reports_partial_when_bootstrap_never_ran
  test_reports_partial_when_only_a_stale_socket_remains
  test_reports_partial_when_the_binary_was_deleted_by_hand
  test_removal_passes_when_everything_is_gone
  test_removal_fails_when_job_survived
  test_removal_fails_when_plist_survived
  test_removal_fails_when_binary_survived
  test_removal_fails_when_socket_survived
  test_yes_no_maps_a_missing_path_to_no
  test_yes_no_maps_an_existing_path_to_yes
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
