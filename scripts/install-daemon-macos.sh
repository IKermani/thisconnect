#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install the thisconnect privileged daemon as a launchd system job.
# docs/SPEC.md §7.2 (macOS daemon), §7.3 (dev socket), §11 (distribution).
#
# Written for /bin/bash 3.2, which is what `sudo bash` gives you on macOS:
# no associative arrays, no negative array indices, no ${var@Q}.

set -euo pipefail

readonly LABEL="net.thisconnect.daemon"
readonly HELPER_DIR="/Library/PrivilegedHelperTools"
readonly HELPER_PATH="/Library/PrivilegedHelperTools/net.thisconnect.daemon"
readonly PLIST_PATH="/Library/LaunchDaemons/net.thisconnect.daemon.plist"
readonly SOCKET_PATH="/var/run/thisconnect.sock"
readonly LOG_DIR="/var/log/thisconnect"
readonly STATE_DIR="/Library/Application Support/thisconnect"
readonly UID_PLACEHOLDER="__INSTALLING_UID__"

# SockPathMode is decimal in a plist. 438 = 0666 (release: peer authentication
# is the control, and wheel holds only root so 0660 locks the GUI out entirely).
# 384 = 0600 (dev-insecure-ipc: relaxed auth is only safe owner-only).
readonly RELEASE_SOCK_MODE_DECIMAL=438
readonly DEV_SOCK_MODE_DECIMAL=384
readonly RELEASE_SOCK_MODE_OCTAL=666
readonly DEV_SOCK_MODE_OCTAL=600

# Feature-gated `describe()` strings in daemon/src/peerauth*. Exactly one is
# present in any given build, which is what makes this a usable discriminator;
# if that ever stops being true the classifier refuses instead of guessing.
readonly DEV_BUILD_MARKER="INSECURE uid-only (dev-insecure-ipc)"
readonly RELEASE_BUILD_MARKER="LOCAL_PEERTOKEN audit token + designated requirement"

readonly SOCKET_WAIT_TRIES=25
readonly SOCKET_WAIT_POLL_S=0.2

CONFIRMED="no"
SELF_TEST="no"
DEV_MODE="no"
BINARY=""
PLIST_SRC=""
INSTALL_UID=""
STAGE_DIR=""

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  [ -z "$STAGE_DIR" ] || rm -rf "$STAGE_DIR"
}

usage() {
  cat <<'EOF'
install-daemon-macos.sh — install the thisconnect daemon as a launchd system job.

  sudo ./scripts/install-daemon-macos.sh --confirm
  sudo ./scripts/install-daemon-macos.sh --confirm --dev

Modes:
  release (default)  Installs a build WITHOUT the dev-insecure-ipc feature. The
                     socket is root:wheel 0666 and every peer is authenticated.
                     A dev-insecure binary is REFUSED here.
  --dev              Installs a dev-insecure-ipc build with the socket tightened
                     to 0600 owned by the installing user. Local development
                     only; a release binary is REFUSED here.

Options:
  --confirm          Required. Without it nothing is changed; the plan is printed.
  --dev              See above. Prints a loud warning.
  --binary PATH      Daemon binary to install
                     (default target/release/thisconnectd, or target/debug in --dev).
  --plist PATH       Source plist (default packaging/macos/net.thisconnect.daemon.plist).
  --uid N            Authorised uid. Defaults to SUDO_UID, i.e. whoever ran sudo.
  --self-test        Run the pure-function unit tests and exit. Touches nothing,
                     needs no root.
  -h, --help         This text.

Re-running is safe: an existing job is booted out before the new one is
bootstrapped, and the install is verified afterwards rather than assumed.
EOF
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --confirm) CONFIRMED="yes" ;;
      --dev) DEV_MODE="yes" ;;
      --self-test) SELF_TEST="yes" ;;
      --binary)
        [ "$#" -ge 2 ] || die "--binary needs a path"
        BINARY="$2"
        shift
        ;;
      --plist)
        [ "$#" -ge 2 ] || die "--plist needs a path"
        PLIST_SRC="$2"
        shift
        ;;
      --uid)
        [ "$#" -ge 2 ] || die "--uid needs a number"
        INSTALL_UID="$2"
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

# uid 0 is rejected on purpose: the GUI never runs as root, so authorising root
# would produce a daemon nobody can drive while looking like a success.
is_valid_uid() {
  case "$1" in
    "" | *[!0-9]*) return 1 ;;
    0) return 1 ;;
  esac
  [ "$1" -le 4294967294 ] || return 1
  return 0
}

# Substitutes the uid placeholder on stdin. Fails if the placeholder is absent,
# which catches a plist that has already been rendered or edited out of shape.
render_installing_uid() {
  local uid="$1" content
  content="$(cat)"
  case "$content" in
    *"$UID_PLACEHOLDER"*) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "${content//$UID_PLACEHOLDER/$uid}"
}

# The two facts about the source plist this installer depends on.
# The mode is matched as the VALUE OF SockPathMode, not merely as an integer
# present somewhere in the document: any other 438 in the plist would otherwise
# vouch for a SockPathMode that had regressed to the decimal/octal footgun.
plist_source_verdict() {
  local content="$1" squeezed
  case "$content" in
    *"$UID_PLACEHOLDER"*) ;;
    *)
      echo "missing-uid-placeholder"
      return 0
      ;;
  esac
  squeezed="$(printf '%s' "$content" | tr -d '[:space:]')"
  case "$squeezed" in
    *"<key>SockPathMode</key><integer>$RELEASE_SOCK_MODE_DECIMAL</integer>"*) echo "ok" ;;
    *) echo "unexpected-sock-mode" ;;
  esac
}

# Fails closed: neither marker or both means we cannot tell what we are holding.
classify_build() {
  local release_marker="$1" dev_marker="$2"
  if [ "$release_marker" = "yes" ] && [ "$dev_marker" = "no" ]; then
    echo "release"
  elif [ "$release_marker" = "no" ] && [ "$dev_marker" = "yes" ]; then
    echo "dev-insecure"
  else
    echo "unknown"
  fi
}

# Refusing a mismatch in BOTH directions matters: a release binary behind a 0600
# socket is not merely over-tight, its verifier denies every peer, so the install
# would "succeed" onto a product that cannot connect.
build_mode_verdict() {
  local build="$1" dev_mode="$2"
  if [ "$build" = "unknown" ]; then
    echo "refuse-unknown-build"
  elif [ "$build" = "dev-insecure" ] && [ "$dev_mode" = "no" ]; then
    echo "refuse-dev-build-in-release-mode"
  elif [ "$build" = "release" ] && [ "$dev_mode" = "yes" ]; then
    echo "refuse-release-build-in-dev-mode"
  else
    echo "ok"
  fi
}

expected_socket_mode_octal() {
  if [ "$1" = "yes" ]; then echo "$DEV_SOCK_MODE_OCTAL"; else echo "$RELEASE_SOCK_MODE_OCTAL"; fi
}

expected_socket_mode_decimal() {
  if [ "$1" = "yes" ]; then echo "$DEV_SOCK_MODE_DECIMAL"; else echo "$RELEASE_SOCK_MODE_DECIMAL"; fi
}

expected_socket_owner_uid() {
  local dev_mode="$1" uid="$2"
  if [ "$dev_mode" = "yes" ]; then echo "$uid"; else echo "0"; fi
}

# A silent success that did not actually work is the failure mode to avoid, so
# the verdict is composed from every observed fact rather than from exit status.
install_verdict() {
  local job_loaded="$1" socket_present="$2" mode_ok="$3" owner_ok="$4"
  [ "$job_loaded" = "yes" ] || {
    echo "FAIL job not loaded"
    return 0
  }
  [ "$socket_present" = "yes" ] || {
    echo "FAIL socket missing at $SOCKET_PATH"
    return 0
  }
  [ "$mode_ok" = "yes" ] || {
    echo "FAIL socket mode wrong"
    return 0
  }
  [ "$owner_ok" = "yes" ] || {
    echo "FAIL socket owner wrong"
    return 0
  }
  echo "PASS job loaded and socket ready"
}

# Fail closed. A non-PASS verdict in --dev means the socket may be the 0666
# root-owned one that uid-only peer auth turns into local root VPN control, so
# an unproven install must not be left loaded. SPEC.md 3.1.5, 7.3.
verdict_requires_rollback() {
  case "$1" in
    PASS*) echo "no" ;;
    *) echo "yes" ;;
  esac
}

# ---------------------------------------------------------------------------
# System interaction.
# ---------------------------------------------------------------------------

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "$0")" && pwd)"
  dirname "$script_dir"
}

resolve_defaults() {
  local root
  root="$(repo_root)"
  if [ -z "$BINARY" ]; then
    if [ "$DEV_MODE" = "yes" ]; then
      BINARY="$root/target/debug/thisconnectd"
    else
      BINARY="$root/target/release/thisconnectd"
    fi
  fi
  [ -n "$PLIST_SRC" ] || PLIST_SRC="$root/packaging/macos/net.thisconnect.daemon.plist"
}

resolve_uid() {
  [ -n "$INSTALL_UID" ] || INSTALL_UID="${SUDO_UID:-}"
  [ -n "$INSTALL_UID" ] ||
    die "cannot tell who to authorise: run under sudo, or pass --uid <uid of the desktop user>"
  is_valid_uid "$INSTALL_UID" ||
    die "--uid must be a non-root numeric uid, got: $INSTALL_UID"
}

detect_build() {
  local release_marker="no" dev_marker="no"
  LC_ALL=C grep -a -q -F "$RELEASE_BUILD_MARKER" "$BINARY" && release_marker="yes"
  LC_ALL=C grep -a -q -F "$DEV_BUILD_MARKER" "$BINARY" && dev_marker="yes"
  classify_build "$release_marker" "$dev_marker"
}

check_build_matches_mode() {
  local build verdict
  build="$(detect_build)"
  verdict="$(build_mode_verdict "$build" "$DEV_MODE")"
  case "$verdict" in
    ok) say "binary is a $build build, which matches the requested mode" ;;
    refuse-unknown-build)
      die "cannot classify $BINARY as a release or dev-insecure-ipc build; refusing to install it"
      ;;
    refuse-dev-build-in-release-mode)
      die "$BINARY is a dev-insecure-ipc build. It authenticates peers by uid only and must never be installed as a release daemon. Rebuild without the feature, or pass --dev."
      ;;
    refuse-release-build-in-dev-mode)
      die "$BINARY is a release build; --dev would put it behind a 0600 socket where its verifier denies every peer. Build with --features dev-insecure-ipc, or drop --dev."
      ;;
  esac
}

stage_plist() {
  local staged="$STAGE_DIR/$LABEL.plist" verdict
  verdict="$(plist_source_verdict "$(cat "$PLIST_SRC")")"
  [ "$verdict" = "ok" ] || die "source plist $PLIST_SRC is not installable: $verdict"

  render_installing_uid "$INSTALL_UID" <"$PLIST_SRC" >"$staged" ||
    die "failed to render $UID_PLACEHOLDER into the plist"

  if [ "$DEV_MODE" = "yes" ]; then
    /usr/libexec/PlistBuddy -c "Set :Sockets:Listener:SockPathMode $DEV_SOCK_MODE_DECIMAL" "$staged" >/dev/null ||
      die "could not set the dev socket mode"
    /usr/libexec/PlistBuddy -c "Add :Sockets:Listener:SockPathOwner integer $INSTALL_UID" "$staged" >/dev/null ||
      /usr/libexec/PlistBuddy -c "Set :Sockets:Listener:SockPathOwner $INSTALL_UID" "$staged" >/dev/null ||
      die "could not set the dev socket owner"
  fi

  plutil -lint "$staged" >/dev/null || die "rendered plist does not parse"
  printf '%s\n' "$staged"
}

# Idempotence: a job that is already loaded, or loaded from an older plist, must
# be gone before bootstrap, and a user may have disabled it in Login Items.
bootout_existing() {
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    say "existing job found; booting it out"
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  else
    say "no existing job loaded"
  fi
  launchctl enable "system/$LABEL" >/dev/null 2>&1 || true
  # launchd normally unlinks its own socket on bootout; a partial install can
  # still leave one behind, and bootstrap will not replace a stale file.
  if [ -S "$SOCKET_PATH" ]; then
    rm -f "$SOCKET_PATH"
  elif [ -e "$SOCKET_PATH" ]; then
    die "$SOCKET_PATH exists and is not a socket; refusing to remove it"
  fi
}

install_files() {
  local staged="$1"
  install -d -o root -g wheel -m 0755 "$HELPER_DIR"
  install -d -o root -g wheel -m 0750 "$LOG_DIR"
  install -d -o root -g wheel -m 0700 "$STATE_DIR"

  # Replace via a temp name in the same directory so a running daemon's binary
  # is never truncated underneath it.
  local tmp_bin="$HELPER_DIR/.$LABEL.incoming"
  install -o root -g wheel -m 0755 "$BINARY" "$tmp_bin"
  mv -f "$tmp_bin" "$HELPER_PATH"

  # Quarantine survives zip and dmg download and blocks launch.
  xattr -d com.apple.quarantine "$HELPER_PATH" >/dev/null 2>&1 || true
  if xattr -p com.apple.quarantine "$HELPER_PATH" >/dev/null 2>&1; then
    die "com.apple.quarantine is still set on $HELPER_PATH"
  fi

  install -o root -g wheel -m 0644 "$staged" "$PLIST_PATH"
}

wait_for_socket() {
  local i=0
  while [ "$i" -lt "$SOCKET_WAIT_TRIES" ]; do
    [ ! -S "$SOCKET_PATH" ] || return 0
    sleep "$SOCKET_WAIT_POLL_S"
    i=$((i + 1))
  done
  return 1
}

bootstrap_job() {
  if ! launchctl bootstrap system "$PLIST_PATH"; then
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
    die "launchctl bootstrap failed; nothing is loaded. Run scripts/uninstall-daemon-macos.sh --confirm to remove the files it left."
  fi
}

verify_install() {
  local job_loaded="no" socket_present="no" mode_ok="no" owner_ok="no"
  local expected_mode actual_mode expected_owner actual_owner verdict

  launchctl print "system/$LABEL" >/dev/null 2>&1 && job_loaded="yes"
  wait_for_socket && socket_present="yes"

  expected_mode="$(expected_socket_mode_octal "$DEV_MODE")"
  expected_owner="$(expected_socket_owner_uid "$DEV_MODE" "$INSTALL_UID")"
  actual_mode="?"
  actual_owner="?"
  if [ "$socket_present" = "yes" ]; then
    actual_mode="$(stat -f '%Lp' "$SOCKET_PATH")"
    actual_owner="$(stat -f '%u' "$SOCKET_PATH")"
    if [ "$actual_mode" = "$expected_mode" ]; then mode_ok="yes"; fi
    if [ "$actual_owner" = "$expected_owner" ]; then owner_ok="yes"; fi
  fi

  say "job         system/$LABEL loaded: $job_loaded"
  say "socket      $SOCKET_PATH present: $socket_present"
  say "socket mode $actual_mode (expected $expected_mode)"
  say "socket uid  $actual_owner (expected $expected_owner)"

  verdict="$(install_verdict "$job_loaded" "$socket_present" "$mode_ok" "$owner_ok")"
  say ""
  say "$verdict"
  if [ "$(verdict_requires_rollback "$verdict")" = "no" ]; then
    return 0
  fi

  say "Rolling back: booting the job out so nothing is left listening."
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  if [ -S "$SOCKET_PATH" ]; then
    rm -f "$SOCKET_PATH" || warn "could not remove $SOCKET_PATH"
  fi
  say "The daemon is NOT usable and is no longer loaded. Check $LOG_DIR/daemon.log,"
  say "then run scripts/uninstall-daemon-macos.sh --confirm to remove the files."
  return 1
}

print_plan() {
  local mode_label="release" sock_mode sock_owner
  [ "$DEV_MODE" = "no" ] || mode_label="DEV (insecure IPC)"
  sock_mode="$(expected_socket_mode_octal "$DEV_MODE")"
  sock_owner="$(expected_socket_owner_uid "$DEV_MODE" "${INSTALL_UID:-<SUDO_UID>}")"

  cat <<EOF
install-daemon-macos.sh would change this machine as follows ($mode_label):

  install  $BINARY
        -> $HELPER_PATH            root:wheel 0755
  strip    com.apple.quarantine from $HELPER_PATH
  render   $PLIST_SRC
           ($UID_PLACEHOLDER -> ${INSTALL_UID:-<SUDO_UID>})
        -> $PLIST_PATH  root:wheel 0644
  mkdir    $LOG_DIR                        root:wheel 0750
  mkdir    $STATE_DIR    root:wheel 0700
  run      launchctl bootout   system/$LABEL   (if already loaded)
           launchctl enable    system/$LABEL
           launchctl bootstrap system $PLIST_PATH
  expect   $SOCKET_PATH created by launchd, mode 0$sock_mode, uid $sock_owner

It will NOT touch routes, DNS, the firewall, or any other launchd job.
Re-run with --confirm to execute.
EOF

  # Classifying here too means the refusal is visible before anyone types sudo.
  if [ -f "$BINARY" ]; then
    local build
    build="$(detect_build)"
    say ""
    say "binary detected as: $build"
    say "mode check:         $(build_mode_verdict "$build" "$DEV_MODE")"
  else
    say ""
    say "binary not built yet: $BINARY"
  fi
}

warn_dev_mode() {
  cat <<EOF >&2

  ############################################################
  #  DEV MODE: installing a dev-insecure-ipc daemon.         #
  #  IPC peers are authenticated by uid ONLY — there is no    #
  #  code-signature check. The 0600 socket owned by uid       #
  #  $INSTALL_UID is the only thing standing between any process   #
  #  that user runs and root VPN control. Never ship this.    #
  ############################################################

EOF
}

main() {
  parse_args "$@"

  if [ "$SELF_TEST" = "yes" ]; then
    run_self_test
    return
  fi

  [ "$(uname -s)" = "Darwin" ] || die "this installer is macOS-only"
  resolve_defaults

  if [ "$CONFIRMED" != "yes" ]; then
    INSTALL_UID="${INSTALL_UID:-${SUDO_UID:-}}"
    print_plan
    return
  fi

  [ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0 --confirm)"
  [ -f "$BINARY" ] || die "daemon binary not found: $BINARY"
  [ -r "$PLIST_SRC" ] || die "plist not readable: $PLIST_SRC"
  resolve_uid
  [ "$DEV_MODE" = "no" ] || warn_dev_mode

  trap cleanup EXIT INT TERM
  STAGE_DIR="$(mktemp -d)"

  step "Checking the binary against the requested mode"
  check_build_matches_mode

  step "Rendering the plist for uid $INSTALL_UID"
  local staged
  staged="$(stage_plist)"
  say "staged $staged"

  step "Clearing any previous installation"
  bootout_existing

  step "Installing files"
  install_files "$staged"
  say "installed $HELPER_PATH and $PLIST_PATH"

  step "Bootstrapping system/$LABEL"
  bootstrap_job

  step "Verifying"
  verify_install
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

sample_plist() {
  cat <<EOF
<key>SockPathMode</key>
<integer>$RELEASE_SOCK_MODE_DECIMAL</integer>
<key>THISCONNECT_ALLOWED_UIDS</key>
<string>$UID_PLACEHOLDER</string>
EOF
}

test_accepts_ordinary_desktop_uid() {
  check_accepts "accepts_ordinary_desktop_uid" is_valid_uid "501"
}

test_rejects_root_uid() {
  check_rejects "rejects_root_uid" is_valid_uid "0"
}

test_rejects_non_numeric_uid() {
  check_rejects "rejects_non_numeric_uid" is_valid_uid "501; rm -rf /"
}

test_rejects_empty_uid() {
  check_rejects "rejects_empty_uid" is_valid_uid ""
}

test_renders_uid_into_plist() {
  local out
  out="$(sample_plist | render_installing_uid 501 | grep -c '<string>501</string>')"
  check_eq "renders_uid_into_plist" "1" "$out"
}

test_render_leaves_no_placeholder() {
  local out
  out="$(sample_plist | render_installing_uid 501 | grep -c "$UID_PLACEHOLDER" || true)"
  check_eq "render_leaves_no_placeholder" "0" "$out"
}

test_render_fails_on_already_rendered_plist() {
  local rc=0
  printf '<string>501</string>\n' | render_installing_uid 501 >/dev/null || rc=$?
  check_eq "render_fails_on_already_rendered_plist" "1" "$rc"
}

test_accepts_the_shipped_plist_shape() {
  check_eq "accepts_the_shipped_plist_shape" "ok" "$(plist_source_verdict "$(sample_plist)")"
}

test_rejects_plist_without_uid_placeholder() {
  local content
  content="$(sample_plist | sed "s/$UID_PLACEHOLDER/501/")"
  check_eq "rejects_plist_without_uid_placeholder" "missing-uid-placeholder" \
    "$(plist_source_verdict "$content")"
}

# 660 in a plist means 01224. This is the silent footgun the classifier exists for.
test_rejects_plist_with_octal_looking_sock_mode() {
  local content
  content="$(sample_plist | sed "s/<integer>$RELEASE_SOCK_MODE_DECIMAL<\/integer>/<integer>660<\/integer>/")"
  check_eq "rejects_plist_with_octal_looking_sock_mode" "unexpected-sock-mode" \
    "$(plist_source_verdict "$content")"
}

# The shipped artifact, not a stand-in for it: the synthetic cases above pass
# even if this file is deleted, renamed, or regressed to <integer>660</integer>.
shipped_plist_path() {
  printf '%s\n' "$(repo_root)/packaging/macos/net.thisconnect.daemon.plist"
}

test_shipped_plist_exists() {
  local path rc=0
  path="$(shipped_plist_path)"
  [ -r "$path" ] || rc=1
  check_eq "shipped_plist_exists" "0" "$rc"
}

test_shipped_plist_is_installable() {
  local path verdict
  path="$(shipped_plist_path)"
  if [ -r "$path" ]; then
    verdict="$(plist_source_verdict "$(cat "$path")")"
  else
    verdict="unreadable:$path"
  fi
  check_eq "shipped_plist_is_installable" "ok" "$verdict"
}

test_shipped_plist_parses() {
  local path result
  path="$(shipped_plist_path)"
  if ! command -v plutil >/dev/null 2>&1; then
    result="ok"
  elif [ ! -r "$path" ]; then
    result="unreadable"
  elif plutil -lint "$path" >/dev/null 2>&1; then
    result="ok"
  else
    result="malformed"
  fi
  check_eq "shipped_plist_parses" "ok" "$result"
}

# A 438 anywhere else in the document must not vouch for SockPathMode.
test_rejects_sock_mode_regression_despite_stray_decimal() {
  local content
  content="$(printf '%s\n' \
    "<key>SockPathMode</key>" \
    "<integer>660</integer>" \
    "<key>Nice</key>" \
    "<integer>$RELEASE_SOCK_MODE_DECIMAL</integer>" \
    "<string>$UID_PLACEHOLDER</string>")"
  check_eq "rejects_sock_mode_regression_despite_stray_decimal" "unexpected-sock-mode" \
    "$(plist_source_verdict "$content")"
}

test_rollback_is_skipped_on_pass() {
  check_eq "rollback_is_skipped_on_pass" "no" \
    "$(verdict_requires_rollback "PASS job loaded and socket ready")"
}

test_rollback_runs_when_socket_mode_is_wrong() {
  check_eq "rollback_runs_when_socket_mode_is_wrong" "yes" \
    "$(verdict_requires_rollback "FAIL socket mode wrong")"
}

test_rollback_runs_when_socket_owner_is_wrong() {
  check_eq "rollback_runs_when_socket_owner_is_wrong" "yes" \
    "$(verdict_requires_rollback "FAIL socket owner wrong")"
}

test_rollback_runs_for_every_non_pass_verdict() {
  local combo rollback="" v
  for combo in "no yes yes yes" "yes no yes yes" "yes yes no yes" "yes yes yes no"; do
    # shellcheck disable=SC2086 # the split into four arguments is the point
    v="$(install_verdict $combo)"
    rollback="$rollback$(verdict_requires_rollback "$v")"
  done
  check_eq "rollback_runs_for_every_non_pass_verdict" "yesyesyesyes" "$rollback"
}

test_classifies_release_build() {
  check_eq "classifies_release_build" "release" "$(classify_build yes no)"
}

test_classifies_dev_build() {
  check_eq "classifies_dev_build" "dev-insecure" "$(classify_build no yes)"
}

test_classifies_marker_free_binary_as_unknown() {
  check_eq "classifies_marker_free_binary_as_unknown" "unknown" "$(classify_build no no)"
}

test_classifies_both_markers_as_unknown() {
  check_eq "classifies_both_markers_as_unknown" "unknown" "$(classify_build yes yes)"
}

test_refuses_dev_build_in_release_mode() {
  check_eq "refuses_dev_build_in_release_mode" "refuse-dev-build-in-release-mode" \
    "$(build_mode_verdict dev-insecure no)"
}

test_refuses_release_build_in_dev_mode() {
  check_eq "refuses_release_build_in_dev_mode" "refuse-release-build-in-dev-mode" \
    "$(build_mode_verdict release yes)"
}

test_refuses_unclassifiable_build() {
  check_eq "refuses_unclassifiable_build" "refuse-unknown-build" \
    "$(build_mode_verdict unknown no)"
}

test_allows_matching_release_install() {
  check_eq "allows_matching_release_install" "ok" "$(build_mode_verdict release no)"
}

test_allows_matching_dev_install() {
  check_eq "allows_matching_dev_install" "ok" "$(build_mode_verdict dev-insecure yes)"
}

test_release_socket_is_world_reachable() {
  check_eq "release_socket_is_world_reachable" "666" "$(expected_socket_mode_octal no)"
}

test_dev_socket_is_owner_only() {
  check_eq "dev_socket_is_owner_only" "600" "$(expected_socket_mode_octal yes)"
}

test_plist_sock_mode_is_decimal() {
  check_eq "plist_sock_mode_is_decimal" "438" "$(expected_socket_mode_decimal no)"
}

test_dev_plist_sock_mode_is_decimal() {
  check_eq "dev_plist_sock_mode_is_decimal" "384" "$(expected_socket_mode_decimal yes)"
}

test_release_socket_is_owned_by_root() {
  check_eq "release_socket_is_owned_by_root" "0" "$(expected_socket_owner_uid no 501)"
}

test_dev_socket_is_owned_by_installer() {
  check_eq "dev_socket_is_owned_by_installer" "501" "$(expected_socket_owner_uid yes 501)"
}

test_install_passes_only_when_every_check_holds() {
  check_eq "install_passes_only_when_every_check_holds" "PASS job loaded and socket ready" \
    "$(install_verdict yes yes yes yes)"
}

test_install_fails_when_job_did_not_load() {
  check_eq "install_fails_when_job_did_not_load" "FAIL job not loaded" \
    "$(install_verdict no yes yes yes)"
}

test_install_fails_when_socket_never_appeared() {
  check_eq "install_fails_when_socket_never_appeared" "FAIL socket missing at $SOCKET_PATH" \
    "$(install_verdict yes no yes yes)"
}

test_install_fails_on_wrong_socket_mode() {
  check_eq "install_fails_on_wrong_socket_mode" "FAIL socket mode wrong" \
    "$(install_verdict yes yes no yes)"
}

test_install_fails_on_wrong_socket_owner() {
  check_eq "install_fails_on_wrong_socket_owner" "FAIL socket owner wrong" \
    "$(install_verdict yes yes yes no)"
}

run_self_test() {
  test_accepts_ordinary_desktop_uid
  test_rejects_root_uid
  test_rejects_non_numeric_uid
  test_rejects_empty_uid
  test_renders_uid_into_plist
  test_render_leaves_no_placeholder
  test_render_fails_on_already_rendered_plist
  test_accepts_the_shipped_plist_shape
  test_rejects_plist_without_uid_placeholder
  test_rejects_plist_with_octal_looking_sock_mode
  test_rejects_sock_mode_regression_despite_stray_decimal
  test_shipped_plist_exists
  test_shipped_plist_is_installable
  test_shipped_plist_parses
  test_rollback_is_skipped_on_pass
  test_rollback_runs_when_socket_mode_is_wrong
  test_rollback_runs_when_socket_owner_is_wrong
  test_rollback_runs_for_every_non_pass_verdict
  test_classifies_release_build
  test_classifies_dev_build
  test_classifies_marker_free_binary_as_unknown
  test_classifies_both_markers_as_unknown
  test_refuses_dev_build_in_release_mode
  test_refuses_release_build_in_dev_mode
  test_refuses_unclassifiable_build
  test_allows_matching_release_install
  test_allows_matching_dev_install
  test_release_socket_is_world_reachable
  test_dev_socket_is_owner_only
  test_plist_sock_mode_is_decimal
  test_dev_plist_sock_mode_is_decimal
  test_release_socket_is_owned_by_root
  test_dev_socket_is_owned_by_installer
  test_install_passes_only_when_every_check_holds
  test_install_fails_when_job_did_not_load
  test_install_fails_when_socket_never_appeared
  test_install_fails_on_wrong_socket_mode
  test_install_fails_on_wrong_socket_owner
  say ""
  say "$((TESTS_RUN - TESTS_FAILED))/$TESTS_RUN self-tests passed"
  [ "$TESTS_FAILED" -eq 0 ]
}

main "$@"
