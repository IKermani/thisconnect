// SPDX-License-Identifier: GPL-3.0-or-later

//! `thisconnectd` — the privileged daemon (SPEC.md 7).
//!
//! It owns the control socket, the openvpn supervisor, and tunnel policy. The
//! GUI never runs as root and never touches packets; everything privileged
//! happens behind the peer-authenticated socket set up here.

mod ipc;
// The supervisor's public surface is re-exported for the tunnel-policy and IPC
// command modules that are not wired up yet; until they land nothing consumes it.
#[allow(unused_imports, dead_code)]
mod mgmt;
mod peerauth;
mod signals;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use ipc::listener::{acquire, ListenerConfig, SocketSource};
use ipc::{IpcServer, SkeletonHandler};
#[cfg(all(not(feature = "dev-insecure-ipc"), target_os = "linux"))]
use peerauth::lookup_group_id;
use peerauth::AUTHORISED_GROUP;
use peerauth::{authenticator, PeerPolicy};

#[cfg(target_os = "macos")]
const DEFAULT_SOCKET_PATH: &str = "/var/run/thisconnect.sock";
#[cfg(not(target_os = "macos"))]
const DEFAULT_SOCKET_PATH: &str = "/run/thisconnect/thisconnectd.sock";

const SOCKET_PATH_ENV: &str = "THISCONNECT_SOCKET";
const ALLOWED_UIDS_ENV: &str = "THISCONNECT_ALLOWED_UIDS";
const ALLOWED_GIDS_ENV: &str = "THISCONNECT_ALLOWED_GIDS";

fn init_tracing() {
    let filter = EnvFilter::try_from_env("THISCONNECT_LOG")
        .unwrap_or_else(|_| EnvFilter::new("thisconnectd=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // Credentials and TOTP codes must never reach a log sink; auth-flow
        // logging is opt-in and redacted elsewhere.
        .init();
}

/// Parse a comma-separated id list. Empty input yields an empty list rather than
/// a wildcard — a policy that authorises nobody is rejected later, loudly.
fn parse_id_list(raw: &str) -> Result<Vec<u32>> {
    raw.split(',')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .map(|field| {
            field
                .parse::<u32>()
                .with_context(|| format!("{field:?} is not a numeric id"))
        })
        .collect()
}

fn ids_from_env(key: &str) -> Result<Vec<u32>> {
    match std::env::var(key) {
        Ok(raw) => parse_id_list(&raw).with_context(|| format!("{key} is malformed")),
        Err(_) => Ok(Vec::new()),
    }
}

/// Who may drive this daemon. Explicit configuration always wins; otherwise the
/// platform default applies, and if neither yields anything the daemon refuses
/// to start rather than listening for anyone.
fn resolve_policy() -> Result<PeerPolicy> {
    let uids = ids_from_env(ALLOWED_UIDS_ENV)?;
    let gids = ids_from_env(ALLOWED_GIDS_ENV)?;
    if !uids.is_empty() || !gids.is_empty() {
        return Ok(PeerPolicy::new(uids, gids)?);
    }
    platform_default_policy()
}

/// The dev socket is 0600 owned by this uid, so the developer running the daemon
/// is the only peer that can reach it in the first place.
#[cfg(feature = "dev-insecure-ipc")]
fn platform_default_policy() -> Result<PeerPolicy> {
    let uid = ids_from_env("SUDO_UID")?
        .first()
        .copied()
        // SAFETY: reading our own uid has no preconditions.
        .unwrap_or_else(|| unsafe { libc::getuid() });
    Ok(PeerPolicy::new([uid], [])?)
}

/// Users named in a group's `/etc/group` member list, i.e. everyone for whom it
/// is a *supplementary* group.
#[allow(dead_code)] // Linux-only authorisation model
fn parse_group_members(etc_group: &str, name: &str) -> Vec<String> {
    etc_group
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let group = fields.next()?;
            let _passwd = fields.next()?;
            let _gid = fields.next()?;
            let members = fields.next()?;
            (group == name).then(|| {
                members
                    .split(',')
                    .map(str::trim)
                    .filter(|member| !member.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
        })
        .next()
        .unwrap_or_default()
}

/// uids of every local account in the authorised group, whether it is their
/// primary group (passwd field 4) or a supplementary one (`members`).
#[allow(dead_code)] // Linux-only authorisation model
fn parse_authorised_uids(etc_passwd: &str, members: &[String], gid: u32) -> Vec<u32> {
    etc_passwd
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _passwd = fields.next()?;
            let uid = fields.next()?.trim().parse::<u32>().ok()?;
            let primary_gid = fields.next()?.trim().parse::<u32>().ok()?;
            let is_authorised = primary_gid == gid || members.iter().any(|member| member == name);
            is_authorised.then_some(uid)
        })
        .collect()
}

/// Expand group membership into the uid set the authenticator can actually match.
///
/// `SO_PEERCRED` reports only the peer's *primary* gid, but users are added with
/// `usermod -aG`, which makes `thisconnect` a *supplementary* group. Matching the
/// reported gid alone therefore denies every real desktop user (SPEC.md 7.1,
/// "Group-membership UX trap"). The gid stays in the policy for the minority of
/// accounts whose primary group it is; root is always authorised.
#[allow(dead_code)] // Linux-only authorisation model
fn group_backed_policy(etc_group: &str, etc_passwd: &str, gid: u32) -> Result<PeerPolicy> {
    let members = parse_group_members(etc_group, AUTHORISED_GROUP);
    let uids = parse_authorised_uids(etc_passwd, &members, gid);
    Ok(PeerPolicy::new(uids.into_iter().chain([0]), [gid])?)
}

/// Group membership is the authorisation model in v1 (SPEC.md 7.1).
///
/// The kernel-enforced `root:thisconnect 0660` socket is the live gate on
/// `connect()` and does honour supplementary groups; this uid set is the second,
/// independent control and is a startup snapshot — a user added to the group
/// afterwards is authorised only once the daemon restarts.
#[cfg(all(not(feature = "dev-insecure-ipc"), target_os = "linux"))]
fn platform_default_policy() -> Result<PeerPolicy> {
    let gid = lookup_group_id(AUTHORISED_GROUP)?;
    let etc_group = std::fs::read_to_string("/etc/group").context("read /etc/group")?;
    let etc_passwd = std::fs::read_to_string("/etc/passwd").context("read /etc/passwd")?;
    let policy = group_backed_policy(&etc_group, &etc_passwd, gid)?;
    // TODO: local files only; NSS-backed (LDAP/SSSD) members are invisible here.
    if parse_group_members(&etc_group, AUTHORISED_GROUP).is_empty() {
        warn!(
            group = AUTHORISED_GROUP,
            "no local account is a member; only root can drive the daemon until a user is added and the daemon is restarted"
        );
    }
    Ok(policy)
}

#[cfg(all(not(feature = "dev-insecure-ipc"), not(target_os = "linux")))]
fn platform_default_policy() -> Result<PeerPolicy> {
    Err(anyhow::anyhow!(
        "no peer policy: set {ALLOWED_UIDS_ENV} to the console user's uid. \
         Resolving it automatically needs SCDynamicStoreCopyConsoleUser (SPEC.md 7.3)"
    ))
}

/// `IFF_PERSIST` outlives the process by design, and macOS scoped routes outlive
/// a dead utun, so a crashed daemon leaks state that the next run collides with.
async fn reconcile_startup_state() {
    // TODO: Linux — enumerate tc* devices owned by our uid, tear down leftovers
    // and their table-218 routes and `from <tunip>` rules, floor route last.
    // TODO: macOS — drop scoped routes pointing at a dead or recycled utun.
    // Both need the tunnel-policy module; until it lands, say so rather than
    // pretending the host is clean.
    warn!("startup reconciliation is not implemented yet; leftover tun devices and routes from a crashed run are not cleaned up");
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    if cfg!(feature = "dev-insecure-ipc") {
        warn!("INSECURE BUILD: dev-insecure-ipc authenticates IPC peers by uid only, with no code-signature check. Never ship this.");
    }

    let policy = resolve_policy()?;
    let authenticator = authenticator(policy)?;

    let path = std::env::var(SOCKET_PATH_ENV).unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_owned());
    let config = ListenerConfig::new(path.clone());
    let (listener, source) = acquire(&config)?;
    if source == SocketSource::SelfBound {
        warn!(
            path = %path,
            "socket activation unavailable; the daemon bound the socket itself, which leaves a bind-to-chmod window"
        );
    }

    reconcile_startup_state().await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    signals::install(shutdown_tx).context("install signal handlers")?;

    info!(
        path = %path,
        source = ?source,
        auth = authenticator.describe(),
        "IPC server listening"
    );
    IpcServer::new(listener, authenticator, Arc::new(SkeletonHandler))
        .run(shutdown_rx)
        .await;

    info!("stopped");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_comma_separated_id_list() {
        assert_eq!(
            parse_id_list("0, 501,977").expect("parse"),
            vec![0, 501, 977]
        );
    }

    #[test]
    fn treats_an_empty_setting_as_no_ids_rather_than_all_ids() {
        assert_eq!(parse_id_list("").expect("parse"), Vec::<u32>::new());
    }

    #[test]
    fn rejects_a_non_numeric_id_instead_of_skipping_it() {
        assert!(parse_id_list("501,root").is_err());
    }

    #[test]
    fn rejects_a_negative_id_instead_of_wrapping_it() {
        assert!(parse_id_list("-1").is_err());
    }

    const ETC_GROUP: &str = "root:x:0:\nthisconnect:x:977:alice, bob\nwheel:x:10:alice\n";
    const ETC_PASSWD: &str = concat!(
        "root:x:0:0::/root:/bin/sh\n",
        "alice:x:1000:1000::/home/alice:/bin/sh\n",
        "bob:x:1001:1001::/home/bob:/bin/sh\n",
        "carol:x:1002:1002::/home/carol:/bin/sh\n",
        "dave:x:1003:977::/home/dave:/bin/sh\n",
    );

    fn peer(uid: u32, gid: u32) -> peerauth::PeerIdentity {
        peerauth::PeerIdentity {
            uid,
            gid: Some(gid),
            pid: None,
        }
    }

    #[test]
    fn permits_a_peer_whose_supplementary_group_is_authorised() {
        let policy = group_backed_policy(ETC_GROUP, ETC_PASSWD, 977).expect("policy");

        // alice is in thisconnect only as a supplementary group, so SO_PEERCRED
        // reports her own primary gid 1000, not 977.
        assert!(policy.permits(&peer(1000, 1000)));
    }

    #[test]
    fn permits_a_peer_whose_primary_group_is_authorised() {
        let policy = group_backed_policy(ETC_GROUP, ETC_PASSWD, 977).expect("policy");

        assert!(policy.permits(&peer(1003, 977)));
    }

    #[test]
    fn permits_root_so_the_daemon_is_never_locked_out() {
        let policy = group_backed_policy("root:x:0:\nthisconnect:x:977:\n", ETC_PASSWD, 977)
            .expect("policy");

        assert!(policy.permits(&peer(0, 0)));
    }

    #[test]
    fn denies_a_peer_who_is_not_in_the_authorised_group() {
        let policy = group_backed_policy(ETC_GROUP, ETC_PASSWD, 977).expect("policy");

        assert!(!policy.permits(&peer(1002, 1002)));
    }

    #[test]
    fn reads_supplementary_members_ignoring_surrounding_whitespace() {
        assert_eq!(
            parse_group_members(ETC_GROUP, "thisconnect"),
            vec!["alice".to_owned(), "bob".to_owned()]
        );
    }

    #[test]
    fn treats_a_group_with_no_members_as_empty_rather_than_a_blank_name() {
        assert_eq!(
            parse_group_members("thisconnect:x:977:\n", "thisconnect"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn returns_no_members_for_a_group_that_is_absent() {
        assert_eq!(
            parse_group_members("wheel:x:10:alice\n", "thisconnect"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn collects_both_primary_and_supplementary_members_from_passwd() {
        let members = vec!["alice".to_owned(), "bob".to_owned()];

        let uids = parse_authorised_uids(ETC_PASSWD, &members, 977);

        assert_eq!(uids, vec![1000, 1001, 1003]);
    }

    #[test]
    fn skips_a_malformed_passwd_line_instead_of_authorising_it() {
        let members = vec!["alice".to_owned()];

        let uids = parse_authorised_uids("alice:x:notanumber:1000::/:/bin/sh\n", &members, 977);

        assert_eq!(uids, Vec::<u32>::new());
    }

    #[test]
    fn socket_path_matches_the_packaging_for_this_platform() {
        if cfg!(target_os = "macos") {
            assert_eq!(DEFAULT_SOCKET_PATH, "/var/run/thisconnect.sock");
        } else {
            assert_eq!(DEFAULT_SOCKET_PATH, "/run/thisconnect/thisconnectd.sock");
        }
    }
}
