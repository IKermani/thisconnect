// SPDX-License-Identifier: GPL-3.0-or-later

//! IPC peer authentication (SPEC.md 7.3).
//!
//! A root daemon with an unauthenticated local socket is a local privilege
//! escalation, so every connection is authenticated before a single byte of it
//! is interpreted, and every error path denies.

use std::collections::BTreeSet;
use std::sync::Arc;

use thiserror::Error;
use tokio::net::UnixStream;

/// Shipping a relaxed authenticator in a release artifact is a straight
/// local-privilege-escalation bug, so make it impossible rather than a CI-only
/// assertion.
#[cfg(all(feature = "dev-insecure-ipc", not(debug_assertions)))]
compile_error!(
    "feature `dev-insecure-ipc` relaxes IPC peer authentication to a uid check and must never \
     be built into a release artifact. Build without --release, or drop the feature."
);

/// Designated requirement the macOS peer's code signature must satisfy once the
/// `security-framework` dependency is available. The Developer ID Application
/// marker OID is not optional: without it a Mac App Store or development
/// certificate issued to the same team also satisfies the requirement.
#[allow(dead_code)] // consumed by the code-signature seam in peerauth::macos
pub const GUI_DESIGNATED_REQUIREMENT: &str = "anchor apple generic \
     and identifier \"net.thisconnect.gui\" \
     and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
     and certificate leaf[subject.OU] = \"TEAMID\"";

/// Linux authorisation group. Membership in it is the whole authorisation model
/// in v1 (SPEC.md 7.1); there is deliberately no polkit.
#[allow(dead_code)] // Linux-only authorisation model
pub const AUTHORISED_GROUP: &str = "thisconnect";

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("peer uid {uid} gid {gid:?} is not authorised")]
    NotAuthorised { uid: u32, gid: Option<u32> },

    #[error("an empty peer policy would authorise nobody or everybody; refusing to start")]
    EmptyPolicy,

    #[error("{op} failed: {source}")]
    Syscall {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },

    #[error("peer audit token was {0} bytes, expected 32")]
    TokenSize(usize),

    #[error(
        "peer code-signature verification is not implemented in this build; \
         denying. See SPEC.md 7.3"
    )]
    CodeVerificationUnavailable,

    #[error("group {0} does not exist")]
    UnknownGroup(String),
}

/// Everything the daemon is allowed to know about a peer before it decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: Option<u32>,
    pub pid: Option<i32>,
}

/// Who may talk to the daemon. Built once at startup and never mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    uids: BTreeSet<u32>,
    gids: BTreeSet<u32>,
}

impl PeerPolicy {
    pub fn new(
        uids: impl IntoIterator<Item = u32>,
        gids: impl IntoIterator<Item = u32>,
    ) -> Result<Self, AuthError> {
        let policy = Self {
            uids: uids.into_iter().collect(),
            gids: gids.into_iter().collect(),
        };
        if policy.uids.is_empty() && policy.gids.is_empty() {
            return Err(AuthError::EmptyPolicy);
        }
        Ok(policy)
    }

    pub fn permits(&self, peer: &PeerIdentity) -> bool {
        self.uids.contains(&peer.uid) || peer.gid.is_some_and(|gid| self.gids.contains(&gid))
    }

    fn check(&self, peer: PeerIdentity) -> Result<PeerIdentity, AuthError> {
        if self.permits(&peer) {
            return Ok(peer);
        }
        Err(AuthError::NotAuthorised {
            uid: peer.uid,
            gid: peer.gid,
        })
    }
}

pub trait PeerAuthenticator: Send + Sync + 'static {
    /// Must be called on every connection, before any command is read.
    fn authenticate(&self, stream: &UnixStream) -> Result<PeerIdentity, AuthError>;

    /// Human-readable name of the control in force, for the startup log.
    fn describe(&self) -> &'static str;
}

#[allow(dead_code)] // unused on macOS, where the audit token is authoritative
fn peer_cred(stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
    let cred = stream.peer_cred().map_err(|source| AuthError::Syscall {
        op: "SO_PEERCRED",
        source,
    })?;
    Ok(PeerIdentity {
        uid: cred.uid(),
        gid: Some(cred.gid()),
        pid: cred.pid(),
    })
}

/// Linux: `SO_PEERCRED` via tokio, checking uid *and* gid (SPEC.md 7.3).
///
/// The 0660 `root:thisconnect` socket already gates `connect()`, so this is the
/// second of two independent controls, not the only one.
#[allow(dead_code)] // not constructed on macOS
pub struct PeercredAuthenticator {
    policy: PeerPolicy,
}

#[allow(dead_code)] // not constructed on macOS
impl PeercredAuthenticator {
    pub fn new(policy: PeerPolicy) -> Self {
        Self { policy }
    }
}

impl PeerAuthenticator for PeercredAuthenticator {
    fn authenticate(&self, stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
        self.policy.check(peer_cred(stream)?)
    }

    fn describe(&self) -> &'static str {
        "SO_PEERCRED uid+gid"
    }
}

/// Relaxed development authenticator: uid only, no code-signature check.
///
/// Paired with a 0600 socket owned by that uid (SPEC.md 7.3) — relaxed auth on a
/// 0666 socket would hand root VPN control to any process the desktop user runs.
#[cfg(feature = "dev-insecure-ipc")]
pub struct UidOnlyAuthenticator {
    policy: PeerPolicy,
}

#[cfg(feature = "dev-insecure-ipc")]
impl UidOnlyAuthenticator {
    pub fn new(uid: u32) -> Result<Self, AuthError> {
        Ok(Self {
            policy: PeerPolicy::new([uid], [])?,
        })
    }
}

#[cfg(feature = "dev-insecure-ipc")]
impl PeerAuthenticator for UidOnlyAuthenticator {
    fn authenticate(&self, stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
        let peer = peer_cred(stream)?;
        self.policy.check(PeerIdentity { gid: None, ..peer })
    }

    fn describe(&self) -> &'static str {
        "INSECURE uid-only (dev-insecure-ipc)"
    }
}

/// Parse `/etc/group` content for a gid. Reading the file rather than calling
/// `getgrnam` keeps this pure, testable, and free of a non-reentrant libc call
/// on a multi-threaded runtime.
pub fn parse_group_id(etc_group: &str, name: &str) -> Option<u32> {
    etc_group
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let group = fields.next()?;
            let _passwd = fields.next()?;
            let gid = fields.next()?;
            (group == name).then(|| gid.trim().parse().ok())?
        })
        .next()
}

#[allow(dead_code)] // Linux-only authorisation model
pub fn lookup_group_id(name: &str) -> Result<u32, AuthError> {
    let content = std::fs::read_to_string("/etc/group").map_err(|source| AuthError::Syscall {
        op: "read /etc/group",
        source,
    })?;
    parse_group_id(&content, name).ok_or_else(|| AuthError::UnknownGroup(name.to_owned()))
}

/// Build the authenticator this build and platform is allowed to use.
///
/// One definition per build configuration, so an unreachable combination is a
/// compile error rather than a silently permissive fallback.
#[cfg(feature = "dev-insecure-ipc")]
pub fn authenticator(policy: PeerPolicy) -> Result<Arc<dyn PeerAuthenticator>, AuthError> {
    let uid = policy
        .uids
        .iter()
        .copied()
        .next()
        .ok_or(AuthError::EmptyPolicy)?;
    Ok(Arc::new(UidOnlyAuthenticator::new(uid)?))
}

#[cfg(all(not(feature = "dev-insecure-ipc"), target_os = "macos"))]
pub fn authenticator(policy: PeerPolicy) -> Result<Arc<dyn PeerAuthenticator>, AuthError> {
    Ok(Arc::new(macos::AuditTokenAuthenticator::new(
        policy,
        Arc::new(macos::UnimplementedCodeVerifier),
    )))
}

#[cfg(all(not(feature = "dev-insecure-ipc"), not(target_os = "macos")))]
pub fn authenticator(policy: PeerPolicy) -> Result<Arc<dyn PeerAuthenticator>, AuthError> {
    Ok(Arc::new(PeercredAuthenticator::new(policy)))
}

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn peer(uid: u32, gid: Option<u32>) -> PeerIdentity {
        PeerIdentity {
            uid,
            gid,
            pid: None,
        }
    }

    #[test]
    fn rejects_an_empty_policy_at_construction_rather_than_authorising_nobody() {
        let result = PeerPolicy::new([], []);

        assert!(matches!(result, Err(AuthError::EmptyPolicy)));
    }

    #[test]
    fn permits_a_peer_whose_uid_is_listed() {
        let policy = PeerPolicy::new([501], []).expect("policy");

        assert!(policy.permits(&peer(501, Some(20))));
    }

    #[test]
    fn permits_a_peer_whose_gid_is_listed_even_with_an_unlisted_uid() {
        let policy = PeerPolicy::new([], [977]).expect("policy");

        assert!(policy.permits(&peer(1234, Some(977))));
    }

    #[test]
    fn denies_a_peer_matching_neither_uid_nor_gid() {
        let policy = PeerPolicy::new([501], [977]).expect("policy");

        assert!(!policy.permits(&peer(1234, Some(20))));
    }

    #[test]
    fn denies_a_peer_with_an_unknown_gid_when_only_gids_are_authorised() {
        let policy = PeerPolicy::new([], [977]).expect("policy");

        assert!(!policy.permits(&peer(977, None)));
    }

    #[test]
    fn check_reports_the_offending_identity_instead_of_succeeding() {
        let policy = PeerPolicy::new([501], []).expect("policy");

        let result = policy.check(peer(0, Some(0)));

        assert!(matches!(
            result,
            Err(AuthError::NotAuthorised {
                uid: 0,
                gid: Some(0)
            })
        ));
    }

    #[test]
    fn parses_the_gid_of_the_named_group() {
        let content = "root:x:0:\nthisconnect:x:977:alice,bob\nwheel:x:10:\n";

        assert_eq!(parse_group_id(content, "thisconnect"), Some(977));
    }

    #[test]
    fn returns_none_for_a_group_that_is_absent() {
        let content = "root:x:0:\nwheel:x:10:\n";

        assert_eq!(parse_group_id(content, "thisconnect"), None);
    }

    #[test]
    fn returns_none_for_a_malformed_group_line_rather_than_a_wrong_gid() {
        let content = "thisconnect:x:notanumber:\n";

        assert_eq!(parse_group_id(content, "thisconnect"), None);
    }

    #[test]
    fn designated_requirement_pins_the_developer_id_marker_oid() {
        assert!(GUI_DESIGNATED_REQUIREMENT.contains("field.1.2.840.113635.100.6.1.13"));
        assert!(GUI_DESIGNATED_REQUIREMENT.contains("net.thisconnect.gui"));
    }
}
