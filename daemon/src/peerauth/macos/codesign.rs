// SPDX-License-Identifier: GPL-3.0-or-later

//! Code-signature half of macOS peer authentication (SPEC.md 7.3).
//!
//! `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` turns the peer's
//! audit token into a live code object, and `SecCodeCheckValidity` holds that
//! object to a compiled-in designated requirement. Every non-zero `OSStatus`
//! is a denial: the interesting failures here — `errSecCSUnsigned`,
//! `kPOSIXErrorEPERM` when the peer has already exited, a translocated app —
//! are exactly the states an attacker would try to provoke, so
//! log-and-continue would be the vulnerability rather than a robustness
//! nicety.

use core_foundation::base::TCFType;
use core_foundation::data::CFData;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use super::console::{console_user, ConsoleUser};
// `requirement` is reached only from the release path and from tests.
#[cfg_attr(feature = "dev-insecure-ipc", allow(unused_imports))]
use super::{deny, requirement, AuditToken, CodeVerifier, AUDIT_TOKEN_WORDS};
use crate::peerauth::AuthError;

/// Reinterpret the audit token as the byte string the kernel produced.
///
/// The token arrives from `getsockopt` as eight host-order words, so
/// native-endian bytes reproduce the original 32 octets exactly.
const AUDIT_TOKEN_BYTES: usize = AUDIT_TOKEN_WORDS * 4;

fn token_bytes(token: &AuditToken) -> [u8; AUDIT_TOKEN_BYTES] {
    let mut bytes = [0u8; AUDIT_TOKEN_BYTES];
    for (word, chunk) in token.words().iter().zip(bytes.chunks_exact_mut(4)) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    bytes
}

/// Turn a Security framework failure into a denial, keeping the numeric
/// `OSStatus` so an operator can tell `errSecCSReqFailed` from a peer that
/// exited, and deliberately keeping the peer's path out of the log.
fn security_failure(op: &'static str, err: &security_framework::base::Error) -> AuthError {
    deny(op, format!("OSStatus {}", err.code()))
}

/// Check a peer's audit token against an arbitrary requirement string.
///
/// Separated from the policy above it so the requirement can be varied in
/// tests; production callers always pass [`requirement::designated_requirement`].
pub fn check_audit_token(token: &AuditToken, requirement_text: &str) -> Result<(), AuthError> {
    let requirement: SecRequirement = requirement_text
        .parse()
        .map_err(|err| security_failure("SecRequirementCreateWithString", &err))?;

    // The dictionary stores the CFDataRef without retaining it, so `data` must
    // outlive every use of `attrs`. Binding it here rather than passing a
    // temporary is load-bearing, not style.
    let data = CFData::from_buffer(&token_bytes(token));
    let mut attrs = GuestAttributes::new();
    attrs.set_audit_token(data.as_concrete_TypeRef());

    let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
        .map_err(|err| security_failure("SecCodeCopyGuestWithAttributes", &err))?;

    code.check_validity(Flags::NONE, &requirement)
        .map_err(|err| security_failure("SecCodeCheckValidity", &err))
}

/// Release verifier: console-user ownership plus the designated requirement.
pub struct DesignatedRequirementVerifier;

impl DesignatedRequirementVerifier {
    /// The peer must belong to the human currently at the machine. A daemon
    /// that skips this authenticates a background uid nobody is sitting in
    /// front of.
    fn check_console_user(token: &AuditToken) -> Result<(), AuthError> {
        match console_user() {
            ConsoleUser::None => Err(deny(
                "SCDynamicStoreCopyConsoleUser",
                "no console user (login window, headless, or SSH-only session)",
            )),
            ConsoleUser::LoggedIn { uid } if uid == token.euid() => Ok(()),
            ConsoleUser::LoggedIn { .. } => Err(AuthError::NotAuthorised {
                uid: token.euid(),
                gid: Some(token.egid()),
            }),
        }
    }

    /// The two authentication paths are mutually exclusive by construction: the
    /// parent module refuses to build `dev-insecure-ipc` into a release
    /// artifact, and this function refuses to accept anything when that feature
    /// is on. Neither can silently stand in for the other.
    #[cfg(not(feature = "dev-insecure-ipc"))]
    fn check(token: &AuditToken) -> Result<(), AuthError> {
        Self::check_console_user(token)?;
        check_audit_token(token, &requirement::designated_requirement()?)
    }

    #[cfg(feature = "dev-insecure-ipc")]
    fn check(_token: &AuditToken) -> Result<(), AuthError> {
        Err(AuthError::CodeVerificationUnavailable)
    }
}

impl CodeVerifier for DesignatedRequirementVerifier {
    fn verify(&self, token: &AuditToken) -> Result<(), AuthError> {
        Self::check(token)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::peerauth::macos::peer_audit_token;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// errSecCSReqFailed: "code failed to satisfy specified code requirement(s)".
    const ERR_SEC_CS_REQ_FAILED: i32 = -67050;

    /// An Apple-signed binary that will connect to an `AF_UNIX` path and stay
    /// alive, so the token under test belongs to a real, separately signed peer
    /// rather than to the test harness.
    const SIGNED_PEER: &str = "/usr/bin/nc";
    const SIGNED_PEER_REQUIREMENT: &str = "anchor apple and identifier \"com.apple.nc\"";

    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);

    /// A live connection from a separately signed process, torn down on drop.
    ///
    /// A `socketpair` cannot stand in for this: both ends carry the audit token
    /// of the process that created the pair, so a forked-and-exec'd child on
    /// the far end still reports the harness's own code identity. Only a real
    /// `bind`/`connect` produces the peer's token.
    struct SignedPeer {
        stream: UnixStream,
        child: Child,
        dir: std::path::PathBuf,
    }

    impl SignedPeer {
        fn connect() -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("tc-peerauth-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let path = dir.join("sock");
            let _ = std::fs::remove_file(&path);

            let listener = UnixListener::bind(&path).expect("bind");
            listener.set_nonblocking(true).expect("nonblocking");

            let child = Command::new(SIGNED_PEER)
                .arg("-U")
                .arg(&path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn signed peer");

            let deadline = Instant::now() + ACCEPT_TIMEOUT;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "signed peer never connected");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept: {err}"),
                }
            };

            Self { stream, child, dir }
        }

        fn token(&self) -> AuditToken {
            peer_audit_token(self.stream.as_raw_fd()).expect("peer audit token")
        }
    }

    impl Drop for SignedPeer {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn osstatus_of(result: Result<(), AuthError>) -> String {
        match result {
            Err(AuthError::Syscall { source, .. }) => source.to_string(),
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn token_bytes_round_trip_the_kernel_octets_in_host_order() {
        let token = AuditToken::from_words([1, 2, 3, 4, 5, 6, 7, 8]);

        let bytes = token_bytes(&token);

        assert_eq!(bytes.len(), AUDIT_TOKEN_BYTES);
        assert_eq!(
            u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            2
        );
    }

    #[test]
    fn a_malformed_requirement_string_denies_instead_of_defaulting_to_accept() {
        let token = AuditToken::from_words([0; 8]);

        let result = check_audit_token(&token, "this is not a requirement");

        assert!(matches!(result, Err(AuthError::Syscall { .. })));
    }

    #[test]
    fn an_audit_token_belonging_to_no_live_process_denies() {
        let token = AuditToken::from_words([0; 8]);

        let result = check_audit_token(&token, "anchor apple");

        // UNIX[No such process] surfaces as OSStatus 100003, not a success.
        assert!(matches!(result, Err(AuthError::Syscall { .. })));
    }

    #[test]
    fn a_matching_requirement_accepts_a_real_connected_peer() {
        let peer = SignedPeer::connect();

        let result = check_audit_token(&peer.token(), SIGNED_PEER_REQUIREMENT);

        assert!(result.is_ok(), "expected errSecSuccess, got {result:?}");
    }

    #[test]
    fn a_wrong_designated_requirement_denies_the_same_real_peer() {
        let peer = SignedPeer::connect();
        let wrong = requirement::build("net.thisconnect.gui", "ABCDE12345").expect("requirement");

        let message = osstatus_of(check_audit_token(&peer.token(), &wrong));

        assert!(
            message.contains(&ERR_SEC_CS_REQ_FAILED.to_string()),
            "expected errSecCSReqFailed, got {message}"
        );
    }

    #[test]
    fn a_peer_signed_by_apple_still_fails_the_developer_id_marker_oid_clause() {
        let peer = SignedPeer::connect();

        // Apple's own anchor is not a Developer ID leaf; the marker clause is
        // what stops "signed by somebody" from meaning "signed by us".
        let message = osstatus_of(check_audit_token(
            &peer.token(),
            "anchor apple and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",
        ));

        assert!(message.contains(&ERR_SEC_CS_REQ_FAILED.to_string()));
    }

    #[test]
    fn the_release_verifier_denies_a_peer_that_is_not_the_console_user() {
        let impossible_uid = u32::MAX - 1;
        let token = AuditToken::from_words([0, impossible_uid, 20, impossible_uid, 20, 1, 0, 1]);

        let result = DesignatedRequirementVerifier.verify(&token);

        assert!(result.is_err());
    }

    #[test]
    fn the_release_verifier_denies_a_console_user_peer_with_a_dead_audit_token() {
        // euid matches whoever is at the console (or there is none, which also
        // denies); the token itself names no live process.
        // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no
        // memory the caller owns.
        let uid = unsafe { libc::geteuid() };
        let token = AuditToken::from_words([0, uid, 20, uid, 20, 0, 0, 0]);

        let result = DesignatedRequirementVerifier.verify(&token);

        assert!(result.is_err());
    }
}
