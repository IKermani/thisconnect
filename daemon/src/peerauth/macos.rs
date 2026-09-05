// SPDX-License-Identifier: GPL-3.0-or-later

//! macOS peer authentication: `LOCAL_PEERTOKEN` → audit token → (seam)
//! `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity`.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use super::{AuthError, PeerAuthenticator, PeerIdentity, PeerPolicy};
use tokio::net::UnixStream;

/// `SOL_LOCAL` and `LOCAL_PEERTOKEN` from `<sys/un.h>`; the `libc` crate
/// exposes neither, so they are pinned here with their header values.
const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;
const AUDIT_TOKEN_WORDS: usize = 8;

/// `audit_token_t`: eight `u32`s. Field order is fixed by the kernel ABI and
/// mirrors the `audit_token_to_*` accessors in `<bsm/libbsm.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditToken([u32; AUDIT_TOKEN_WORDS]);

#[allow(dead_code)] // full accessor set kept: the ABI is fixed and the seam needs it
impl AuditToken {
    pub fn from_words(words: [u32; AUDIT_TOKEN_WORDS]) -> Self {
        Self(words)
    }

    pub fn words(&self) -> [u32; AUDIT_TOKEN_WORDS] {
        self.0
    }

    pub fn auid(&self) -> u32 {
        self.0[0]
    }

    pub fn euid(&self) -> u32 {
        self.0[1]
    }

    pub fn egid(&self) -> u32 {
        self.0[2]
    }

    pub fn ruid(&self) -> u32 {
        self.0[3]
    }

    pub fn pid(&self) -> i32 {
        self.0[5] as i32
    }
}

/// Read the peer's audit token off a connected `AF_UNIX` socket.
pub fn peer_audit_token(fd: RawFd) -> Result<AuditToken, AuthError> {
    let mut words = [0u32; AUDIT_TOKEN_WORDS];
    let mut len = std::mem::size_of_val(&words) as libc::socklen_t;

    // SAFETY: `fd` is a live socket owned by the caller for the duration of
    // the call, and the buffer pointer/length pair describes exactly the
    // 32-byte `audit_token_t` the kernel writes. `len` is updated in place.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            words.as_mut_ptr().cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(AuthError::Syscall {
            op: "getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)",
            source: std::io::Error::last_os_error(),
        });
    }
    let expected = std::mem::size_of::<[u32; AUDIT_TOKEN_WORDS]>();
    if len as usize != expected {
        return Err(AuthError::TokenSize(len as usize));
    }
    Ok(AuditToken(words))
}

/// Seam for the code-signature half of SPEC.md 7.3.
pub trait CodeVerifier: Send + Sync + 'static {
    fn verify(&self, token: &AuditToken) -> Result<(), AuthError>;
}

/// The shipping verifier is not implementable without `security-framework`,
/// which is not in the dependency set, so it denies. This is deliberate: a
/// permissive placeholder would be a silent local privilege escalation.
pub struct UnimplementedCodeVerifier;

impl CodeVerifier for UnimplementedCodeVerifier {
    fn verify(&self, _token: &AuditToken) -> Result<(), AuthError> {
        // TODO: with `security-framework` 3.7 available, build the requirement
        // with `FromStr` (`SecRequirement::create_with_string` does not exist):
        //   let req: SecRequirement = super::GUI_DESIGNATED_REQUIREMENT.parse()?;
        // then `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit = token)`
        // and `SecCodeCheckValidity(code, kSecCSDefaultFlags, req)`. Treat
        // errSecCSUnsigned, kPOSIXErrorEPERM and every other non-zero status as
        // a denial, and resolve the console user via SCDynamicStoreCopyConsoleUser,
        // denying outright when there is none.
        Err(AuthError::CodeVerificationUnavailable)
    }
}

pub struct AuditTokenAuthenticator {
    policy: PeerPolicy,
    verifier: Arc<dyn CodeVerifier>,
}

impl AuditTokenAuthenticator {
    pub fn new(policy: PeerPolicy, verifier: Arc<dyn CodeVerifier>) -> Self {
        Self { policy, verifier }
    }

    fn identify(&self, fd: RawFd) -> Result<PeerIdentity, AuthError> {
        let token = peer_audit_token(fd)?;
        let peer = PeerIdentity {
            uid: token.euid(),
            gid: Some(token.egid()),
            pid: Some(token.pid()),
        };
        let peer = self.policy.check(peer)?;
        self.verifier.verify(&token)?;
        Ok(peer)
    }
}

impl PeerAuthenticator for AuditTokenAuthenticator {
    fn authenticate(&self, stream: &UnixStream) -> Result<PeerIdentity, AuthError> {
        self.identify(stream.as_raw_fd())
    }

    fn describe(&self) -> &'static str {
        "LOCAL_PEERTOKEN audit token + designated requirement"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    struct AcceptingVerifier;

    impl CodeVerifier for AcceptingVerifier {
        fn verify(&self, _token: &AuditToken) -> Result<(), AuthError> {
            Ok(())
        }
    }

    fn token(euid: u32, egid: u32, pid: i32) -> AuditToken {
        AuditToken::from_words([0, euid, egid, euid, egid, pid as u32, 0, 1])
    }

    #[test]
    fn extracts_euid_egid_and_pid_from_the_audit_token_layout() {
        let token = token(501, 20, 4242);

        assert_eq!(token.euid(), 501);
        assert_eq!(token.egid(), 20);
        assert_eq!(token.pid(), 4242);
        assert_eq!(token.ruid(), 501);
    }

    #[test]
    fn peer_audit_token_fails_closed_on_a_non_socket_descriptor() {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");

        let result = peer_audit_token(file.as_raw_fd());

        assert!(matches!(result, Err(AuthError::Syscall { .. })));
    }

    #[test]
    fn release_verifier_denies_rather_than_accepting_an_unverified_peer() {
        let result = UnimplementedCodeVerifier.verify(&token(501, 20, 1));

        assert!(matches!(
            result,
            Err(AuthError::CodeVerificationUnavailable)
        ));
    }

    #[test]
    fn denies_an_unauthorised_uid_before_consulting_the_code_verifier() {
        let auth = AuditTokenAuthenticator::new(
            PeerPolicy::new([501], []).expect("policy"),
            Arc::new(AcceptingVerifier),
        );

        let result = auth.policy.check(PeerIdentity {
            uid: 999,
            gid: Some(20),
            pid: Some(1),
        });

        assert!(matches!(
            result,
            Err(AuthError::NotAuthorised { uid: 999, .. })
        ));
        assert_eq!(
            auth.describe(),
            "LOCAL_PEERTOKEN audit token + designated requirement"
        );
    }
}
