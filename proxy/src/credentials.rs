// SPDX-License-Identifier: GPL-3.0-or-later

//! Proxy credentials: generation, redaction, and the `socks5h://` URL the GUI
//! copies. See `docs/SPEC.md` §5.6 L2 and §5.4 D8.
//!
//! Auth is on even on loopback. Loopback is a weak boundary on a multi-user
//! machine: without credentials any local uid could egress through the tunnel
//! under the user's VPN identity.

use std::fmt;
use std::net::SocketAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use thisconnect_shared::ipc::{ProxyAuth, Secret};

use crate::socks5::Credentials as Socks5Credentials;

/// SPEC.md §5.6 L2. 128 bits is well past guessing range for a listener that
/// also rate-limits failures.
pub const CREDENTIAL_BYTES: usize = 16;

/// RFC 1929 encodes both fields with a single length byte.
const MAX_FIELD_LEN: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("credential field is empty")]
    Empty,
    #[error("credential field exceeds the 255-byte RFC 1929 limit")]
    TooLong,
    #[error("credential field contains a byte that would need escaping in a proxy URL")]
    NotUrlSafe,
}

/// A username/password pair for the local proxy.
///
/// Both halves are constrained to RFC 3986 unreserved characters so the
/// rendered URL never needs percent-encoding — a URL that has to be escaped is
/// a URL users paste wrong.
pub struct ProxyCredentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl ProxyCredentials {
    /// Fresh random credentials for one tunnel lifetime.
    pub fn generate() -> Self {
        Self {
            username: random_token(),
            password: random_token(),
        }
    }

    pub fn new(
        username: impl Into<Vec<u8>>,
        password: impl Into<Vec<u8>>,
    ) -> Result<Self, CredentialError> {
        let username = validated(username.into())?;
        let password = validated(password.into())?;
        Ok(Self { username, password })
    }

    pub fn username(&self) -> &str {
        as_str(&self.username)
    }

    /// Every call site is a place the password can escape. There are three:
    /// the keyring, the IPC `ProxyInfo`, and the SOCKS5 comparator.
    pub fn expose_password(&self) -> &str {
        as_str(&self.password)
    }

    /// The comparator used by the SOCKS5 sub-negotiation. Constant time.
    pub fn to_socks5(&self) -> Socks5Credentials {
        Socks5Credentials::new(self.username.clone(), self.password.clone())
    }

    pub fn to_ipc_auth(&self) -> ProxyAuth {
        ProxyAuth::Credentials {
            username: self.username().to_string(),
            password: Secret::new(self.expose_password()),
        }
    }

    /// The scheme is load-bearing: plain `socks5://` makes the *client* resolve
    /// the name locally, which leaks every hostname (SPEC.md §5.4 D8).
    pub fn socks5h_url(&self, addr: SocketAddr) -> Secret {
        Secret::new(format!(
            "socks5h://{}:{}@{addr}",
            self.username(),
            self.expose_password()
        ))
    }
}

/// A `socks5h://` URL for a listener running without authentication.
pub fn socks5h_url_without_auth(addr: SocketAddr) -> Secret {
    Secret::new(format!("socks5h://{addr}"))
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentials(redacted)")
    }
}

impl Drop for ProxyCredentials {
    fn drop(&mut self) {
        // Best effort without a `zeroize` dependency in this crate: overwrite,
        // then fence so the stores are not elided as dead.
        for byte in self.username.iter_mut().chain(self.password.iter_mut()) {
            *byte = 0;
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn random_token() -> Vec<u8> {
    let mut raw = [0u8; CREDENTIAL_BYTES];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw).into_bytes()
}

fn validated(value: Vec<u8>) -> Result<Vec<u8>, CredentialError> {
    if value.is_empty() {
        return Err(CredentialError::Empty);
    }
    if value.len() > MAX_FIELD_LEN {
        return Err(CredentialError::TooLong);
    }
    if !value.iter().all(|byte| is_url_unreserved(*byte)) {
        return Err(CredentialError::NotUrlSafe);
    }
    Ok(value)
}

fn is_url_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Infallible in practice: construction validated the bytes as ASCII.
fn as_str(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or("")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn generated_credentials_encode_sixteen_random_bytes_url_safely() {
        // Arrange / Act
        let creds = ProxyCredentials::generate();

        // Assert
        let expected_len = URL_SAFE_NO_PAD.encode([0u8; CREDENTIAL_BYTES]).len();
        assert_eq!(creds.username().len(), expected_len);
        assert_eq!(creds.expose_password().len(), expected_len);
        assert!(creds.expose_password().bytes().all(is_url_unreserved));
    }

    #[test]
    fn two_generated_credentials_differ() {
        // Arrange / Act
        let first = ProxyCredentials::generate();
        let second = ProxyCredentials::generate();

        // Assert
        assert_ne!(first.expose_password(), second.expose_password());
        assert_ne!(first.username(), second.username());
    }

    #[test]
    fn debug_does_not_render_the_secret() {
        // Arrange
        let creds = ProxyCredentials::new("alice", "hunter2").expect("valid credentials");

        // Act
        let rendered = format!("{creds:?}");

        // Assert
        assert_eq!(rendered, "ProxyCredentials(redacted)");
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("alice"));
    }

    #[test]
    fn ipc_auth_keeps_the_password_in_a_redacting_wrapper() {
        // Arrange
        let creds = ProxyCredentials::generate();

        // Act
        let auth = creds.to_ipc_auth();

        // Assert
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains(creds.expose_password()));
    }

    #[test]
    fn url_uses_socks5h_because_socks5_resolves_locally_and_leaks() {
        // Arrange
        let creds = ProxyCredentials::new("u", "p").expect("valid credentials");

        // Act
        let url = creds.socks5h_url(loopback(1080));

        // Assert
        assert_eq!(url.expose(), "socks5h://u:p@127.0.0.1:1080");
    }

    #[test]
    fn url_brackets_an_ipv6_listen_address() {
        // Arrange
        let creds = ProxyCredentials::new("u", "p").expect("valid credentials");
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1080);

        // Act
        let url = creds.socks5h_url(addr);

        // Assert
        assert_eq!(url.expose(), "socks5h://u:p@[::1]:1080");
    }

    #[test]
    fn url_without_auth_still_uses_socks5h() {
        // Arrange / Act
        let url = socks5h_url_without_auth(loopback(1080));

        // Assert
        assert_eq!(url.expose(), "socks5h://127.0.0.1:1080");
    }

    #[test]
    fn rejects_empty_too_long_and_unsafe_fields() {
        // Arrange / Act / Assert
        assert_eq!(
            ProxyCredentials::new("", "p").err(),
            Some(CredentialError::Empty)
        );
        assert_eq!(
            ProxyCredentials::new("u", vec![b'a'; MAX_FIELD_LEN + 1]).err(),
            Some(CredentialError::TooLong)
        );
        assert_eq!(
            ProxyCredentials::new("u", "pass word").err(),
            Some(CredentialError::NotUrlSafe)
        );
        assert_eq!(
            ProxyCredentials::new("u:name", "p").err(),
            Some(CredentialError::NotUrlSafe)
        );
    }

    #[test]
    fn socks5_comparator_accepts_only_the_exact_pair() {
        // Arrange
        let creds = ProxyCredentials::new("alice", "s3cret").expect("valid credentials");

        // Act
        let comparator = creds.to_socks5();

        // Assert
        assert!(bool::from(comparator.verify(b"alice", b"s3cret")));
        assert!(!bool::from(comparator.verify(b"alice", b"s3cres")));
        assert!(!bool::from(comparator.verify(b"bob", b"s3cret")));
    }
}
