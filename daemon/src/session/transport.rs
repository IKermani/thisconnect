// SPDX-License-Identifier: GPL-3.0-or-later

//! Accepting openvpn's reverse management connection (SPEC.md §4.1).
//!
//! `--management-client` makes openvpn connect *out* to a socket the daemon
//! already created at mode 0600. openvpn's own default creates the socket
//! `srwxrwxrwx` and answers commands with no authentication, which under a root
//! daemon is a local privilege escalation. The socket must therefore exist,
//! owned and tightened by us, before the child is spawned.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;

use super::spawn::BoxFuture;
use super::workspace::restrict_socket;
use super::SessionError;

/// openvpn connects back within a few hundred milliseconds; a minute is generous
/// enough to survive a loaded machine and short enough to fail rather than hang.
pub const ACCEPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Anything the management client can be driven over. Implemented blanket-style
/// so `tokio::io::duplex` stands in for a real socket in tests.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

/// A management socket that is already listening.
pub trait MgmtTransport: Send + Sync {
    fn accept(&self, timeout: Duration) -> BoxFuture<'_, Result<BoxStream, SessionError>>;
}

/// Creates the listening socket. Separate from `SessionWorkspace` so tests can
/// swap the whole transport without touching the filesystem.
pub trait MgmtTransportFactory: Send + Sync {
    fn bind(&self, path: &Path) -> Result<Box<dyn MgmtTransport>, SessionError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnixTransportFactory;

impl MgmtTransportFactory for UnixTransportFactory {
    fn bind(&self, path: &Path) -> Result<Box<dyn MgmtTransport>, SessionError> {
        let listener = UnixListener::bind(path)
            .map_err(|source| SessionError::workspace("bind the management socket", source))?;
        restrict_socket(path)?;
        Ok(Box::new(UnixTransport { listener }))
    }
}

struct UnixTransport {
    listener: UnixListener,
}

impl MgmtTransport for UnixTransport {
    fn accept(&self, timeout: Duration) -> BoxFuture<'_, Result<BoxStream, SessionError>> {
        Box::pin(async move {
            let accepted = tokio::time::timeout(timeout, self.listener.accept())
                .await
                .map_err(|_| SessionError::ManagementTimeout)?;
            let (stream, _addr) = accepted.map_err(|source| {
                SessionError::workspace("accept openvpn's management connection", source)
            })?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Mutex;

    use tokio::io::DuplexStream;

    use super::*;

    /// Hands out one pre-made in-memory stream, then reports that openvpn never
    /// connected back.
    pub(crate) struct ScriptedTransport {
        stream: Mutex<Option<DuplexStream>>,
    }

    impl ScriptedTransport {
        pub(crate) fn new(stream: DuplexStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl MgmtTransport for ScriptedTransport {
        fn accept(&self, _timeout: Duration) -> BoxFuture<'_, Result<BoxStream, SessionError>> {
            let taken = self.stream.lock().expect("scripted stream").take();
            Box::pin(async move {
                taken
                    .map(|stream| Box::new(stream) as BoxStream)
                    .ok_or(SessionError::ManagementTimeout)
            })
        }
    }

    /// A transport openvpn never connects back to.
    pub(crate) struct SilentTransport;

    impl MgmtTransport for SilentTransport {
        fn accept(&self, _timeout: Duration) -> BoxFuture<'_, Result<BoxStream, SessionError>> {
            Box::pin(async { Err(SessionError::ManagementTimeout) })
        }
    }

    pub(crate) struct FixedFactory {
        transports: Mutex<Vec<Box<dyn MgmtTransport>>>,
    }

    impl FixedFactory {
        pub(crate) fn new(transport: Box<dyn MgmtTransport>) -> Self {
            Self {
                transports: Mutex::new(vec![transport]),
            }
        }
    }

    impl MgmtTransportFactory for FixedFactory {
        fn bind(&self, _path: &Path) -> Result<Box<dyn MgmtTransport>, SessionError> {
            self.transports
                .lock()
                .expect("transports")
                .pop()
                .ok_or(SessionError::ManagementTimeout)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        let dir = std::env::temp_dir().join(format!("thisconnect-tp-{pid}-{name}"));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("mgmt.sock")
    }

    #[tokio::test]
    async fn binds_the_management_socket_at_0600() {
        // Arrange
        let path = scratch("mode");
        let _ = std::fs::remove_file(&path);

        // Act
        let _transport = UnixTransportFactory.bind(&path).expect("bind");

        // Assert
        let mode = std::fs::symlink_metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn accepts_a_connection_that_arrives_before_the_deadline() {
        // Arrange
        let path = scratch("accept");
        let _ = std::fs::remove_file(&path);
        let transport = UnixTransportFactory.bind(&path).expect("bind");
        let dial = path.clone();
        tokio::spawn(async move {
            let _ = tokio::net::UnixStream::connect(&dial).await;
        });

        // Act
        let accepted = transport.accept(Duration::from_secs(5)).await;

        // Assert
        assert!(accepted.is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn reports_a_timeout_when_openvpn_never_connects_back() {
        let path = scratch("timeout");
        let _ = std::fs::remove_file(&path);
        let transport = UnixTransportFactory.bind(&path).expect("bind");

        let accepted = transport.accept(Duration::from_millis(30)).await;

        assert!(matches!(accepted, Err(SessionError::ManagementTimeout)));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn refuses_to_bind_where_a_socket_already_exists() {
        let path = scratch("collide");
        let _ = std::fs::remove_file(&path);
        let _first = UnixTransportFactory.bind(&path).expect("bind");

        assert!(UnixTransportFactory.bind(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
