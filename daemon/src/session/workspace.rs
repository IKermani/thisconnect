// SPDX-License-Identifier: GPL-3.0-or-later

//! The per-session directory holding the canonical config and the management
//! socket (SPEC.md §4.1).
//!
//! Both files are secrets: the config carries inline `<key>` material, and the
//! socket is an unauthenticated command channel into a root-spawned openvpn. They
//! live in a 0700 daemon-owned directory at mode 0600, and the directory is
//! removed by `Drop` rather than by remembering to call a cleanup function —
//! every early return on the connect path would otherwise be a leak.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::warn;

use super::SessionError;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const CONFIG_NAME: &str = "canonical.ovpn";
const SOCKET_NAME: &str = "mgmt.sock";

/// Distinguishes concurrent sessions within one daemon run. Only one connection
/// exists in v1, but a torn-down session's directory may still be on disk when
/// the next one is created.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A session's private directory. Dropping it removes the directory and
/// everything in it.
#[derive(Debug)]
pub struct SessionWorkspace {
    root: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl SessionWorkspace {
    /// Creates `<base>/session-<pid>-<n>` at 0700. The base directory is created
    /// if missing and tightened to 0700 either way: a pre-existing world-writable
    /// runtime directory would let anyone swap our config for their own.
    pub fn create(base: &Path) -> Result<Self, SessionError> {
        prepare_base(base)?;
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!("session-{pid}-{sequence}"));

        // `create` (not `create_all`) fails if the path already exists, which is
        // what we want: an attacker-planted directory must not be reused.
        DirBuilder::new()
            .mode(DIR_MODE)
            .create(&root)
            .map_err(|source| SessionError::workspace("create the session directory", source))?;

        Ok(Self {
            config: root.join(CONFIG_NAME),
            socket: root.join(SOCKET_NAME),
            root,
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Writes the canonical config at 0600. `create_new` refuses to follow a
    /// pre-placed symlink, so the file we hand openvpn is always the one we wrote.
    pub fn write_config(&self, body: &str) -> Result<(), SessionError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&self.config)
            .map_err(|source| SessionError::workspace("create the canonical config", source))?;
        file.write_all(body.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|source| SessionError::workspace("write the canonical config", source))
    }
}

impl Drop for SessionWorkspace {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.root) {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %self.root.display(), %error, "could not remove the session directory");
            }
        }
    }
}

fn prepare_base(base: &Path) -> Result<(), SessionError> {
    match std::fs::symlink_metadata(base) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(SessionError::Workspace {
                what: "the runtime directory is a symlink",
                detail: base.display().to_string(),
            })
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(SessionError::Workspace {
                what: "the runtime directory is not a directory",
                detail: base.display().to_string(),
            })
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DirBuilder::new()
                .recursive(true)
                .mode(DIR_MODE)
                .create(base)
                .map_err(|source| {
                    SessionError::workspace("create the runtime directory", source)
                })?;
        }
        Err(source) => {
            return Err(SessionError::workspace(
                "inspect the runtime directory",
                source,
            ))
        }
    }

    std::fs::set_permissions(base, std::fs::Permissions::from_mode(DIR_MODE))
        .map_err(|source| SessionError::workspace("tighten the runtime directory", source))
}

/// Tightens a socket the daemon just bound. Bind cannot take a mode, and the
/// parent directory is already 0700, so the window is closed to everyone but us.
pub fn restrict_socket(path: &Path) -> Result<(), SessionError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(FILE_MODE))
        .map_err(|source| SessionError::workspace("tighten the management socket", source))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        std::env::temp_dir().join(format!("thisconnect-ws-{pid}-{name}"))
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn creates_the_session_directory_at_0700() {
        // Arrange
        let base = scratch("mode");
        let _ = std::fs::remove_dir_all(&base);

        // Act
        let workspace = SessionWorkspace::create(&base).expect("workspace");

        // Assert
        assert_eq!(mode_of(workspace.root()), DIR_MODE);
        assert_eq!(mode_of(&base), DIR_MODE);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn writes_the_canonical_config_at_0600() {
        let base = scratch("config");
        let _ = std::fs::remove_dir_all(&base);
        let workspace = SessionWorkspace::create(&base).expect("workspace");

        workspace.write_config("client\n").expect("write");

        assert_eq!(mode_of(workspace.config_path()), FILE_MODE);
        assert_eq!(
            std::fs::read_to_string(workspace.config_path()).expect("read"),
            "client\n"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn removes_the_directory_and_its_contents_on_drop() {
        // Arrange
        let base = scratch("drop");
        let _ = std::fs::remove_dir_all(&base);
        let workspace = SessionWorkspace::create(&base).expect("workspace");
        workspace.write_config("client\n").expect("write");
        let root = workspace.root().to_path_buf();

        // Act
        drop(workspace);

        // Assert
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_a_runtime_directory_that_is_a_symlink() {
        // Arrange
        let base = scratch("symlink");
        let target = scratch("symlink-target");
        let _ = std::fs::remove_file(&base);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&target);
        std::fs::create_dir_all(&target).expect("target");
        std::os::unix::fs::symlink(&target, &base).expect("symlink");

        // Act
        let outcome = SessionWorkspace::create(&base);

        // Assert
        assert!(matches!(outcome, Err(SessionError::Workspace { .. })));
        let _ = std::fs::remove_file(&base);
        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn refuses_to_overwrite_an_existing_config() {
        let base = scratch("no-clobber");
        let _ = std::fs::remove_dir_all(&base);
        let workspace = SessionWorkspace::create(&base).expect("workspace");
        workspace.write_config("client\n").expect("first");

        assert!(workspace.write_config("client\n").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
