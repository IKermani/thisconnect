// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a stored profile's text comes from.
//!
//! The store hands back *text*, never a parsed profile: the connect path
//! re-runs the allowlist validator on every connect. Stored state is written by
//! this daemon, but it lives on a filesystem a root compromise or a botched
//! upgrade can edit, and the result is handed to a privileged process. Trusting
//! it because we wrote it once is exactly the assumption SPEC.md §6 refuses.

use std::path::{Path, PathBuf};

use thisconnect_shared::ipc::ProfileId;
use zeroize::Zeroizing;

use super::SessionError;

/// Stored profiles are the same shape as imported ones, so the parser's own cap
/// applies here too.
pub const MAX_STORED_BYTES: u64 = thisconnect_shared::ovpn::MAX_FILE_BYTES as u64;

pub trait ProfileSource: Send + Sync {
    /// The stored `.ovpn` text, still untrusted.
    fn load(&self, id: &ProfileId) -> Result<Zeroizing<String>, SessionError>;
}

/// One file per profile under a daemon-owned directory.
#[derive(Clone, Debug)]
pub struct FileProfileStore {
    root: PathBuf,
}

impl FileProfileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Profile ids arrive over IPC. Anything that is not a plain identifier is
    /// refused before it can become a path component.
    fn path_for(&self, id: &ProfileId) -> Result<PathBuf, SessionError> {
        let raw = id.0.as_str();
        let is_safe = !raw.is_empty()
            && raw.len() <= 64
            && raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
        if !is_safe {
            return Err(SessionError::ProfileNotFound { id: id.clone() });
        }
        Ok(self.root.join(format!("{raw}.ovpn")))
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The same validation as `path_for`, exposed for the lifecycle operations.
    pub(crate) fn path_of(&self, id: &ProfileId) -> Result<PathBuf, SessionError> {
        self.path_for(id)
    }

    /// Finds a free id near `base`. Importing two profiles under one name must
    /// not silently overwrite the first.
    pub(crate) fn allocate_id(&self, base: &str) -> Result<String, SessionError> {
        for suffix in 0..1000 {
            let candidate = if suffix == 0 {
                base.to_owned()
            } else {
                format!("{base}-{suffix}")
            };
            let path = self.path_for(&ProfileId(candidate.clone()))?;
            if !path.exists() {
                return Ok(candidate);
            }
        }
        Err(SessionError::Workspace {
            what: "could not find a free profile id",
            detail: base.to_owned(),
        })
    }

    /// Import time is the file's mtime: it needs no separate sidecar, and a
    /// missing or unreadable timestamp is reported as unknown rather than failing.
    pub(crate) fn imported_at(&self, id: &ProfileId) -> Option<u64> {
        let path = self.path_for(id).ok()?;
        let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }
}

impl ProfileSource for FileProfileStore {
    fn load(&self, id: &ProfileId) -> Result<Zeroizing<String>, SessionError> {
        let path = self.path_for(id)?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| SessionError::ProfileNotFound { id: id.clone() })?;
        if !metadata.is_file() {
            return Err(SessionError::ProfileNotFound { id: id.clone() });
        }
        if metadata.len() > MAX_STORED_BYTES {
            return Err(SessionError::Workspace {
                what: "the stored profile is larger than the import limit",
                detail: path.display().to_string(),
            });
        }
        let body = std::fs::read_to_string(&path)
            .map_err(|source| SessionError::workspace("read the stored profile", source))?;
        Ok(Zeroizing::new(body))
    }
}

/// The profile directory the daemon stores imports in.
pub fn default_profile_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("profiles")
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::HashMap;

    use super::*;

    pub(crate) struct MemoryProfiles {
        entries: HashMap<String, String>,
    }

    impl MemoryProfiles {
        pub(crate) fn new() -> Self {
            Self {
                entries: HashMap::new(),
            }
        }

        pub(crate) fn with(mut self, id: &str, body: &str) -> Self {
            self.entries.insert(id.to_owned(), body.to_owned());
            self
        }
    }

    impl ProfileSource for MemoryProfiles {
        fn load(&self, id: &ProfileId) -> Result<Zeroizing<String>, SessionError> {
            self.entries
                .get(&id.0)
                .map(|body| Zeroizing::new(body.clone()))
                .ok_or_else(|| SessionError::ProfileNotFound { id: id.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        let dir = std::env::temp_dir().join(format!("thisconnect-pf-{pid}-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn loads_a_stored_profile_by_id() {
        // Arrange
        let dir = scratch("load");
        std::fs::write(dir.join("work.ovpn"), "client\n").expect("write");
        let store = FileProfileStore::new(&dir);

        // Act
        let body = store.load(&ProfileId("work".into())).expect("load");

        // Assert
        assert_eq!(body.as_str(), "client\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_a_profile_id_that_traverses_out_of_the_store() {
        let store = FileProfileStore::new(scratch("traversal"));

        let outcome = store.load(&ProfileId("../../etc/passwd".into()));

        assert!(matches!(outcome, Err(SessionError::ProfileNotFound { .. })));
    }

    #[test]
    fn refuses_a_profile_id_containing_a_path_separator() {
        let store = FileProfileStore::new(scratch("separator"));

        assert!(store.load(&ProfileId("a/b".into())).is_err());
    }

    #[test]
    fn reports_a_missing_profile_rather_than_an_io_error() {
        let store = FileProfileStore::new(scratch("missing"));

        let outcome = store.load(&ProfileId("absent".into()));

        assert!(matches!(outcome, Err(SessionError::ProfileNotFound { .. })));
    }

    #[test]
    fn refuses_a_profile_that_is_a_symlink_to_something_else() {
        // Arrange
        let dir = scratch("symlink");
        std::os::unix::fs::symlink("/etc/hosts", dir.join("evil.ovpn")).expect("symlink");
        let store = FileProfileStore::new(&dir);

        // Act
        let outcome = store.load(&ProfileId("evil".into()));

        // Assert
        assert!(matches!(outcome, Err(SessionError::ProfileNotFound { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
