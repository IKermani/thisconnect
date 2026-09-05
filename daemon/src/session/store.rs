// SPDX-License-Identifier: GPL-3.0-or-later

//! Profile lifecycle: import, list, get, delete.
//!
//! Import is where an untrusted `.ovpn` becomes stored state, so validation and
//! canonicalisation happen here and nowhere else. What lands on disk is the
//! canonical config the validator produced, never the bytes the GUI sent — the
//! stored form is then the same shape the connect path will re-validate.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use thisconnect_shared::ipc::{ProfileId, ProfileSummary};
use thisconnect_shared::ovpn::{parse_profile, summarise};
use zeroize::Zeroizing;

use super::profiles::{FileProfileStore, MAX_STORED_BYTES};
use super::SessionError;

/// A profile body can carry a private key, so it is never group- or
/// world-readable.
const PROFILE_MODE: u32 = 0o600;
const PROFILE_DIR_MODE: u32 = 0o700;

/// Ids are derived from the user's chosen name, which is arbitrary text. The
/// derivation is deliberately lossy: only characters that are safe as a single
/// path component survive, and the result is length-capped.
pub fn derive_id(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = slug.trim_matches('-');
    let collapsed = collapse_dashes(trimmed);
    if collapsed.is_empty() {
        "profile".to_owned()
    } else {
        collapsed.chars().take(48).collect()
    }
}

fn collapse_dashes(input: &str) -> String {
    input.chars().fold(String::new(), |mut acc, c| {
        if c == '-' && acc.ends_with('-') {
            acc
        } else {
            acc.push(c);
            acc
        }
    })
}

pub trait ProfileStore: Send + Sync {
    fn import(&self, name: &str, config: &str) -> Result<ProfileSummary, SessionError>;
    fn list(&self) -> Result<Vec<ProfileSummary>, SessionError>;
    fn get(&self, id: &ProfileId) -> Result<ProfileSummary, SessionError>;
    fn delete(&self, id: &ProfileId) -> Result<(), SessionError>;
}

impl ProfileStore for FileProfileStore {
    fn import(&self, name: &str, config: &str) -> Result<ProfileSummary, SessionError> {
        if config.len() as u64 > MAX_STORED_BYTES {
            return Err(SessionError::Workspace {
                what: "the imported profile is larger than the parser's limit",
                detail: format!("{} bytes", config.len()),
            });
        }

        // Validate before anything touches the filesystem: a rejected profile
        // must leave no trace.
        let profile = parse_profile(config).map_err(SessionError::Profile)?;
        let canonical = profile.to_canonical_config();

        ensure_dir(self.root())?;
        let id = ProfileId(self.allocate_id(&derive_id(name))?);
        let path = self.path_of(&id)?;

        write_private(&path, &canonical)?;

        Ok(summarise(id, name.to_owned(), &profile, now_unix()))
    }

    fn list(&self) -> Result<Vec<ProfileSummary>, SessionError> {
        let root = self.root();
        if !root.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(root)
            .map_err(|source| SessionError::workspace("read the profile directory", source))?;

        let mut summaries: Vec<ProfileSummary> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| stem_of(&entry.path()))
            .filter_map(|id| self.get(&ProfileId(id)).ok())
            .collect();

        // A stable order so the GUI's list does not reshuffle between calls.
        summaries.sort_by(|a, b| a.id.0.cmp(&b.id.0));
        Ok(summaries)
    }

    fn get(&self, id: &ProfileId) -> Result<ProfileSummary, SessionError> {
        let raw = <FileProfileStore as super::profiles::ProfileSource>::load(self, id)?;
        // A stored profile is re-validated on read, not trusted because we
        // wrote it: the filesystem is editable by anything running as root.
        let profile = parse_profile(&raw).map_err(SessionError::Profile)?;
        let imported = self.imported_at(id).unwrap_or(0);
        Ok(summarise(id.clone(), id.0.clone(), &profile, imported))
    }

    fn delete(&self, id: &ProfileId) -> Result<(), SessionError> {
        let path = self.path_of(id)?;
        fs::remove_file(&path).map_err(|_| SessionError::ProfileNotFound { id: id.clone() })
    }
}

fn stem_of(path: &std::path::Path) -> Option<String> {
    if path.extension()?.to_str()? != "ovpn" {
        return None;
    }
    Some(path.file_stem()?.to_str()?.to_owned())
}

fn ensure_dir(root: &std::path::Path) -> Result<(), SessionError> {
    fs::create_dir_all(root)
        .map_err(|source| SessionError::workspace("create the profile directory", source))?;
    fs::set_permissions(root, fs::Permissions::from_mode(PROFILE_DIR_MODE))
        .map_err(|source| SessionError::workspace("tighten the profile directory", source))
}

/// Creates with the restrictive mode rather than widening then narrowing, so
/// there is no window in which the key material is readable by others.
fn write_private(path: &PathBuf, body: &Zeroizing<String>) -> Result<(), SessionError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PROFILE_MODE)
        .open(path)
        .map_err(|source| SessionError::workspace("create the profile file", source))?;

    file.write_all(body.as_bytes())
        .map_err(|source| SessionError::workspace("write the profile file", source))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::super::profiles::FileProfileStore;
    use super::*;

    const VALID: &str = "client\ndev tun\nremote vpn.example.com 1194 udp\nnobind\n";
    const HOSTILE: &str = "client\ndev tun\nremote vpn.example.com 1194\nup /bin/sh\n";

    fn store(name: &str) -> (FileProfileStore, PathBuf) {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("thisconnect-store-{pid}-{name}"));
        let _ = fs::remove_dir_all(&dir);
        (FileProfileStore::new(&dir), dir)
    }

    #[test]
    fn imports_a_valid_profile_and_lists_it() {
        // Arrange
        let (s, dir) = store("valid");

        // Act
        let summary = s.import("Work VPN", VALID).expect("import");
        let listed = s.list().expect("list");

        // Assert
        assert_eq!(summary.id.0, "work-vpn");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, summary.id);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_a_profile_carrying_a_script_hook_and_writes_nothing() {
        // Arrange
        let (s, dir) = store("hostile");

        // Act
        let result = s.import("evil", HOSTILE);

        // Assert
        assert!(result.is_err());
        assert!(s.list().expect("list").is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stores_the_canonical_config_not_the_imported_bytes() {
        // Arrange: a comment and odd spacing survive in the import but must not
        // survive canonicalisation.
        let (s, dir) = store("canonical");
        let messy = format!("# a comment\n{VALID}");

        // Act
        let summary = s.import("work", &messy).expect("import");
        let on_disk = fs::read_to_string(dir.join("work.ovpn")).expect("read");

        // Assert
        assert!(!on_disk.contains("a comment"));
        assert_eq!(
            summary.canonical_sha256,
            thisconnect_shared::ovpn::canonical_digest(&on_disk)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn writes_the_profile_unreadable_by_anyone_else() {
        // Arrange
        let (s, dir) = store("mode");

        // Act
        s.import("work", VALID).expect("import");
        let mode = fs::metadata(dir.join("work.ovpn"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;

        // Assert: a profile can carry a private key.
        assert_eq!(mode, PROFILE_MODE);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_second_import_of_the_same_name_gets_its_own_id() {
        // Arrange
        let (s, dir) = store("collide");

        // Act
        let one = s.import("work", VALID).expect("first");
        let two = s.import("work", VALID).expect("second");

        // Assert: the first must not be silently overwritten.
        assert_ne!(one.id, two.id);
        assert_eq!(s.list().expect("list").len(), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn deletes_a_profile_and_reports_a_missing_one() {
        // Arrange
        let (s, dir) = store("delete");
        let summary = s.import("work", VALID).expect("import");

        // Act / Assert
        s.delete(&summary.id).expect("delete");
        assert!(s.list().expect("list").is_empty());
        assert!(s.delete(&summary.id).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_an_id_that_would_escape_the_profile_directory() {
        // Arrange
        let (s, dir) = store("traversal");

        // Act / Assert
        assert!(s.get(&ProfileId("../../etc/passwd".to_owned())).is_err());
        assert!(s.delete(&ProfileId("../../etc/passwd".to_owned())).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn derives_a_safe_id_from_hostile_names() {
        // Arrange / Act / Assert
        assert_eq!(derive_id("../../etc/passwd"), "etc-passwd");
        assert_eq!(derive_id("Work VPN"), "work-vpn");
        assert_eq!(derive_id("///"), "profile");
        assert_eq!(derive_id(""), "profile");
        assert!(derive_id(&"a".repeat(200)).len() <= 48);
    }

    #[test]
    fn listing_skips_a_stored_file_that_no_longer_validates() {
        // Arrange: something edited the stored profile into an unsafe one.
        let (s, dir) = store("tampered");
        s.import("work", VALID).expect("import");
        fs::write(dir.join("work.ovpn"), HOSTILE).expect("tamper");

        // Act / Assert: it is skipped rather than surfaced as usable.
        assert!(s.list().expect("list").is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
