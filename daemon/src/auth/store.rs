// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the password and the TOTP seed live (SPEC.md §8).
//!
//! Storage sits behind [`SecretStore`] so the auth flow is testable without a real keyring, and
//! so the one place that talks to the OS credential store is the one place that has to get the
//! error mapping right. There is deliberately **no** on-disk fallback: a missing Secret Service
//! is a typed [`StoreError::Unavailable`], never a plaintext file the user was never told about.

use std::fmt;

use thisconnect_shared::ipc::ProfileId;
use zeroize::Zeroizing;

/// Keyring service names. Two services rather than one keeps the seed and the password as
/// separately revocable items, so forgetting one cannot accidentally take the other.
const PASSWORD_SERVICE: &str = "net.thisconnect.profile-password";
const TOTP_SEED_SERVICE: &str = "net.thisconnect.profile-totp-seed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecretKind {
    Password,
    TotpSeed,
}

impl SecretKind {
    fn service(self) -> &'static str {
        match self {
            Self::Password => PASSWORD_SERVICE,
            Self::TotpSeed => TOTP_SEED_SERVICE,
        }
    }
}

impl fmt::Display for SecretKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password => f.write_str("password"),
            Self::TotpSeed => f.write_str("TOTP seed"),
        }
    }
}

/// Which secret, for which profile. Carries no secret material, so it is safe to log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CredentialKey {
    pub profile_id: ProfileId,
    pub kind: SecretKind,
}

impl CredentialKey {
    pub fn new(profile_id: ProfileId, kind: SecretKind) -> Self {
        Self { profile_id, kind }
    }

    pub fn password(profile_id: ProfileId) -> Self {
        Self::new(profile_id, SecretKind::Password)
    }

    pub fn totp_seed(profile_id: ProfileId) -> Self {
        Self::new(profile_id, SecretKind::TotpSeed)
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    /// No usable credential store: headless Linux with no Secret Service, a locked keychain, an
    /// unsupported platform. The caller must prompt or fail, never write the secret elsewhere.
    #[error("the OS credential store is unavailable ({detail}); storing secrets is disabled")]
    Unavailable { detail: String },

    #[error("no {kind} is stored for this profile")]
    NotFound { kind: SecretKind },

    /// Several credentials match. Guessing which one is right could send the wrong password to
    /// the wrong server, so this is an error rather than a first-match.
    #[error("more than one stored {kind} matches this profile; refusing to guess")]
    Ambiguous { kind: SecretKind },

    /// The store answered, and said no. `detail` is the platform's own message and never
    /// contains the secret.
    #[error("the OS credential store rejected the request: {detail}")]
    Rejected { detail: String },
}

pub trait SecretStore: Send + Sync {
    fn load(&self, key: &CredentialKey) -> Result<Zeroizing<String>, StoreError>;
    fn store(&self, key: &CredentialKey, secret: &str) -> Result<(), StoreError>;
    fn forget(&self, key: &CredentialKey) -> Result<(), StoreError>;
}

/// The real OS credential store: Keychain on macOS, Secret Service on other unixes.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyringStore;

impl KeyringStore {
    /// Probes the credential store without creating an entry, so startup can tell the user their
    /// keyring is missing before they have configured anything that depends on it.
    pub fn availability() -> Result<(), StoreError> {
        match keyring::Entry::store_status() {
            Ok(()) => Ok(()),
            Err(error) => Err(map_error(error, SecretKind::Password)),
        }
    }

    fn entry(key: &CredentialKey) -> Result<keyring::Entry, StoreError> {
        keyring::Entry::new(key.kind.service(), key.profile_id.0.as_str())
            .map_err(|error| map_error(&error, key.kind))
    }
}

impl SecretStore for KeyringStore {
    fn load(&self, key: &CredentialKey) -> Result<Zeroizing<String>, StoreError> {
        Self::entry(key)?
            .get_password()
            .map(Zeroizing::new)
            .map_err(|error| map_error(&error, key.kind))
    }

    fn store(&self, key: &CredentialKey, secret: &str) -> Result<(), StoreError> {
        Self::entry(key)?
            .set_password(secret)
            .map_err(|error| map_error(&error, key.kind))
    }

    fn forget(&self, key: &CredentialKey) -> Result<(), StoreError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(map_error(&error, key.kind)),
        }
    }
}

/// Everything that means "there is no keyring here" collapses to `Unavailable`, because the
/// caller's decision is the same for all of them and only the message differs.
fn map_error(error: &keyring::Error, kind: SecretKind) -> StoreError {
    match error {
        keyring::Error::NoEntry => StoreError::NotFound { kind },
        keyring::Error::Ambiguous(_) => StoreError::Ambiguous { kind },
        keyring::Error::NoDefaultStore
        | keyring::Error::NoStorageAccess(_)
        | keyring::Error::PlatformFailure(_)
        | keyring::Error::NotSupportedByStore(_) => StoreError::Unavailable {
            detail: error.to_string(),
        },
        other => StoreError::Rejected {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
pub mod testing {
    //! An in-memory store, test-only on purpose: a non-test build must not be able to reach for
    //! something that looks like a keyring but forgets everything and encrypts nothing.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    pub struct MemoryStore {
        entries: Mutex<HashMap<(String, SecretKind), String>>,
        availability: Option<StoreError>,
    }

    impl MemoryStore {
        pub fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                availability: None,
            }
        }

        /// A store that behaves like headless Linux with no Secret Service running.
        pub fn unavailable() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                availability: Some(StoreError::Unavailable {
                    detail: "no Secret Service provider".to_owned(),
                }),
            }
        }

        pub fn with_secret(self, key: &CredentialKey, secret: &str) -> Self {
            self.store(key, secret).ok();
            self
        }

        fn check(&self) -> Result<(), StoreError> {
            match &self.availability {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn slot(key: &CredentialKey) -> (String, SecretKind) {
            (key.profile_id.0.clone(), key.kind)
        }
    }

    impl SecretStore for MemoryStore {
        fn load(&self, key: &CredentialKey) -> Result<Zeroizing<String>, StoreError> {
            self.check()?;
            let entries = super::lock(&self.entries);
            entries
                .get(&Self::slot(key))
                .cloned()
                .map(Zeroizing::new)
                .ok_or(StoreError::NotFound { kind: key.kind })
        }

        fn store(&self, key: &CredentialKey, secret: &str) -> Result<(), StoreError> {
            self.check()?;
            let mut entries = super::lock(&self.entries);
            entries.insert(Self::slot(key), secret.to_owned());
            Ok(())
        }

        fn forget(&self, key: &CredentialKey) -> Result<(), StoreError> {
            self.check()?;
            let mut entries = super::lock(&self.entries);
            entries.remove(&Self::slot(key));
            Ok(())
        }
    }
}

/// A poisoned mutex means another thread panicked while holding it; the map itself is still
/// consistent, and the daemon must not panic a second time over it.
#[cfg(test)]
fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::testing::MemoryStore;
    use super::*;

    fn profile() -> ProfileId {
        ProfileId("profile-1".to_owned())
    }

    #[test]
    fn separates_the_password_and_the_seed_of_one_profile() {
        let password = CredentialKey::password(profile());
        let seed = CredentialKey::totp_seed(profile());

        let store = MemoryStore::new()
            .with_secret(&password, "hunter2")
            .with_secret(&seed, "JBSWY3DPEHPK3PXP");

        assert_eq!(store.load(&password).expect("password").as_str(), "hunter2");
        assert_eq!(
            store.load(&seed).expect("seed").as_str(),
            "JBSWY3DPEHPK3PXP"
        );
        assert_ne!(password.kind.service(), seed.kind.service());
    }

    #[test]
    fn reports_a_missing_secret_as_not_found_rather_than_an_empty_string() {
        let store = MemoryStore::new();
        assert_eq!(
            store.load(&CredentialKey::password(profile())),
            Err(StoreError::NotFound {
                kind: SecretKind::Password
            })
        );
    }

    #[test]
    fn propagates_an_absent_secret_service_as_unavailable_on_every_operation() {
        let store = MemoryStore::unavailable();
        let key = CredentialKey::totp_seed(profile());

        assert!(matches!(
            store.load(&key),
            Err(StoreError::Unavailable { .. })
        ));
        assert!(matches!(
            store.store(&key, "seed"),
            Err(StoreError::Unavailable { .. })
        ));
        assert!(matches!(
            store.forget(&key),
            Err(StoreError::Unavailable { .. })
        ));
    }

    #[test]
    fn unavailable_message_names_the_backend_problem_and_not_the_secret() {
        let error = StoreError::Unavailable {
            detail: "no Secret Service provider".to_owned(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("no Secret Service provider"));
        assert!(rendered.contains("unavailable"));
    }

    #[test]
    fn forgetting_a_secret_makes_a_later_load_report_not_found() {
        let key = CredentialKey::password(profile());
        let store = MemoryStore::new().with_secret(&key, "hunter2");

        store.forget(&key).expect("forget");

        assert!(matches!(store.load(&key), Err(StoreError::NotFound { .. })));
    }

    #[test]
    fn maps_keyring_failures_onto_the_typed_errors_the_flow_branches_on() {
        assert_eq!(
            map_error(&keyring::Error::NoEntry, SecretKind::Password),
            StoreError::NotFound {
                kind: SecretKind::Password
            }
        );
        assert!(matches!(
            map_error(&keyring::Error::NoDefaultStore, SecretKind::TotpSeed),
            StoreError::Unavailable { .. }
        ));
        assert!(matches!(
            map_error(
                &keyring::Error::NotSupportedByStore("headless".to_owned()),
                SecretKind::TotpSeed
            ),
            StoreError::Unavailable { .. }
        ));
        assert!(matches!(
            map_error(
                &keyring::Error::Invalid("service".to_owned(), "empty".to_owned()),
                SecretKind::Password
            ),
            StoreError::Rejected { .. }
        ));
    }
}
