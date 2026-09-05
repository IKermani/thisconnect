// SPDX-License-Identifier: GPL-3.0-or-later

//! TOTP autofill (SPEC.md §8). **Opt-in and off by default** — [`TotpSettings::default`] prompts.
//!
//! Storing the seed beside the password collapses two factors into one. That is the user's
//! tradeoff to make, but it is never made for them, and a weak seed is reported rather than
//! quietly accepted or quietly rejected.

use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

pub const DEFAULT_DIGITS: u8 = 6;
pub const DEFAULT_STEP_SECONDS: u64 = 30;

/// RFC 4226 §5.3. `build_noncompliant` would panic at generate time above this, so the range is
/// enforced before the builder is ever asked to skip its own checks.
const MIN_DIGITS: u8 = 6;
const MAX_DIGITS: u8 = 8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("TOTP autofill is not enabled for this profile")]
    Disabled,

    #[error("the stored TOTP seed is not valid base32")]
    SeedNotBase32,

    #[error("refusing to build a TOTP generator: {detail}")]
    Rejected { detail: String },

    /// The code for this time step has already been sent to the server. Replaying it is what
    /// `--auth-retry nointeract` does, and it locks accounts.
    #[error("this one-time code was already used; the next one is {seconds}s away")]
    AlreadyConsumed { seconds: u64 },

    #[error("the system clock is before the unix epoch")]
    Clock,
}

/// Per-profile TOTP configuration. The default is the SPEC.md §8 default: prompt the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpSettings {
    pub enabled: bool,
    pub digits: u8,
    pub step_seconds: u64,
}

impl Default for TotpSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            digits: DEFAULT_DIGITS,
            step_seconds: DEFAULT_STEP_SECONDS,
        }
    }
}

impl TotpSettings {
    /// The only way to turn autofill on, so that no default construction can enable it by accident.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }
}

/// Whether the seed met RFC 4226's 128-bit floor. A short seed is usable — real deployments
/// issue 80-bit seeds — but the user is told, because the alternative is hiding a weak secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedCompliance {
    Compliant,
    ShortSeed { bits: usize },
}

impl SeedCompliance {
    pub fn warning(self) -> Option<String> {
        match self {
            Self::Compliant => None,
            Self::ShortSeed { bits } => Some(format!(
                "This account's TOTP seed is {bits} bits. RFC 4226 requires at least 128. \
                 Codes will still be generated, but the second factor is weaker than it looks."
            )),
        }
    }
}

pub struct TotpGenerator {
    totp: Totp,
    compliance: SeedCompliance,
    step_seconds: u64,
}

impl TotpGenerator {
    /// Tries the compliant build first and falls back to `build_noncompliant` only for a short
    /// seed — every other rejection (bad digits, zero step) is a real configuration error.
    pub fn from_base32_seed(seed: &str, settings: &TotpSettings) -> Result<Self, TotpError> {
        if !settings.enabled {
            return Err(TotpError::Disabled);
        }
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&settings.digits) {
            return Err(TotpError::Rejected {
                detail: format!("digits must be {MIN_DIGITS}-{MAX_DIGITS}"),
            });
        }
        if settings.step_seconds == 0 {
            return Err(TotpError::Rejected {
                detail: "step duration must not be zero".to_owned(),
            });
        }

        let secret = Secret::try_from_base32(seed).map_err(|_| TotpError::SeedNotBase32)?;
        let builder = Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(settings.digits)
            .with_step_duration(settings.step_seconds)
            .with_secret(secret);

        let (totp, compliance) = match builder.clone().build() {
            Ok(totp) => (totp, SeedCompliance::Compliant),
            Err(totp_rs::TotpError::SecretTooShort { bits }) => (
                builder.build_noncompliant(),
                SeedCompliance::ShortSeed { bits },
            ),
            Err(other) => {
                return Err(TotpError::Rejected {
                    detail: other.to_string(),
                })
            }
        };

        Ok(Self {
            totp,
            compliance,
            step_seconds: settings.step_seconds,
        })
    }

    pub fn compliance(&self) -> SeedCompliance {
        self.compliance
    }

    pub fn step_seconds(&self) -> u64 {
        self.step_seconds
    }

    pub fn step_at(&self, unix_secs: u64) -> u64 {
        unix_secs / self.step_seconds
    }

    pub fn code_at(&self, unix_secs: u64) -> Zeroizing<String> {
        Zeroizing::new(self.totp.generate(unix_secs).to_string())
    }
}

/// Remembers which time step was already handed to openvpn.
///
/// It is a value, not a cell: `admit` returns the next guard, so a caller that drops the result
/// on an error path cannot accidentally mark a code consumed that was never sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayGuard {
    last_step: Option<u64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits `step` exactly once. A second admission of the same step is refused with the wait
    /// until the next one, so the caller can prompt instead of replaying.
    pub fn admit(self, step: u64, step_seconds: u64, now: u64) -> Result<Self, TotpError> {
        if self.last_step == Some(step) {
            let elapsed = now % step_seconds.max(1);
            return Err(TotpError::AlreadyConsumed {
                seconds: step_seconds.saturating_sub(elapsed),
            });
        }
        Ok(Self {
            last_step: Some(step),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// 20 bytes = 160 bits, the RFC 6238 test vector seed.
    const COMPLIANT_SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    /// 10 bytes = 80 bits, the shape real VPN deployments hand out.
    const SHORT_SEED: &str = "GEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_is_disabled_by_default() {
        let settings = TotpSettings::default();

        assert!(!settings.enabled);
        assert!(matches!(
            TotpGenerator::from_base32_seed(COMPLIANT_SEED, &settings),
            Err(TotpError::Disabled)
        ));
    }

    #[test]
    fn accepts_a_compliant_seed_without_a_warning() {
        let generator = TotpGenerator::from_base32_seed(COMPLIANT_SEED, &TotpSettings::enabled())
            .expect("generator");

        assert_eq!(generator.compliance(), SeedCompliance::Compliant);
        assert!(generator.compliance().warning().is_none());
    }

    #[test]
    fn accepts_a_sub_128_bit_seed_but_reports_it_as_short() {
        let generator = TotpGenerator::from_base32_seed(SHORT_SEED, &TotpSettings::enabled())
            .expect("fallback");

        assert_eq!(
            generator.compliance(),
            SeedCompliance::ShortSeed { bits: 80 }
        );
        let warning = generator.compliance().warning().expect("warning");
        assert!(warning.contains("80 bits"));
        assert!(warning.contains("128"));
    }

    #[test]
    fn a_short_seed_still_generates_a_code_of_the_configured_length() {
        let generator = TotpGenerator::from_base32_seed(SHORT_SEED, &TotpSettings::enabled())
            .expect("fallback");

        let code = generator.code_at(1_700_000_000);

        assert_eq!(code.len(), usize::from(DEFAULT_DIGITS));
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn rejects_a_seed_that_is_not_base32() {
        assert!(matches!(
            TotpGenerator::from_base32_seed("not base32!", &TotpSettings::enabled()),
            Err(TotpError::SeedNotBase32)
        ));
    }

    #[test]
    fn rejects_a_digit_count_the_generator_would_panic_on() {
        let settings = TotpSettings {
            digits: 10,
            ..TotpSettings::enabled()
        };

        assert!(matches!(
            TotpGenerator::from_base32_seed(COMPLIANT_SEED, &settings),
            Err(TotpError::Rejected { .. })
        ));
    }

    #[test]
    fn rejects_a_zero_step_duration() {
        let settings = TotpSettings {
            step_seconds: 0,
            ..TotpSettings::enabled()
        };

        assert!(matches!(
            TotpGenerator::from_base32_seed(COMPLIANT_SEED, &settings),
            Err(TotpError::Rejected { .. })
        ));
    }

    #[test]
    fn the_same_time_step_yields_the_same_code_which_is_why_replay_must_be_tracked() {
        let generator = TotpGenerator::from_base32_seed(COMPLIANT_SEED, &TotpSettings::enabled())
            .expect("generator");

        assert_eq!(
            generator.code_at(1_700_000_000).as_str(),
            generator.code_at(1_700_000_005).as_str()
        );
        assert_eq!(
            generator.step_at(1_700_000_000),
            generator.step_at(1_700_000_005)
        );
    }

    #[test]
    fn refuses_to_admit_the_same_step_twice() {
        let guard = ReplayGuard::new().admit(100, 30, 3_015).expect("first");

        let replay = guard.admit(100, 30, 3_015);

        assert_eq!(replay, Err(TotpError::AlreadyConsumed { seconds: 15 }));
    }

    #[test]
    fn admits_the_next_step_after_one_was_consumed() {
        let guard = ReplayGuard::new().admit(100, 30, 3_000).expect("first");

        assert!(guard.admit(101, 30, 3_030).is_ok());
    }

    #[test]
    fn a_rejected_admission_leaves_the_guard_unchanged_so_an_unsent_code_is_not_burned() {
        let guard = ReplayGuard::new();

        let _ = guard.admit(7, 30, 210);

        assert_eq!(guard, ReplayGuard::new());
    }
}
