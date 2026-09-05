// SPDX-License-Identifier: GPL-3.0-or-later

//! Turning a validated [`Profile`] into the [`ProfileSummary`] the GUI lists.
//!
//! The summary is derived from the canonical config, never from the imported
//! text: the digest must describe what the daemon would actually hand to
//! openvpn, so a profile whose stored form changed underneath us shows a
//! different hash.

use sha2::{Digest, Sha256};

use crate::ipc::{ProfileId, ProfileSummary, RemoteSummary, StaticChallengeSummary, Transport};
use crate::ovpn::profile::{InlineMaterial, Profile, TransportProto};

/// Hex-encoded SHA-256 of the canonical config body.
pub fn canonical_digest(canonical: &str) -> String {
    let digest = Sha256::digest(canonical.as_bytes());
    digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        // Writing to a String cannot fail; the Result is discarded deliberately.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// `imported_unix_secs` is passed in rather than read from the clock here, so
/// the caller owns time and this stays a pure function.
pub fn summarise(
    id: ProfileId,
    name: String,
    profile: &Profile,
    imported_unix_secs: u64,
) -> ProfileSummary {
    let canonical = profile.to_canonical_config();

    ProfileSummary {
        id,
        name,
        remotes: profile
            .remotes()
            .iter()
            .map(|remote| RemoteSummary {
                host: remote.host.to_string(),
                port: remote.port,
                transport: match remote.proto {
                    Some(TransportProto::Tcp) => Transport::Tcp,
                    // openvpn's own default when the profile does not say.
                    Some(TransportProto::Udp) | None => Transport::Udp,
                },
            })
            .collect(),
        requires_username_password: profile.needs_auth_user_pass(),
        static_challenge: profile
            .static_challenge()
            .map(|challenge| StaticChallengeSummary {
                text: challenge.prompt.clone(),
                echo: challenge.echo,
            }),
        has_inline_ca: has_tag(profile, "ca"),
        has_inline_cert: has_tag(profile, "cert"),
        has_inline_key: has_tag(profile, "key"),
        canonical_sha256: canonical_digest(&canonical),
        imported_unix_secs,
    }
}

fn has_tag(profile: &Profile, tag: &str) -> bool {
    profile
        .inline()
        .iter()
        .any(|material: &InlineMaterial| material.tag == tag)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::ovpn::parse_profile;

    const MINIMAL: &str = "client\ndev tun\nremote vpn.example.com 1194 udp\nnobind\n";

    #[test]
    fn digest_is_sixty_four_hex_characters() {
        // Arrange / Act
        let digest = canonical_digest("client\n");

        // Assert
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digest_matches_the_known_sha256_of_its_input() {
        // Arrange / Act / Assert: the empty string's SHA-256 is a fixed value,
        // so a wrong hash function or encoding shows up immediately.
        assert_eq!(
            canonical_digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_changes_when_the_canonical_config_changes() {
        // Arrange / Act
        let one = canonical_digest("client\n");
        let two = canonical_digest("client\nnobind\n");

        // Assert
        assert_ne!(one, two);
    }

    #[test]
    fn summarises_remotes_and_defaults_missing_transport_to_udp() {
        // Arrange
        let profile = parse_profile("client\ndev tun\nremote vpn.example.com 1194\n")
            .expect("the profile is valid");

        // Act
        let summary = summarise(ProfileId("p".to_owned()), "work".to_owned(), &profile, 7);

        // Assert
        assert_eq!(summary.remotes.len(), 1);
        assert_eq!(summary.remotes[0].host, "vpn.example.com");
        assert_eq!(summary.remotes[0].port, 1194);
        assert_eq!(summary.remotes[0].transport, Transport::Udp);
        assert_eq!(summary.imported_unix_secs, 7);
    }

    #[test]
    fn reports_whether_credentials_are_required() {
        // Arrange
        let without = parse_profile(MINIMAL).expect("valid");
        let with = parse_profile(&format!("{MINIMAL}auth-user-pass\n")).expect("valid");

        // Act / Assert
        assert!(
            !summarise(ProfileId("a".to_owned()), "a".to_owned(), &without, 0)
                .requires_username_password
        );
        assert!(
            summarise(ProfileId("b".to_owned()), "b".to_owned(), &with, 0)
                .requires_username_password
        );
    }

    #[test]
    fn reports_which_inline_material_is_present() {
        // Arrange
        let config = format!("{MINIMAL}<ca>\nPEM\n</ca>\n");
        let profile = parse_profile(&config).expect("valid");

        // Act
        let summary = summarise(ProfileId("p".to_owned()), "p".to_owned(), &profile, 0);

        // Assert
        assert!(summary.has_inline_ca);
        assert!(!summary.has_inline_cert);
        assert!(!summary.has_inline_key);
    }

    #[test]
    fn summary_carries_no_secret_material() {
        // Arrange: a profile with an inline key must not leak it into the
        // summary, which the GUI renders and may log.
        let config = format!("{MINIMAL}<key>\nSUPERSECRETKEYMATERIAL\n</key>\n");
        let profile = parse_profile(&config).expect("valid");

        // Act
        let summary = summarise(ProfileId("p".to_owned()), "p".to_owned(), &profile, 0);
        let rendered = format!("{summary:?}");

        // Assert
        assert!(summary.has_inline_key);
        assert!(!rendered.contains("SUPERSECRETKEYMATERIAL"));
    }
}
