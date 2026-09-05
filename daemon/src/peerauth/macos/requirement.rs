// SPDX-License-Identifier: GPL-3.0-or-later

//! Build-time configuration of the GUI's designated requirement (SPEC.md 7.3).
//!
//! The team id cannot be a source-code constant with a placeholder value: a
//! placeholder that ships is a requirement no real signature satisfies, and the
//! obvious "fix" under release pressure is to delete the clause. It is supplied
//! by the packager through the environment at build time, and its absence is a
//! compile error in a release build rather than a runtime denial nobody sees
//! until a user reports it.

use super::deny;
use crate::peerauth::AuthError;

/// Developer ID Application marker OID. Without this clause a Mac App Store or
/// a development certificate issued to the same team also satisfies the
/// requirement, which defeats the point of pinning the team at all.
const DEVELOPER_ID_MARKER_OID: &str = "1.2.840.113635.100.6.1.13";

const DEFAULT_IDENTIFIER: &str = "net.thisconnect.gui";

/// Signing identifier of the GUI bundle. Overridable so a fork or a rebrand
/// does not have to patch source to build a working package.
pub const GUI_IDENTIFIER: &str = match option_env!("THISCONNECT_GUI_IDENTIFIER") {
    Some(id) => id,
    None => DEFAULT_IDENTIFIER,
};

/// Apple Developer team id the GUI is signed with. There is no safe default.
pub const GUI_TEAM_ID: Option<&str> = option_env!("THISCONNECT_GUI_TEAM_ID");

/// A release daemon whose peer authentication cannot be satisfied by any
/// signature is either dead on arrival or about to be "fixed" by weakening the
/// requirement. Fail the build instead.
#[cfg(all(not(feature = "dev-insecure-ipc"), not(debug_assertions)))]
#[allow(clippy::panic)]
const _: () = {
    if GUI_TEAM_ID.is_none() {
        panic!(
            "THISCONNECT_GUI_TEAM_ID must be set at build time to the Apple Developer team id the \
             GUI is signed with; a release daemon cannot authenticate its peer without it. See \
             docs/SPEC.md 7.3."
        );
    }
};

const TEAM_ID_LEN: usize = 10;

/// Reject anything that could terminate a string literal or otherwise reshape
/// the requirement expression. The requirement language has no parameter
/// binding, so this is the only defence against a build-time injection.
fn is_valid_team_id(team_id: &str) -> bool {
    team_id.len() == TEAM_ID_LEN
        && team_id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn is_valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= 255
        && identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Assemble the designated requirement from validated parts.
pub fn build(identifier: &str, team_id: &str) -> Result<String, AuthError> {
    if !is_valid_identifier(identifier) {
        return Err(deny(
            "designated requirement",
            "configured GUI signing identifier is not a valid bundle identifier",
        ));
    }
    if !is_valid_team_id(team_id) {
        return Err(deny(
            "designated requirement",
            "configured GUI team id is not a 10-character Apple Developer team id",
        ));
    }
    Ok(format!(
        "anchor apple generic \
         and identifier \"{identifier}\" \
         and certificate leaf[field.{DEVELOPER_ID_MARKER_OID}] exists \
         and certificate leaf[subject.OU] = \"{team_id}\""
    ))
}

/// The requirement this build will hold peers to.
// Unused under `dev-insecure-ipc`, which never reaches the release path.
#[cfg_attr(feature = "dev-insecure-ipc", allow(dead_code))]
pub fn designated_requirement() -> Result<String, AuthError> {
    // A build with no team id cannot express the requirement at all, which is
    // exactly what `CodeVerificationUnavailable` means. Release builds cannot
    // reach this: the const assertion above fails them at compile time.
    let team_id = GUI_TEAM_ID.ok_or(AuthError::CodeVerificationUnavailable)?;
    build(GUI_IDENTIFIER, team_id)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn requirement_pins_anchor_identifier_marker_oid_and_team() {
        let req = build("net.thisconnect.gui", "ABCDE12345").expect("requirement");

        assert!(req.starts_with("anchor apple generic"));
        assert!(req.contains("identifier \"net.thisconnect.gui\""));
        assert!(req.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert!(req.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
    }

    #[test]
    fn omitting_the_marker_oid_would_admit_a_same_team_development_certificate() {
        let req = build("net.thisconnect.gui", "ABCDE12345").expect("requirement");

        // Guards against a future "simplification" that drops the clause.
        assert_eq!(req.matches("1.2.840.113635.100.6.1.13").count(), 1);
    }

    #[test]
    fn rejects_a_team_id_that_is_not_ten_uppercase_alphanumerics() {
        for bad in ["abcde12345", "SHORT", "ABCDE123456", ""] {
            assert!(
                build("net.thisconnect.gui", bad).is_err(),
                "accepted team id {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_a_team_id_carrying_requirement_language_metacharacters() {
        let injected = "A\" or true";

        assert!(build("net.thisconnect.gui", injected).is_err());
    }

    #[test]
    fn rejects_an_identifier_carrying_a_quote_that_would_reshape_the_expression() {
        let injected = "net.evil\" or anchor apple generic and identifier \"x";

        assert!(build(injected, "ABCDE12345").is_err());
    }

    #[test]
    fn rejects_an_empty_identifier() {
        assert!(build("", "ABCDE12345").is_err());
    }

    #[test]
    fn designated_requirement_denies_when_no_team_id_was_compiled_in() {
        let result = designated_requirement();

        // Dev builds have no team id; release builds fail to compile without one.
        match GUI_TEAM_ID {
            None => assert!(result.is_err()),
            Some(_) => assert!(result.is_ok()),
        }
    }
}
