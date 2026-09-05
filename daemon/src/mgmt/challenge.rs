// SPDX-License-Identifier: GPL-3.0-or-later

//! Static (SCRV1) and dynamic (CRV1) challenge/response encoding (SPEC.md §4.3 point 7).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use super::MgmtError;

/// How the server wants the static-challenge answer delivered.
///
/// `static-challenge "<text>" <echo> [<format>]`: format 0 is the SCRV1 envelope, format 1 is a
/// bare concatenation of password and response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StaticChallengeFormat {
    #[default]
    Scrv1,
    Concat,
}

/// The `SC:<echo>,<text>` suffix of a `>PASSWORD:Need ...` event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticChallenge {
    /// True when the UI may echo the typed answer (a PIN prompt, not a password prompt).
    pub echo: bool,
    pub text: String,
}

impl StaticChallenge {
    /// Parses `SC:1,Please enter your token`. Returns `None` when the payload is not a challenge.
    pub fn parse(payload: &str) -> Option<Self> {
        let rest = payload.strip_prefix("SC:")?;
        let (flag, text) = rest.split_once(',')?;
        Some(Self {
            echo: flag.trim() == "1",
            text: text.to_owned(),
        })
    }
}

/// Builds the value for the management `password` command answering a static challenge.
pub fn encode_static_response(
    password: &str,
    response: &str,
    format: StaticChallengeFormat,
) -> Zeroizing<String> {
    match format {
        StaticChallengeFormat::Scrv1 => Zeroizing::new(format!(
            "SCRV1:{}:{}",
            B64.encode(password.as_bytes()),
            B64.encode(response.as_bytes())
        )),
        StaticChallengeFormat::Concat => Zeroizing::new(format!("{password}{response}")),
    }
}

/// A `CRV1:<flags>:<state_id>:<username_b64>:<challenge_text>` dynamic challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicChallenge {
    pub flags: String,
    pub state_id: String,
    pub username_b64: String,
    /// May contain `:` — which is exactly why parsing uses `splitn(5, ':')`.
    pub challenge_text: String,
}

impl DynamicChallenge {
    pub fn parse(raw: &str) -> Result<Self, MgmtError> {
        let trimmed = raw.trim().trim_matches('\'');
        let mut fields = trimmed.splitn(5, ':');

        let tag = fields.next().unwrap_or_default();
        if tag != "CRV1" {
            return Err(MgmtError::InvalidChallenge("not a CRV1 challenge"));
        }

        let flags = fields
            .next()
            .ok_or(MgmtError::InvalidChallenge("missing flags"))?;
        let state_id = fields
            .next()
            .ok_or(MgmtError::InvalidChallenge("missing state id"))?;
        let username_b64 = fields
            .next()
            .ok_or(MgmtError::InvalidChallenge("missing username"))?;
        let challenge_text = fields
            .next()
            .ok_or(MgmtError::InvalidChallenge("missing challenge text"))?;

        if state_id.is_empty() {
            return Err(MgmtError::InvalidChallenge("empty state id"));
        }

        Ok(Self {
            flags: flags.to_owned(),
            state_id: state_id.to_owned(),
            username_b64: username_b64.to_owned(),
            challenge_text: challenge_text.to_owned(),
        })
    }

    /// `E`: the answer may be echoed by the UI.
    pub fn echo(&self) -> bool {
        self.flags.contains('E')
    }

    /// `R`: a response is required rather than merely informational.
    pub fn response_required(&self) -> bool {
        self.flags.contains('R')
    }

    /// The username the server wants the answer bound to, when it is decodable.
    pub fn username(&self) -> Option<String> {
        B64.decode(self.username_b64.as_bytes())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }
}

/// Builds the password value that answers a dynamic challenge: `CRV1::<state_id>::<response>`.
pub fn encode_dynamic_response(
    state_id: &str,
    response: &str,
) -> Result<Zeroizing<String>, MgmtError> {
    if state_id.is_empty() || state_id.contains(':') {
        return Err(MgmtError::InvalidChallenge(
            "state id is not a single field",
        ));
    }
    Ok(Zeroizing::new(format!("CRV1::{state_id}::{response}")))
}

/// Builds the parameter for `cr-response <base64>`, answering `>INFOMSG:CR_TEXT:`.
pub fn encode_cr_response(response: &str) -> Zeroizing<String> {
    Zeroizing::new(B64.encode(response.as_bytes()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn parses_a_static_challenge_with_echo_enabled() {
        let sc = StaticChallenge::parse("SC:1,Enter your token").expect("challenge");
        assert_eq!(
            sc,
            StaticChallenge {
                echo: true,
                text: "Enter your token".to_owned()
            }
        );
    }

    #[test]
    fn keeps_commas_inside_static_challenge_text() {
        let sc = StaticChallenge::parse("SC:0,Enter code, then press OK").expect("challenge");
        assert!(!sc.echo);
        assert_eq!(sc.text, "Enter code, then press OK");
    }

    #[test]
    fn returns_none_for_a_payload_that_is_not_a_static_challenge() {
        assert!(StaticChallenge::parse("username/password").is_none());
        assert!(StaticChallenge::parse("SC:1").is_none());
    }

    #[test]
    fn encodes_scrv1_as_base64_of_both_halves() {
        let encoded = encode_static_response("pass", "123456", StaticChallengeFormat::Scrv1);
        assert_eq!(encoded.as_str(), "SCRV1:cGFzcw==:MTIzNDU2");
    }

    #[test]
    fn encodes_format_one_as_plain_concatenation() {
        let encoded = encode_static_response("pass", "123456", StaticChallengeFormat::Concat);
        assert_eq!(encoded.as_str(), "pass123456");
    }

    #[test]
    fn parses_crv1_challenge_text_containing_colons() {
        let raw = "CRV1:R,E:Sf23fks9:dXNlcm5hbWU=:Please enter token: code 1:2";
        let challenge = DynamicChallenge::parse(raw).expect("crv1");
        assert_eq!(challenge.state_id, "Sf23fks9");
        assert_eq!(challenge.challenge_text, "Please enter token: code 1:2");
        assert_eq!(challenge.username().as_deref(), Some("username"));
        assert!(challenge.echo());
        assert!(challenge.response_required());
    }

    #[test]
    fn parses_crv1_wrapped_in_single_quotes_as_the_log_line_presents_it() {
        let challenge =
            DynamicChallenge::parse("'CRV1:R,E:Sf23fks9:dXNlcg==:Enter token'").expect("crv1");
        assert_eq!(challenge.state_id, "Sf23fks9");
        assert_eq!(challenge.challenge_text, "Enter token");
    }

    #[test]
    fn treats_a_missing_echo_flag_as_no_echo() {
        let challenge = DynamicChallenge::parse("CRV1:R:st8:dXNlcg==:Token?").expect("crv1");
        assert!(!challenge.echo());
        assert!(challenge.response_required());
    }

    #[test]
    fn rejects_a_challenge_that_is_not_crv1() {
        assert!(matches!(
            DynamicChallenge::parse("CRV2:R:st8:dXNlcg==:Token?"),
            Err(MgmtError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn rejects_a_truncated_crv1_challenge() {
        assert!(matches!(
            DynamicChallenge::parse("CRV1:R,E:Sf23fks9:dXNlcg=="),
            Err(MgmtError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn rejects_an_empty_state_id() {
        assert!(matches!(
            DynamicChallenge::parse("CRV1:R,E::dXNlcg==:Token?"),
            Err(MgmtError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn encodes_a_dynamic_response_in_the_double_colon_form() {
        let encoded = encode_dynamic_response("Sf23fks9", "987654").expect("response");
        assert_eq!(encoded.as_str(), "CRV1::Sf23fks9::987654");
    }

    #[test]
    fn refuses_a_state_id_containing_a_colon() {
        assert!(matches!(
            encode_dynamic_response("bad:id", "1"),
            Err(MgmtError::InvalidChallenge(_))
        ));
    }

    #[test]
    fn encodes_cr_response_as_base64() {
        assert_eq!(encode_cr_response("123456").as_str(), "MTIzNDU2");
    }
}
