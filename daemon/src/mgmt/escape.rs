// SPDX-License-Identifier: GPL-3.0-or-later

//! Parameter escaping for the management channel (SPEC.md §4.3 point 8).
//!
//! WHY this is not shell or JSON quoting: openvpn splits management commands with `parse_line()`,
//! the *config-file* lexer. A parameter is whitespace delimited unless double quoted; inside a
//! double-quoted parameter a backslash escapes the next character. Quoting unconditionally is
//! what makes leading and trailing spaces, `#`, and `;` survive intact — a password that differs
//! by one trailing space authenticates as a different password with no error anywhere.

use super::{MgmtError, MAX_LINE_BYTES};

/// Renders `raw` as a single config-lexer parameter, always double quoted.
pub fn escape_param(raw: &str) -> Result<String, MgmtError> {
    if raw.bytes().any(is_framing_hazard) {
        return Err(MgmtError::ForbiddenControlChar);
    }

    let body = raw
        .chars()
        .fold(String::with_capacity(raw.len()), |mut acc, ch| {
            if matches!(ch, '"' | '\\') {
                acc.push('\\');
            }
            acc.push(ch);
            acc
        });

    Ok(format!("\"{body}\""))
}

/// Builds `verb "p1" "p2"`, rejecting anything openvpn would silently truncate.
pub fn build_command(verb: &str, params: &[&str]) -> Result<String, MgmtError> {
    if verb.is_empty() || !verb.bytes().all(is_verb_byte) {
        return Err(MgmtError::InvalidVerb);
    }

    let line =
        params
            .iter()
            .try_fold(verb.to_owned(), |acc, param| -> Result<String, MgmtError> {
                let escaped = escape_param(param)?;
                Ok(format!("{acc} {escaped}"))
            })?;

    check_line_length(&line)?;
    Ok(line)
}

/// The overflow is discarded without any error reply, so length is checked before every write.
pub fn check_line_length(line: &str) -> Result<(), MgmtError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(MgmtError::LineTooLong { bytes: line.len() });
    }
    if line.bytes().any(is_framing_hazard) {
        return Err(MgmtError::ForbiddenControlChar);
    }
    Ok(())
}

fn is_framing_hazard(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | 0)
}

fn is_verb_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn wraps_a_plain_value_in_double_quotes() {
        let escaped = escape_param("hunter2").expect("plain value");
        assert_eq!(escaped, "\"hunter2\"");
    }

    #[test]
    fn escapes_an_embedded_double_quote() {
        let escaped = escape_param("pa\"ss").expect("quoted value");
        assert_eq!(escaped, "\"pa\\\"ss\"");
    }

    #[test]
    fn escapes_a_backslash_so_it_is_not_read_as_an_escape() {
        let escaped = escape_param("pa\\ss").expect("backslash value");
        assert_eq!(escaped, "\"pa\\\\ss\"");
    }

    #[test]
    fn escapes_a_trailing_backslash_without_swallowing_the_closing_quote() {
        let escaped = escape_param("pass\\").expect("trailing backslash");
        assert_eq!(escaped, "\"pass\\\\\"");
    }

    #[test]
    fn escapes_backslash_before_quote_in_the_right_order() {
        let escaped = escape_param("a\\\"b").expect("mixed value");
        assert_eq!(escaped, "\"a\\\\\\\"b\"");
    }

    #[test]
    fn preserves_leading_and_trailing_spaces() {
        let escaped = escape_param("  pad  ").expect("padded value");
        assert_eq!(escaped, "\"  pad  \"");
    }

    #[test]
    fn preserves_interior_whitespace_and_tabs() {
        let escaped = escape_param("two words\tand tab").expect("spaced value");
        assert_eq!(escaped, "\"two words\tand tab\"");
    }

    #[test]
    fn preserves_comment_introducers_that_would_truncate_unquoted() {
        assert_eq!(escape_param("a#b").expect("hash"), "\"a#b\"");
        assert_eq!(escape_param("a;b").expect("semicolon"), "\"a;b\"");
    }

    #[test]
    fn preserves_single_quotes_verbatim() {
        let escaped = escape_param("it's").expect("apostrophe");
        assert_eq!(escaped, "\"it's\"");
    }

    #[test]
    fn emits_an_empty_quoted_parameter_for_an_empty_value() {
        assert_eq!(escape_param("").expect("empty"), "\"\"");
    }

    #[test]
    fn preserves_non_ascii_bytes() {
        assert_eq!(escape_param("pässwörd").expect("utf8"), "\"pässwörd\"");
    }

    #[test]
    fn rejects_newline_carriage_return_and_nul() {
        for hazard in ["a\nb", "a\rb", "a\0b"] {
            assert!(matches!(
                escape_param(hazard),
                Err(MgmtError::ForbiddenControlChar)
            ));
        }
    }

    #[test]
    fn builds_a_two_parameter_command() {
        let line = build_command("username", &["Auth", "al ice"]).expect("command");
        assert_eq!(line, "username \"Auth\" \"al ice\"");
    }

    #[test]
    fn builds_a_bare_verb_when_there_are_no_parameters() {
        assert_eq!(build_command("hold", &[]).expect("verb"), "hold");
    }

    #[test]
    fn rejects_a_verb_containing_a_space() {
        assert!(matches!(
            build_command("hold release", &[]),
            Err(MgmtError::InvalidVerb)
        ));
    }

    #[test]
    fn rejects_a_command_longer_than_the_send_limit() {
        let long = "x".repeat(MAX_LINE_BYTES);
        assert!(matches!(
            build_command("password", &["Auth", &long]),
            Err(MgmtError::LineTooLong { .. })
        ));
    }

    #[test]
    fn accepts_a_command_exactly_at_the_send_limit() {
        // verb + space + two quotes = 12 bytes of overhead for `password "<body>"`.
        let body = "x".repeat(MAX_LINE_BYTES - 11);
        let line = build_command("password", &[&body]).expect("boundary");
        assert_eq!(line.len(), MAX_LINE_BYTES);
    }
}
