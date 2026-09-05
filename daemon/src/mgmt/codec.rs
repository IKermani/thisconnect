// SPDX-License-Identifier: GPL-3.0-or-later

//! Line framing and reply accumulation (SPEC.md §4.3 points 1 and 2).

use super::event::Event;
use super::{MgmtError, MAX_INBOUND_LINE_BYTES};

/// Splits an inbound byte stream into lines.
///
/// The wire is CRLF terminated, but a partial read can land anywhere, so the split is on `\n`
/// with the `\r` stripped afterwards. Decoding is lossy on purpose: a non-UTF-8 byte in a
/// `>LOG:` line must not tear down the management channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineSplitter {
    buffered: Vec<u8>,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds a chunk in, returning the next splitter and the lines it completed.
    pub fn push(&self, chunk: &[u8]) -> Result<(Self, Vec<String>), MgmtError> {
        let combined: Vec<u8> = self
            .buffered
            .iter()
            .copied()
            .chain(chunk.iter().copied())
            .collect();

        let mut lines = Vec::new();
        let mut rest: &[u8] = &combined;
        while let Some(index) = rest.iter().position(|byte| *byte == b'\n') {
            let (line, tail) = rest.split_at(index);
            lines.push(decode_line(line));
            rest = tail.get(1..).unwrap_or_default();
        }

        if rest.len() > MAX_INBOUND_LINE_BYTES {
            return Err(MgmtError::LineTooLong { bytes: rest.len() });
        }

        Ok((
            Self {
                buffered: rest.to_vec(),
            },
            lines,
        ))
    }
}

fn decode_line(raw: &[u8]) -> String {
    let trimmed = match raw.last() {
        Some(b'\r') => raw.get(..raw.len() - 1).unwrap_or_default(),
        _ => raw,
    };
    String::from_utf8_lossy(trimmed).into_owned()
}

/// The four shapes a management line can take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// A `>TYPE:` notification. It belongs to nobody's command and is dispatched immediately.
    Event(Event),
    Success(String),
    Error(String),
    /// The bare `END` closing a multiline body.
    End,
    /// A body line of a multiline reply.
    Data(String),
}

/// Classifies one already-unframed line.
pub fn classify(line: &str) -> Frame {
    if line.starts_with('>') {
        return Frame::Event(Event::parse(line));
    }
    if let Some(text) = line.strip_prefix("SUCCESS: ") {
        return Frame::Success(text.to_owned());
    }
    if let Some(text) = line.strip_prefix("ERROR: ") {
        return Frame::Error(text.to_owned());
    }
    if line == "END" {
        return Frame::End;
    }
    Frame::Data(line.to_owned())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyStatus {
    Success,
    Error,
    /// Multiline output closed by a bare `END`.
    End,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandReply {
    pub status: ReplyStatus,
    /// The text after `SUCCESS: ` / `ERROR: `; empty for a multiline reply.
    pub text: String,
    pub lines: Vec<String>,
}

impl CommandReply {
    pub fn is_error(&self) -> bool {
        self.status == ReplyStatus::Error
    }
}

/// Collects the body of the single in-flight command until a terminal line arrives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplyAccumulator {
    lines: Vec<String>,
}

impl ReplyAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one frame in, returning the next accumulator and the reply if this frame ended it.
    ///
    /// An event frame is never accumulated: notifications interleave freely with a command and
    /// its reply, and letting one into the body corrupts the reply.
    pub fn accept(&self, frame: &Frame) -> (Self, Option<CommandReply>) {
        match frame {
            Frame::Event(_) => (self.clone(), None),
            Frame::Data(line) => (
                Self {
                    lines: self
                        .lines
                        .iter()
                        .cloned()
                        .chain(std::iter::once(line.clone()))
                        .collect(),
                },
                None,
            ),
            Frame::Success(text) => (Self::new(), Some(self.finish(ReplyStatus::Success, text))),
            Frame::Error(text) => (Self::new(), Some(self.finish(ReplyStatus::Error, text))),
            Frame::End => (Self::new(), Some(self.finish(ReplyStatus::End, ""))),
        }
    }

    fn finish(&self, status: ReplyStatus, text: &str) -> CommandReply {
        CommandReply {
            status,
            text: text.to_owned(),
            lines: self.lines.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mgmt::event::PasswordEvent;

    fn split_all(chunks: &[&[u8]]) -> Vec<String> {
        chunks
            .iter()
            .fold(
                (LineSplitter::new(), Vec::new()),
                |(splitter, acc), chunk| {
                    let (next, lines) = splitter.push(chunk).expect("split");
                    (next, acc.into_iter().chain(lines).collect())
                },
            )
            .1
    }

    #[test]
    fn strips_the_carriage_return_from_crlf_lines() {
        let lines = split_all(&[b">INFO:hello\r\nSUCCESS: real\r\n"]);
        assert_eq!(lines, vec![">INFO:hello", "SUCCESS: real"]);
    }

    #[test]
    fn reassembles_a_line_split_across_reads() {
        let lines = split_all(&[
            b">STATE:1741000000,CON",
            b"NECTED,SUCCESS,10.8.0.2,,\r",
            b"\n",
        ]);
        assert_eq!(
            lines,
            vec![">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,,"]
        );
    }

    #[test]
    fn holds_back_a_line_that_has_no_terminator_yet() {
        let (splitter, lines) = LineSplitter::new().push(b"SUCCESS: par").expect("split");
        assert!(lines.is_empty());
        let (_, lines) = splitter.push(b"tial\r\n").expect("split");
        assert_eq!(lines, vec!["SUCCESS: partial"]);
    }

    #[test]
    fn accepts_bare_lf_without_a_carriage_return() {
        assert_eq!(split_all(&[b"END\n"]), vec!["END"]);
    }

    #[test]
    fn emits_an_empty_line_for_a_blank_line() {
        assert_eq!(split_all(&[b"\r\n"]), vec![""]);
    }

    #[test]
    fn decodes_invalid_utf8_lossily_instead_of_failing() {
        let lines = split_all(&[b">LOG:1741000000,I,bad \xff byte\r\n"]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with(">LOG:"));
    }

    #[test]
    fn refuses_to_buffer_an_unterminated_line_without_bound() {
        let flood = vec![b'x'; MAX_INBOUND_LINE_BYTES + 1];
        assert!(matches!(
            LineSplitter::new().push(&flood),
            Err(MgmtError::LineTooLong { .. })
        ));
    }

    #[test]
    fn classifies_the_three_reply_shapes_and_a_body_line() {
        assert_eq!(
            classify("SUCCESS: real-time state notification set to ON"),
            Frame::Success("real-time state notification set to ON".to_owned())
        );
        assert_eq!(
            classify("ERROR: unknown command, enter 'help' for more options"),
            Frame::Error("unknown command, enter 'help' for more options".to_owned())
        );
        assert_eq!(classify("END"), Frame::End);
        assert_eq!(
            classify("OpenVPN Version: OpenVPN 2.7.6"),
            Frame::Data("OpenVPN Version: OpenVPN 2.7.6".to_owned())
        );
    }

    #[test]
    fn classifies_any_leading_angle_bracket_line_as_an_event() {
        assert!(matches!(
            classify(">HOLD:Waiting for hold release:0"),
            Frame::Event(_)
        ));
        assert!(matches!(
            classify(">SOMETHING-NEW:payload"),
            Frame::Event(_)
        ));
    }

    #[test]
    fn does_not_treat_a_success_word_inside_a_body_line_as_terminal() {
        assert_eq!(
            classify("SUCCESS: "),
            Frame::Success(String::new()),
            "the prefix with an empty tail is still terminal"
        );
        assert!(matches!(classify("SUCCESS:no space"), Frame::Data(_)));
    }

    fn feed(lines: &[&str]) -> Vec<CommandReply> {
        lines
            .iter()
            .fold(
                (ReplyAccumulator::new(), Vec::new()),
                |(acc, replies), line| {
                    let (next, reply) = acc.accept(&classify(line));
                    (next, replies.into_iter().chain(reply).collect())
                },
            )
            .1
    }

    #[test]
    fn terminates_a_single_line_command_on_success() {
        let replies = feed(&["SUCCESS: hold release succeeded"]);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].status, ReplyStatus::Success);
        assert_eq!(replies[0].text, "hold release succeeded");
        assert!(replies[0].lines.is_empty());
    }

    #[test]
    fn terminates_a_multiline_command_on_a_bare_end() {
        let replies = feed(&[
            "OpenVPN Version: OpenVPN 2.7.6 aarch64-apple-darwin25.6.0",
            "Management Version: 6",
            "END",
        ]);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].status, ReplyStatus::End);
        assert_eq!(replies[0].lines.len(), 2);
        assert_eq!(replies[0].lines[1], "Management Version: 6");
    }

    #[test]
    fn reports_an_error_reply_without_treating_it_as_a_body_line() {
        let replies = feed(&["ERROR: unknown command"]);
        assert!(replies[0].is_error());
        assert_eq!(replies[0].text, "unknown command");
    }

    #[test]
    fn never_feeds_an_event_into_the_command_accumulator() {
        // Verified against openvpn 2.7.6: a >LOG: line arrives before the SUCCESS: of the
        // command that produced it.
        let replies = feed(&[
            ">LOG:1741000000,I,MANAGEMENT: CMD 'state on'",
            ">STATE:1741000000,WAIT,,,",
            "SUCCESS: real-time state notification set to ON",
        ]);
        assert_eq!(replies.len(), 1);
        assert!(
            replies[0].lines.is_empty(),
            "events must not appear in the reply body"
        );
    }

    #[test]
    fn keeps_events_out_of_a_multiline_body_too() {
        let replies = feed(&[
            "TITLE,OpenVPN 2.7.6",
            ">BYTECOUNT:10,20",
            "TIME,1741000000",
            "END",
        ]);
        assert_eq!(
            replies[0].lines,
            vec!["TITLE,OpenVPN 2.7.6", "TIME,1741000000"]
        );
    }

    #[test]
    fn classifies_a_captured_password_prompt_as_an_event() {
        let stream = b">PASSWORD:Need 'Auth' username/password SC:1,Enter token\r\n";
        let lines = split_all(&[stream]);
        let Frame::Event(Event::Password(PasswordEvent::Need { challenge, .. })) =
            classify(&lines[0])
        else {
            panic!("expected a password event");
        };
        assert_eq!(challenge.expect("challenge").text, "Enter token");
    }

    #[test]
    fn resets_between_two_consecutive_commands() {
        let replies = feed(&["line one", "END", "SUCCESS: second"]);
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].lines, vec!["line one"]);
        assert!(replies[1].lines.is_empty());
    }
}
