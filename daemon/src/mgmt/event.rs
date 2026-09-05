// SPDX-License-Identifier: GPL-3.0-or-later

//! Asynchronous `>TYPE:payload` notifications (SPEC.md §4.3 points 1, 5, 6, 7).
//!
//! Parsing is total: an unrecognised or malformed notification becomes `Event::Unknown` rather
//! than an error, because a parse failure must never take the management channel down.

use super::challenge::{DynamicChallenge, StaticChallenge};
use super::MgmtError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The greeting, e.g. `OpenVPN Management Interface Version 6 -- type 'help' for more info`.
    Info(String),
    State(StateEvent),
    Hold {
        message: String,
        seconds: Option<u64>,
    },
    Password(PasswordEvent),
    Log(LogEvent),
    ByteCount {
        bytes_in: u64,
        bytes_out: u64,
    },
    UpDown(UpDown),
    Fatal(String),
    InfoMsg(InfoMsg),
    NeedOk {
        kind: String,
        message: String,
    },
    NeedStr {
        kind: String,
        message: String,
    },
    Unknown {
        tag: String,
        payload: String,
    },
}

impl Event {
    /// Parses one `>`-prefixed line. The leading `>` may be present or already stripped.
    pub fn parse(line: &str) -> Self {
        let body = line.strip_prefix('>').unwrap_or(line);
        let (tag, payload) = body.split_once(':').unwrap_or((body, ""));

        match tag {
            "INFO" => Event::Info(payload.to_owned()),
            "STATE" => {
                StateEvent::parse(payload).map_or_else(|| unknown(tag, payload), Event::State)
            }
            "HOLD" => parse_hold(payload),
            "PASSWORD" => Event::Password(PasswordEvent::parse(payload)),
            "LOG" => Event::Log(LogEvent::parse(payload)),
            "BYTECOUNT" => parse_bytecount(payload).unwrap_or_else(|| unknown(tag, payload)),
            "UPDOWN" => Event::UpDown(UpDown::parse(payload)),
            "FATAL" => Event::Fatal(payload.to_owned()),
            "INFOMSG" => Event::InfoMsg(InfoMsg::parse(payload)),
            "NEED-OK" => parse_need(payload).map_or_else(
                || unknown(tag, payload),
                |(kind, message)| Event::NeedOk { kind, message },
            ),
            "NEED-STR" => parse_need(payload).map_or_else(
                || unknown(tag, payload),
                |(kind, message)| Event::NeedStr { kind, message },
            ),
            _ => unknown(tag, payload),
        }
    }
}

fn unknown(tag: &str, payload: &str) -> Event {
    Event::Unknown {
        tag: tag.to_owned(),
        payload: payload.to_owned(),
    }
}

/// `>HOLD:Waiting for hold release:0` — the trailing integer is the hold hint in seconds.
fn parse_hold(payload: &str) -> Event {
    match payload.rsplit_once(':') {
        Some((message, tail)) => match tail.trim().parse::<u64>() {
            Ok(seconds) => Event::Hold {
                message: message.to_owned(),
                seconds: Some(seconds),
            },
            Err(_) => Event::Hold {
                message: payload.to_owned(),
                seconds: None,
            },
        },
        None => Event::Hold {
            message: payload.to_owned(),
            seconds: None,
        },
    }
}

fn parse_bytecount(payload: &str) -> Option<Event> {
    let (raw_in, raw_out) = payload.split_once(',')?;
    Some(Event::ByteCount {
        bytes_in: raw_in.trim().parse().ok()?,
        bytes_out: raw_out.trim().parse().ok()?,
    })
}

/// `>NEED-OK:token-insertion-request:Need token insertion`
fn parse_need(payload: &str) -> Option<(String, String)> {
    let (kind, message) = payload.split_once(':')?;
    Some((kind.to_owned(), message.to_owned()))
}

/// `>STATE:` parsed strictly by index: 2.7.6 emits a trailing empty IPv6 field, so the field
/// count is 8 on some builds and 9 on others and must never be matched on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateEvent {
    pub time: Option<i64>,
    pub name: String,
    pub description: Option<String>,
    pub local_v4: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<String>,
    pub local_addr: Option<String>,
    pub local_port: Option<String>,
    pub local_v6: Option<String>,
}

impl StateEvent {
    pub fn parse(payload: &str) -> Option<Self> {
        let fields: Vec<&str> = payload.split(',').collect();
        let at = |index: usize| -> Option<String> {
            fields
                .get(index)
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };

        let name = at(1)?;
        Some(Self {
            time: at(0).and_then(|value| value.parse().ok()),
            name,
            description: at(2),
            local_v4: at(3),
            remote_addr: at(4),
            remote_port: at(5),
            local_addr: at(6),
            local_port: at(7),
            local_v6: at(8),
        })
    }

    /// The only admissible connected signal. `GET_CONFIG`, `ASSIGN_IP` and `ADD_ROUTES` are not
    /// gates: `ADD_ROUTES` never fires at all under `--route-noexec`.
    pub fn is_connected(&self) -> bool {
        self.name == "CONNECTED"
    }
}

/// A raw `>LOG:` line. Never persisted and never traced: openvpn redacts `password` but not
/// `username`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvent {
    pub time: Option<i64>,
    pub flags: String,
    pub text: String,
}

impl LogEvent {
    pub fn parse(payload: &str) -> Self {
        let mut fields = payload.splitn(3, ',');
        let time = fields.next().and_then(|value| value.trim().parse().ok());
        let flags = fields.next().unwrap_or_default().to_owned();
        let text = fields.next().unwrap_or_default().to_owned();
        Self { time, flags, text }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordEvent {
    Need {
        kind: String,
        needs_username: bool,
        needs_password: bool,
        challenge: Option<StaticChallenge>,
    },
    VerificationFailed {
        kind: String,
        reason: Option<String>,
        dynamic: Option<DynamicChallenge>,
    },
    /// A pushed auth token. The value is deliberately discarded: it is a bearer credential and
    /// this type is `Debug` and broadcast to every subscriber.
    AuthToken,
    Other(String),
}

impl PasswordEvent {
    pub fn parse(payload: &str) -> Self {
        if let Some(rest) = payload.strip_prefix("Need ") {
            return Self::parse_need(rest);
        }
        if let Some(rest) = payload.strip_prefix("Verification Failed:") {
            return Self::parse_verification_failed(rest.trim());
        }
        if payload.starts_with("Auth-Token:") {
            return PasswordEvent::AuthToken;
        }
        PasswordEvent::Other(payload.to_owned())
    }

    fn parse_need(rest: &str) -> Self {
        let (kind, tail) = split_quoted(rest);
        let (want, challenge) = match tail.split_once("SC:") {
            Some((want, sc)) => (want, StaticChallenge::parse(&format!("SC:{sc}"))),
            None => (tail, None),
        };
        PasswordEvent::Need {
            kind,
            needs_username: want.contains("username"),
            needs_password: want.contains("password"),
            challenge,
        }
    }

    fn parse_verification_failed(rest: &str) -> Self {
        let (kind, tail) = split_quoted(rest);
        let reason = extract_quoted(tail);
        let dynamic = reason
            .as_deref()
            .and_then(|value| DynamicChallenge::parse(value).ok());
        PasswordEvent::VerificationFailed {
            kind,
            reason,
            dynamic,
        }
    }
}

/// `>INFOMSG:CR_TEXT:Enter token` carries the 2.6+ challenge answered with `cr-response`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InfoMsg {
    CrText(String),
    Other(String),
}

impl InfoMsg {
    pub fn parse(payload: &str) -> Self {
        match payload.strip_prefix("CR_TEXT:") {
            Some(text) => InfoMsg::CrText(text.to_owned()),
            None => InfoMsg::Other(payload.to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpDown {
    Up,
    Down,
    EnvBegin,
    EnvEnd,
    Env { key: String, value: String },
    Other(String),
}

impl UpDown {
    pub fn parse(payload: &str) -> Self {
        match payload.split_once(',') {
            Some(("ENV", "END")) => UpDown::EnvEnd,
            Some(("ENV", "BEGIN")) => UpDown::EnvBegin,
            Some(("ENV", entry)) => match entry.split_once('=') {
                Some((key, value)) => UpDown::Env {
                    key: key.to_owned(),
                    value: value.to_owned(),
                },
                None => UpDown::Other(payload.to_owned()),
            },
            _ => match payload.trim() {
                "UP" => UpDown::Up,
                "DOWN" => UpDown::Down,
                other => UpDown::Other(other.to_owned()),
            },
        }
    }
}

/// The only source of tunnel identity: it is not in `>STATE:` at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelIdentity {
    pub dev: String,
    pub dev_type: Option<String>,
    pub ifconfig_local: Option<String>,
    pub ifconfig_ipv6_local: Option<String>,
}

/// Accumulates one `>UPDOWN:UP` … `>UPDOWN:ENV,END` block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpDownCollector {
    in_up_block: bool,
    env: Vec<(String, String)>,
}

/// What an `>UPDOWN:ENV,END` closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpDownOutcome {
    Up(TunnelIdentity),
    Down,
}

impl UpDownCollector {
    /// Folds one `>UPDOWN:` line in, returning the next collector and any completed block.
    ///
    /// A block that ends without `dev=` is a hard error: §5 egress binding has nothing to bind to.
    pub fn observe(&self, line: &UpDown) -> (Self, Option<Result<UpDownOutcome, MgmtError>>) {
        match line {
            UpDown::Up => (
                Self {
                    in_up_block: true,
                    env: Vec::new(),
                },
                None,
            ),
            UpDown::Down => (Self::default(), Some(Ok(UpDownOutcome::Down))),
            UpDown::EnvBegin => (self.clone(), None),
            UpDown::Env { key, value } => {
                let env = self
                    .env
                    .iter()
                    .cloned()
                    .chain(std::iter::once((key.clone(), value.clone())))
                    .collect();
                (
                    Self {
                        in_up_block: self.in_up_block,
                        env,
                    },
                    None,
                )
            }
            UpDown::EnvEnd if self.in_up_block => (Self::default(), Some(self.finish())),
            UpDown::EnvEnd | UpDown::Other(_) => (Self::default(), None),
        }
    }

    fn finish(&self) -> Result<UpDownOutcome, MgmtError> {
        let get = |wanted: &str| -> Option<String> {
            self.env
                .iter()
                .find(|(key, _)| key == wanted)
                .map(|(_, value)| value.clone())
                .filter(|value| !value.is_empty())
        };

        let dev = get("dev").ok_or(MgmtError::MissingDev)?;
        Ok(UpDownOutcome::Up(TunnelIdentity {
            dev,
            dev_type: get("dev_type"),
            ifconfig_local: get("ifconfig_local"),
            ifconfig_ipv6_local: get("ifconfig_ipv6_local"),
        }))
    }
}

/// Splits a leading `'quoted'` token from the rest of a payload.
fn split_quoted(input: &str) -> (String, &str) {
    let trimmed = input.trim_start();
    match trimmed.strip_prefix('\'').and_then(|rest| {
        rest.split_once('\'')
            .map(|(inner, tail)| (inner.to_owned(), tail))
    }) {
        Some(split) => split,
        None => (String::new(), trimmed),
    }
}

/// Extracts the first `'quoted'` token anywhere in the payload.
fn extract_quoted(input: &str) -> Option<String> {
    let start = input.find('\'')?;
    let rest = input.get(start + 1..)?;
    let end = rest.rfind('\'')?;
    rest.get(..end).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn parses_the_greeting_as_an_info_event() {
        let event = Event::parse(
            ">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info",
        );
        assert!(matches!(event, Event::Info(text) if text.contains("Version 6")));
    }

    #[test]
    fn parses_a_nine_field_state_line_with_a_trailing_empty_ipv6_field() {
        let event = Event::parse(">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,");
        let Event::State(state) = event else {
            panic!("expected a state event");
        };
        assert!(state.is_connected());
        assert_eq!(state.time, Some(1741000000));
        assert_eq!(state.local_v4.as_deref(), Some("10.8.0.2"));
        assert_eq!(state.remote_addr.as_deref(), Some("203.0.113.7"));
        assert_eq!(state.remote_port.as_deref(), Some("1194"));
        assert_eq!(state.local_v6, None);
    }

    #[test]
    fn parses_an_eight_field_state_line_from_an_older_build() {
        let event = Event::parse(
            ">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,192.0.2.5,49152",
        );
        let Event::State(state) = event else {
            panic!("expected a state event");
        };
        assert!(state.is_connected());
        assert_eq!(state.local_addr.as_deref(), Some("192.0.2.5"));
        assert_eq!(state.local_port.as_deref(), Some("49152"));
        assert_eq!(state.local_v6, None);
    }

    #[test]
    fn parses_a_state_line_carrying_an_ipv6_address() {
        let event =
            Event::parse(">STATE:1741000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.7,1194,,,fd00::2");
        let Event::State(state) = event else {
            panic!("expected a state event");
        };
        assert_eq!(state.local_v6.as_deref(), Some("fd00::2"));
    }

    #[test]
    fn parses_a_short_state_line_without_panicking() {
        let event = Event::parse(">STATE:1741000000,RECONNECTING,tls-error");
        let Event::State(state) = event else {
            panic!("expected a state event");
        };
        assert_eq!(state.name, "RECONNECTING");
        assert!(!state.is_connected());
        assert_eq!(state.local_v4, None);
    }

    #[test]
    fn does_not_treat_get_config_or_add_routes_as_connected() {
        for name in ["GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "AUTH", "WAIT"] {
            let event = Event::parse(&format!(">STATE:1741000000,{name},,,"));
            let Event::State(state) = event else {
                panic!("expected a state event");
            };
            assert!(!state.is_connected(), "{name} must not signal connected");
        }
    }

    #[test]
    fn parses_hold_with_its_seconds_hint() {
        let event = Event::parse(">HOLD:Waiting for hold release:10");
        assert_eq!(
            event,
            Event::Hold {
                message: "Waiting for hold release".to_owned(),
                seconds: Some(10)
            }
        );
    }

    #[test]
    fn parses_hold_without_a_seconds_hint() {
        let event = Event::parse(">HOLD:Waiting for hold release");
        assert_eq!(
            event,
            Event::Hold {
                message: "Waiting for hold release".to_owned(),
                seconds: None
            }
        );
    }

    #[test]
    fn parses_a_plain_username_password_prompt() {
        let event = Event::parse(">PASSWORD:Need 'Auth' username/password");
        assert_eq!(
            event,
            Event::Password(PasswordEvent::Need {
                kind: "Auth".to_owned(),
                needs_username: true,
                needs_password: true,
                challenge: None
            })
        );
    }

    #[test]
    fn parses_a_private_key_password_only_prompt() {
        let event = Event::parse(">PASSWORD:Need 'Private Key' password");
        assert_eq!(
            event,
            Event::Password(PasswordEvent::Need {
                kind: "Private Key".to_owned(),
                needs_username: false,
                needs_password: true,
                challenge: None
            })
        );
    }

    #[test]
    fn parses_a_static_challenge_prompt() {
        let event = Event::parse(">PASSWORD:Need 'Auth' username/password SC:1,Enter token");
        assert_eq!(
            event,
            Event::Password(PasswordEvent::Need {
                kind: "Auth".to_owned(),
                needs_username: true,
                needs_password: true,
                challenge: Some(StaticChallenge {
                    echo: true,
                    text: "Enter token".to_owned()
                })
            })
        );
    }

    #[test]
    fn parses_a_verification_failure_carrying_a_crv1_challenge() {
        let event = Event::parse(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Sf23fks9:dXNlcg==:Enter token: now']",
        );
        let Event::Password(PasswordEvent::VerificationFailed { kind, dynamic, .. }) = event else {
            panic!("expected a verification failure");
        };
        assert_eq!(kind, "Auth");
        let challenge = dynamic.expect("crv1 challenge");
        assert_eq!(challenge.state_id, "Sf23fks9");
        assert_eq!(challenge.challenge_text, "Enter token: now");
    }

    #[test]
    fn parses_a_verification_failure_without_a_challenge() {
        let event = Event::parse(">PASSWORD:Verification Failed: 'Auth'");
        assert_eq!(
            event,
            Event::Password(PasswordEvent::VerificationFailed {
                kind: "Auth".to_owned(),
                reason: None,
                dynamic: None
            })
        );
    }

    #[test]
    fn discards_the_value_of_a_pushed_auth_token() {
        let event = Event::parse(">PASSWORD:Auth-Token:SESS_ID_SECRET");
        assert_eq!(event, Event::Password(PasswordEvent::AuthToken));
        assert!(!format!("{event:?}").contains("SESS_ID_SECRET"));
    }

    #[test]
    fn parses_a_log_line_keeping_commas_in_the_text() {
        let event =
            Event::parse(">LOG:1741000000,I,OPTIONS IMPORT: --ifconfig/up options modified, ok");
        assert_eq!(
            event,
            Event::Log(LogEvent {
                time: Some(1741000000),
                flags: "I".to_owned(),
                text: "OPTIONS IMPORT: --ifconfig/up options modified, ok".to_owned()
            })
        );
    }

    #[test]
    fn parses_a_bytecount_event() {
        assert_eq!(
            Event::parse(">BYTECOUNT:12345,67890"),
            Event::ByteCount {
                bytes_in: 12345,
                bytes_out: 67890
            }
        );
    }

    #[test]
    fn falls_back_to_unknown_for_a_malformed_bytecount() {
        assert!(matches!(
            Event::parse(">BYTECOUNT:not,numbers"),
            Event::Unknown { .. }
        ));
    }

    #[test]
    fn parses_infomsg_cr_text() {
        assert_eq!(
            Event::parse(">INFOMSG:CR_TEXT:Enter your 2FA code"),
            Event::InfoMsg(InfoMsg::CrText("Enter your 2FA code".to_owned()))
        );
    }

    #[test]
    fn parses_need_ok_and_need_str() {
        assert_eq!(
            Event::parse(">NEED-OK:token-insertion-request:Need token insertion"),
            Event::NeedOk {
                kind: "token-insertion-request".to_owned(),
                message: "Need token insertion".to_owned()
            }
        );
        assert_eq!(
            Event::parse(">NEED-STR:pkcs11-id-request:Please provide a PKCS#11 id"),
            Event::NeedStr {
                kind: "pkcs11-id-request".to_owned(),
                message: "Please provide a PKCS#11 id".to_owned()
            }
        );
    }

    #[test]
    fn parses_fatal_and_unknown_events() {
        assert_eq!(
            Event::parse(">FATAL:Cannot open TUN/TAP dev"),
            Event::Fatal("Cannot open TUN/TAP dev".to_owned())
        );
        assert!(matches!(
            Event::parse(">CLIENT:ESTABLISHED,1"),
            Event::Unknown { .. }
        ));
    }

    fn updown_block(lines: &[&str]) -> Option<Result<UpDownOutcome, MgmtError>> {
        lines
            .iter()
            .fold(
                (UpDownCollector::default(), None),
                |(collector, last), line| {
                    let (next, outcome) = collector.observe(&UpDown::parse(line));
                    (next, outcome.or(last))
                },
            )
            .1
    }

    #[test]
    fn collects_tunnel_identity_from_a_complete_up_block() {
        let outcome = updown_block(&[
            "UP",
            "ENV,dev=utun4",
            "ENV,dev_type=tun",
            "ENV,ifconfig_local=10.8.0.2",
            "ENV,ifconfig_ipv6_local=fd00::2",
            "ENV,END",
        ]);
        let Some(Ok(UpDownOutcome::Up(identity))) = outcome else {
            panic!("expected a tunnel identity");
        };
        assert_eq!(identity.dev, "utun4");
        assert_eq!(identity.dev_type.as_deref(), Some("tun"));
        assert_eq!(identity.ifconfig_local.as_deref(), Some("10.8.0.2"));
        assert_eq!(identity.ifconfig_ipv6_local.as_deref(), Some("fd00::2"));
    }

    #[test]
    fn keeps_equals_signs_inside_an_env_value() {
        let outcome = updown_block(&["UP", "ENV,dev=utun4", "ENV,foo=a=b", "ENV,END"]);
        assert!(matches!(outcome, Some(Ok(UpDownOutcome::Up(_)))));
    }

    #[test]
    fn treats_a_missing_dev_as_a_hard_error() {
        let outcome = updown_block(&["UP", "ENV,ifconfig_local=10.8.0.2", "ENV,END"]);
        assert!(matches!(outcome, Some(Err(MgmtError::MissingDev))));
    }

    #[test]
    fn treats_an_empty_dev_as_a_hard_error() {
        let outcome = updown_block(&["UP", "ENV,dev=", "ENV,END"]);
        assert!(matches!(outcome, Some(Err(MgmtError::MissingDev))));
    }

    #[test]
    fn yields_nothing_until_the_env_block_ends() {
        let (collector, first) = UpDownCollector::default().observe(&UpDown::Up);
        assert!(first.is_none());
        let (_, second) = collector.observe(&UpDown::parse("ENV,dev=utun4"));
        assert!(second.is_none());
    }

    #[test]
    fn reports_a_down_block_separately() {
        let (_, outcome) = UpDownCollector::default().observe(&UpDown::Down);
        assert!(matches!(outcome, Some(Ok(UpDownOutcome::Down))));
    }
}
