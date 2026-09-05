// SPDX-License-Identifier: GPL-3.0-or-later

//! Line-delimited JSON control protocol (SPEC.md 7.4).
//!
//! One JSON object per line, no JSON-RPC framing. The GUI sends a profile id,
//! never a raw config, so nothing on this wire is ever a `.ovpn` body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A request from the GUI. Unknown fields are rejected: this is untrusted input
/// to a privileged process, and silently ignoring a field the GUI thought was
/// meaningful is how security controls get skipped.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Opaque correlation id, echoed back untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub cmd: Command,
}

/// Commands the skeleton answers on its own. Connection lifecycle commands are
/// added by the supervisor module, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Command {
    Ping,
    Version,
    Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// Malformed JSON, unknown command, or an oversized line.
    BadRequest,
    /// Peer authentication failed. Never sent with any detail about why.
    Unauthorised,
    /// The command is known but not wired up in this build.
    NotImplemented,
    /// Something failed inside the daemon. Details go to the log, not the wire.
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn success(id: Option<String>, data: Value) -> Self {
        Self {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(id: Option<String>, code: ErrorCode, message: &str) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(ErrorBody {
                code,
                message: message.to_owned(),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_well_formed_request_with_a_correlation_id() {
        let line = r#"{"id":"7","cmd":"status"}"#;

        let request: Request = serde_json::from_str(line).expect("parse");

        assert_eq!(
            request,
            Request {
                id: Some("7".to_owned()),
                cmd: Command::Status,
            }
        );
    }

    #[test]
    fn parses_a_request_without_an_id() {
        let request: Request = serde_json::from_str(r#"{"cmd":"ping"}"#).expect("parse");

        assert_eq!(request.id, None);
    }

    #[test]
    fn rejects_a_request_carrying_an_unknown_field() {
        let line = r#"{"cmd":"ping","script_security":0}"#;

        let result = serde_json::from_str::<Request>(line);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_an_unknown_command_rather_than_defaulting() {
        let result = serde_json::from_str::<Request>(r#"{"cmd":"connect-anything"}"#);

        assert!(result.is_err());
    }

    #[test]
    fn success_response_serialises_without_an_error_field() {
        let response = Response::success(Some("1".to_owned()), json!({"pong": true}));

        let encoded = serde_json::to_string(&response).expect("encode");

        assert_eq!(encoded, r#"{"id":"1","ok":true,"data":{"pong":true}}"#);
    }

    #[test]
    fn failure_response_serialises_without_a_data_field() {
        let response = Response::failure(None, ErrorCode::Unauthorised, "unauthorised");

        let encoded = serde_json::to_string(&response).expect("encode");

        assert_eq!(
            encoded,
            r#"{"ok":false,"error":{"code":"unauthorised","message":"unauthorised"}}"#
        );
    }

    #[test]
    fn encoded_responses_never_contain_a_newline_that_would_break_framing() {
        let response = Response::failure(
            Some("a\nb".to_owned()),
            ErrorCode::BadRequest,
            "bad\nrequest",
        );

        let encoded = serde_json::to_string(&response).expect("encode");

        assert!(!encoded.contains('\n'));
    }
}
