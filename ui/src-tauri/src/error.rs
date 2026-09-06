// SPDX-License-Identifier: GPL-3.0-or-later
//! Error surface crossing the Tauri command boundary (design doc §5).

use serde::Serialize;
use thisconnect_shared::ipc::{IpcError, Response};

use crate::ipc_client::IpcClientError;

// `tag`/`rename_all` live on `UiErrorWire` below, not here: `into` makes serde
// serialize via that conversion and ignore any representation attributes on
// this enum directly, so putting them here too would be dead and misleading.
#[derive(Debug, Clone, Serialize)]
#[serde(into = "UiErrorWire")]
pub enum UiError {
    Daemon(IpcError),
    DaemonUnreachable { reason: UiUnreachableReason },
    Timeout,
    Internal { message: String },
}

// Tagged on "reason", not "type": this mirrors the hand-built JSON that
// `lib.rs`'s `reason_to_json` already emits for the `connection-lost` event
// (`{"reason": "not_running"}`, etc). The frontend's `DaemonUnreachableReason`
// type is shared between that push path and this pull path, so both need the
// identical wire shape.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum UiUnreachableReason {
    NotRunning,
    PermissionDenied,
    ProtocolMismatch { daemon_version: String },
}

impl From<crate::ipc_client::DaemonUnreachableReason> for UiUnreachableReason {
    fn from(reason: crate::ipc_client::DaemonUnreachableReason) -> Self {
        use crate::ipc_client::DaemonUnreachableReason as R;
        match reason {
            R::NotRunning => Self::NotRunning,
            R::PermissionDenied => Self::PermissionDenied,
            R::ProtocolMismatch { daemon_version } => Self::ProtocolMismatch { daemon_version },
        }
    }
}

// `IpcError`'s own fields (`code`, `message`, `validation`) need to appear
// flattened at the top level for the `daemon` variant so the frontend reads
// `err.code`/`err.message` the same way regardless of variant. `serde`'s tag
// + flatten combination on an enum needs an explicit wire shape to do that.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum UiErrorWire {
    Daemon {
        #[serde(flatten)]
        error: IpcError,
    },
    DaemonUnreachable {
        reason: UiUnreachableReason,
    },
    Timeout,
    Internal {
        message: String,
    },
}

impl From<UiError> for UiErrorWire {
    fn from(err: UiError) -> Self {
        match err {
            UiError::Daemon(error) => UiErrorWire::Daemon { error },
            UiError::DaemonUnreachable { reason } => UiErrorWire::DaemonUnreachable { reason },
            UiError::Timeout => UiErrorWire::Timeout,
            UiError::Internal { message } => UiErrorWire::Internal { message },
        }
    }
}

impl From<IpcClientError> for UiError {
    fn from(err: IpcClientError) -> Self {
        match err {
            IpcClientError::Daemon(wrapper) => UiError::Daemon(wrapper.0),
            IpcClientError::Timeout => UiError::Timeout,
            IpcClientError::ActorGone => UiError::Internal {
                message: "IPC actor is not running".to_owned(),
            },
        }
    }
}

pub fn unexpected_response(command: &str, response: &Response) -> UiError {
    UiError::Internal {
        message: format!("command `{command}` got an unexpected response shape: {response:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use thisconnect_shared::ipc::{ErrorCode, IpcError as SharedIpcError};

    #[test]
    fn daemon_error_round_trips_through_serialization() {
        let err = UiError::from(crate::ipc_client::IpcClientError::Daemon(
            crate::ipc_client::IpcErrorWrapper(SharedIpcError::new(
                ErrorCode::NotConnected,
                "no active tunnel",
            )),
        ));
        let json = serde_json::to_value(&err).expect("serialize");
        assert_eq!(json["type"], "daemon");
        assert_eq!(json["code"], "not_connected");
    }

    #[test]
    fn timeout_serializes_to_its_own_tag() {
        let json = serde_json::to_value(UiError::from(crate::ipc_client::IpcClientError::Timeout))
            .expect("serialize");
        assert_eq!(json["type"], "timeout");
    }
}
