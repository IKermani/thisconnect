// SPDX-License-Identifier: GPL-3.0-or-later
//! Error surface crossing the Tauri command boundary (design doc §5).
//!
//! Nothing in this crate wires this module's public API into the Tauri command
//! layer yet (that's Task 5), so the error types are otherwise-unreachable
//! from outside themselves; `dead_code` is suppressed accordingly until that
//! wiring lands.
#![allow(dead_code)]

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
    Timeout,
    Internal { message: String },
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
    Timeout,
    Internal {
        message: String,
    },
}

impl From<UiError> for UiErrorWire {
    fn from(err: UiError) -> Self {
        match err {
            UiError::Daemon(error) => UiErrorWire::Daemon { error },
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
