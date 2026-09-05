// SPDX-License-Identifier: GPL-3.0-or-later

//! Everything the connect path can refuse or fail with.
//!
//! The variants exist so the GUI can react differently — a second connect, a
//! profile that no longer validates and a policy that would not install are
//! three different user-facing situations, not one "internal error".

use thisconnect_shared::ipc::ProfileId;
use thisconnect_shared::ovpn::ValidationError;

use crate::auth::AuthError;
use crate::mgmt::MgmtError;
use crate::policy::PolicyError;

use super::state::SessionState;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("a connection is already up")]
    AlreadyConnected,

    #[error("nothing is connected")]
    NotConnected,

    #[error("another connect or disconnect is already in flight")]
    Busy,

    #[error("cannot move from {from:?} to {to:?}")]
    IllegalTransition {
        from: SessionState,
        to: SessionState,
    },

    #[error("no profile with that id")]
    ProfileNotFound { id: ProfileId },

    #[error("the profile did not pass validation: {0}")]
    Profile(#[source] ValidationError),

    #[error("could not {what}: {detail}")]
    Workspace { what: &'static str, detail: String },

    #[error("could not find an openvpn binary: {detail}")]
    OpenvpnNotFound { detail: String },

    #[error("could not start {command}: {detail}")]
    Spawn { command: String, detail: String },

    #[error("openvpn exited (code {code:?}, signal {signal:?})")]
    OpenvpnExited {
        code: Option<i32>,
        signal: Option<i32>,
    },

    #[error("openvpn reported a fatal error: {detail}")]
    OpenvpnFatal { detail: String },

    #[error("openvpn did not connect back to the management socket in time")]
    ManagementTimeout,

    #[error(transparent)]
    Mgmt(#[from] MgmtError),

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error("authentication was rejected: {detail}")]
    AuthRejected { detail: String },

    #[error("tunnel policy failed: {0}")]
    Policy(#[source] PolicyError),

    #[error("the tunnel came up without an address to bind egress sockets to")]
    MissingTunnelAddress,

    #[error("the connection attempt was cancelled")]
    Cancelled,

    #[error("internal error: {detail}")]
    Internal { detail: String },
}

impl SessionError {
    pub(crate) fn workspace(what: &'static str, source: std::io::Error) -> Self {
        Self::Workspace {
            what,
            detail: source.to_string(),
        }
    }

    /// Text the GUI may display verbatim. Never carries a credential: the only
    /// variants that see one redact it before it reaches here.
    pub fn user_facing(&self) -> String {
        self.to_string()
    }
}
