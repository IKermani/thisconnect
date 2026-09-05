// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenVPN management-interface client (SPEC.md §4.3).
//!
//! The wire protocol is line oriented and CRLF terminated with exactly three reply shapes
//! (`SUCCESS: `, `ERROR: `, or a multiline body closed by a bare `END`) plus asynchronous
//! `>TYPE:payload` notifications that interleave freely with a command and its reply.

pub mod challenge;
pub mod client;
pub mod codec;
pub mod escape;
pub mod event;
pub mod tunnel;

use std::time::Duration;

pub use challenge::{DynamicChallenge, StaticChallenge, StaticChallengeFormat};
pub use client::MgmtClient;
pub use codec::{CommandReply, Frame, LineSplitter, ReplyAccumulator, ReplyStatus};
pub use escape::{build_command, escape_param};
pub use event::{Event, LogEvent, PasswordEvent, StateEvent, TunnelIdentity, UpDown};
pub use tunnel::{TunnelEvent, TunnelState, TunnelTracker};

/// openvpn's management input buffer is 1024 bytes and silently discards the overflow, so we
/// refuse to emit anything close to it rather than sending a command that is dropped without
/// an error.
pub const MAX_LINE_BYTES: usize = 900;

/// Inbound lines are bounded too: a peer that never sends `\n` must not grow the daemon's heap.
pub const MAX_INBOUND_LINE_BYTES: usize = 8192;

/// There is no correlation id in the protocol, so a lost reply desynchronises the channel
/// permanently. Bound the wait and treat expiry as fatal.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// Version we announce. Anything <= 3 gets no reply at all and deadlocks the reader.
pub const ANNOUNCED_VERSION: u32 = 6;

/// openvpn 2.6 is the floor; below that the events this daemon depends on are not all present.
pub const MIN_MANAGEMENT_VERSION: u32 = 5;
/// The first management version whose `version <n>` command answers. openvpn 2.6.19 (management
/// version 5) accepts the command and replies to nothing, so awaiting a reply there consumes the
/// command timeout and then tears down the channel.
pub const REPLY_BEARING_VERSION: u32 = 6;

#[derive(Debug, thiserror::Error)]
pub enum MgmtError {
    #[error("management socket I/O failed")]
    Io(#[from] std::io::Error),

    #[error("refusing to send a {bytes} byte line; openvpn discards over {MAX_LINE_BYTES}")]
    LineTooLong { bytes: usize },

    #[error("value contains a control character that would break line framing")]
    ForbiddenControlChar,

    #[error("invalid command verb")]
    InvalidVerb,

    #[error("no reply within {COMMAND_TIMEOUT:?}; the management channel is desynchronised")]
    Timeout,

    #[error("management socket closed")]
    Eof,

    #[error("management client is no longer running")]
    Closed,

    #[error("management interface version {found} is below the required {MIN_MANAGEMENT_VERSION}")]
    UnsupportedVersion { found: u32 },

    #[error("did not receive a parsable >INFO: greeting")]
    Greeting,

    #[error("management command rejected: {text}")]
    CommandFailed { text: String },

    #[error("tunnel up block carried no dev=; there is nothing to bind egress sockets to")]
    MissingDev,

    #[error("malformed challenge: {0}")]
    InvalidChallenge(&'static str),
}
