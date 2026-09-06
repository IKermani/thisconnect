// SPDX-License-Identifier: GPL-3.0-or-later

//! What woke the policy watchdog, independent of how the kernel told us.
//!
//! Linux reports deletions over netlink and macOS over `PF_ROUTE`; the two sockets share no
//! constants, no message layout and no subscription model, but they answer the same question,
//! so the answer lives here rather than being defined twice and drifting.

/// Why the watchdog woke up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// A deletion arrived that could have removed part of the tunnel policy.
    Deletion,
    /// The kernel dropped messages (`ENOBUFS`) or the socket errored. We cannot know what was
    /// missed, so the only safe reading is that it was the deletion we exist to catch.
    Desynchronised,
}
