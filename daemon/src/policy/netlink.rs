// SPDX-License-Identifier: GPL-3.0-or-later

//! The netlink edge trigger for tunnel policy re-assertion (SPEC.md §5.2).
//!
//! This module deliberately does not understand netlink. It reads `nlmsg_type` out of the fixed
//! 16-byte header and nothing else: no attributes, no addresses, no rule priorities. What decides
//! whether the policy still stands is [`super::plan::reassert`], which re-runs the same read-back
//! `Check`s that verified the install — assertions four distributions have already exercised. A
//! parser we do not write cannot be wrong about a message that decides whether traffic leaks,
//! which is why there is no netlink crate here.
//!
//! Every raw syscall in this change lives in this file.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

/// `sizeof(struct nlmsghdr)`: u32 len, u16 type, u16 flags, u32 seq, u32 pid.
const NLMSG_HDRLEN: usize = 16;

/// Big enough that a burst of rule deletions arrives in one read. Undersizing this does not lose
/// messages — the kernel reports `ENOBUFS` and we re-assert pessimistically — but it makes the
/// common case take several wakeups.
const READ_BUFFER: usize = 8192;

/// The kernel drops messages rather than blocking when a listener falls behind, so the receive
/// buffer is the real defence against `ENOBUFS`; the pessimistic path is the backstop.
const RECV_BUFFER_BYTES: libc::c_int = 1 << 20;

/// Deletions in any of these mean our policy may no longer be installed. Rules cover both the
/// policy rule and the backstop; routes cover the floor and the tunnel route; addresses cover
/// the tun address the whole policy is keyed on. Both families throughout.
const GROUPS: [libc::c_uint; 6] = [
    libc::RTNLGRP_IPV4_RULE,
    libc::RTNLGRP_IPV6_RULE,
    libc::RTNLGRP_IPV4_ROUTE,
    libc::RTNLGRP_IPV6_ROUTE,
    libc::RTNLGRP_IPV4_IFADDR,
    libc::RTNLGRP_IPV6_IFADDR,
];

/// Why the watchdog woke up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// An `RTM_DEL*` arrived in a group we watch.
    Deletion,
    /// The kernel dropped messages (`ENOBUFS`) or the socket errored. We cannot know what was
    /// missed, so the only safe reading is that it was the deletion we exist to catch.
    Desynchronised,
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Walks a netlink read buffer looking only for a deletion we care about.
///
/// A malformed or truncated header stops the walk rather than being skipped: an attacker cannot
/// reach this socket, so a bad length means a bug, and continuing past one would mean reading
/// `nlmsg_type` out of arbitrary offsets.
fn mentions_deletion(buffer: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + NLMSG_HDRLEN <= buffer.len() {
        let Some(header) = buffer.get(offset..offset + NLMSG_HDRLEN) else {
            return false;
        };
        let (len_bytes, rest) = header.split_at(4);
        let Ok(len_bytes) = <[u8; 4]>::try_from(len_bytes) else {
            return false;
        };
        let Ok(kind_bytes) = <[u8; 2]>::try_from(&rest[..2]) else {
            return false;
        };
        // Netlink is host-endian on the wire.
        let len = u32::from_ne_bytes(len_bytes) as usize;
        let kind = u16::from_ne_bytes(kind_bytes);
        if len < NLMSG_HDRLEN || offset + len > buffer.len() {
            return false;
        }
        if matches!(
            kind,
            libc::RTM_DELRULE | libc::RTM_DELROUTE | libc::RTM_DELADDR
        ) {
            return true;
        }
        offset += nlmsg_align(len);
    }
    false
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("could not open a netlink route socket")]
    Socket(#[source] io::Error),

    #[error("could not join netlink multicast group {group}")]
    Register {
        group: libc::c_uint,
        #[source]
        source: io::Error,
    },
}

/// A subscription to the deletions that could take our policy down.
pub struct PolicyWatch {
    fd: AsyncFd<OwnedFd>,
}

impl PolicyWatch {
    pub fn open() -> Result<Self, WatchError> {
        let fd = open_netlink_socket()?;
        for group in GROUPS {
            join_group(&fd, group)?;
        }
        set_receive_buffer(&fd);
        AsyncFd::new(fd)
            .map(|fd| Self { fd })
            .map_err(WatchError::Socket)
    }

    /// Resolves the moment something happened that could have removed our policy. Returns
    /// [`Trigger::Desynchronised`] rather than an error on *any* socket trouble: a watchdog that
    /// stops watching because it could not read is the failure this module exists to prevent, so
    /// every uncertain outcome resolves toward re-asserting.
    pub async fn next(&self) -> Trigger {
        let mut buffer = [0u8; READ_BUFFER];
        loop {
            let Ok(mut guard) = self.fd.readable().await else {
                return Trigger::Desynchronised;
            };
            match guard.try_io(|inner| recv(inner.get_ref(), &mut buffer)) {
                // Spurious readiness: the guard has cleared it, so wait again.
                Err(_would_block) => continue,
                Ok(Ok(read)) => match buffer.get(..read) {
                    Some(message) if mentions_deletion(message) => return Trigger::Deletion,
                    _ => continue,
                },
                Ok(Err(_)) => return Trigger::Desynchronised,
            }
        }
    }
}

fn open_netlink_socket() -> Result<OwnedFd, WatchError> {
    // SAFETY: socket(2) with constant arguments has no preconditions and returns an owned fd or
    // -1. The descriptor is handed to OwnedFd immediately, so it is closed exactly once.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(WatchError::Socket(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh descriptor this function owns and never uses again.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // nl_pid 0 asks the kernel to assign a unique port id, which is what lets more than one
    // netlink listener exist in a process. Groups are joined by setsockopt rather than through
    // nl_groups: the bitmask cannot express a group above 32, and RTNLGRP numbering has already
    // passed that once.
    //
    // SAFETY: sockaddr_nl is a plain-old-data struct with no invalid bit pattern, and libc 0.2.189
    // keeps its padding field private, so a field literal cannot be built; zeroing then setting
    // the fields we care about is the only way to construct it.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    // SAFETY: `address` is a fully initialised sockaddr_nl and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let bound = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(address).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(WatchError::Socket(io::Error::last_os_error()));
    }
    Ok(fd)
}

fn join_group(fd: &OwnedFd, group: libc::c_uint) -> Result<(), WatchError> {
    // SAFETY: the option value is a single initialised c_uint and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let joined = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_NETLINK,
            libc::NETLINK_ADD_MEMBERSHIP,
            std::ptr::addr_of!(group).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if joined < 0 {
        return Err(WatchError::Register {
            group,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Best effort by design. A kernel that refuses the size still delivers messages; it only makes
/// `ENOBUFS` likelier, and that path is already handled pessimistically.
fn set_receive_buffer(fd: &OwnedFd) {
    let size = RECV_BUFFER_BYTES;
    // SAFETY: the option value is a single initialised c_int and the length passed is its own
    // size; `fd` is open for the duration of the call.
    let outcome = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if outcome < 0 {
        tracing::debug!(
            error = %io::Error::last_os_error(),
            "could not enlarge the netlink receive buffer; ENOBUFS will be handled by re-asserting"
        );
    }
}

fn recv(fd: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is a valid mutable slice and the length passed is its own length; `fd` is
    // open for the duration of the call.
    let read = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    // A non-negative ssize_t always fits usize on every target this daemon builds for.
    Ok(read.max(0) as usize)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// One netlink message: a 16-byte header with `payload` bytes after it.
    fn message(kind: u16, payload: usize) -> Vec<u8> {
        let len = NLMSG_HDRLEN + payload;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(len as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // flags
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // seq
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // pid
        bytes.resize(nlmsg_align(len), 0);
        bytes
    }

    #[test]
    fn sees_each_deletion_we_watch_for() {
        for kind in [libc::RTM_DELRULE, libc::RTM_DELROUTE, libc::RTM_DELADDR] {
            assert!(
                mentions_deletion(&message(kind, 24)),
                "type {kind} must trigger a re-assertion"
            );
        }
    }

    #[test]
    fn ignores_messages_that_are_not_deletions() {
        for kind in [libc::RTM_NEWRULE, libc::RTM_NEWROUTE, libc::RTM_NEWADDR] {
            assert!(
                !mentions_deletion(&message(kind, 24)),
                "type {kind} must not trigger a re-assertion"
            );
        }
    }

    #[test]
    fn finds_a_deletion_behind_other_messages_in_one_read() {
        // The realistic shape: a burst arrives in a single recv, and the interesting message
        // is not the first one.
        let mut buffer = message(libc::RTM_NEWROUTE, 40);
        buffer.extend_from_slice(&message(libc::RTM_NEWADDR, 12));
        buffer.extend_from_slice(&message(libc::RTM_DELRULE, 20));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn walks_past_a_payload_that_is_not_a_multiple_of_four() {
        // NLMSG_ALIGN pads to 4; getting this wrong reads the next header at the wrong offset
        // and silently stops seeing every message after the first odd-sized one.
        let mut buffer = message(libc::RTM_NEWROUTE, 13);
        buffer.extend_from_slice(&message(libc::RTM_DELROUTE, 20));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_reading_past_a_truncated_message() {
        let mut buffer = message(libc::RTM_NEWROUTE, 64);
        buffer.truncate(20);

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_spinning_on_a_length_below_the_header() {
        // A zero length would otherwise advance the offset by nothing, forever.
        let mut buffer = vec![0u8; NLMSG_HDRLEN];
        buffer.extend_from_slice(&message(libc::RTM_DELRULE, 8));

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn treats_an_empty_read_as_nothing_to_do() {
        assert!(!mentions_deletion(&[]));
    }

    /// Unprivileged processes may open NETLINK_ROUTE and join these groups, so this must pass
    /// without any capability. It is the only check that the six group registrations are
    /// actually accepted rather than silently wrong.
    ///
    /// `#[tokio::test]` rather than the brief's bare `#[test]`: `PolicyWatch::open` registers the
    /// fd with `AsyncFd`, which requires a running reactor, not just this thread's privilege.
    #[tokio::test]
    async fn opens_and_joins_every_group_without_privilege() {
        assert!(
            PolicyWatch::open().is_ok(),
            "the daemon must be able to watch netlink without extra privilege"
        );
    }

    /// Needs CAP_NET_ADMIN and a network namespace of its own; run by
    /// `scripts/verify-egress-linux.sh --watcher`. A unit test cannot establish anything about
    /// netlink delivery, so this one drives a real socket and a real deletion.
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN in a private netns"]
    async fn a_real_rule_deletion_wakes_the_watch() {
        let watch = PolicyWatch::open().expect("netlink socket");

        let add = std::process::Command::new("ip")
            .args([
                "rule",
                "add",
                "from",
                "10.255.255.9/32",
                "lookup",
                "219",
                "priority",
                "18999",
            ])
            .status()
            .expect("ip rule add");
        assert!(
            add.success(),
            "could not install the rule this test deletes"
        );

        let deleted = std::process::Command::new("ip")
            .args(["rule", "del", "priority", "18999"])
            .status()
            .expect("ip rule del");
        assert!(deleted.success(), "could not delete the rule");

        let trigger = tokio::time::timeout(std::time::Duration::from_secs(5), watch.next())
            .await
            .expect("the watch did not wake within 5s of a real rule deletion");
        assert_eq!(trigger, Trigger::Deletion);
    }
}
