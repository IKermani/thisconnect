// SPDX-License-Identifier: GPL-3.0-or-later

//! The `PF_ROUTE` edge trigger for tunnel policy re-assertion on macOS (SPEC.md §5.2).
//!
//! The Linux counterpart in [`super::netlink`] and this module answer the same question with
//! almost nothing in common. A routing socket has no multicast groups to join — it receives every
//! routing message on the host as soon as it is open — and its messages carry a four-byte prefix
//! rather than netlink's sixteen. What the two share is the discipline: read the message *type*
//! and nothing else, and let [`super::plan::reassert`] decide whether the policy still stands by
//! re-running the same read-back `Check`s that verified the install.
//!
//! Observed on macOS 26.6.2 (Darwin 25.6.0, arm64) with `route -n monitor`: deleting an
//! interface-scoped route emits `RTM_DELETE` on an unrelated listener's socket, carrying the pid
//! of the process that made the change. That pid is `/sbin/route`, not this daemon, because our
//! own mutations run through a child process — so a deletion we caused is indistinguishable from
//! one another VPN client caused, and filtering by pid is not available to us. Nothing needs it:
//! re-assertion is check-then-apply per step, teardown holds the `InstalledPolicy` guard across
//! itself, and `RTM_ADD` — which our own re-assertion emits — is deliberately not watched, so
//! there is no feedback loop.
//!
//! Every raw syscall for this platform lives in this file.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

use super::watch::Trigger;

/// The bytes every routing message begins with: `u_short msglen, u_char version, u_char type`.
///
/// Deliberately *not* `size_of::<rt_msghdr>()`. Route changes use `rt_msghdr` but address changes
/// use `ifa_msghdr`, which is far smaller and shares only this prefix; requiring the larger size
/// would silently discard every `RTM_DELADDR`. Four bytes is all this module ever reads, so four
/// bytes is what it requires.
const RT_MSGHDR_PREFIX: usize = 4;

/// A routing socket delivers one message per read, so this only has to hold the largest single
/// message. Undersizing it does not lose messages silently — the read fails and the failure is
/// treated as [`Trigger::Desynchronised`].
const READ_BUFFER: usize = 8192;

/// A routing socket that falls behind drops messages and reports `ENOBUFS`, so the receive buffer
/// is the real defence; the pessimistic path is the backstop.
const RECV_BUFFER_BYTES: libc::c_int = 1 << 20;

/// Deletions that could mean the scoped default route is gone. `RTM_DELETE` is the route itself —
/// the only policy macOS installs, since the kernel's refusal to fall back to the physical
/// interface *is* the fail-closed floor. `RTM_DELADDR` covers the utun address the scope is keyed
/// on.
///
/// `RTM_IFINFO` is deliberately absent: it fires on every Wi-Fi transition and would produce
/// steady churn without catching anything the periodic sweep does not already cover.
fn is_deletion(kind: u8) -> bool {
    // libc types these as c_int; rtm_type is a u_char on the wire.
    kind == libc::RTM_DELETE as u8 || kind == libc::RTM_DELADDR as u8
}

/// Walks a routing-socket read buffer looking only for a deletion we care about.
///
/// A message whose version is not `RTM_VERSION` stops the walk: the layout this reads is only
/// guaranteed for the version it was compiled against, and guessing past a version bump would
/// mean reading a type byte out of a structure that has moved. A malformed length stops it for
/// the same reason. Unlike netlink there is no alignment padding — each message is exactly
/// `msglen` bytes.
fn mentions_deletion(buffer: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + RT_MSGHDR_PREFIX <= buffer.len() {
        let Some(prefix) = buffer.get(offset..offset + RT_MSGHDR_PREFIX) else {
            return false;
        };
        let Ok(len_bytes) = <[u8; 2]>::try_from(&prefix[..2]) else {
            return false;
        };
        // Routing messages are host-endian on the wire.
        let len = u16::from_ne_bytes(len_bytes) as usize;
        let version = prefix[2];
        let kind = prefix[3];
        if len < RT_MSGHDR_PREFIX || offset + len > buffer.len() {
            return false;
        }
        if version != libc::RTM_VERSION as u8 {
            return false;
        }
        if is_deletion(kind) {
            return true;
        }
        offset += len;
    }
    false
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("could not open a PF_ROUTE socket")]
    Socket(#[source] io::Error),

    #[error("could not put the PF_ROUTE socket into non-blocking close-on-exec mode")]
    Configure(#[source] io::Error),
}

/// A subscription to the deletions that could take our policy down.
pub struct PolicyWatch {
    fd: AsyncFd<OwnedFd>,
}

impl PolicyWatch {
    pub fn open() -> Result<Self, WatchError> {
        let fd = open_route_socket()?;
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
            match guard.try_io(|inner| read(inner.get_ref(), &mut buffer)) {
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

fn open_route_socket() -> Result<OwnedFd, WatchError> {
    // SAFETY: socket(2) with constant arguments has no preconditions and returns an owned fd or
    // -1. The descriptor is handed to OwnedFd immediately, so it is closed exactly once.
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if raw < 0 {
        return Err(WatchError::Socket(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a fresh descriptor this function owns and never uses again.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Darwin's socket(2) does not accept SOCK_CLOEXEC or SOCK_NONBLOCK in the type argument —
    // those are Linux extensions — so both have to be set afterwards. Close-on-exec matters
    // because this daemon spawns `openvpn` and `/sbin/route`; leaking a routing socket into
    // either is needless authority in a child process.
    set_flag(&fd, libc::F_SETFD, libc::FD_CLOEXEC)?;
    set_flag(&fd, libc::F_SETFL, libc::O_NONBLOCK)?;
    Ok(fd)
}

/// `fcntl(2)`'s `F_SETFD`/`F_SETFL` replace the whole flag word, so the current value is read
/// first and the new bit added to it. Overwriting it outright would clear flags the runtime set.
fn set_flag(fd: &OwnedFd, set_cmd: libc::c_int, flag: libc::c_int) -> Result<(), WatchError> {
    let get_cmd = if set_cmd == libc::F_SETFD {
        libc::F_GETFD
    } else {
        libc::F_GETFL
    };
    // SAFETY: `fd` is open for the duration of the call and both commands take no argument.
    let current = unsafe { libc::fcntl(fd.as_raw_fd(), get_cmd) };
    if current < 0 {
        return Err(WatchError::Configure(io::Error::last_os_error()));
    }
    // SAFETY: `fd` is open for the duration of the call and both commands take an int argument.
    let outcome = unsafe { libc::fcntl(fd.as_raw_fd(), set_cmd, current | flag) };
    if outcome < 0 {
        return Err(WatchError::Configure(io::Error::last_os_error()));
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
            "could not enlarge the PF_ROUTE receive buffer; ENOBUFS will be handled by re-asserting"
        );
    }
}

fn read(fd: &OwnedFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` is a valid mutable slice and the length passed is its own length; `fd` is
    // open for the duration of the call.
    let count = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    // count >= 0 here (negative already returned above), and a non-negative ssize_t always fits
    // usize on every target this daemon builds for.
    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// One routing message: the four-byte prefix followed by `payload` bytes. Routing messages
    /// carry no alignment padding, so the message is exactly `len` bytes.
    fn message(kind: u8, payload: usize) -> Vec<u8> {
        message_versioned(kind, payload, libc::RTM_VERSION as u8)
    }

    fn message_versioned(kind: u8, payload: usize, version: u8) -> Vec<u8> {
        let len = RT_MSGHDR_PREFIX + payload;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        bytes.push(version);
        bytes.push(kind);
        bytes.resize(len, 0);
        bytes
    }

    #[test]
    fn sees_each_deletion_we_watch_for() {
        for kind in [libc::RTM_DELETE as u8, libc::RTM_DELADDR as u8] {
            assert!(
                mentions_deletion(&message(kind, 132)),
                "type {kind} must trigger a re-assertion"
            );
        }
    }

    #[test]
    fn ignores_the_additions_our_own_reassertion_emits() {
        // Watching RTM_ADD would make every re-assertion wake the watchdog that caused it.
        for kind in [
            libc::RTM_ADD as u8,
            libc::RTM_NEWADDR as u8,
            libc::RTM_GET as u8,
        ] {
            assert!(
                !mentions_deletion(&message(kind, 132)),
                "type {kind} must not trigger a re-assertion"
            );
        }
    }

    #[test]
    fn accepts_the_smaller_header_an_address_deletion_uses() {
        // RTM_DELADDR carries an ifa_msghdr, which is far smaller than the rt_msghdr a route
        // change uses. Requiring the larger size would discard every address deletion.
        let ifa_msghdr_payload = std::mem::size_of::<libc::ifa_msghdr>() - RT_MSGHDR_PREFIX;

        assert!(mentions_deletion(&message(
            libc::RTM_DELADDR as u8,
            ifa_msghdr_payload
        )));
        assert!(
            std::mem::size_of::<libc::ifa_msghdr>() < std::mem::size_of::<libc::rt_msghdr>(),
            "the premise of this test is that ifa_msghdr is the smaller of the two"
        );
    }

    #[test]
    fn finds_a_deletion_behind_other_messages_in_one_read() {
        let mut buffer = message(libc::RTM_ADD as u8, 132);
        buffer.extend_from_slice(&message(libc::RTM_NEWADDR as u8, 20));
        buffer.extend_from_slice(&message(libc::RTM_DELETE as u8, 132));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn walks_by_exact_length_with_no_alignment_padding() {
        // Netlink rounds every message up to a 4-byte boundary; PF_ROUTE does not. Applying
        // netlink's NLMSG_ALIGN here would read the next header at the wrong offset.
        let mut buffer = message(libc::RTM_ADD as u8, 13);
        buffer.extend_from_slice(&message(libc::RTM_DELETE as u8, 20));

        assert!(mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_reading_past_a_truncated_message() {
        let mut buffer = message(libc::RTM_ADD as u8, 132);
        buffer.truncate(20);

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn stops_rather_than_spinning_on_a_length_below_the_prefix() {
        // A zero length would otherwise advance the offset by nothing, forever.
        let mut buffer = vec![0u8; RT_MSGHDR_PREFIX];
        buffer.extend_from_slice(&message(libc::RTM_DELETE as u8, 132));

        assert!(!mentions_deletion(&buffer));
    }

    #[test]
    fn refuses_a_message_whose_version_it_was_not_compiled_against() {
        // The type byte's position is only guaranteed for the version we know; reading it out of
        // a structure that has moved is how a watcher silently stops watching.
        let bumped = libc::RTM_VERSION as u8 + 1;

        assert!(!mentions_deletion(&message_versioned(
            libc::RTM_DELETE as u8,
            132,
            bumped
        )));
    }

    #[test]
    fn treats_an_empty_read_as_nothing_to_do() {
        assert!(!mentions_deletion(&[]));
    }

    /// Unprivileged processes may open a routing socket — `route -n monitor` does exactly this —
    /// so this must pass without any capability. It is the only check that the socket is opened
    /// and configured the way Darwin actually requires rather than the way Linux would.
    #[tokio::test]
    async fn opens_a_route_socket_without_privilege() {
        assert!(
            PolicyWatch::open().is_ok(),
            "the daemon must be able to watch PF_ROUTE without extra privilege"
        );
    }
}
