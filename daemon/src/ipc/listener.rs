// SPDX-License-Identifier: GPL-3.0-or-later

//! Control-socket acquisition (SPEC.md 7.1, 7.2).
//!
//! Socket activation is preferred on both platforms because it removes the
//! `bind()` → `chmod()` TOCTOU window and the stale-socket cleanup entirely: the
//! init system creates the socket with the right owner and mode before we run.

use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::net::UnixListener;

/// The first descriptor systemd passes is always 3 (`SD_LISTEN_FDS_START`).
const SD_LISTEN_FDS_START: RawFd = 3;

/// `Sockets` key in the launchd plist. Must match packaging/macos.
#[allow(dead_code)] // macOS-only socket activation
pub const LAUNCHD_SOCKET_NAME: &str = "Listener";

/// 0666 on macOS is deliberate, not sloppy: group `wheel` holds only root and
/// Darwin enforces permissions on AF_UNIX `connect()`, so 0660 would make the
/// GUI unable to connect at all. Security comes from peer authentication.
#[cfg(all(target_os = "macos", not(feature = "dev-insecure-ipc")))]
pub const DEFAULT_SOCKET_MODE: u32 = 0o666;
/// Linux gates `connect()` on membership of the `thisconnect` group.
#[cfg(all(not(target_os = "macos"), not(feature = "dev-insecure-ipc")))]
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;
/// Relaxed peer authentication is only safe behind an owner-only socket.
#[cfg(feature = "dev-insecure-ipc")]
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

#[derive(Debug, Error)]
pub enum ListenerError {
    #[error("{op} failed: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("{0} exists and is not a socket; refusing to unlink it")]
    PathOccupied(PathBuf),

    #[allow(dead_code)] // macOS-only socket activation
    #[error("launch_activate_socket({name}) returned {status}")]
    LaunchActivate { name: String, status: i32 },

    #[allow(dead_code)] // macOS-only socket activation
    #[error("expected exactly one activated socket, got {0}")]
    SocketCount(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketSource {
    Systemd,
    #[allow(dead_code)] // macOS-only socket activation
    Launchd,
    /// Fallback path: we created the socket ourselves and chmod'ed it after
    /// `bind()`. The window between the two is why activation is preferred.
    SelfBound,
}

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub path: PathBuf,
    pub mode: u32,
}

impl ListenerConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: DEFAULT_SOCKET_MODE,
        }
    }
}

/// Decide whether the descriptors in the environment are ours.
///
/// A `LISTEN_PID` that is not our pid means the variables were inherited by a
/// child, and adopting fd 3 in that case would hijack an unrelated descriptor.
fn systemd_fd(listen_pid: Option<&str>, listen_fds: Option<&str>, our_pid: i32) -> Option<RawFd> {
    let pid: i32 = listen_pid?.parse().ok()?;
    if pid != our_pid {
        return None;
    }
    let count: i32 = listen_fds?.parse().ok()?;
    (count == 1).then_some(SD_LISTEN_FDS_START)
}

fn take_systemd_fd() -> Option<RawFd> {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    // SAFETY of adoption below rests on this: the variables are removed so a
    // second call cannot hand out the same descriptor twice, and so a spawned
    // openvpn child never inherits them.
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");

    // SAFETY: reading our own pid has no preconditions.
    let our_pid = unsafe { libc::getpid() };
    systemd_fd(listen_pid.as_deref(), listen_fds.as_deref(), our_pid)
}

#[cfg(target_os = "macos")]
extern "C" {
    /// Public SDK since 10.10, not deprecated. `fds` is allocated by the callee
    /// and must be released with `free(3)`.
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        count: *mut libc::size_t,
    ) -> libc::c_int;
}

#[cfg(target_os = "macos")]
fn take_launchd_fd(name: &str) -> Result<RawFd, ListenerError> {
    let c_name = std::ffi::CString::new(name).map_err(|_| ListenerError::LaunchActivate {
        name: name.to_owned(),
        status: libc::EINVAL,
    })?;
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count: libc::size_t = 0;

    // SAFETY: `c_name` is a valid NUL-terminated string that outlives the call,
    // and `fds`/`count` are valid out-parameters. On success launchd allocates
    // the array and we own it until the `free` below.
    let status = unsafe { launch_activate_socket(c_name.as_ptr(), &mut fds, &mut count) };
    if status != 0 {
        return Err(ListenerError::LaunchActivate {
            name: name.to_owned(),
            status,
        });
    }

    // SAFETY: on a zero status launchd guarantees `fds` points to `count`
    // descriptors. We read them before freeing the array, and only the array is
    // freed — the descriptors stay open and become ours.
    let result = unsafe {
        let fds_slice = std::slice::from_raw_parts(fds, count);
        let first = fds_slice.first().copied();
        libc::free(fds.cast::<libc::c_void>());
        first
    };

    match (result, count) {
        (Some(fd), 1) => Ok(fd),
        (_, n) => Err(ListenerError::SocketCount(n)),
    }
}

/// Adopt an already-listening descriptor handed to us by the init system.
fn adopt(fd: RawFd) -> Result<UnixListener, ListenerError> {
    // SAFETY: the fd was handed to us by systemd or launchd, is a listening
    // AF_UNIX socket, and is adopted exactly once — the environment variables
    // that name it are cleared, and launchd's array is consumed in one call.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Io {
            op: "set_nonblocking",
            source,
        })?;
    UnixListener::from_std(std_listener).map_err(|source| ListenerError::Io {
        op: "UnixListener::from_std",
        source,
    })
}

/// Remove a leftover socket file, but never anything that is not a socket.
fn clear_stale_socket(path: &Path) -> Result<(), ListenerError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ListenerError::Io {
                op: "symlink_metadata",
                source,
            })
        }
    };
    if !metadata.file_type().is_socket() {
        return Err(ListenerError::PathOccupied(path.to_path_buf()));
    }
    std::fs::remove_file(path).map_err(|source| ListenerError::Io {
        op: "remove stale socket",
        source,
    })
}

pub fn bind_fallback(config: &ListenerConfig) -> Result<UnixListener, ListenerError> {
    clear_stale_socket(&config.path)?;
    let listener = UnixListener::bind(&config.path)
        .map_err(|source| ListenerError::Io { op: "bind", source })?;
    std::fs::set_permissions(&config.path, std::fs::Permissions::from_mode(config.mode)).map_err(
        |source| ListenerError::Io {
            op: "chmod socket",
            source,
        },
    )?;
    Ok(listener)
}

/// Preference order: systemd → launchd → self-bound.
pub fn acquire(config: &ListenerConfig) -> Result<(UnixListener, SocketSource), ListenerError> {
    if let Some(fd) = take_systemd_fd() {
        return Ok((adopt(fd)?, SocketSource::Systemd));
    }

    #[cfg(target_os = "macos")]
    if let Ok(fd) = take_launchd_fd(LAUNCHD_SOCKET_NAME) {
        return Ok((adopt(fd)?, SocketSource::Launchd));
    }

    Ok((bind_fallback(config)?, SocketSource::SelfBound))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> PathBuf {
        // SAFETY: reading our own pid has no preconditions.
        let pid = unsafe { libc::getpid() };
        std::env::temp_dir().join(format!("thisconnect-test-{pid}-{name}"))
    }

    #[test]
    fn adopts_fd_three_when_systemd_addressed_this_process() {
        assert_eq!(systemd_fd(Some("42"), Some("1"), 42), Some(3));
    }

    #[test]
    fn ignores_activation_variables_addressed_to_another_pid() {
        assert_eq!(systemd_fd(Some("41"), Some("1"), 42), None);
    }

    #[test]
    fn ignores_activation_variables_offering_more_than_one_socket() {
        assert_eq!(systemd_fd(Some("42"), Some("2"), 42), None);
    }

    #[test]
    fn ignores_a_malformed_listen_fds_value() {
        assert_eq!(systemd_fd(Some("42"), Some("one"), 42), None);
    }

    #[test]
    fn ignores_a_missing_listen_pid() {
        assert_eq!(systemd_fd(None, Some("1"), 42), None);
    }

    #[tokio::test]
    async fn self_bound_socket_gets_the_configured_mode() {
        let path = scratch_path("mode.sock");
        let _ = std::fs::remove_file(&path);
        let config = ListenerConfig {
            path: path.clone(),
            mode: 0o600,
        };

        let listener = bind_fallback(&config).expect("bind");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn replaces_a_stale_socket_left_by_a_crashed_daemon() {
        let path = scratch_path("stale.sock");
        let _ = std::fs::remove_file(&path);
        let config = ListenerConfig::new(path.clone());
        let first = bind_fallback(&config).expect("first bind");
        drop(first);

        let second = bind_fallback(&config);

        assert!(second.is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_to_unlink_a_regular_file_standing_where_the_socket_belongs() {
        let path = scratch_path("regular.file");
        std::fs::write(&path, b"not a socket").expect("write");

        let result = clear_stale_socket(&path);

        assert!(matches!(result, Err(ListenerError::PathOccupied(_))));
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn default_mode_is_owner_only_in_dev_builds_and_group_reachable_otherwise() {
        if cfg!(feature = "dev-insecure-ipc") {
            assert_eq!(DEFAULT_SOCKET_MODE, 0o600);
        } else if cfg!(target_os = "macos") {
            assert_eq!(DEFAULT_SOCKET_MODE, 0o666);
        } else {
            assert_eq!(DEFAULT_SOCKET_MODE, 0o660);
        }
    }
}
