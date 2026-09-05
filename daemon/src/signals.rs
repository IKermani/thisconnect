// SPDX-License-Identifier: GPL-3.0-or-later

//! SIGTERM/SIGINT handling for graceful shutdown.
//!
//! `tokio::signal` is gated behind a feature this crate does not enable, so the
//! classic self-pipe is used instead: the handler does nothing but write one
//! async-signal-safe byte, and an ordinary thread turns that byte into a
//! shutdown broadcast.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::sync::watch;

/// Write end of the self-pipe. `-1` means "no handler installed yet", which is
/// the state the handler must tolerate if a signal races installation.
static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);

const NO_PIPE: RawFd = -1;

#[cfg(target_os = "macos")]
// SAFETY: `__error` is the libc-provided accessor for this thread's errno slot.
unsafe fn errno_slot() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

#[cfg(not(target_os = "macos"))]
// SAFETY: `__errno_location` is the libc-provided accessor for this thread's errno slot.
unsafe fn errno_slot() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

/// Signal handler. Only async-signal-safe calls, and errno is restored so the
/// interrupted code still sees its own error state.
extern "C" fn handle_signal(signum: libc::c_int) {
    let fd = SIGNAL_PIPE.load(Ordering::Relaxed);
    if fd == NO_PIPE {
        return;
    }
    // SAFETY: `errno_slot` returns a valid pointer for the current thread, and
    // `write` is async-signal-safe. The byte written is the signal number, read
    // by the shutdown thread purely as a wake-up.
    unsafe {
        let errno = errno_slot();
        let saved = *errno;
        let byte = signum as u8;
        libc::write(fd, std::ptr::addr_of!(byte).cast::<libc::c_void>(), 1);
        *errno = saved;
    }
}

fn install_handler(signum: libc::c_int) -> io::Result<()> {
    // SAFETY: `action` is a fully initialised `sigaction` naming an
    // `extern "C"` handler with the correct signature; `sigaction` with a null
    // old-action pointer is defined behaviour.
    let rc = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let handler: extern "C" fn(libc::c_int) = handle_signal;
        action.sa_sigaction = handler as usize;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask));
        libc::sigaction(signum, std::ptr::addr_of!(action), std::ptr::null_mut())
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [NO_PIPE; 2];
    // SAFETY: `fds` is a two-element array, exactly what `pipe` writes into.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in fds {
        // SAFETY: `fd` is a live descriptor we own; setting FD_CLOEXEC keeps the
        // pipe out of the spawned openvpn child.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok((fds[0], fds[1]))
}

/// Install handlers for SIGTERM and SIGINT and flip `shutdown` when one arrives.
///
/// Called once; a second call would leak the previous pipe's write end.
pub fn install(shutdown: watch::Sender<bool>) -> io::Result<()> {
    let (read_fd, write_fd) = create_pipe()?;
    SIGNAL_PIPE.store(write_fd, Ordering::SeqCst);

    install_handler(libc::SIGTERM)?;
    install_handler(libc::SIGINT)?;

    std::thread::Builder::new()
        .name("signal-wait".to_owned())
        .spawn(move || {
            wait_for_signal(read_fd);
            // A closed receiver means the server already stopped on its own.
            let _ = shutdown.send(true);
        })?;
    Ok(())
}

fn wait_for_signal(read_fd: RawFd) {
    let mut byte = 0u8;
    loop {
        // SAFETY: `read_fd` is the pipe's read end, owned by this thread, and
        // the buffer is exactly one byte long.
        let n = unsafe {
            libc::read(
                read_fd,
                std::ptr::addr_of_mut!(byte).cast::<libc::c_void>(),
                1,
            )
        };
        if n == 1 {
            return;
        }
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        // EOF or a hard error: nothing will ever wake this thread again, and a
        // silent hang would mean SIGTERM never stops the daemon.
        return;
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_arriving_before_installation_is_ignored_rather_than_writing_to_a_stale_fd() {
        SIGNAL_PIPE.store(NO_PIPE, Ordering::SeqCst);

        handle_signal(libc::SIGTERM);
        // Reaching here without a crash is the assertion: no write was attempted.
        assert_eq!(SIGNAL_PIPE.load(Ordering::SeqCst), NO_PIPE);
    }

    #[test]
    fn sigterm_flips_the_shutdown_flag() {
        let (tx, mut rx) = watch::channel(false);
        install(tx).expect("install handlers");

        // SAFETY: raising a signal in our own process is defined behaviour.
        let rc = unsafe { libc::raise(libc::SIGTERM) };
        assert_eq!(rc, 0);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !*rx.borrow_and_update() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(*rx.borrow());
    }
}
