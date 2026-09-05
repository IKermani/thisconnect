// SPDX-License-Identifier: GPL-3.0-or-later

//! Console-user resolution via `SCDynamicStoreCopyConsoleUser` (SPEC.md 7.3).
//!
//! The call has three distinct outcomes and only one of them names a human:
//! a real short name at an active graphical session, the literal
//! `loginwindow` while nobody is logged in, and NULL on a headless or
//! SSH-only box. Collapsing the last two into "uid 0" or into whatever the
//! out-parameter happened to hold is how a login screen becomes an
//! authenticated peer, so they are modelled explicitly and denied.

use std::os::raw::c_void;

use core_foundation::base::TCFType;
use core_foundation::string::{CFString, CFStringRef};

/// Placeholder name reported while the login window owns the console.
const LOGIN_WINDOW_USER: &str = "loginwindow";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleUser {
    /// A human is logged in at the graphical console.
    LoggedIn { uid: u32 },
    /// Login window, fast-user-switching gap, or a headless/SSH-only session.
    None,
}

#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCDynamicStoreCopyConsoleUser(
        store: *const c_void,
        uid: *mut libc::uid_t,
        gid: *mut libc::gid_t,
    ) -> CFStringRef;
}

/// Interpretation of the raw call, split out so every branch is testable
/// without a display server.
pub fn classify(name: Option<&str>, uid: u32) -> ConsoleUser {
    match name {
        None => ConsoleUser::None,
        Some(name) if name.is_empty() || name == LOGIN_WINDOW_USER => ConsoleUser::None,
        // uid 0 is never a graphical console user; it is what the kernel
        // leaves in the out-parameter when it has nothing to report.
        Some(_) if uid == 0 => ConsoleUser::None,
        Some(_) => ConsoleUser::LoggedIn { uid },
    }
}

/// Who currently owns the graphical console, if anyone.
///
/// Infallible by construction: every failure mode of the underlying call is a
/// "nobody" answer, and the caller denies on it.
pub fn console_user() -> ConsoleUser {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    // SAFETY: a NULL store is documented as "create a transient one for this
    // call"; both out-parameters are live for the duration of the call. The
    // returned CFStringRef follows the Copy rule, so it is adopted below and
    // released exactly once when the CFString is dropped.
    let name_ref = unsafe { SCDynamicStoreCopyConsoleUser(std::ptr::null(), &mut uid, &mut gid) };

    if name_ref.is_null() {
        return classify(None, uid);
    }

    // SAFETY: non-NULL result of a Copy-rule function; we take ownership.
    let name = unsafe { CFString::wrap_under_create_rule(name_ref) }.to_string();
    classify(Some(&name), uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_result_is_no_console_user_not_uid_zero() {
        assert_eq!(classify(None, 0), ConsoleUser::None);
    }

    #[test]
    fn a_null_result_ignores_whatever_the_out_parameter_held() {
        assert_eq!(classify(None, 501), ConsoleUser::None);
    }

    #[test]
    fn the_login_window_is_not_a_console_user() {
        assert_eq!(classify(Some("loginwindow"), 0), ConsoleUser::None);
    }

    #[test]
    fn an_empty_name_is_not_a_console_user() {
        assert_eq!(classify(Some(""), 501), ConsoleUser::None);
    }

    #[test]
    fn a_named_user_with_uid_zero_is_not_treated_as_a_console_user() {
        assert_eq!(classify(Some("root"), 0), ConsoleUser::None);
    }

    #[test]
    fn a_logged_in_user_reports_its_uid() {
        assert_eq!(
            classify(Some("alice"), 501),
            ConsoleUser::LoggedIn { uid: 501 }
        );
    }

    #[test]
    fn querying_the_real_system_never_panics_and_yields_a_definite_answer() {
        // On CI and over SSH this is legitimately `None`; both arms are valid.
        let observed = console_user();

        assert!(matches!(
            observed,
            ConsoleUser::None | ConsoleUser::LoggedIn { .. }
        ));
    }
}
