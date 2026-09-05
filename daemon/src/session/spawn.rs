// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolving the `openvpn` binary and building its argument vector (SPEC.md §4.1),
//! plus the process seam the connect path is tested against.
//!
//! Only `--config` and daemon-owned flags are ever passed. Rebuilding the whole
//! configuration on the command line would put the management socket path and
//! inline key material into world-readable `ps` output.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use super::SessionError;

/// Where a packaged `openvpn` lives on the platforms we support. Searched after
/// `PATH`, because a user who put a specific build first meant it.
pub const CANDIDATE_DIRS: &[&str] = &[
    "/opt/homebrew/sbin",
    "/opt/homebrew/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
];

const BINARY: &str = "openvpn";

/// Resolve the binary at runtime. Hardcoding `/usr/sbin/openvpn` breaks every
/// Homebrew and Nix install; an explicit configured path always wins.
pub fn resolve_openvpn(configured: Option<&Path>) -> Result<PathBuf, SessionError> {
    if let Some(path) = configured {
        if !path.is_absolute() {
            return Err(SessionError::OpenvpnNotFound {
                detail: format!("{} is not an absolute path", path.display()),
            });
        }
        return is_executable_file(path)
            .then(|| path.to_path_buf())
            .ok_or_else(|| SessionError::OpenvpnNotFound {
                detail: format!("{} is not an executable file", path.display()),
            });
    }

    path_dirs()
        .chain(CANDIDATE_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join(BINARY))
        .find(|candidate| is_executable_file(candidate))
        .ok_or_else(|| SessionError::OpenvpnNotFound {
            detail: format!("no {BINARY} on PATH or in {CANDIDATE_DIRS:?}"),
        })
}

fn path_dirs() -> impl Iterator<Item = PathBuf> {
    std::env::var_os("PATH")
        .map(|raw| std::env::split_paths(&raw).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter(|dir| dir.is_absolute())
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// What the resolved `openvpn` accepts. Options that do not exist on every supported release
/// cannot simply be passed: openvpn rejects an unknown option and exits before it connects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenvpnCapabilities {
    /// `--dns-updown` exists from 2.7. On 2.6 there is no built-in dns-updown handler to disable,
    /// so omitting it there loses nothing — but the flag is a security control, so the default is
    /// to pass it and only positive proof of rejection takes it away.
    pub dns_updown: bool,
}

impl Default for OpenvpnCapabilities {
    fn default() -> Self {
        Self { dns_updown: true }
    }
}

/// openvpn names the option it could not parse, so asking it to parse the option and print its
/// version answers the question directly. This is deliberately not a version comparison: a distro
/// that backports `--dns-updown` into a 2.6 build would still get the security control, where a
/// version test would silently drop it.
///
/// Every ambiguous outcome — probe failed to run, unreadable output, some other error — keeps the
/// capability enabled, because the failure that matters is dropping the flag on a release whose
/// built-in handler runs as root.
pub fn detect_capabilities(program: &Path) -> OpenvpnCapabilities {
    OpenvpnCapabilities {
        dns_updown: probe_accepts(program, &["--dns-updown", "disable"], "dns-updown"),
    }
}

fn probe_accepts(program: &Path, args: &[&str], option: &str) -> bool {
    let output = std::process::Command::new(program)
        .args(args)
        .arg("--version")
        .stdin(Stdio::null())
        .output();
    let Ok(output) = output else {
        warn!(
            option,
            "could not probe openvpn for option support; assuming it is supported"
        );
        return true;
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    !rejects_option(&text, option)
}

/// `Options error: Unrecognized option or missing or extra parameter(s) in [CMD-LINE]:1: <option>`
fn rejects_option(output: &str, option: &str) -> bool {
    output
        .lines()
        .any(|line| line.contains("Unrecognized option") && line.contains(option))
}

/// The daemon-injected flags, appended last.
///
/// Order matters: `script_security_set()` is applied per occurrence in parse
/// order and last-wins, so a profile that somehow carried a `script-security`
/// line could not raise ours. `--route-nopull` is deliberately absent — it
/// suppresses pushed DNS too and makes leak-free resolution impossible.
pub fn build_args(
    config: &Path,
    socket: &Path,
    capabilities: OpenvpnCapabilities,
) -> Result<Vec<String>, SessionError> {
    let config = utf8(config)?;
    let socket = utf8(socket)?;
    let mut args: Vec<String> = vec![
        "--config".into(),
        config,
        "--management".into(),
        socket,
        "unix".into(),
        "--management-client".into(),
        "--management-hold".into(),
        "--management-query-passwords".into(),
        "--management-up-down".into(),
        "--script-security".into(),
        "1".into(),
        "--pull-filter".into(),
        "ignore".into(),
        "route".into(),
        "--pull-filter".into(),
        "ignore".into(),
        "redirect-gateway".into(),
        "--route-noexec".into(),
    ];
    if capabilities.dns_updown {
        args.push("--dns-updown".into());
        args.push("disable".into());
    }
    args.extend([
        "--allow-compression".to_owned(),
        "no".to_owned(),
        "--auth-retry".to_owned(),
        "interact".to_owned(),
        "--auth-nocache".to_owned(),
        "--verb".to_owned(),
        "3".to_owned(),
    ]);
    Ok(args)
}

fn utf8(path: &Path) -> Result<String, SessionError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SessionError::Workspace {
            what: "a session path is not valid UTF-8",
            detail: path.to_string_lossy().into_owned(),
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

/// Asking a spawned openvpn to stop. `terminate` is the polite `SIGTERM`;
/// `kill` is the deadline.
pub trait ProcessControl: Send + Sync {
    fn terminate(&self);
    fn kill(&self);
}

pub struct SpawnedProcess {
    pub control: Arc<dyn ProcessControl>,
    /// Resolves once, when the child is reaped.
    pub exit: oneshot::Receiver<ProcessExit>,
}

/// The seam the whole connect path is tested through: no test starts a real
/// openvpn.
pub trait ProcessSpawner: Send + Sync {
    fn spawn(&self, program: &Path, args: &[String]) -> Result<SpawnedProcess, SessionError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSpawner;

#[derive(Clone, Copy, Debug)]
enum Stop {
    Term,
    Kill,
}

impl ProcessSpawner for SystemSpawner {
    fn spawn(&self, program: &Path, args: &[String]) -> Result<SpawnedProcess, SessionError> {
        let child = tokio::process::Command::new(program)
            .args(args)
            // A pushed `setenv` cannot reach us, but the daemon's own environment
            // has no business inside a child that parses attacker-controlled data.
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| SessionError::Spawn {
                command: program.display().to_string(),
                detail: source.to_string(),
            })?;

        let (stop_tx, stop_rx) = mpsc::channel(2);
        let (exit_tx, exit) = oneshot::channel();
        // The child is owned by exactly one task, so its pid is never reaped
        // behind a signal we are about to send: no recycled-pid kill.
        tokio::spawn(async move {
            let _ = exit_tx.send(supervise(child, stop_rx).await);
        });

        Ok(SpawnedProcess {
            control: Arc::new(ChannelControl {
                stop: Mutex::new(Some(stop_tx)),
            }),
            exit,
        })
    }
}

struct ChannelControl {
    stop: Mutex<Option<mpsc::Sender<Stop>>>,
}

impl ChannelControl {
    fn request(&self, stop: Stop) {
        let sender = self
            .stop
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(sender) = sender {
            if sender.try_send(stop).is_err() {
                warn!(?stop, "openvpn supervisor is not accepting stop requests");
            }
        }
    }
}

impl ProcessControl for ChannelControl {
    fn terminate(&self) {
        self.request(Stop::Term);
    }

    fn kill(&self) {
        self.request(Stop::Kill);
    }
}

async fn supervise(
    mut child: tokio::process::Child,
    mut stop: mpsc::Receiver<Stop>,
) -> ProcessExit {
    loop {
        tokio::select! {
            // `Child::wait` is cancel safe, so losing this branch to a stop
            // request does not lose the exit status.
            status = child.wait() => return summarise(status),
            request = stop.recv() => match request {
                Some(Stop::Term) => send_term(&child),
                Some(Stop::Kill) | None => {
                    let _ = child.start_kill();
                }
            },
        }
    }
}

fn send_term(child: &tokio::process::Child) {
    let Some(pid) = child.id() else {
        return;
    };
    // SAFETY: `pid` belongs to a child this task still owns and has not reaped,
    // so it cannot have been recycled by another process.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

fn summarise(status: std::io::Result<std::process::ExitStatus>) -> ProcessExit {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(status) => ProcessExit {
            code: status.code(),
            signal: status.signal(),
        },
        Err(error) => {
            warn!(%error, "could not reap openvpn");
            ProcessExit {
                code: None,
                signal: None,
            }
        }
    }
}

/// Boxed future alias so the transport and process seams stay object safe
/// without an `async-trait` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn args() -> Vec<String> {
        args_with(OpenvpnCapabilities::default())
    }

    fn args_with(capabilities: OpenvpnCapabilities) -> Vec<String> {
        build_args(
            Path::new("/run/tc/canonical.ovpn"),
            Path::new("/run/tc/mgmt.sock"),
            capabilities,
        )
        .expect("args")
    }

    fn window(args: &[String], first: &str) -> Vec<String> {
        let start = args.iter().position(|a| a == first).expect("flag present");
        args[start..].to_vec()
    }

    #[test]
    fn passes_the_config_by_path_and_never_the_body() {
        let args = args();

        assert_eq!(args[0], "--config");
        assert_eq!(args[1], "/run/tc/canonical.ovpn");
    }

    #[test]
    fn requests_a_reverse_connection_to_a_unix_management_socket() {
        let args = args();

        assert_eq!(
            window(&args, "--management")[..3],
            ["--management", "/run/tc/mgmt.sock", "unix"]
        );
        assert!(args.iter().any(|a| a == "--management-client"));
    }

    #[test]
    fn injects_every_mandatory_flag_from_the_spec() {
        let args = args();

        for flag in [
            "--management-hold",
            "--management-query-passwords",
            "--management-up-down",
            "--route-noexec",
            "--auth-nocache",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
    }

    #[test]
    fn never_passes_route_nopull_which_would_suppress_pushed_dns() {
        assert!(!args().iter().any(|a| a == "--route-nopull"));
    }

    #[test]
    fn sets_script_security_to_one_not_zero() {
        assert_eq!(
            window(&args(), "--script-security")[..2],
            ["--script-security", "1"]
        );
    }

    #[test]
    fn disables_the_builtin_dns_updown_handler_that_runs_as_root() {
        assert_eq!(
            window(&args(), "--dns-updown")[..2],
            ["--dns-updown", "disable"]
        );
    }

    #[test]
    fn omits_dns_updown_only_when_the_binary_cannot_parse_it() {
        // openvpn 2.6 rejects an unknown option and exits before it connects, so passing it there
        // is not a harmless extra flag — it is a total failure to start.
        let without = args_with(OpenvpnCapabilities { dns_updown: false });

        assert!(!without.iter().any(|a| a == "--dns-updown"));
        assert!(!without.iter().any(|a| a == "disable"));
        // Everything after it must survive its removal.
        assert_eq!(
            window(&without, "--allow-compression")[..2],
            ["--allow-compression", "no"]
        );
        assert_eq!(
            window(&without, "--auth-retry")[..2],
            ["--auth-retry", "interact"]
        );
        assert!(without.iter().any(|a| a == "--auth-nocache"));
        assert_eq!(window(&without, "--verb")[..2], ["--verb", "3"]);
        assert_eq!(window(&without, "--route-noexec")[..1], ["--route-noexec"]);
    }

    #[test]
    fn the_capability_default_keeps_the_security_control() {
        assert!(OpenvpnCapabilities::default().dns_updown);
    }

    #[test]
    fn recognises_the_option_rejection_openvpn_prints() {
        let rejection = "Options error: Unrecognized option or missing or extra parameter(s) in \
                         [CMD-LINE]:1: dns-updown (2.6.19)";

        assert!(rejects_option(rejection, "dns-updown"));
        // A build that accepts it prints its version banner and nothing else.
        assert!(!rejects_option(
            "OpenVPN 2.7.6 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]",
            "dns-updown"
        ));
        // A rejection naming a different option must not disable this one.
        assert!(!rejects_option(
            "Options error: Unrecognized option or missing or extra parameter(s) in [CMD-LINE]:1: nonsense",
            "dns-updown"
        ));
    }

    #[test]
    fn retries_auth_interactively_so_a_consumed_totp_is_never_replayed() {
        assert_eq!(
            window(&args(), "--auth-retry")[..2],
            ["--auth-retry", "interact"]
        );
    }

    #[test]
    fn ignores_pushed_routes_and_redirect_gateway_by_pull_filter() {
        let args = args();
        let filters: Vec<&[String]> = args
            .windows(3)
            .filter(|w| w[0] == "--pull-filter")
            .collect();

        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0][1..], ["ignore".to_owned(), "route".to_owned()]);
        assert_eq!(
            filters[1][1..],
            ["ignore".to_owned(), "redirect-gateway".to_owned()]
        );
    }

    #[test]
    fn rejects_a_relative_configured_binary_path() {
        let outcome = resolve_openvpn(Some(Path::new("openvpn")));

        assert!(matches!(outcome, Err(SessionError::OpenvpnNotFound { .. })));
    }

    #[test]
    fn rejects_a_configured_path_that_is_not_executable() {
        let outcome = resolve_openvpn(Some(Path::new("/etc/hosts")));

        assert!(matches!(outcome, Err(SessionError::OpenvpnNotFound { .. })));
    }

    #[test]
    fn accepts_a_configured_executable() {
        let resolved = resolve_openvpn(Some(Path::new("/bin/sh"))).expect("resolve");

        assert_eq!(resolved, PathBuf::from("/bin/sh"));
    }

    #[tokio::test]
    async fn reports_the_exit_status_of_a_spawned_process() {
        // Arrange
        let spawner = SystemSpawner;

        // Act
        let spawned = spawner
            .spawn(
                Path::new("/bin/sh"),
                &["-c".to_owned(), "exit 7".to_owned()],
            )
            .expect("spawn");

        // Assert
        assert_eq!(spawned.exit.await.expect("exit").code, Some(7));
    }

    #[tokio::test]
    async fn terminates_a_running_process_with_sigterm() {
        // Arrange
        let spawned = SystemSpawner
            .spawn(
                Path::new("/bin/sh"),
                &["-c".to_owned(), "sleep 30".to_owned()],
            )
            .expect("spawn");

        // Act
        spawned.control.terminate();

        // Assert
        let exit = tokio::time::timeout(std::time::Duration::from_secs(5), spawned.exit)
            .await
            .expect("did not exit in time")
            .expect("exit");
        assert_eq!(exit.signal, Some(libc::SIGTERM));
    }

    #[test]
    fn refuses_to_spawn_a_binary_that_does_not_exist() {
        let outcome = SystemSpawner.spawn(Path::new("/nonexistent/openvpn"), &[]);

        assert!(matches!(outcome, Err(SessionError::Spawn { .. })));
    }
}
