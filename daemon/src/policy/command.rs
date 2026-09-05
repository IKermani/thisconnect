// SPDX-License-Identifier: GPL-3.0-or-later

//! Subprocess construction and execution for tunnel policy.
//!
//! Two rules hold everywhere in this module. Commands are executed with an argument vector and
//! never through a shell, and every *dynamic* argument is re-validated at build time even though
//! it already came from a typed value in `types.rs` — the injection bug in
//! `scripts/verify-ifscope-macos.sh` existed because one layer trusted another.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use super::PolicyError;

/// Long enough for any address, device name or metric we emit; short enough that nothing
/// resembling a config blob can reach a root command line.
const MAX_VALUE_LEN: usize = 64;

/// One argument. `Flag` is a compile-time literal from this crate; `Value` is data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arg {
    Flag(&'static str),
    Value(String),
}

pub fn flag(literal: &'static str) -> Arg {
    Arg::Flag(literal)
}

pub fn value(data: impl fmt::Display) -> Arg {
    Arg::Value(data.to_string())
}

/// A fully built, immutable command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    program: PathBuf,
    args: Vec<String>,
}

impl Command {
    pub fn build(program: &Path, args: Vec<Arg>) -> Result<Self, PolicyError> {
        let args = args
            .into_iter()
            .map(|arg| match arg {
                Arg::Flag(literal) => Ok(literal.to_owned()),
                Arg::Value(data) => validate_value(&data),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            program: program.to_path_buf(),
            args,
        })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.program.display())?;
        self.args.iter().try_for_each(|arg| write!(f, " {arg}"))
    }
}

/// The allowlist a data argument must satisfy. Notably a leading `-` is refused: an argument that
/// starts a new option turns `route add default <peer>` into whatever the attacker named.
fn validate_value(data: &str) -> Result<String, PolicyError> {
    let reject = |reason: &'static str| {
        Err(PolicyError::UnsafeArgument {
            reason,
            value: data.to_owned(),
        })
    };
    if data.is_empty() {
        return reject("empty arguments are never meaningful here");
    }
    if data.len() > MAX_VALUE_LEN {
        return reject("argument is longer than any address, device or metric we emit");
    }
    if data.starts_with('-') {
        return reject("an argument starting with '-' would be read as an option");
    }
    if !data
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-' | '/'))
    {
        return reject("only [A-Za-z0-9.:_/-] may reach a privileged command line");
    }
    Ok(data.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn succeeded(&self) -> bool {
        self.status == Some(0)
    }
}

/// Injected so that argument construction, ordering and teardown are unit-testable without root.
pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &Command) -> Result<CommandOutput, PolicyError>;
}

/// Runs commands for real. No shell, no inherited environment: the daemon is root and both
/// `route(8)` and `ip(8)` are addressed by absolute path, so an inherited `PATH` or `IFS` buys
/// nothing and can only be a lever.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, command: &Command) -> Result<CommandOutput, PolicyError> {
        let output = std::process::Command::new(command.program())
            .args(command.args().iter().map(OsStr::new))
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .map_err(|source| PolicyError::Spawn {
                command: command.to_string(),
                source,
            })?;
        Ok(CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Mutex;

    use super::*;

    /// A runner that answers from a closure and records every command it was asked to run, in
    /// order. Ordering assertions in the other policy tests read that log.
    pub(crate) struct ScriptedRunner<F> {
        reply: F,
        log: Mutex<Vec<Command>>,
    }

    impl<F> ScriptedRunner<F>
    where
        F: Fn(&Command) -> CommandOutput + Send + Sync,
    {
        pub(crate) fn new(reply: F) -> Self {
            Self {
                reply,
                log: Mutex::new(Vec::new()),
            }
        }

        /// The command lines seen so far, rendered exactly as they would be executed.
        pub(crate) fn log(&self) -> Vec<String> {
            self.log
                .lock()
                .expect("log mutex")
                .iter()
                .map(Command::to_string)
                .collect()
        }
    }

    impl<F> CommandRunner for ScriptedRunner<F>
    where
        F: Fn(&Command) -> CommandOutput + Send + Sync,
    {
        fn run(&self, command: &Command) -> Result<CommandOutput, PolicyError> {
            self.log.lock().expect("log mutex").push(command.clone());
            Ok((self.reply)(command))
        }
    }

    pub(crate) fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            status: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    pub(crate) fn failed(stderr: &str) -> CommandOutput {
        CommandOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::testing::{ok, ScriptedRunner};
    use super::*;

    #[test]
    fn builds_a_command_from_flags_and_values() {
        let command = Command::build(
            Path::new("/sbin/route"),
            vec![flag("-n"), flag("add"), flag("-ifscope"), value("utun4")],
        )
        .expect("valid");

        assert_eq!(command.to_string(), "/sbin/route -n add -ifscope utun4");
    }

    #[test]
    fn rejects_a_value_carrying_a_shell_metacharacter() {
        let outcome = Command::build(
            Path::new("/sbin/route"),
            vec![value("10.8.0.1; touch /tmp/pwned")],
        );

        assert!(matches!(outcome, Err(PolicyError::UnsafeArgument { .. })));
    }

    #[test]
    fn rejects_a_value_that_would_be_read_as_an_option() {
        let outcome = Command::build(Path::new("/sbin/route"), vec![value("-interface")]);

        assert!(matches!(outcome, Err(PolicyError::UnsafeArgument { .. })));
    }

    #[test]
    fn rejects_an_empty_or_overlong_value() {
        assert!(Command::build(Path::new("/sbin/route"), vec![value("")]).is_err());
        assert!(Command::build(Path::new("/sbin/route"), vec![value("a".repeat(65))]).is_err());
    }

    #[test]
    fn accepts_the_shapes_policy_actually_emits() {
        for accepted in ["10.8.0.2/32", "fd00::2", "utun90", "218", "1400"] {
            assert!(
                Command::build(Path::new("/sbin/ip"), vec![value(accepted)]).is_ok(),
                "{accepted} must be accepted"
            );
        }
    }

    #[test]
    fn the_scripted_runner_records_commands_in_order() {
        let runner = ScriptedRunner::new(|_| ok(""));
        let first = Command::build(Path::new("/bin/a"), vec![flag("one")]).expect("valid");
        let second = Command::build(Path::new("/bin/b"), vec![flag("two")]).expect("valid");

        runner.run(&first).expect("ran");
        runner.run(&second).expect("ran");

        assert_eq!(runner.log(), vec!["/bin/a one", "/bin/b two"]);
    }
}
