//! Every external program `seaworthy`'s signers run (a manifest signing
//! command, osslsigncode or a jsign/signtool command, rpmsign, gpg,
//! rpmkeys) goes through [`run`]: no shell, a deadline, and a cap on what
//! it may print.
//!
//! The runner is [`seaworthy_updater::process`], which the update helper uses
//! for its package-manager calls too: one implementation, reviewed once.
//! The deadline covers the whole run, draining the program's output
//! included, and on Unix the program's whole process group is killed when
//! it passes. This module maps its errors to [`DistError::Tool`].

use std::process::Command;
use std::time::Duration;

pub use seaworthy_updater::process::{Finished, MAX_OUTPUT_SHOWN, MAX_TIMEOUT};

use crate::DistError;

/// Checks a configured deadline: 1 second to [`MAX_TIMEOUT`].
///
/// # Errors
/// [`DistError::Sign`] naming `what` for a value outside that range.
pub fn check_timeout(timeout: Duration, what: &str) -> Result<Duration, DistError> {
    if timeout < Duration::from_secs(1) || timeout > MAX_TIMEOUT {
        return Err(DistError::Sign(format!(
            "{what}: a timeout must be 1 to {} seconds",
            MAX_TIMEOUT.as_secs()
        )));
    }
    Ok(timeout)
}

/// Runs `command` (`what` names it in messages) with `stdin` on its
/// standard input (or none), under `timeout`, keeping at most
/// `stdout_limit` bytes of its stdout ([`seaworthy_updater::process::run`]).
///
/// # Errors
/// [`DistError::Tool`] when it can't start, or doesn't finish (its output
/// drained) within `timeout`. A non-zero exit is not an error here: the
/// caller decides, with [`Finished::shown`] for the message.
pub fn run(
    command: &mut Command,
    what: &str,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Finished, DistError> {
    seaworthy_updater::process::run(command, what, stdin, timeout, stdout_limit)
        .map_err(|e| DistError::Tool(e.to_string()))
}

/// [`run`], then a non-zero exit is an error; returns stdout as text.
///
/// # Errors
/// As [`run`]; [`DistError::Tool`] for a non-zero exit, with what the
/// program printed (cut short).
pub fn run_ok(command: &mut Command, what: &str, timeout: Duration) -> Result<String, DistError> {
    seaworthy_updater::process::run_ok(command, what, timeout)
        .map_err(|e| DistError::Tool(e.to_string()))
}
