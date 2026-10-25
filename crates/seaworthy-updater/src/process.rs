//! A bounded way to run an external program: no shell, a deadline, and a
//! cap on what it may print. The update helper runs every package-manager
//! query, signature check and install through [`run`]; the seaworthy CLI
//! runs its signers through it too, so one implementation is reviewed once.
//!
//! The deadline covers the whole run, draining the program's output
//! included: a program that exits while a child of its own still holds the
//! pipes (`sh -c 'sleep 600 & …'`) would otherwise hold the caller until
//! that child exits. On Unix the program starts its own process group,
//! and the whole group is killed when the deadline passes. Each pipe has
//! its own thread, so no fill order can deadlock.
//!
//! Every program runs in the C locale (`LC_ALL=C`, `LANGUAGE` removed):
//! callers parse what programs print (`rpmkeys`' `signatures OK`, rpm's
//! and dpkg's "not installed"), and a service inherits `LANG` from
//! `/etc/locale.conf`, under which those messages are translated.
//! What a failure repeats ([`Finished::shown`]) has its control characters
//! removed, so a program's output can't forge log lines.
//!
//! Everything here blocks: call it from a blocking task, never on an async
//! executor's worker.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The longest any one program may run.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(3600);

/// How much of a failing program's output an error message repeats.
pub const MAX_OUTPUT_SHOWN: usize = 400;

/// Why a program didn't run to an exit status in time.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// It couldn't start (not installed, not executable).
    #[error("cannot run {program} ({what}): {source}")]
    Spawn {
        /// The program.
        program: String,
        /// What it was run for.
        what: String,
        /// The spawn error.
        source: std::io::Error,
    },
    /// It didn't finish, its output drained, within its deadline: it and
    /// its process group were killed.
    #[error("{program} ({what}) didn't finish within {} s", timeout.as_secs())]
    Timeout {
        /// The program.
        program: String,
        /// What it was run for.
        what: String,
        /// The deadline it missed.
        timeout: Duration,
    },
    /// Waiting for it failed, or the deadline is past the clock's range.
    #[error("{program} ({what}): {detail}")]
    Wait {
        /// The program.
        program: String,
        /// What it was run for.
        what: String,
        /// What went wrong.
        detail: String,
    },
    /// It exited 0 without reading all of its input.
    #[error("{program} ({what}) didn't read its input: {detail}")]
    Input {
        /// The program.
        program: String,
        /// What it was run for.
        what: String,
        /// The write error.
        detail: String,
    },
    /// It exited non-zero ([`run_ok`] only).
    #[error("{program} ({what}) failed ({status}): {shown}")]
    Failed {
        /// The program.
        program: String,
        /// What it was run for.
        what: String,
        /// Its exit status.
        status: ExitStatus,
        /// What it printed ([`Finished::shown`]).
        shown: String,
    },
}

/// A program that ran to its exit within its deadline.
#[derive(Debug)]
pub struct Finished {
    /// Its exit status.
    pub status: ExitStatus,
    /// What it printed on stdout, up to the cap.
    pub stdout: Vec<u8>,
    /// Whether it printed more than the cap on stdout.
    pub stdout_overflow: bool,
    /// What it printed on stderr, up to [`MAX_OUTPUT_SHOWN`].
    pub stderr: Vec<u8>,
    /// Whether it printed more than that on stderr.
    pub stderr_overflow: bool,
}

impl Finished {
    /// What to repeat of a failure: stderr, or stdout when stderr is
    /// empty, cut to [`MAX_OUTPUT_SHOWN`] bytes, its lines joined with
    /// ` | ` and control characters removed.
    #[must_use]
    pub fn shown(&self) -> String {
        let (bytes, overflow) = if self.stderr.iter().all(u8::is_ascii_whitespace) {
            let end = self.stdout.len().min(MAX_OUTPUT_SHOWN);
            (
                self.stdout.get(..end).unwrap_or_default(),
                self.stdout_overflow || self.stdout.len() > end,
            )
        } else {
            (self.stderr.as_slice(), self.stderr_overflow)
        };
        let joined = String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        let mut text = crate::log::line_safe(&joined);
        if overflow {
            text.push_str(" …");
        }
        text
    }
}

/// What a child printed, up to `limit` bytes (the rest is drained and
/// counted, never stored), sent on a channel when the pipe closes.
fn capture(
    mut stream: impl std::io::Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut overflow = false;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = limit.saturating_sub(kept.len());
                    kept.extend_from_slice(chunk.get(..n.min(room)).unwrap_or_default());
                    overflow |= n > room;
                }
            }
        }
        let _ = tx.send((kept, overflow));
    });
    rx
}

/// Kills the program and, on Unix, every process left in its group.
fn kill(child: &mut std::process::Child) {
    // A child's pid is never 0 (kill(0) would signal this process's own
    // group); checked anyway.
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(child.id())
        && pid > 0
    {
        #[allow(
            unsafe_code,
            reason = "kill(2) on the process group: std can only signal the child itself"
        )]
        // SAFETY: kill(2) with a negative pid signals the process group the
        // child leads (it was spawned with process_group(0)); no memory is
        // touched.
        let _ = unsafe { libc::kill(pid.saturating_neg(), libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Runs `command` (`what` names it in messages) with `stdin` on its
/// standard input (or none), under `timeout`, keeping at most
/// `stdout_limit` bytes of its stdout.
///
/// # Errors
/// [`ProcessError`] when it can't start, or doesn't finish (its output
/// drained) within `timeout`. A non-zero exit is not an error here: the
/// caller decides, with [`Finished::shown`] for the message.
pub fn run(
    command: &mut Command,
    what: &str,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Finished, ProcessError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ProcessError::Wait {
            program: program.clone(),
            what: what.to_owned(),
            detail: "a timeout past the clock's range".to_owned(),
        })?;
    command.env("LC_ALL", "C").env_remove("LANGUAGE");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ProcessError::Spawn {
            program: program.clone(),
            what: what.to_owned(),
            source,
        })?;
    let (wrote_tx, wrote) = mpsc::channel();
    if let (Some(mut pipe), Some(bytes)) = (child.stdin.take(), stdin) {
        std::thread::spawn(move || {
            let _ = wrote_tx.send(pipe.write_all(&bytes).map_err(|e| e.to_string()));
        });
    } else {
        let _ = wrote_tx.send(Ok(()));
    }
    let stdout = child.stdout.take().map(|s| capture(s, stdout_limit));
    let stderr = child.stderr.take().map(|s| capture(s, MAX_OUTPUT_SHOWN));
    let late = |child: &mut std::process::Child| {
        kill(child);
        ProcessError::Timeout {
            program: program.clone(),
            what: what.to_owned(),
            timeout,
        }
    };
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => return Err(late(&mut child)),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                kill(&mut child);
                return Err(ProcessError::Wait {
                    program,
                    what: what.to_owned(),
                    detail: e.to_string(),
                });
            }
        }
    };
    // The program has exited; its output must still be drained in time (a
    // child of its own may hold the pipes).
    let mut collect = |rx: Option<mpsc::Receiver<(Vec<u8>, bool)>>| {
        let Some(rx) = rx else {
            return Ok((Vec::new(), false));
        };
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| late(&mut child))
    };
    let (stdout, stdout_overflow) = collect(stdout)?;
    let (stderr, stderr_overflow) = collect(stderr)?;
    let written = wrote
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| late(&mut child))?;
    let finished = Finished {
        status,
        stdout,
        stdout_overflow,
        stderr,
        stderr_overflow,
    };
    if status.success()
        && let Err(detail) = written
    {
        return Err(ProcessError::Input {
            program,
            what: what.to_owned(),
            detail,
        });
    }
    Ok(finished)
}

/// [`run`] without input, then a non-zero exit is an error; returns stdout
/// (up to 1 MiB) as text.
///
/// # Errors
/// As [`run`]; [`ProcessError::Failed`] for a non-zero exit, with what the
/// program printed (cut short).
pub fn run_ok(
    command: &mut Command,
    what: &str,
    timeout: Duration,
) -> Result<String, ProcessError> {
    let program = command.get_program().to_string_lossy().into_owned();
    let finished = run(command, what, None, timeout, 1 << 20)?;
    if !finished.status.success() {
        return Err(ProcessError::Failed {
            program,
            what: what.to_owned(),
            status: finished.status,
            shown: finished.shown(),
        });
    }
    Ok(String::from_utf8_lossy(&finished.stdout).into_owned())
}

/// A private scratch directory (0700), removed with its contents on drop:
/// a throwaway gpg home or rpm database. Its path stays short (gpg's
/// sockets live under it when `/run/user` is missing).
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    /// A new directory named after `purpose`, under the system's temporary
    /// directory.
    ///
    /// # Errors
    /// When it can't be created.
    pub fn new(purpose: &str) -> std::io::Result<Self> {
        Self::new_in(&std::env::temp_dir(), purpose)
    }

    /// A new directory named after `purpose`, under `parent` (the update
    /// helper's root-only staging directory). The name is unique to this
    /// process and call, and creating it fails rather than reuse anything
    /// already there.
    ///
    /// # Errors
    /// When it can't be created.
    pub fn new_in(parent: &Path, purpose: &str) -> std::io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let name = format!(
            "sw-{purpose}-{}-{}-{nanos:x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = parent.join(name);
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        builder
            .create(&path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        Ok(Self(path))
    }

    /// Its path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn output_is_capped_and_failures_are_shown_from_stderr() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "head -c 100000 /dev/zero | tr '\\0' x; echo oops >&2; exit 3",
        ]);
        let finished = run(&mut command, "test", None, Duration::from_secs(20), 1000).unwrap();
        assert_eq!(finished.stdout.len(), 1000);
        assert!(finished.stdout_overflow);
        assert_eq!(finished.status.code(), Some(3));
        assert_eq!(finished.shown(), "oops");
        let mut failing = Command::new("sh");
        failing.args(["-c", "echo nope; exit 1"]);
        let error = run_ok(&mut failing, "test", Duration::from_secs(20)).unwrap_err();
        assert!(
            matches!(error, ProcessError::Failed { ref shown, .. } if shown == "nope"),
            "{error}"
        );
    }

    #[test]
    fn programs_run_in_the_c_locale_and_failures_are_shown_on_one_line() {
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "echo \"$LC_ALL|${LANGUAGE-unset}\"; printf 'one\\ntwo\\033[2J' >&2",
            ])
            .env("LANGUAGE", "de")
            .env("LC_ALL", "de_DE.UTF-8");
        let finished = run(&mut command, "test", None, Duration::from_secs(20), 1000).unwrap();
        assert_eq!(String::from_utf8_lossy(&finished.stdout), "C|unset\n");
        assert_eq!(finished.shown(), "one | two[2J");
    }

    #[test]
    fn the_deadline_covers_children_that_keep_the_pipes() {
        let started = Instant::now();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 600 & echo started"]);
        let error = run(&mut command, "test", None, Duration::from_secs(1), 1000).unwrap_err();
        assert!(matches!(error, ProcessError::Timeout { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(30));
        let mut missing = Command::new("/nonexistent/seaworthy-no-such-program");
        assert!(matches!(
            run(&mut missing, "test", None, Duration::from_secs(1), 10),
            Err(ProcessError::Spawn { .. })
        ));
    }

    #[test]
    fn scratch_directories_are_private_and_removed() {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = tempfile::tempdir().unwrap();
        let path = {
            let scratch = TempDir::new_in(parent.path(), "test").unwrap();
            let mode = std::fs::metadata(scratch.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
            std::fs::write(scratch.path().join("x"), b"x").unwrap();
            scratch.path().to_owned()
        };
        assert!(!path.exists());
    }
}
