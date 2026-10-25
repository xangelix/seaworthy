//! The service-main state machine (the `runtime` feature), generalized
//! from a production Windows service.
//!
//! Two cfg-selected entries:
//!
//! * **Windows** does the full SCM dance. `run_windows_service` starts
//!   the dispatcher (`StartServiceCtrlDispatcherW`) from `main`; the
//!   SCM-invoked service main then registers the control handler, reports
//!   `StartPending` while it builds the runtime, then `Running` BEFORE init
//!   (init is raced against STOP, so a service retrying its connect
//!   can always be stopped), then translates the
//!   body's [`Outcome`](crate::Outcome) into `Stopped`-clean (success, exit
//!   code 0) or `Stopped` with [`EXIT_CODE_FATAL`] (fatal: the SCM recovery
//!   actions do the restart). Running the binary outside the
//!   SCM (a console, `cargo run`) answers the dispatcher with 1063 and
//!   falls back to the foreground shape — Ctrl-C shutdown, no status
//!   protocol. Every failure path (fatal, escalation, a panic, a
//!   status-report failure) reports `Stopped` with the
//!   service-specific [`EXIT_CODE_FATAL`] — the dispatcher only returns
//!   once the service is `Stopped`, and the non-zero code fires the SCM's
//!   recovery actions. [`run_service`] is the ServiceMain body itself, for apps
//!   that wire their own dispatcher. Reporting `Running` before a slow
//!   init also keeps the SCM's start timeout (Code 1053) out of reach.
//! * **Unix** degenerates to "just run the loop": systemd already watches
//!   the process, so the only extra wiring is forwarding SIGTERM/SIGINT into
//!   the shutdown channel, raced against init so a stop during a
//!   retry-forever connect exits cleanly (the Windows shape does the same). Fatal outcomes simply return
//!   `Err`, which a well-behaved `main` turns into a non-zero exit for
//!   `Restart=on-failure`.

use std::{future::Future, time::Duration};

use tokio::sync::mpsc;

// ---------------------------------------------------------------------------

/// How long a finished service main waits for its runtime's blocking work
/// (a DNS lookup inside a connect, the update request's `StartServiceW`)
/// before it reports `Stopped` and returns. Dropping a tokio
/// runtime waits FOREVER for its `spawn_blocking` jobs: a service that told
/// the SCM `Stopped` while its process lingered on a slow lookup kept its
/// files in use, so an MSI upgrade deferred them to a reboot. Under the
/// SCM's 10 s stop hint; a blocking thread still running after it ends
/// with the process.
pub(crate) const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The service main's tokio runtime, shut down with a bounded grace
/// ([`RUNTIME_SHUTDOWN_GRACE`]) on every path: an explicit
/// [`ServiceRuntime::shut_down`], an early return, or a panic unwinding
/// through it.
pub(crate) struct ServiceRuntime {
    runtime: Option<tokio::runtime::Runtime>,
    /// Drives `block_on` (the same as the runtime's own on a multi-thread
    /// runtime), so the runtime itself can stay an `Option` for the drop.
    handle: tokio::runtime::Handle,
    grace: Duration,
}

impl ServiceRuntime {
    /// A multi-thread runtime with every driver enabled.
    pub(crate) fn build(grace: Duration) -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        Ok(Self {
            handle: runtime.handle().clone(),
            runtime: Some(runtime),
            grace,
        })
    }

    /// Run `future` to completion on this thread.
    pub(crate) fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.handle.block_on(future)
    }

    /// Shut the runtime down now, waiting at most the grace for its
    /// blocking work.
    pub(crate) fn shut_down(mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(self.grace);
        }
    }
}

impl Drop for ServiceRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(self.grace);
        }
    }
}

// The SCM status protocol, platform-neutral: compiled on Windows (the real
// handle plugs in) and in every test build, so Linux CI pins the Windows
// state machine's every exit path.
#[cfg(any(windows, test))]
mod scm;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::run_service;
#[cfg(windows)]
pub use windows::{run_service, run_windows_service};

/// Receiving end of the shutdown signal handed to the service body.
///
/// `recv()` resolving (or the channel closing) means "the supervisor wants
/// us gone" — SCM STOP on Windows, SIGTERM/SIGINT on unix.
pub type ShutdownRx = mpsc::Receiver<()>;

/// The documented non-zero exit code of every FAILURE path (fatal init or
/// body, a supervisor's escalation breaches, task panics, a status-report
/// failure):
/// [`crate::RunError::exit_code`] on unix, and on
/// Windows the service-specific code the state machine reports with its
/// final `Stopped` (`ERROR_SERVICE_SPECIFIC_ERROR` +
/// `dwServiceSpecificExitCode` = 1), so the SCM's
/// failure-actions-on-non-crash-failures recovery restarts the service.
pub const EXIT_CODE_FATAL: i32 = 1;

/// How a finished service main must exit the process — the library never
/// calls `std::process::exit` itself (apps embed services in larger
/// processes), so `main` turns the disposition into the exit code:
///
/// ```no_run
/// # async fn example() -> Result<(), seaworthy_service::RunError<std::io::Error>> {
/// # let exit = seaworthy_service::ServiceExit::Stopped;
/// match exit {
///     seaworthy_service::ServiceExit::Stopped | seaworthy_service::ServiceExit::Retired => {
///         std::process::exit(0)
///     }
/// }
/// # }
/// ```
///
/// (`Result<ServiceExit, _>` from [`run_service`] maps straight onto this;
/// [`ServiceExit::exit_process`] is the one-call form.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the exit disposition only takes effect when `main` exits with `code()`"]
pub enum ServiceExit {
    /// Clean, supervisor-requested stop (SIGTERM/SIGINT, SCM STOP, or an
    /// in-process shutdown the body honors): exit code 0. The supervisor
    /// must NOT restart us.
    Stopped,
    /// The server PERMANENTLY refused this client (e.g. an archived
    /// device), as classified by a supervisor layered on [`run_service`],
    /// which itself never returns it: exit code 0, like [`Self::Stopped`], so neither systemd's
    /// `Restart=on-failure` nor the SCM's failure actions start it again —
    /// retrying would only hammer a server that will always say no. (A
    /// unit configured `Restart=always` WOULD restart it; this crate's
    /// renderer never emits that.) Distinct from `Stopped` so `main` and
    /// its logs can tell "told to stop" from "revoked".
    Retired,
}

impl ServiceExit {
    /// The process exit code for this disposition: 0 (failures are
    /// [`crate::RunError`]s, which exit [`EXIT_CODE_FATAL`]).
    pub fn code(self) -> i32 {
        match self {
            Self::Stopped | Self::Retired => 0,
        }
    }

    /// `std::process::exit(self.code())` — the standard end of a supervised
    /// `main`. Never returns.
    pub fn exit_process(self) -> ! {
        std::process::exit(self.code())
    }
}
