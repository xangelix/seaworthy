//! Windows body of [`run_service`](crate::run_service): the SCM status
//! protocol around init + body, and the dispatcher entry that makes the
//! whole shape reachable from the SCM at all.
//!
//! # The two entries (without the dispatcher a service is dead on arrival)
//!
//! The SCM contract has two chained requirements:
//!
//! 1. The process's entry point must call `StartServiceCtrlDispatcherW`
//!    (`windows_service::service_dispatcher::start`) so the SCM learns the
//!    process is a service; only then does it invoke the `ServiceMain`
//!    callback on its own thread.
//! 2. `RegisterServiceCtrlHandlerExW` — and every `SetServiceStatus` —
//!    may only run on that SCM-invoked thread.
//!
//! Calling `register` without the dispatcher fails with Win32 **1063**
//! (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) 100% of the time under a
//! real SCM: the service is dead on arrival. The two entries below split
//! the contract at its seam:
//!
//! * [`run_windows_service`] — what `main` calls. It stashes the
//!   type-erased service-main pieces (the dispatcher accepts only a
//!   non-capturing `extern "system"` fn — one service main per process is
//!   the SCM's contract anyway), starts the dispatcher, and the SCM-invoked
//!   [`scm_service_main`] shim unwraps the stash and runs [`run_service`]
//!   — register, `Running`, init raced against STOP, the body — on the
//!   SCM's thread. **1063 means the binary is not under the SCM** (a
//!   developer console, `cargo run`): the console fallback runs the
//!   foreground shape instead, mirroring the unix SIGINT runner, and the
//!   process remembers it — Windows admits one dispatcher call per process
//!   (a second answers 1056), so a later run in the same process (an
//!   embedder, a test of two cases) goes straight to the console shape.
//!   Both paths run under a real SCM on a Windows runner
//!   (`scripts/windows-scm-e2e.ps1`); what a CI machine can't show (OS
//!   shutdown, boot and a domain) stays a physical-Windows check before a
//!   release.
//! * [`run_service`] — the ServiceMain body itself. Public so advanced
//!   apps can wire their own dispatcher (e.g. `windows_service`'s
//!   `define_windows_service!`), with the caveat that the name they
//!   register under must match the installed service.
//!
//! The discipline inside [`run_service`] is load-bearing, ported from a
//! production service:
//!
//! * `Running` is reported as soon as the runtime exists, BEFORE init, and
//!   init is raced against STOP and SHUTDOWN like the unix twin races it
//!   against SIGTERM. Init is typically a retry-forever connect, which an
//!   unreachable server or a version mismatch can hold for hours. A service
//!   still `StartPending` then could be neither stopped (`sc stop` answers
//!   1061, `ERROR_SERVICE_CANNOT_ACCEPT_CTRL`) nor started by an MSI
//!   (`ServiceControl` waits for `Running`: error 1920 and a rollback), and
//!   the package manager stops and restarts the service to update it. A
//!   stop during init is a clean exit.
//! * `controls_accepted` is `STOP | SHUTDOWN` in `Running` (an OS shutdown
//!   takes the same graceful path as a stop); pending states accept nothing
//!   (`StartPending` lasts only while the runtime is built).
//! * **Every failure path reports `Stopped` + the service-specific
//!   [`crate::EXIT_CODE_FATAL`].** A fatal path that returns WITHOUT a
//!   final report breaks under the dispatcher:
//!   `StartServiceCtrlDispatcherW` returns only once every service in the
//!   process reports `Stopped`, so every dirty exit (fatal, escalation,
//!   panic) would leave a zombie the SCM still shows "Running" and never
//!   restarts. The MSI's failure-actions-on-non-crash-failures flag fires
//!   recovery on a non-zero `Stopped`. If even that final report fails the
//!   process exits with the same code (a dead handle cannot be unwedged any
//!   other way). The whole protocol lives in the platform-neutral
//!   `run::scm` module so Linux CI pins every exit path; this module only
//!   plugs the real status handle in.

use std::{
    any::Any,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};

use windows_service::{
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as WinServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};
use windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;

use crate::{
    EXIT_CODE_FATAL, Outcome, RunError, ShutdownRx,
    run::{
        ServiceExit,
        scm::{self, ScmExitCode, ScmReporter, ScmState, ScmStatus},
    },
};

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The dispatcher entry. `StartServiceCtrlDispatcherW` accepts only a
// non-capturing `extern "system"` fn, so the generic service-main pieces are
// type-erased into a process-global stash (one service main per process is
// the SCM's contract anyway) and the SCM-invoked shim downcasts them back.

/// The app error, type-erased so the erased service main can live in the
/// process-global stash. `as_any_box` is the recovery path: the boxed value
/// IS the original `E`, handed back to `run_windows_service`'s caller.
trait ErasedError: fmt::Debug + Send + Any {
    fn as_any_box(self: Box<Self>) -> Box<dyn Any + Send>;
}

impl<T: fmt::Debug + Send + 'static> ErasedError for T {
    fn as_any_box(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

type ErasedConn = Box<dyn Any + Send + 'static>;
type ErasedErr = Box<dyn ErasedError>;
type ErasedInit = Pin<Box<dyn Future<Output = Outcome<ErasedConn, ErasedErr>> + Send + 'static>>;
type ErasedBodyFut = Pin<Box<dyn Future<Output = Outcome<(), ErasedErr>> + Send + 'static>>;
type ErasedBody = Box<dyn FnOnce(ErasedConn, ShutdownRx) -> ErasedBodyFut + Send + 'static>;

/// Map the error side of an [`Outcome`] — the enum carries no `map_err`,
/// and the erased-stash adapters below need it three times.
fn map_outcome_err<T, E, F>(outcome: Outcome<T, E>, f: impl FnOnce(E) -> F) -> Outcome<T, F> {
    match outcome {
        Outcome::Success(value) => Outcome::Success(value),
        Outcome::Fatal(e) => Outcome::Fatal(f(e)),
    }
}

/// The service-main pieces, stashed before the dispatcher starts and taken
/// by the SCM-invoked [`scm_service_main`].
struct StashedMain {
    service_name: String,
    init: ErasedInit,
    body: ErasedBody,
    result_tx: mpsc::Sender<Result<ServiceExit, RunError<ErasedErr>>>,
}

static STASH: Mutex<Option<StashedMain>> = Mutex::new(None);

/// Set once the dispatcher has answered 1063: this process wasn't started by
/// the SCM, and never will be. Windows lets a process call
/// `StartServiceCtrlDispatcherW` ONCE — a second call fails with 1056
/// (`ERROR_SERVICE_ALREADY_RUNNING`) even after a 1063 — so a process that
/// runs a service main again (an embedder, a test running two cases) goes straight
/// to the console shape, as the unix runner does.
static NOT_UNDER_SCM: AtomicBool = AtomicBool::new(false);

/// Run the service as a Windows service: start the SCM dispatcher, let the
/// SCM invoke the service main on its thread, and translate the outcome the
/// same way [`run_service`] always has. When the binary runs OUTSIDE the
/// SCM (a developer console, `cargo run`), the dispatcher's 1063
/// (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) is caught and the
/// foreground shape runs instead — Ctrl-C forwards into the shutdown
/// channel, mirroring the unix SIGINT runner, with no status protocol.
///
/// Call it from `main` directly: the SCM's documented contract names the
/// process's initial thread. (Calling it from another thread, such as a
/// `spawn_blocking` bridge, works in practice but is outside that contract;
/// verify it on real Windows if you do.)
///
/// The app error is type-erased across the dispatcher boundary and restored
/// before this returns: the value handed back in [`RunError::Fatal`] is the
/// original `E`.
pub fn run_windows_service<IFut, B, BFut, I, E>(
    service_name: &str,
    init: IFut,
    body: B,
) -> Result<ServiceExit, RunError<E>>
where
    IFut: Future<Output = Outcome<I, E>> + Send + 'static,
    B: FnOnce(I, ShutdownRx) -> BFut + Send + 'static,
    BFut: Future<Output = Outcome<(), E>> + Send + 'static,
    I: Send + 'static,
    E: fmt::Debug + Send + 'static,
{
    let init: ErasedInit = Box::pin(async move {
        map_outcome_err(init.await, |e| Box::new(e) as ErasedErr).map(|i| Box::new(i) as ErasedConn)
    });
    let body: ErasedBody = Box::new(move |conn: ErasedConn, shutdown_rx: ShutdownRx| {
        // The stash erased this value as `I`; the shim hands the same type
        // back. A mismatch is a crate bug, never reachable from app code —
        // answered as a fatal outcome (a panic here would unwind across the
        // SCM's `extern "system"` frame: a process abort).
        let i = match conn.downcast::<I>() {
            Ok(i) => *i,
            Err(_) => {
                let mismatch: ErasedErr = Box::new(
                    "service main connection type mismatch (a seaworthy-service bug)".to_owned(),
                );
                return Box::pin(std::future::ready(Outcome::Fatal(mismatch))) as ErasedBodyFut;
            }
        };
        let fut = body(i, shutdown_rx);
        Box::pin(async move { map_outcome_err(fut.await, |e| Box::new(e) as ErasedErr) })
            as ErasedBodyFut
    });

    let (result_tx, result_rx) = mpsc::channel();
    {
        let mut stash = STASH.lock().unwrap_or_else(PoisonError::into_inner);
        if stash.is_some() {
            return Err(RunError::Platform(
                "run_windows_service was already called: the SCM dispatcher admits exactly \
                 one service main per process"
                    .to_owned(),
            ));
        }
        *stash = Some(StashedMain {
            service_name: service_name.to_owned(),
            init,
            body,
            result_tx,
        });
    }

    if NOT_UNDER_SCM.load(Ordering::Acquire) {
        return run_stashed_console();
    }
    match service_dispatcher::start(service_name, scm_service_main) {
        Ok(()) => {
            // The dispatcher blocks until the service stops; the shim sent
            // the disposition before returning.
            result_rx
                .recv()
                .unwrap_or_else(|_| {
                    Err(RunError::Platform(
                        "the service main exited without reporting its disposition".to_owned(),
                    ))
                })
                .map_err(restore_error)
        }
        Err(error) if is_failed_controller_connect(&error) => {
            // 1063: not running under the SCM — developer console / cargo
            // run. Remembered (the dispatcher can't be asked twice), then
            // the foreground shape runs.
            NOT_UNDER_SCM.store(true, Ordering::Release);
            run_stashed_console()
        }
        // windows-service's Display omits the OS error: name it (1056, 1063,
        // …), so a failure says which one.
        Err(windows_service::Error::Winapi(os)) => Err(RunError::Platform(format!(
            "failed to start the SCM service dispatcher: {os}"
        ))),
        Err(error) => Err(RunError::Platform(format!(
            "failed to start the SCM service dispatcher: {error}"
        ))),
    }
}

/// Outside the SCM: take back the service main this call stashed and run
/// the foreground shape (Ctrl-C forwards into the shutdown channel).
fn run_stashed_console<E: fmt::Debug + Send + 'static>() -> Result<ServiceExit, RunError<E>> {
    tracing::info!(
        "not running under the Service Control Manager (1063); running the console shape \
         (Ctrl-C to stop)"
    );
    let Some(stash) = STASH.lock().unwrap_or_else(PoisonError::into_inner).take() else {
        // Stashed by the caller; gone only if a service main ran after all
        // — typed, never a panic.
        return Err(RunError::Platform(
            "the service main stash was already taken".to_owned(),
        ));
    };
    run_console(stash.init, stash.body).map_err(restore_error)
}

/// The SCM-invoked service main: takes the stash and runs the real
/// state machine ([`run_service`]) on the SCM's thread, then reports the
/// disposition back to the blocked [`run_windows_service`] caller.
extern "system" fn scm_service_main(_argc: u32, _argv: *mut *mut u16) {
    // `run_windows_service` stashes the service main before starting the
    // dispatcher. No panic may cross this `extern "system"` frame (it would
    // abort the process): a missing stash (a second SCM invocation) is
    // logged and ignored — the first invocation owns the result channel.
    let Some(stash) = STASH.lock().unwrap_or_else(PoisonError::into_inner).take() else {
        tracing::error!("SCM invoked the service main with no stashed service (already taken)");
        return;
    };
    let result = run_service(&stash.service_name, stash.init, stash.body);
    let _ = stash.result_tx.send(result);
}

/// 1063 (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`): the dispatcher was
/// started outside the SCM — the console-fallback signal, NOT a service
/// failure.
fn is_failed_controller_connect(error: &windows_service::Error) -> bool {
    match error {
        windows_service::Error::Winapi(e) => {
            e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32)
        }
        _ => false,
    }
}

/// Restore the app error the stash erased: [`RunError::Fatal`] carries the
/// original `E` again (downcast by construction — the stash boxed it).
fn restore_error<E: fmt::Debug + Send + 'static>(error: RunError<ErasedErr>) -> RunError<E> {
    match error {
        // The stash boxed the original `E`; a mismatch (a crate bug — or
        // the connection-mismatch marker above) is a platform error, never
        // a panic.
        RunError::Fatal(e) => match e.as_any_box().downcast::<E>() {
            Ok(e) => RunError::Fatal(*e),
            Err(_) => RunError::Platform(
                "service main error type mismatch (a seaworthy-service bug)".to_owned(),
            ),
        },
        RunError::TaskPanicked(d) => RunError::TaskPanicked(d),
        RunError::TaskFailed(d) => RunError::TaskFailed(d),
        RunError::Platform(m) => RunError::Platform(m),
    }
}

/// The foreground shape for a binary started outside the SCM: no status
/// protocol (there is no SCM to report to), Ctrl-C forwards into the
/// shutdown channel — the unix SIGINT runner's mirror — and init is raced
/// against it the same way it is on unix.
fn run_console(init: ErasedInit, body: ErasedBody) -> Result<ServiceExit, RunError<ErasedErr>> {
    let runtime = crate::run::ServiceRuntime::build(crate::run::RUNTIME_SHUTDOWN_GRACE)
        .map_err(|e| RunError::Platform(format!("failed to build the tokio runtime: {e}")))?;
    let result = runtime.block_on(async move {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            // A listener that fails to REGISTER (no console attached — a
            // detached launch, Wine) must never read as a stop request: the
            // old shape logged and then signalled shutdown, winding the
            // service down the instant it started. Log loudly and keep
            // running (the process is then stopped by other means).
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    tracing::info!("shutdown signal received");
                    let _ = shutdown_tx.try_send(());
                }
                Err(e) => {
                    tracing::warn!(
                        "Ctrl-C listener unavailable ({e}); the console shape cannot be stopped \
                         with Ctrl-C"
                    );
                    // Never return: this task owns the sender, and a
                    // closed channel would read as a stop request to the
                    // init race below.
                    std::future::pending::<()>().await;
                }
            }
        });

        let init_or_stop = tokio::select! {
            init_outcome = init => Some(init_outcome),
            _ = shutdown_rx.recv() => None,
        };
        let outcome = match init_or_stop {
            Some(Outcome::Success(value)) => body(value, shutdown_rx).await,
            Some(Outcome::Fatal(e)) => Outcome::Fatal(e),
            None => {
                tracing::info!("shutdown requested during initialization; exiting cleanly");
                Outcome::Success(())
            }
        };

        match outcome {
            Outcome::Success(()) => Ok(ServiceExit::Stopped),
            Outcome::Fatal(e) => Err(RunError::Fatal(e)),
        }
    });
    // Never wait forever on blocking work left in flight.
    runtime.shut_down();
    result
}

// ---------------------------------------------------------------------------

/// Run the service main under the SCM: `Running`, then `init` raced
/// against STOP, then `body`, translating [`Outcome`]s into
/// service status reports. This
/// is the ServiceMain BODY — it must run on the SCM-invoked thread (the
/// [`scm_service_main`] shim does that; apps wiring their own dispatcher
/// with `windows_service`'s `define_windows_service!` must too). Call
/// [`run_windows_service`] instead unless you own the dispatcher.
///
/// * `init`: startup work (typically the first server contact). Its
///   success value is handed to `body`.
/// * `body`: the service loop; receives the init value and a
///   [`ShutdownRx`] that fires when the SCM sends STOP or SHUTDOWN.
/// * `service_name` must match the name the service was installed under —
///   the control handler registers under it.
///
/// Before `init`, once `Running` is reported, the state directory the
/// seaworthy CLI's MSI made for this program
/// (`%ProgramData%\<Vendor>\<Directory>\state` for a program installed in
/// `%ProgramFiles%\<Vendor>\<Directory>`) is audited
/// ([`crate::run::audit_state_directory`]'s rule, for the process's own
/// account): anything in it that someone other than SYSTEM,
/// Administrators, TrustedInstaller or the service could have written,
/// or a reparse point, refuses the start as a failure.
///
/// Every failure (a `Fatal` outcome, a panic, a status report failure)
/// reports `Stopped` with the service-specific
/// [`EXIT_CODE_FATAL`] and returns the error. A control-handler
/// registration failure — no handle to report through, so the dispatcher
/// could never return — and a failed final report exit the process with
/// [`EXIT_CODE_FATAL`] instead.
pub fn run_service<IFut, B, BFut, I, E>(
    service_name: &str,
    init: IFut,
    body: B,
) -> Result<ServiceExit, RunError<E>>
where
    IFut: Future<Output = Outcome<I, E>> + Send + 'static,
    B: FnOnce(I, ShutdownRx) -> BFut,
    BFut: Future<Output = Outcome<(), E>>,
    I: Send + 'static,
    E: fmt::Debug + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
    let status_handle =
        match service_control_handler::register(service_name, move |control_event| {
            // An OS shutdown takes the same graceful path as a stop.
            if matches!(
                control_event,
                ServiceControl::Stop | ServiceControl::Shutdown
            ) {
                let _ = shutdown_tx.try_send(());
            }
            ServiceControlHandlerResult::NoError
        }) {
            Ok(handle) => handle,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "failed to register the service control handler; exiting (no status handle \
                     exists to report Stopped through, so the dispatcher could never return)"
                );
                std::process::exit(EXIT_CODE_FATAL);
            }
        };
    let reporter = HandleReporter(status_handle);
    scm::drive(
        &reporter,
        shutdown_rx,
        // The MSI's state directory, audited before init: a service that
        // can't trust its own state refuses to run (run::state_audit).
        crate::run::state_audit::audit_installed_state,
        init,
        body,
        scm::PRODUCTION_TIMING,
        |code| std::process::exit(code),
    )
}

/// The real status handle behind the platform-neutral [`ScmReporter`].
struct HandleReporter(ServiceStatusHandle);

impl ScmReporter for HandleReporter {
    fn report(&self, status: ScmStatus) -> Result<(), String> {
        let controls = status.controls_accepted();
        let mut controls_accepted = ServiceControlAccept::empty();
        if controls.stop {
            controls_accepted |= ServiceControlAccept::STOP;
        }
        if controls.shutdown {
            controls_accepted |= ServiceControlAccept::SHUTDOWN;
        }
        self.0
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: match status.state {
                    ScmState::StartPending => WinServiceState::StartPending,
                    ScmState::Running => WinServiceState::Running,
                    ScmState::StopPending => WinServiceState::StopPending,
                    ScmState::Stopped => WinServiceState::Stopped,
                },
                controls_accepted,
                exit_code: match status.exit_code {
                    ScmExitCode::Win32(code) => ServiceExitCode::Win32(code),
                    ScmExitCode::ServiceSpecific(code) => ServiceExitCode::ServiceSpecific(code),
                },
                checkpoint: status.checkpoint,
                wait_hint: status.wait_hint,
                process_id: None,
            })
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, future::Ready};

    use super::*;

    /// Compile-level pin: the dispatcher entry exists with a callable,
    /// generic shape. Runtime verification under a real SCM is
    /// `scripts/windows-scm-e2e.ps1`'s, against an MSI-installed service.
    #[test]
    fn the_windows_service_entry_point_is_exported() {
        #[allow(clippy::type_complexity)] // the fn-pointer shape IS the assertion
        fn assert_entry<E: fmt::Debug + Send + 'static>(
            _f: fn(
                &str,
                Ready<Outcome<(), E>>,
                fn((), ShutdownRx) -> Ready<Outcome<(), E>>,
            ) -> Result<ServiceExit, RunError<E>>,
        ) {
        }
        assert_entry::<Infallible>(run_windows_service::<_, _, _, _, _>);
    }

    /// The SCM-invoked shim exists and is shaped like a ServiceMain —
    /// `service_dispatcher::start` accepts exactly this fn-pointer type.
    #[test]
    fn the_service_main_shim_matches_the_dispatcher_contract() {
        let _main: extern "system" fn(u32, *mut *mut u16) = scm_service_main;
    }
}
