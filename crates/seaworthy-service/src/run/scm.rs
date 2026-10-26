//! The SCM status protocol around init + body, platform-neutral.
//!
//! This is the state machine [`run_service`](crate::run_service) runs on
//! Windows, lifted out of the `cfg(windows)` module so Linux CI pins every
//! exit path. (An earlier fatal path deliberately never reported
//! `Stopped`, which under the SCM dispatcher left the process hanging
//! "Running" forever with no recovery, and the only test that could have
//! noticed ran on Windows alone.) The Windows module plugs the real
//! `ServiceStatusHandle` in through [`ScmReporter`]; the tests plug a
//! recorder in.
//!
//! The protocol:
//!
//! * `StartPending` covers only the process's own setup (the runtime);
//!   `Running` follows at once, BEFORE init. Init is typically a
//!   retry-forever connect: an unreachable server or a version mismatch
//!   can hold it for hours. A `StartPending` service that accepts no
//!   controls answers STOP with 1061, and an MSI's `ServiceControl` start
//!   that waits (`Wait="yes"`) waits at most 30 s for `Running`, then fails
//!   the install with 1920 and rolls it back (its stop on upgrade likewise,
//!   1921). The seaworthy CLI's MSI starts the service without that wait,
//!   since a service may retire at once (exit 0), and waits for the stop.
//!   The package manager stops and restarts the service to update it, so a
//!   service must be startable and stoppable from the start. Init is raced
//!   against the stop instead, as on unix: a stop during init is a clean
//!   exit. Microsoft's guidance for a lengthy start is close: report
//!   `Running`, initialize, and accept controls once ready; this crate
//!   accepts STOP and SHUTDOWN from the start because its init can always
//!   be cancelled. A further reason not to go back: a service can't call
//!   `StartService` while its own start is pending (the SCM holds its
//!   lock), and a connect-time update request starts `<name>-update` from
//!   init.
//! * Every exit shuts the runtime down with a bounded grace BEFORE the
//!   final `Stopped`: a lingering blocking job (a slow DNS lookup) must not
//!   keep the process, and its files, alive after the SCM was told it
//!   stopped.
//! * `Running` accepts STOP **and SHUTDOWN** (an OS shutdown takes the
//!   same graceful path as a stop); every pending state accepts nothing.
//! * **Every failure path ends with `Stopped` + the service-specific
//!   [`EXIT_CODE_FATAL`]**: init/body `Fatal`, a panic anywhere in the
//!   service main, and a status-report failure. The
//!   dispatcher (`StartServiceCtrlDispatcherW`) returns only once the
//!   service reports `Stopped`; the MSI's
//!   failure-actions-on-non-crash-failures flag turns the non-zero code
//!   into the recovery action. If that final report itself fails, the
//!   handle is dead and nothing else can unwedge the dispatcher, so the
//!   injected `hard_exit` (production: `std::process::exit`) ends the
//!   process with the same code — the SCM then sees a crash and recovers.

use std::{
    any::Any,
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use crate::{
    EXIT_CODE_FATAL, Outcome, RunError, ShutdownRx,
    run::{RUNTIME_SHUTDOWN_GRACE, ServiceExit, ServiceRuntime},
};

// ---------------------------------------------------------------------------

/// The SCM states this state machine reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScmState {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

/// The exit-code shapes of a `SERVICE_STATUS`: a Win32 code (0 = clean) or
/// an app-private service-specific code (`ERROR_SERVICE_SPECIFIC_ERROR` +
/// `dwServiceSpecificExitCode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScmExitCode {
    Win32(u32),
    ServiceSpecific(u32),
}

/// The controls a state accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScmControls {
    pub(crate) stop: bool,
    pub(crate) shutdown: bool,
}

/// One status report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScmStatus {
    pub(crate) state: ScmState,
    pub(crate) exit_code: ScmExitCode,
    pub(crate) checkpoint: u32,
    pub(crate) wait_hint: Duration,
}

impl ScmStatus {
    /// STOP + SHUTDOWN only in `Running` (which covers init); the
    /// pending states, which last only while the runtime is built or shut
    /// down, accept nothing.
    pub(crate) fn controls_accepted(&self) -> ScmControls {
        let running = self.state == ScmState::Running;
        ScmControls {
            stop: running,
            shutdown: running,
        }
    }

    fn stopped(exit_code: ScmExitCode) -> Self {
        Self {
            state: ScmState::Stopped,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::ZERO,
        }
    }
}

/// Where status reports go: the real `ServiceStatusHandle` on Windows, a
/// recorder in the tests.
pub(crate) trait ScmReporter {
    fn report(&self, status: ScmStatus) -> Result<(), String>;
}

/// The protocol's wait hints (production values in [`PRODUCTION_TIMING`]).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScmTiming {
    /// How long the SCM should wait before distrusting the `StartPending`
    /// that covers the runtime's setup.
    pub(crate) start_wait_hint: Duration,
    /// Wait hint for a stop.
    pub(crate) stop_wait_hint: Duration,
    /// How long the runtime's blocking work may delay `Stopped`;
    /// below `stop_wait_hint`.
    pub(crate) runtime_shutdown_grace: Duration,
}

/// The production timing: a 30 s start hint, a 10 s stop hint, and the
/// runtime's 5 s shutdown grace.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const PRODUCTION_TIMING: ScmTiming = ScmTiming {
    start_wait_hint: Duration::from_secs(30),
    stop_wait_hint: Duration::from_secs(10),
    runtime_shutdown_grace: RUNTIME_SHUTDOWN_GRACE,
};

// ---------------------------------------------------------------------------

/// Run init + body under the SCM status protocol. `shutdown_rx` is fed by
/// the caller's control handler (STOP and SHUTDOWN). `precheck` runs once
/// `Running` is reported, before `init` (production: the state
/// directory's audit); its error is a failure like a fatal one. `hard_exit`
/// is the last resort when even the final `Stopped` report fails
/// (production: `std::process::exit`); a test hook records the code and
/// returns.
pub(crate) fn drive<R, IFut, B, BFut, I, E>(
    reporter: &R,
    shutdown_rx: ShutdownRx,
    precheck: impl FnOnce() -> Result<(), String>,
    init: IFut,
    body: B,
    timing: ScmTiming,
    hard_exit: impl FnOnce(i32),
) -> Result<ServiceExit, RunError<E>>
where
    R: ScmReporter + ?Sized,
    IFut: Future<Output = Outcome<I, E>> + Send + 'static,
    B: FnOnce(I, ShutdownRx) -> BFut,
    BFut: Future<Output = Outcome<(), E>>,
    I: Send + 'static,
    E: fmt::Debug + Send + 'static,
{
    // A panic anywhere in the service main (init, the body's own future)
    // must take the failure path too: unwinding out
    // of the SCM's `extern "system"` ServiceMain aborts the process with
    // no `Stopped` report at all.
    let result = catch_unwind(AssertUnwindSafe(|| {
        drive_inner(reporter, shutdown_rx, precheck, init, body, timing)
    }))
    .unwrap_or_else(|panic| {
        Err(RunError::TaskPanicked(format!(
            "service main panicked: {}",
            panic_detail(panic.as_ref())
        )))
    });

    if let Err(error) = &result {
        tracing::error!(
            error = %crate::log::line_safe(&format!("{error:?}")),
            exit_code = EXIT_CODE_FATAL,
            "service failed; reporting Stopped with the fatal service-specific exit code \
             so the SCM's recovery actions restart it"
        );
        if let Err(report_error) = reporter.report(ScmStatus::stopped(
            ScmExitCode::ServiceSpecific(EXIT_CODE_FATAL as u32),
        )) {
            // The handle is dead: the dispatcher will never see `Stopped`
            // and never return. Exiting is the only way out, and the SCM
            // then reads a crash — the recovery actions still fire.
            tracing::error!(
                report_error = %crate::log::line_safe(&report_error),
                "the final Stopped report failed; exiting the process"
            );
            hard_exit(EXIT_CODE_FATAL);
        }
    }
    result
}

fn drive_inner<R, IFut, B, BFut, I, E>(
    reporter: &R,
    shutdown_rx: ShutdownRx,
    precheck: impl FnOnce() -> Result<(), String>,
    init: IFut,
    body: B,
    timing: ScmTiming,
) -> Result<ServiceExit, RunError<E>>
where
    R: ScmReporter + ?Sized,
    IFut: Future<Output = Outcome<I, E>> + Send + 'static,
    B: FnOnce(I, ShutdownRx) -> BFut,
    BFut: Future<Output = Outcome<(), E>>,
    I: Send + 'static,
    E: fmt::Debug + Send + 'static,
{
    report(
        reporter,
        ScmState::StartPending,
        ScmExitCode::Win32(0),
        1,
        timing.start_wait_hint,
    )?;

    // Shut down with a bounded grace on every path, panics included
    // (dropping a runtime waits forever for blocking work).
    let runtime = ServiceRuntime::build(timing.runtime_shutdown_grace)
        .map_err(|e| RunError::Platform(format!("failed to build the tokio runtime: {e}")))?;

    // Running (STOP + SHUTDOWN accepted) before init, so a service
    // retrying its connect can always be stopped (see the module docs).
    report(
        reporter,
        ScmState::Running,
        ScmExitCode::Win32(0),
        0,
        Duration::ZERO,
    )?;

    // A service that can't trust its own state refuses to run: the caller
    // (`drive`) reports `Stopped` + EXIT_CODE_FATAL.
    if let Err(why) = precheck() {
        runtime.shut_down();
        return Err(RunError::Platform(format!(
            "refusing to run: {}",
            crate::log::line_safe(&why)
        )));
    }

    let outcome = runtime.block_on(async move {
        let mut shutdown_rx = shutdown_rx;
        let init_or_stop = {
            // A closed channel (no handler holds the sender) means no stop
            // can come: init then runs to completion.
            let stop = async {
                if shutdown_rx.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            };
            tokio::select! {
                init_outcome = init => Some(init_outcome),
                () = stop => None,
            }
        };
        match init_or_stop {
            Some(Outcome::Success(value)) => body(value, shutdown_rx).await,
            Some(Outcome::Fatal(e)) => Outcome::Fatal(e),
            None => {
                tracing::info!("stop requested during initialization; exiting cleanly");
                Outcome::Success(())
            }
        }
    });

    match outcome {
        Outcome::Success(()) => {
            let pending = report(
                reporter,
                ScmState::StopPending,
                ScmExitCode::Win32(0),
                1,
                timing.stop_wait_hint,
            );
            // `Stopped` only once the runtime is down, so an MSI
            // that waits for it never finds the process still holding its
            // files.
            runtime.shut_down();
            pending?;
            report(
                reporter,
                ScmState::Stopped,
                ScmExitCode::Win32(0),
                0,
                Duration::ZERO,
            )?;
            Ok(ServiceExit::Stopped)
        }
        // The caller (`drive`) reports `Stopped` + EXIT_CODE_FATAL, after
        // the runtime is down.
        Outcome::Fatal(e) => {
            runtime.shut_down();
            Err(RunError::Fatal(e))
        }
    }
}

fn report<R: ScmReporter + ?Sized, E: fmt::Debug>(
    reporter: &R,
    state: ScmState,
    exit_code: ScmExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> Result<(), RunError<E>> {
    reporter
        .report(ScmStatus {
            state,
            exit_code,
            checkpoint,
            wait_hint,
        })
        .map_err(|e| RunError::Platform(format!("failed to report {state:?} to the SCM: {e}")))
}

/// The panic payload's message, when it is one of the two standard shapes.
fn panic_detail(panic: &(dyn Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Mutex};

    use super::*;

    const FAST: ScmTiming = ScmTiming {
        start_wait_hint: Duration::from_secs(30),
        stop_wait_hint: Duration::from_secs(10),
        runtime_shutdown_grace: Duration::from_millis(100),
    };

    /// Records every report; optionally fails the Nth report (1-based) or
    /// every report from the Nth on.
    #[derive(Default)]
    struct Recorder {
        reports: Mutex<Vec<ScmStatus>>,
        fail_at: Option<usize>,
        fail_from: Option<usize>,
    }

    impl ScmReporter for Recorder {
        fn report(&self, status: ScmStatus) -> Result<(), String> {
            let mut reports = self.reports.lock().expect("reports");
            reports.push(status);
            let n = reports.len();
            if self.fail_at == Some(n) || self.fail_from.is_some_and(|from| n >= from) {
                return Err("the SCM rejected the status".to_owned());
            }
            Ok(())
        }
    }

    impl Recorder {
        fn last(&self) -> ScmStatus {
            *self
                .reports
                .lock()
                .expect("reports")
                .last()
                .expect("a report")
        }
        fn states(&self) -> Vec<ScmState> {
            self.reports
                .lock()
                .expect("reports")
                .iter()
                .map(|s| s.state)
                .collect()
        }
        /// The states with each run of a pending state's checkpoint bumps
        /// collapsed to one entry (the ORDER of phases is the contract).
        /// Within a run, the checkpoints must count up by one.
        fn phases(&self) -> Vec<ScmState> {
            let reports = self.reports.lock().expect("reports");
            let mut phases: Vec<ScmState> = Vec::new();
            let mut previous: Option<ScmStatus> = None;
            for status in reports.iter() {
                let pending =
                    matches!(status.state, ScmState::StartPending | ScmState::StopPending);
                match previous {
                    Some(prev) if pending && prev.state == status.state => assert_eq!(
                        status.checkpoint,
                        prev.checkpoint + 1,
                        "a {:?} checkpoint must count up by one: {reports:?}",
                        status.state
                    ),
                    _ => phases.push(status.state),
                }
                previous = Some(*status);
            }
            phases
        }
    }

    const FATAL_STOP: ScmStatus = ScmStatus {
        state: ScmState::Stopped,
        exit_code: ScmExitCode::ServiceSpecific(EXIT_CODE_FATAL as u32),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
    };

    /// A shutdown channel nobody can send on (closed).
    fn channel() -> ShutdownRx {
        tokio::sync::mpsc::channel(1).1
    }

    /// Runs `drive` with a recorder, returning the result and whether the
    /// hard exit fired.
    fn run<IFut, B, BFut, E>(
        recorder: &Recorder,
        init: IFut,
        body: B,
    ) -> (Result<ServiceExit, RunError<E>>, Option<i32>)
    where
        IFut: Future<Output = Outcome<(), E>> + Send + 'static,
        B: FnOnce((), ShutdownRx) -> BFut,
        BFut: Future<Output = Outcome<(), E>>,
        E: fmt::Debug + Send + 'static,
    {
        run_with(recorder, channel(), init, body)
    }

    /// [`run`] with the caller's shutdown channel.
    fn run_with<IFut, B, BFut, E>(
        recorder: &Recorder,
        shutdown_rx: ShutdownRx,
        init: IFut,
        body: B,
    ) -> (Result<ServiceExit, RunError<E>>, Option<i32>)
    where
        IFut: Future<Output = Outcome<(), E>> + Send + 'static,
        B: FnOnce((), ShutdownRx) -> BFut,
        BFut: Future<Output = Outcome<(), E>>,
        E: fmt::Debug + Send + 'static,
    {
        let exited = Mutex::new(None);
        let result = drive(
            recorder,
            shutdown_rx,
            || Ok(()),
            init,
            body,
            FAST,
            |code| {
                *exited.lock().expect("exited") = Some(code);
            },
        );
        (result, exited.into_inner().expect("exited"))
    }

    // ---- every failure path reports Stopped + a non-zero code ----

    #[test]
    fn an_untrusted_state_refuses_to_run_before_init() {
        let recorder = Recorder::default();
        let init_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran = std::sync::Arc::clone(&init_ran);
        let exited = Mutex::new(None);
        let result = drive(
            &recorder,
            channel(),
            || {
                Err(
                    "C:\\ProgramData\\Acme\\Agent\\state\\x grants S-1-5-21-1 write access"
                        .to_owned(),
                )
            },
            async move {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                Outcome::<(), Infallible>::Success(())
            },
            |(), _| async { Outcome::Success(()) },
            FAST,
            |code| *exited.lock().expect("exited") = Some(code),
        );
        let error = result.expect_err("refused");
        assert!(
            format!("{error:?}").contains("refusing to run"),
            "{error:?}"
        );
        assert!(
            !init_ran.load(std::sync::atomic::Ordering::SeqCst),
            "init never ran"
        );
        let last = recorder.last();
        assert_eq!(last.state, ScmState::Stopped);
        assert_eq!(
            last.exit_code,
            ScmExitCode::ServiceSpecific(EXIT_CODE_FATAL as u32)
        );
        assert_eq!(*exited.lock().expect("exited"), None, "the report worked");
    }

    #[test]
    fn init_fatal_reports_stopped_with_the_fatal_code() {
        let recorder = Recorder::default();
        let (result, exited) = run(
            &recorder,
            async { Outcome::<(), _>::Fatal("server refused") },
            |(), _| async { Outcome::Success(()) },
        );
        assert!(matches!(result, Err(RunError::Fatal("server refused"))));
        assert_eq!(recorder.last(), FATAL_STOP, "{:?}", recorder.states());
        assert_eq!(exited, None, "the report succeeded: no hard exit");
    }

    #[test]
    fn body_fatal_reports_stopped_with_the_fatal_code() {
        // A supervisor's TaskFailed / TaskPanicked ride this path (the
        // body's `Fatal`).
        let recorder = Recorder::default();
        let (result, _) = run(
            &recorder,
            async { Outcome::<(), _>::Success(()) },
            |(), _| async { Outcome::Fatal("escalation bound exceeded") },
        );
        assert!(matches!(result, Err(RunError::Fatal(_))));
        assert_eq!(
            recorder.phases(),
            vec![ScmState::StartPending, ScmState::Running, ScmState::Stopped]
        );
        assert_eq!(recorder.last(), FATAL_STOP);
    }

    /// `Running` (STOP accepted) is reported BEFORE init
    /// finishes, however long init takes, and StartPending only once.
    #[test]
    fn running_is_reported_before_init_finishes() {
        /// A reporter init can see: the states reported so far.
        struct Shared(std::sync::Arc<Mutex<Vec<ScmState>>>);
        impl ScmReporter for Shared {
            fn report(&self, status: ScmStatus) -> Result<(), String> {
                self.0.lock().expect("states").push(status.state);
                Ok(())
            }
        }
        let states = std::sync::Arc::new(Mutex::new(Vec::new()));
        let observed = std::sync::Arc::clone(&states);
        let at_init_end = std::sync::Arc::new(Mutex::new(None));
        let snapshot = std::sync::Arc::clone(&at_init_end);
        let result = drive(
            &Shared(std::sync::Arc::clone(&states)),
            channel(),
            || Ok(()),
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                *snapshot.lock().expect("snapshot") =
                    Some(observed.lock().expect("states").clone());
                Outcome::<(), Infallible>::Success(())
            },
            |(), _| async { Outcome::Success(()) },
            FAST,
            |_| {},
        );
        assert_eq!(result.expect("clean"), ServiceExit::Stopped);
        assert_eq!(
            at_init_end.lock().expect("snapshot").clone(),
            Some(vec![ScmState::StartPending, ScmState::Running]),
            "init ended after exactly StartPending, Running"
        );
        assert_eq!(
            states.lock().expect("states").clone(),
            vec![
                ScmState::StartPending,
                ScmState::Running,
                ScmState::StopPending,
                ScmState::Stopped
            ]
        );
    }

    /// A stop during a never-ending init (an unreachable server, a
    /// version mismatch) is a clean exit: the init future is dropped, no
    /// body runs, and the SCM sees `Stopped` with Win32 0.
    #[test]
    fn a_stop_during_init_is_a_clean_exit() {
        let recorder = Recorder::default();
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
        shutdown_tx.try_send(()).expect("queue the stop");
        let body_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran = std::sync::Arc::clone(&body_ran);
        let (result, exited) = run_with(
            &recorder,
            shutdown_rx,
            std::future::pending::<Outcome<(), Infallible>>(),
            move |(), _| {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                async { Outcome::Success(()) }
            },
        );
        assert_eq!(result.expect("clean"), ServiceExit::Stopped);
        assert_eq!(exited, None);
        assert!(!body_ran.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            recorder.phases(),
            vec![
                ScmState::StartPending,
                ScmState::Running,
                ScmState::StopPending,
                ScmState::Stopped
            ]
        );
        assert_eq!(recorder.last().exit_code, ScmExitCode::Win32(0));
        drop(shutdown_tx);
    }

    /// Blocking work still in flight when a stop lands mid-init
    /// (a slow DNS lookup inside a connect) delays `Stopped` by the
    /// runtime's grace at most, and `Stopped` comes after it: an MSI that
    /// waits for `Stopped` never finds the process still holding its files.
    #[test]
    fn stopped_follows_the_runtime_shutdown_and_waits_the_grace_at_most() {
        /// The time of each report.
        struct Timed(Mutex<Vec<(ScmState, std::time::Instant)>>);
        impl ScmReporter for Timed {
            fn report(&self, status: ScmStatus) -> Result<(), String> {
                self.0
                    .lock()
                    .expect("times")
                    .push((status.state, std::time::Instant::now()));
                Ok(())
            }
        }
        let reporter = Timed(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);
        let started = std::time::Instant::now();
        let result = drive(
            &reporter,
            shutdown_rx,
            || Ok(()),
            // The stop comes from init itself, once the blocking work is in
            // flight (a stop queued up front could win the race before init
            // was ever polled).
            async move {
                drop(tokio::task::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_secs(60));
                }));
                shutdown_tx.send(()).await.expect("the stop");
                std::future::pending::<Outcome<(), Infallible>>().await
            },
            |(), _| async { Outcome::Success(()) },
            FAST,
            |_| {},
        );
        assert_eq!(result.expect("clean"), ServiceExit::Stopped);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "Stopped waited on the blocking work ({:?})",
            started.elapsed()
        );
        let times = reporter.0.into_inner().expect("times");
        let at = |state| {
            times
                .iter()
                .find(|(s, _)| *s == state)
                .map(|(_, t)| *t)
                .expect("reported")
        };
        assert!(
            at(ScmState::Stopped).duration_since(at(ScmState::StopPending))
                >= FAST.runtime_shutdown_grace,
            "Stopped was reported before the runtime shut down: {times:?}"
        );
    }

    /// A closed shutdown channel never reads as a stop: init runs to the
    /// end and the body runs.
    #[test]
    fn a_closed_shutdown_channel_never_reads_as_a_stop_during_init() {
        let recorder = Recorder::default();
        let (result, _) = run(
            &recorder,
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Outcome::<(), _>::Success(())
            },
            |(), _| async { Outcome::Fatal("the body ran") },
        );
        assert!(matches!(result, Err(RunError::Fatal("the body ran"))));
    }

    #[test]
    fn a_panicking_body_reports_stopped_with_the_fatal_code() {
        let recorder = Recorder::default();
        let (result, _) = run(
            &recorder,
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _| async { panic!("body blew up") },
        );
        match result {
            Err(RunError::TaskPanicked(detail)) => assert!(detail.contains("body blew up")),
            other => panic!("expected TaskPanicked, got {other:?}"),
        }
        assert_eq!(recorder.last(), FATAL_STOP);
    }

    #[test]
    fn a_panicking_init_reports_stopped_with_the_fatal_code() {
        let recorder = Recorder::default();
        let (result, _) = run(&recorder, async { panic!("init blew up") }, |(), _| async {
            Outcome::<(), Infallible>::Success(())
        });
        match result {
            Err(RunError::TaskPanicked(detail)) => assert!(detail.contains("init blew up")),
            other => panic!("expected TaskPanicked, got {other:?}"),
        }
        assert_eq!(recorder.last(), FATAL_STOP);
    }

    #[test]
    fn a_platform_error_reports_stopped_with_the_fatal_code() {
        // The Running report (the 2nd) fails: a Platform error after the
        // handler registered — the final Stopped report still goes out.
        let recorder = Recorder {
            fail_at: Some(2),
            ..Recorder::default()
        };
        let (result, exited) = run(
            &recorder,
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _| async { Outcome::Success(()) },
        );
        assert!(matches!(result, Err(RunError::Platform(_))), "{result:?}");
        assert_eq!(recorder.last(), FATAL_STOP);
        assert_eq!(exited, None);
    }

    #[test]
    fn a_dead_handle_hard_exits_with_the_fatal_code() {
        // Every report fails: the final Stopped cannot land, the
        // dispatcher would never return — the process must exit.
        let recorder = Recorder {
            fail_from: Some(1),
            ..Recorder::default()
        };
        let (result, exited) = run(
            &recorder,
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _| async { Outcome::Success(()) },
        );
        assert!(result.is_err());
        assert_eq!(exited, Some(EXIT_CODE_FATAL));
        assert_ne!(EXIT_CODE_FATAL, 0);
    }

    // ---- the clean disposition ----

    #[test]
    fn a_clean_stop_reports_stopped_win32_zero() {
        let recorder = Recorder::default();
        let (result, _) = run(
            &recorder,
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _| async { Outcome::Success(()) },
        );
        assert_eq!(result.expect("clean"), ServiceExit::Stopped);
        assert_eq!(recorder.last().exit_code, ScmExitCode::Win32(0));
    }

    // ---- SHUTDOWN is accepted in Running ----

    #[test]
    fn running_accepts_stop_and_shutdown_pending_states_nothing() {
        let status = |state| ScmStatus {
            state,
            exit_code: ScmExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
        };
        assert_eq!(
            status(ScmState::Running).controls_accepted(),
            ScmControls {
                stop: true,
                shutdown: true
            }
        );
        for state in [
            ScmState::StartPending,
            ScmState::StopPending,
            ScmState::Stopped,
        ] {
            assert_eq!(
                status(state).controls_accepted(),
                ScmControls {
                    stop: false,
                    shutdown: false
                },
                "{state:?}"
            );
        }
    }
}
