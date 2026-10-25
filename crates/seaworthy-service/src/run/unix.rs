//! Unix body of [`run_service`](crate::run_service): no status protocol to
//! speak — systemd tracks the process itself — so this is init, body, and
//! honest exit codes, plus forwarding SIGTERM/SIGINT into the shutdown
//! channel. Init is RACED against that channel: `systemctl stop` on a
//! daemon still retrying its first connect exits cleanly instead of
//! hanging until the supervisor's SIGKILL (the Windows SCM twin reports
//! `Running` before init and races it against STOP the same way).

use std::{fmt, future::Future};

use tokio::sync::mpsc;

use crate::{
    Outcome, RunError, ShutdownRx,
    run::{RUNTIME_SHUTDOWN_GRACE, ServiceExit, ServiceRuntime},
};

// ---------------------------------------------------------------------------

/// Run the service main: `init`, then `body`, translating [`Outcome`]s into
/// process-level results.
///
/// * `init`: startup work (typically the first server contact). Its
///   success value is handed to `body`.
/// * `body`: the service loop; receives the init value and a
///   [`ShutdownRx`] that fires on SIGTERM/SIGINT.
/// * `service_name` is ignored on unix (systemd learns the name from the
///   unit file); it exists so call sites stay platform-neutral.
///
/// [`Outcome::Fatal`] from either phase returns [`RunError::Fatal`]: `main`
/// should let that escape as a non-zero exit code, which is exactly what
/// `Restart=on-failure` keys on.
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
    let _ = service_name;
    run_with_grace(init, body, RUNTIME_SHUTDOWN_GRACE)
}

/// [`run_service`] with the runtime's shutdown grace as a parameter (the
/// tests drive it at milliseconds).
fn run_with_grace<IFut, B, BFut, I, E>(
    init: IFut,
    body: B,
    grace: std::time::Duration,
) -> Result<ServiceExit, RunError<E>>
where
    IFut: Future<Output = Outcome<I, E>> + Send + 'static,
    B: FnOnce(I, ShutdownRx) -> BFut,
    BFut: Future<Output = Outcome<(), E>>,
    I: Send + 'static,
    E: fmt::Debug + Send + 'static,
{
    let runtime = ServiceRuntime::build(grace)
        .map_err(|e| RunError::Platform(format!("failed to build the tokio runtime: {e}")))?;

    let result = runtime.block_on(async move {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        spawn_shutdown_listener(shutdown_tx).map_err(RunError::Platform)?;

        // `init` (typically a retry-forever connect against a down
        // server) must not outrun the supervisor's stop: a SIGTERM landing
        // while init retries would otherwise sit unread in the channel
        // until systemd's `TimeoutStopSec` (90 s) escalated to SIGKILL.
        // Race init against the signal; a stop during init is a clean
        // exit, and the init future is dropped (its retry sleep cancelled).
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

/// Forward the first SIGTERM (systemd stop) or SIGINT (Ctrl-C during manual
/// runs) into the shutdown channel.
fn spawn_shutdown_listener(shutdown_tx: mpsc::Sender<()>) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|e| format!("failed to install the SIGTERM handler: {e}"))?;
    tokio::spawn(async move {
        // A SIGINT listener that fails to register must never read as a
        // stop request (it used to — the daemon wound down the instant it
        // started); keep waiting on SIGTERM instead.
        let interrupt = async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::warn!(
                    "SIGINT listener unavailable ({e}); SIGTERM still stops the service"
                );
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = terminate.recv() => {}
            () = interrupt => {}
        }
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.try_send(());
    });
    Ok(())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use crate::{Outcome, RunError};

    /// SIGTERM during a retry-forever init (the server down, the
    /// connect retrying per the default policy) must exit cleanly and
    /// promptly — `systemctl stop` would otherwise sit in `TimeoutStopSec`
    /// for 90 s and escalate to SIGKILL. The test runs `run_service` on a
    /// thread with an init that never resolves, delivers SIGTERM to our own
    /// process through `kill(1)` (no libc dep), and asserts the clean exit
    /// lands in seconds. The signal is consumed by the runtime's listener;
    /// under nextest this process hosts only this test.
    #[test]
    fn sigterm_during_a_retry_forever_init_exits_clean_promptly() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = crate::run_service(
                "acme-test-service",
                // Retry-forever connect shape: never resolves.
                std::future::pending::<Outcome<(), &str>>(),
                |(), _shutdown| async { Outcome::<(), &str>::Success(()) },
            );
            let _ = tx.send(result);
        });

        // Give init time to start retrying, then stop the service.
        std::thread::sleep(Duration::from_millis(500));
        let delivered = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .expect("spawn kill(1) to deliver SIGTERM to ourselves");
        assert!(delivered.success(), "kill -TERM must deliver");

        let result = rx.recv_timeout(Duration::from_secs(10)).expect(
            "SIGTERM during a retry-forever init must exit cleanly in seconds, \
             not hang for the supervisor's SIGKILL (a disconnect means the \
             service thread panicked)",
        );
        match result {
            Ok(exit) => assert_eq!(exit.code(), 0, "clean shutdown exits 0"),
            Err(error) => panic!("a signal-driven stop during init must not fail: {error:?}"),
        }
    }

    /// The clean-shutdown path (SIGTERM/SIGINT/SCM STOP/an in-process shutdown →
    /// the body reporting Success) stays exit 0: the supervisor must NOT
    /// restart a service it asked to stop.
    #[test]
    fn a_clean_shutdown_stays_exit_zero() {
        let result = crate::run_service(
            "acme-test-service",
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _shutdown| async { Outcome::Success(()) },
        );
        match result {
            Ok(exit) => assert_eq!(exit.code(), 0, "clean stops exit 0"),
            Err(error) => panic!("a clean shutdown must not fail: {error:?}"),
        }
    }

    /// Blocking work still in flight (a 60 s DNS lookup inside a
    /// connect) delays the exit by the runtime's grace at most, never
    /// until the work ends.
    #[test]
    fn lingering_blocking_work_delays_the_exit_by_the_grace_at_most() {
        let started = std::time::Instant::now();
        let result = super::run_with_grace(
            async { Outcome::<(), Infallible>::Success(()) },
            |(), _shutdown| async {
                drop(tokio::task::spawn_blocking(|| {
                    std::thread::sleep(Duration::from_secs(60));
                }));
                Outcome::Success(())
            },
            Duration::from_millis(100),
        );
        assert!(
            matches!(result, Ok(crate::ServiceExit::Stopped)),
            "{result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the exit waited on the blocking work ({:?})",
            started.elapsed()
        );
    }

    /// Fatal from init or the body is an Err (a non-zero exit `main`
    /// chooses), not a disposition: the dirty-exit contract.
    #[test]
    fn a_fatal_outcome_is_an_error_not_a_disposition() {
        let result = crate::run_service(
            "acme-test-service",
            async { Outcome::<(), &str>::Success(()) },
            |(), _shutdown| async { Outcome::<(), &str>::Fatal("disk gone") },
        );
        assert!(matches!(result, Err(RunError::Fatal("disk gone"))));
        let result = crate::run_service(
            "acme-test-service",
            async { Outcome::<(), &str>::Fatal("no config") },
            |(), _shutdown| async { Outcome::<(), &str>::Success(()) },
        );
        assert!(matches!(result, Err(RunError::Fatal("no config"))));
    }
}
