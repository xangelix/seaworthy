//! Error types for the renderers' validation, service-manager operations
//! and the service-main state machine.
//!
//! Library code never sees the app's own error type: the state machine is
//! generic over it (`RunError<E>`), and validation and backend failures
//! collapse into the small platform-agnostic [`ServiceError`] taxonomy.

#[cfg(feature = "runtime")]
use std::fmt;

// ---------------------------------------------------------------------------

/// Failures of start/stop/status operations against an OS service manager,
/// and of the renderers' validation (`render`).
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The service is not registered.
    #[error("service does not exist")]
    DoesNotExist,
    /// The service did not reach `Running` within the configured timeout.
    #[error("timed out waiting for the service to start")]
    StartTimeout,
    /// The service did not reach `Stopped` within the configured timeout.
    #[error("timed out waiting for the service to stop")]
    StopTimeout,
    /// The service name is unusable as a unit file name / SCM name (must
    /// start with an ASCII letter or digit; no path separators,
    /// whitespace, control characters, `%` specifiers, or a
    /// leading `-`): rejected before the service manager is asked.
    #[error("invalid service name: {0}")]
    InvalidName(String),
    /// The spec's CONTENT is unusable on this platform (a relative or
    /// modifier-prefixed `program` path, non-UTF-8 `ExecStart` tokens,
    /// sub-second `FailurePolicy` durations that would render
    /// zero/disabling values, a whitespace/control-bearing
    /// `EnvironmentFile=` path on systemd, or a malformed Windows service
    /// account): rejected before anything is rendered. Distinct from
    /// [`ServiceError::InvalidName`] by what to fix: the spec, not the
    /// name.
    #[error("invalid service spec: {0}")]
    InvalidSpec(String),
    /// Filesystem or process-spawn failure (exec'ing `systemctl` or
    /// `launchctl`, ...).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Anything else the platform reported; carries the tool's stderr or
    /// the OS error's debug form so no context is lost.
    #[error("platform error: {0}")]
    Platform(String),
}

// Maps the SCM error callers actually branch on; everything else keeps its
// debug form verbatim.
#[cfg(all(feature = "runtime", windows))]
impl From<windows_service::Error> for ServiceError {
    fn from(error: windows_service::Error) -> Self {
        use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST as WSYS_ERROR_SERVICE_DOES_NOT_EXIST;

        match error {
            windows_service::Error::Winapi(e) => e.raw_os_error().map_or_else(
                || Self::Platform(format!("{e:?}")),
                |r| match r as u32 {
                    WSYS_ERROR_SERVICE_DOES_NOT_EXIST => Self::DoesNotExist,
                    _ => Self::Platform(format!("{e:?}")),
                },
            ),
            _ => Self::Platform(format!("{error:?}")),
        }
    }
}

// ---------------------------------------------------------------------------

/// Terminal result of [`crate::run_service`].
///
/// Returning `Err` from the service main is meaningful: it is a dirty exit
/// the supervisor's failure recovery keys on. On Windows the state machine
/// reports `Stopped` with the service-specific code
/// [`crate::EXIT_CODE_FATAL`] before returning (the SCM dispatcher only
/// returns once the service reports `Stopped`, and the MSI's
/// failure-actions-on-non-crash-failures flag turns a non-zero `Stopped`
/// into the recovery action); under systemd `main` exits with
/// [`RunError::exit_code`] and `Restart=on-failure` keys on it. `Fatal`
/// therefore means "the supervisor should restart us", never "report a
/// clean stop".
#[cfg(feature = "runtime")]
#[derive(Debug, thiserror::Error)]
pub enum RunError<E: fmt::Debug> {
    /// The app's init or body reported a fatal error. Carries the app's own
    /// error type untouched.
    #[error("fatal service error: {0:?}")]
    Fatal(E),
    /// A service task panicked; the loop cannot be trusted to continue.
    /// Same dirty-exit semantics as [`RunError::Fatal`]. The Windows state
    /// machine reports a panic anywhere in the service main this way.
    #[error("service task panicked: {0}")]
    TaskPanicked(String),
    /// A service task exceeded its consecutive-failure bound, for a
    /// supervisor layered on [`crate::run_service`] that escalates a
    /// permanently degraded task (one must not read as "Running" to the
    /// OS service manager). Same dirty-exit semantics as
    /// [`RunError::TaskPanicked`].
    #[error("service task failed repeatedly: {0}")]
    TaskFailed(String),
    /// The service-manager machinery itself failed (status reporting,
    /// runtime construction, signal handlers).
    #[error("service runtime platform error: {0}")]
    Platform(String),
}

#[cfg(feature = "runtime")]
impl<E: fmt::Debug> RunError<E> {
    /// The process exit code for this failure: always
    /// [`crate::EXIT_CODE_FATAL`], non-zero, so the supervisor restarts us.
    pub fn exit_code(&self) -> i32 {
        crate::EXIT_CODE_FATAL
    }
}
