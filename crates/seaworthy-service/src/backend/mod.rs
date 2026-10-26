//! Backends drive an installed service through its OS service manager:
//! `start`, `stop` and `status` (the `runtime` feature). Installing is a
//! package's (the MSI, deb, rpm, pacman and pkg the seaworthy CLI builds).
//!
//! A trait (not a concrete enum) because the platform backends share no
//! state and callers benefit from being able to fake the trait in their own
//! tests; the price — no cross-platform `match` — isn't one, because
//! platform choice is compile-time anyway. [`DefaultBackend`] aliases the
//! right backend type for the target platform.
//!
//! - [`systemd`] (Linux), [`launchd`] (macOS; compiled on every unix
//!   so Linux CI tests it), `windows` (the SCM).

use std::time::Duration;

use crate::ServiceError;
/// The state the backends report (it lives at the crate root, outside the
/// `runtime` feature, because [`crate::render::launchd::state`] maps
/// `launchctl print` onto it).
pub use crate::ServiceState;

// ---------------------------------------------------------------------------

// Compiled on every unix so Linux CI runs its lifecycle against a stub
// `launchctl`; macOS's default backend.
#[cfg(unix)]
pub mod launchd;
#[cfg(all(unix, not(target_os = "macos")))]
pub mod systemd;
#[cfg(windows)]
pub mod windows;
// The Windows backend's pure rules live in `render::windows_policy`,
// compiled everywhere (no `runtime` needed) so Linux CI runs their tests.

/// The backend for the target platform.
#[cfg(target_os = "macos")]
pub use launchd::LaunchdBackend as DefaultBackend;
/// The backend for the target platform.
#[cfg(all(unix, not(target_os = "macos")))]
pub use systemd::SystemdBackend as DefaultBackend;
/// The backend for the target platform.
#[cfg(windows)]
pub use windows::WindowsBackend as DefaultBackend;

/// Default delay between status polls while waiting on a state transition.
pub(crate) const DEFAULT_CLOCK_INTERVAL: Duration = Duration::from_secs(1);
/// Default total wait for a start/stop transition before giving up.
pub(crate) const DEFAULT_TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------

/// Lifecycle operations against an OS service manager, for a service a
/// package installed.
///
/// `start` and `stop` poll the manager at `clock_interval` until the
/// target state is reached or `timeout` elapses, mirroring the
/// production-tested service tooling this crate grew out of.
pub trait ServiceBackend {
    /// Start the service, waiting until it reports `Running`.
    fn start(&self) -> Result<(), ServiceError>;
    /// Stop the service, waiting until it reports `Stopped`.
    fn stop(&self) -> Result<(), ServiceError>;
    /// Current state, or `None` when the service is not installed.
    fn status(&self) -> Result<Option<ServiceState>, ServiceError>;
}

// ---------------------------------------------------------------------------

/// Test support shared by the backends' tests.
#[cfg(all(test, unix))]
#[allow(
    clippy::unwrap_used,
    reason = "test support: a failed fixture write fails the test"
)]
pub(crate) mod test_support {
    /// Writes an executable test stub (mode 0755) at `path` through a child
    /// process, so the test process never holds it open for writing: tests
    /// run on parallel threads, and a stub still open for writing in another
    /// thread's forked, not yet exec'd child fails to run with `ETXTBSY`
    /// ("Text file busy").
    pub(crate) fn write_script(path: &std::path::Path, contents: &str) {
        use std::io::Write as _;
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
            .arg(path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(contents.as_bytes())
            .unwrap();
        assert!(
            child.wait().unwrap().success(),
            "writing {}",
            path.display()
        );
    }
}
