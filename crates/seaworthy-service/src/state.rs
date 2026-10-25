//! The platform-agnostic service state: what the backends report and what
//! [`crate::render::launchd::state`] reads from `launchctl print`. Pure
//! data, so it lives outside the `runtime` feature.

/// Platform-agnostic service state.
///
/// Mirrors the Windows SCM state set; systemd maps its `ActiveState` onto
/// the same vocabulary (`failed` collapses into `Stopped`: the process is
/// not running either way; the unit's failure detail is a `systemctl status`
/// question, not a lifecycle one). A state the mapping does not know is
/// [`ServiceState::Unknown`], never read as `Running` (that made `start()`
/// succeed on a state it did not understand).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is running.
    Running,
    /// Service is not running.
    Stopped,
    /// Service is paused.
    Paused,
    /// Service is transitioning to [`ServiceState::Running`].
    StartPending,
    /// Service is transitioning to [`ServiceState::Stopped`].
    StopPending,
    /// Service is transitioning to [`ServiceState::Paused`].
    PausePending,
    /// Service is transitioning out of [`ServiceState::Paused`].
    ContinuePending,
    /// A state the backend does not recognize (a newer systemd's
    /// `ActiveState`, `maintenance`): neither a start nor a stop wait ever
    /// reads it as success; both time out loudly.
    Unknown,
}
