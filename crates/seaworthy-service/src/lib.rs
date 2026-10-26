//! # seaworthy-service: service definitions and lifecycle
//!
//! One backend-agnostic [`ServiceSpec`], validated and rendered into what
//! each OS service manager needs, plus (behind the `runtime` feature) the
//! install-free lifecycle against those managers and the service-main
//! state machine that turns fatal errors into supervisor restarts.
//!
//! ## Two halves
//!
//! - **Always present, pure:** the spec ([`ServiceSpec`], [`FailurePolicy`],
//!   [`UnixIdentity`], [`SystemdSandbox`], [`SystemdHardening`],
//!   [`WindowsServiceAccount`])
//!   and [`render`]: the systemd units and `sysusers.d` entry, the update
//!   helper's units, a Windows service's MSI record and SDDLs, and a macOS
//!   package's LaunchDaemons. No OS-specific dependency and no tokio, so a
//!   packaging tool (the seaworthy CLI) renders every platform's files on
//!   one Linux host.
//! - **`runtime` (off by default):** `backend` (start/stop/status against
//!   the Windows SCM, systemd and launchctl) and `run` (`run_service`: the
//!   Unix signal loop, the Windows SCM dispatcher and its console
//!   fallback). This is what a service binary links.
//!
//! ## The three-layer liveness story
//!
//! Keeping a service alive and current is split across three layers, each
//! owning exactly one failure mode:
//!
//! 1. **The OS service manager handles *process death*.** Crashes and fatal
//!    exits are restarted with escalating, capped backoff FOREVER: SCM
//!    recovery actions on Windows, `Restart=on-failure` +
//!    `RestartSteps=`/`RestartMaxDelaySec=` with no start limit under
//!    systemd (a fleet never fail-stops behind a start-limit budget only a
//!    reboot clears). This crate renders that policy from
//!    [`FailurePolicy`].
//! 2. **The caller's connect retry handles *"server not up yet"*.**
//!    Jittered startup backoff while the server is unreachable,
//!    deliberately NOT a supervisor concern, so the service doesn't burn its
//!    restart budget on a routine server reboot. The run loop races that
//!    init against the stop request, so a retrying service always stops
//!    cleanly.
//! 3. **seaworthy-updater handles *version rejection*.** When the caller's
//!    server refuses the connection (at connect or mid-run), the service
//!    asks the product's update helper and keeps going: it never exits to
//!    update. The helper installs the server's release with the OS package
//!    manager, which restarts the service (the package scripts'
//!    `try-restart`, the MSI's `ServiceControl`).
//!
//! ## Known gap
//!
//! There is no crash-loop rollback: if a freshly installed release crashes
//! on startup, the supervisor keeps restarting it at the capped
//! [`FailurePolicy`] delay; it stays down on that release until a
//! fix-forward release reaches it.
//!
//! ## Rendering for packages
//!
//! [`render`] computes what an OS installer needs from a [`ServiceSpec`]:
//! the systemd units and `sysusers.d` entry, a Windows service's MSI
//! record and SDDL, and a macOS package's LaunchDaemons. It is pure and
//! compiles on every platform. The backends render through it too.
//!
//! ## Platform coverage
//!
//! Windows (SCM), Linux (systemd, system + user units) and macOS (launchd)
//! are implemented. On Windows a service enters through the SCM dispatcher
//! (`run_windows_service`, exported on Windows targets with `runtime`):
//! `StartServiceCtrlDispatcherW` runs from `main`, the SCM invokes the
//! service main on its thread (control-handler registration and the
//! status protocol live there), and a console launch (Win32 1063) falls
//! back to the foreground shape with Ctrl-C shutdown. The SCM paths run for
//! real against an MSI-installed service on a Windows runner
//! (`scripts/windows-scm-e2e.ps1`); what a CI machine can't show (OS
//! shutdown, boot, a domain) stays a physical-Windows check before a
//! release. macOS (launchd) is the third backend: `launchctl` loads the
//! LaunchDaemon [`render::launchd`] renders, and a package installs the
//! same daemon with its log file, beside the update helper's on-demand
//! daemon.

// No FFI of its own: the runtime's state-directory audit (run::state_audit)
// reads security descriptors and the effective uid through
// seaworthy-fsguard, the SCM through windows-service.
#![forbid(unsafe_code)]
// The security baseline beyond the workspace lints: no panicking index or
// slice and no `unreachable!` in library code (tests may index).
#![deny(clippy::indexing_slicing, clippy::unreachable)]

// ---------------------------------------------------------------------------

mod error;
// The SCM state machine's error lines (compiled on Windows and in tests).
#[cfg(all(feature = "runtime", any(windows, test)))]
mod log;
#[cfg(feature = "runtime")]
mod outcome;
mod spec;
mod state;

#[cfg(feature = "runtime")]
pub mod backend;
pub mod render;
#[cfg(feature = "runtime")]
pub mod run;

#[cfg(feature = "runtime")]
pub use backend::{DefaultBackend, ServiceBackend};
#[cfg(feature = "runtime")]
pub use error::RunError;
pub use error::ServiceError;
#[cfg(feature = "runtime")]
pub use outcome::Outcome;
/// The Windows SCM dispatcher entry: `main` calls it on Windows. See
/// [`run`]'s module docs for the dispatcher contract and the console
/// fallback. (Re-exported on Windows targets only.)
#[cfg(all(feature = "runtime", windows))]
pub use run::run_windows_service;
#[cfg(feature = "runtime")]
pub use run::{EXIT_CODE_FATAL, ServiceExit, ShutdownRx, run_service};
pub use spec::{
    DEFAULT_OPEN_FILES_LIMIT, FailurePolicy, MIN_OPEN_FILES_LIMIT, ServiceSpec, SystemdHardening,
    SystemdSandbox, UnixIdentity, WindowsServiceAccount,
};
pub use state::ServiceState;

// The runtime needs an OS service manager. Guard explicitly so an
// accidental wasm/cross build of it fails loudly instead of with a pile of
// missing-module errors. The spec and the renderers build everywhere.
#[cfg(all(feature = "runtime", not(any(unix, windows))))]
compile_error!("the seaworthy-service `runtime` feature supports only Windows and Unix platforms");

/// Doc-hidden, NOT-API access to the crate-private systemd unit renderer
/// for the in-repo `fuzz/` crate. Behind the off-by-default `fuzzing`
/// feature, so no normal build carries it.
#[cfg(all(feature = "fuzzing", unix, not(target_os = "macos")))]
#[doc(hidden)]
pub mod __fuzz {
    /// Render the systemd unit for `spec` (`user` = a `--user` unit),
    /// validating it first exactly as packaging does.
    ///
    /// # Errors
    /// Whatever the renderer's validation refuses.
    pub fn render_systemd_unit(
        spec: &crate::ServiceSpec,
        user: bool,
    ) -> Result<String, crate::ServiceError> {
        crate::render::systemd::render_unit(spec, user)
    }
}

// ---------------------------------------------------------------------------
// README doctests: the crate README's Rust examples compile as doctests
// (`cargo test --doc`), so the crates.io front page can never drift from
// the API. Pseudo-code blocks are fenced `ignore` with a stated reason.
// ---------------------------------------------------------------------------

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
