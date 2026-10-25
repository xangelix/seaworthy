//! The app side of an update: when the product's server rejects this
//! version, read the update policy, then either ask the update helper to
//! run or log the version the server requires.
//!
//! Asking is all an app can do, and it carries nothing: the helper takes
//! no input from the app, and learns the server's version itself.
//!
//! - **Linux service:** truncate `/var/lib/<state>/update-request`
//!   ([`Product::request_file`]); the helper's path unit,
//!   `<service>-update.path`, starts `<service>-update.service`.
//! - **macOS service:** write the request time to
//!   `/Library/Application Support/<Vendor>/<Directory>/state/update-request`
//!   ([`Product::macos_request_file`]); launchd starts the helper's daemon,
//!   which watches it (`WatchPaths`). A write, not a bare truncation: an
//!   empty file truncated again may not change at all.
//! - **Windows service:** start the `<service>-update` service
//!   ([`Product::helper_service`]), the one right the MSI grants the
//!   service's account on it.
//! - **Windows desktop app**: start the `<package>-update` service
//!   ([`Product::helper_name`]), which the MSI lets interactive users
//!   (`IU`) start and query, nothing more.
//! - **Linux desktop app** (no service): start
//!   `<package>-update.service` ([`Product::helper_name`]) with `systemctl
//!   start --no-block --no-ask-password`, as the logged-in user. The
//!   package's polkit rule lets an active, local session start exactly
//!   that unit, and nothing else; any other subject is refused without a
//!   prompt. A product with no such unit installed has no helper to ask.
//!
//! [`UpdateRequester`] wraps both in the policy check and a rate limit, so
//! an app that reconnects every few seconds asks (and logs) at most once
//! per interval. The helper's own failure memo is the real backoff.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Product;
use crate::UpdatePolicy;
use crate::policy::{PolicyDecision, PolicySource, read_policy};

/// The default interval between two requests (or two `notify` log
/// entries) from one [`UpdateRequester`].
pub const DEFAULT_REQUEST_INTERVAL: Duration = Duration::from_secs(300);

/// Why a request couldn't be made.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The product has no service, or no state directory to hold the
    /// request file, or (a Linux desktop app) no helper unit installed:
    /// there's no helper to ask this way.
    #[error("{0}")]
    NoHelper(String),
    /// Writing the request file, or starting the helper's service, failed
    /// (a Linux desktop app: polkit refused the session).
    #[error("requesting an update failed: {0}")]
    Failed(String),
}

/// Asks the update helper to run, once, now (see the module docs). Most
/// callers want [`UpdateRequester`], which checks the policy first.
///
/// # Errors
/// [`RequestError::NoHelper`] for a product without a service (on Linux: a
/// service without a state directory, or a desktop app without its helper
/// unit; on Windows a desktop app asks its `<package>-update` service);
/// [`RequestError::Failed`] when the request file can't be written or the
/// helper's service can't be started.
pub fn request_update(product: &Product) -> Result<(), RequestError> {
    #[cfg(windows)]
    {
        windows::start_helper(product)
    }
    #[cfg(target_os = "macos")]
    {
        let path = product.macos_request_file().ok_or_else(|| {
            RequestError::NoHelper(format!(
                "product {} has no service state directory: a product ships the update helper only with one",
                product.package()
            ))
        })?;
        touch_request_file(&path)
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        if product.service().is_none() {
            return start_session_helper(product, std::path::Path::new(SYSTEMCTL));
        }
        let path = product.request_file().ok_or_else(|| {
            RequestError::NoHelper(format!(
                "product {} has no service state directory: the update request file lives there",
                product.package()
            ))
        })?;
        touch_request_file(&path)
    }
}

/// `systemctl` on every distribution the packages target (merged `/usr`).
#[cfg(all(not(windows), not(target_os = "macos")))]
const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// How long `systemctl start --no-block` may take: polkit's verdict, then
/// the job queued (it never waits for the helper).
#[cfg(all(not(windows), not(target_os = "macos")))]
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(30);

/// `systemctl`'s exit status for a unit that isn't installed (LSB's
/// "program is not installed").
#[cfg(all(not(windows), not(target_os = "macos")))]
const UNIT_NOT_FOUND: i32 = 5;

/// A desktop app's ask on Linux: `systemctl start --no-block
/// --no-ask-password <helper_name>.service` as the logged-in user. Its
/// package's polkit rule lets an active, local session start exactly that
/// unit; any other subject is refused without a password prompt
/// (`--no-ask-password`), and the refusal is the error. No unit by that
/// name (a tool, or a product built without the helper) is
/// [`RequestError::NoHelper`].
#[cfg(all(not(windows), not(target_os = "macos")))]
fn start_session_helper(
    product: &Product,
    systemctl: &std::path::Path,
) -> Result<(), RequestError> {
    let unit = format!("{}.service", product.helper_name());
    let finished = crate::process::run(
        std::process::Command::new(systemctl).args([
            "start",
            "--no-block",
            "--no-ask-password",
            unit.as_str(),
        ]),
        "starting the update helper",
        None,
        SYSTEMCTL_TIMEOUT,
        64 * 1024,
    )
    .map_err(|e| RequestError::Failed(e.to_string()))?;
    match finished.status.code() {
        Some(0) => Ok(()),
        Some(UNIT_NOT_FOUND) => Err(RequestError::NoHelper(format!(
            "product {} has no update helper unit {unit}: {}",
            product.package(),
            finished.shown()
        ))),
        _ => Err(RequestError::Failed(format!(
            "systemctl start {unit}: {}",
            finished.shown()
        ))),
    }
}

/// Truncates (creating if needed) the request file: closing a file opened
/// for writing is what the path unit's `PathChanged=` watches. On macOS it
/// then writes the request time, so the file always changes for launchd's
/// `WatchPaths`. Never through a symlink, never readable by others.
#[cfg(not(windows))]
pub(crate) fn touch_request_file(path: &std::path::Path) -> Result<(), RequestError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let failed = |e: std::io::Error| RequestError::Failed(format!("{}: {e}", path.display()));
    #[allow(unused_mut, reason = "written to on macOS only")]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(failed)?;
    #[cfg(target_os = "macos")]
    {
        use std::io::Write as _;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        writeln!(file, "{now}").map_err(failed)?;
    }
    drop(file);
    Ok(())
}

/// What [`UpdateRequester::on_version_mismatch`] did.
#[derive(Debug)]
pub enum RequestOutcome {
    /// The policy is `auto`, and the helper was asked to run.
    Requested(PolicyDecision),
    /// The policy isn't `auto`: the required version was logged (a
    /// warning, for the journal or the Event Log) and nothing else
    /// happened.
    NotAuto(PolicyDecision),
    /// Within the interval since the last request: nothing was done.
    Throttled {
        /// When the next request may be made.
        retry_after: Duration,
    },
    /// The policy is `auto`, but asking failed (logged as an error).
    Failed(PolicyDecision, RequestError),
}

/// The app side's one call on a version mismatch (see the module docs).
#[derive(Debug)]
pub struct UpdateRequester {
    product: Product,
    interval: Duration,
    last: Mutex<Option<Instant>>,
    /// This crate's tests write the request file here instead.
    #[cfg(all(test, not(windows)))]
    request_file: Option<std::path::PathBuf>,
    /// This crate's tests decide the policy instead of reading it.
    #[cfg(all(test, not(windows)))]
    policy: Option<PolicyDecision>,
}

impl UpdateRequester {
    /// A requester for `product`, asking at most once per
    /// [`DEFAULT_REQUEST_INTERVAL`].
    #[must_use]
    pub fn new(product: Product) -> Self {
        Self {
            product,
            interval: DEFAULT_REQUEST_INTERVAL,
            last: Mutex::new(None),
            #[cfg(all(test, not(windows)))]
            request_file: None,
            #[cfg(all(test, not(windows)))]
            policy: None,
        }
    }

    /// Asks at most once per `interval` (the first mismatch always asks).
    #[must_use]
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// The product.
    #[must_use]
    pub fn product(&self) -> &Product {
        &self.product
    }

    /// Handles the server's rejection of this version: `local` is this
    /// app's version token, `remote` the one the server requires (both
    /// only logged, line-safe). Reads the policy (local files or the
    /// registry), then asks the helper under `auto` or logs the required
    /// version otherwise.
    ///
    /// The requester knows no transport or RPC framework: the caller
    /// recognizes the rejection in its own error type and passes the two
    /// versions. Calls within the [`interval`](Self::interval) of the last
    /// one do nothing ([`RequestOutcome::Throttled`]).
    ///
    /// BLOCKING: on Windows the ask is `StartServiceW`, which can take up
    /// to 30 s while the SCM starts the helper. From async code run it on a
    /// blocking thread (`tokio::task::spawn_blocking`), never inside a
    /// synchronous callback of a connection library: record the rejection
    /// there and let a task hand it over.
    ///
    /// ```no_run
    /// # fn product() -> seaworthy_updater::Product { unimplemented!() }
    /// use seaworthy_updater::{RequestOutcome, UpdateRequester};
    ///
    /// /// The app's own error: its server answered "version mismatch".
    /// enum ConnectError {
    ///     VersionMismatch { local: String, remote: String },
    ///     Other(std::io::Error),
    /// }
    ///
    /// fn on_connect_error(requester: &UpdateRequester, error: &ConnectError) {
    ///     let ConnectError::VersionMismatch { local, remote } = error else {
    ///         return; // not a rejection: nothing to ask
    ///     };
    ///     match requester.on_version_mismatch(local, remote) {
    ///         RequestOutcome::Requested(_) => {} // the helper runs; keep retrying meanwhile
    ///         RequestOutcome::NotAuto(_) => {}   // the required version was logged
    ///         RequestOutcome::Throttled { .. } | RequestOutcome::Failed(..) => {}
    ///     }
    /// }
    ///
    /// let requester = UpdateRequester::new(product()); // at most one request per 5 minutes
    /// on_connect_error(
    ///     &requester,
    ///     &ConnectError::VersionMismatch { local: "1.3.0".into(), remote: "1.4.0".into() },
    /// );
    /// ```
    pub fn on_version_mismatch(&self, local: &str, remote: &str) -> RequestOutcome {
        let now = Instant::now();
        {
            let mut last = self
                .last
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(previous) = *last {
                let elapsed = now.saturating_duration_since(previous);
                if elapsed < self.interval {
                    return RequestOutcome::Throttled {
                        retry_after: self.interval - elapsed,
                    };
                }
            }
            *last = Some(now);
        }
        let (local, remote) = (crate::log::line_safe(local), crate::log::line_safe(remote));
        let package = self.product.package();
        #[cfg(all(test, not(windows)))]
        let decision = self
            .policy
            .clone()
            .unwrap_or_else(|| read_policy(&self.product));
        #[cfg(not(all(test, not(windows))))]
        let decision = read_policy(&self.product);
        // A policy file the app can't read (a root-only file) isn't the
        // app's to judge: the helper reads it as root and decides.
        let unreadable = matches!(decision.source, PolicySource::Unreadable(_));
        if decision.policy != UpdatePolicy::Auto && !unreadable {
            tracing::warn!(
                package,
                required_version = %remote,
                running_version = %local,
                policy = decision.policy.as_str(),
                "the server requires {package} {remote} (this is {local}); the update policy is {decision}, so it isn't installed automatically: install it from the product's package repository"
            );
            return RequestOutcome::NotAuto(decision);
        }
        match self.request() {
            Ok(()) => {
                tracing::info!(
                    package,
                    required_version = %remote,
                    running_version = %local,
                    "the server requires {package} {remote} (this is {local}); asked the update helper to install it (policy {decision})"
                );
                RequestOutcome::Requested(decision)
            }
            Err(error) => {
                tracing::error!(
                    package,
                    required_version = %remote,
                    "the server requires {package} {remote}, but asking the update helper failed: {error}"
                );
                RequestOutcome::Failed(decision, error)
            }
        }
    }

    fn request(&self) -> Result<(), RequestError> {
        #[cfg(all(test, not(windows)))]
        if let Some(path) = &self.request_file {
            return touch_request_file(path);
        }
        request_update(&self.product)
    }
}

#[cfg(windows)]
mod windows {
    // FFI: starting a service through windows-sys. Each `unsafe` block is
    // allowed on its own, with the invariant it relies on.

    use windows_sys::Win32::Foundation::{ERROR_SERVICE_ALREADY_RUNNING, GetLastError};
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
        SERVICE_START, StartServiceW,
    };

    use super::RequestError;
    use crate::Product;

    struct Handle(SC_HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            #[allow(unsafe_code, reason = "closes a service handle")]
            // SAFETY: a handle from OpenSCManagerW/OpenServiceW, closed
            // once, here.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }

    /// The calling thread's last error code.
    fn last_error_code() -> u32 {
        #[allow(unsafe_code, reason = "reads the thread's last error")]
        // SAFETY: GetLastError takes nothing and reads only the calling
        // thread's last-error value.
        unsafe {
            GetLastError()
        }
    }

    fn last_error(what: &str) -> RequestError {
        let code = last_error_code();
        RequestError::Failed(format!(
            "{what}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        ))
    }

    /// Starts the helper's service ([`Product::helper_name`]: a service
    /// product's `<service>-update`, which the MSI lets the service's
    /// account start; a desktop product's `<package>-update`, which it lets
    /// interactive users start); already running counts as started.
    pub(super) fn start_helper(product: &Product) -> Result<(), RequestError> {
        let name = product.helper_name();
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        #[allow(unsafe_code, reason = "connects to the service control manager")]
        // SAFETY: NULL machine and database names select the local SCM's
        // active database; SC_MANAGER_CONNECT is the least right needed.
        let manager =
            unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(last_error("OpenSCManagerW"));
        }
        let manager = Handle(manager);
        #[allow(unsafe_code, reason = "opens the helper's service")]
        // SAFETY: an open SCM handle; `wide` is NUL-terminated and outlives
        // the call.
        let service = unsafe { OpenServiceW(manager.0, wide.as_ptr(), SERVICE_START) };
        if service.is_null() {
            return Err(last_error(&format!("opening service {name} to start it")));
        }
        let service = Handle(service);
        #[allow(unsafe_code, reason = "starts the helper's service")]
        // SAFETY: an open service handle with SERVICE_START; no arguments
        // (the helper takes no input from the app).
        let started = unsafe { StartServiceW(service.0, 0, std::ptr::null()) };
        if started == 0 {
            if last_error_code() == ERROR_SERVICE_ALREADY_RUNNING {
                return Ok(());
            }
            return Err(last_error(&format!("starting service {name}")));
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(windows))]
mod tests {
    use super::*;
    use crate::ServiceNames;

    #[test]
    fn the_request_file_is_truncated_privately_and_never_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update-request");
        touch_request_file(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&path, b"stale").unwrap();
        touch_request_file(&path).unwrap();
        let written = std::fs::read(&path).unwrap();
        if cfg!(target_os = "macos") {
            // The request time: the file changes on every request.
            let text = String::from_utf8(written).unwrap();
            assert!(
                text.ends_with('\n') && text.trim_end().parse::<u128>().is_ok(),
                "{text:?}"
            );
        } else {
            assert_eq!(written, b"");
        }
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(touch_request_file(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(touch_request_file(&dir.path().join("missing/update-request")).is_err());
    }

    #[test]
    fn a_product_without_a_service_has_nothing_to_ask() {
        let product = Product::new("Acme", "console", "Console", "stable").unwrap();
        // Linux asks systemd for the desktop helper's unit instead
        // (`a_desktop_app_starts_its_helper_unit_through_systemctl`).
        #[cfg(target_os = "macos")]
        assert!(matches!(
            request_update(&product),
            Err(RequestError::NoHelper(_))
        ));
        let no_state = product
            .with_service(ServiceNames {
                name: "AcmeConsole".into(),
                state_directory: None,
            })
            .unwrap();
        assert!(matches!(
            request_update(&no_state),
            Err(RequestError::NoHelper(_))
        ));
    }

    /// A stand-in `systemctl` logging its arguments, printing `stderr` and
    /// exiting `code`.
    #[cfg(target_os = "linux")]
    fn stub_systemctl(dir: &std::path::Path, code: i32, stderr: &str) -> std::path::PathBuf {
        let path = dir.join(format!("systemctl-{code}"));
        crate::tests_support::write_script(
            &path,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '%s\\n' '{stderr}' >&2\nexit {code}\n",
                dir.join("calls").display()
            ),
        );
        path
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_desktop_app_starts_its_helper_unit_through_systemctl() {
        let dir = tempfile::tempdir().unwrap();
        let product = Product::new("Acme", "console", "Console", "stable").unwrap();
        let ok = stub_systemctl(dir.path(), 0, "");
        start_session_helper(&product, &ok).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("calls")).unwrap(),
            "start --no-block --no-ask-password acme-console-update.service\n",
            "queued, never waited for, never prompting"
        );
        // polkit refusing the session (systemctl's "no permission").
        let refused = stub_systemctl(
            dir.path(),
            4,
            "Failed to start acme-console-update.service: Access denied",
        );
        match start_session_helper(&product, &refused) {
            Err(RequestError::Failed(why)) => assert!(why.contains("Access denied"), "{why}"),
            other => panic!("{other:?}"),
        }
        // No such unit: a product built without the helper, or a tool.
        let missing = stub_systemctl(
            dir.path(),
            5,
            "Failed to start acme-console-update.service: Unit acme-console-update.service not found.",
        );
        assert!(matches!(
            start_session_helper(&product, &missing),
            Err(RequestError::NoHelper(_))
        ));
        // systemctl itself missing.
        assert!(matches!(
            start_session_helper(&product, &dir.path().join("absent")),
            Err(RequestError::Failed(_))
        ));
    }

    #[test]
    fn under_auto_the_helper_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("update-request");
        let product = Product::new("Seaworthy-Test-Vendor", "asker", "Asker", "stable").unwrap();
        let requester = UpdateRequester {
            request_file: Some(file.clone()),
            ..UpdateRequester::new(product).interval(Duration::ZERO)
        };
        assert!(matches!(
            requester.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::Requested(PolicyDecision {
                policy: UpdatePolicy::Auto,
                ..
            })
        ));
        assert!(file.exists());
        // A request that can't be written is a failure, not a silent no-op.
        let broken = UpdateRequester {
            request_file: Some(dir.path().join("missing/update-request")),
            ..UpdateRequester::new(requester.product().clone()).interval(Duration::ZERO)
        };
        assert!(matches!(
            broken.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::Failed(..)
        ));
    }

    #[test]
    fn a_policy_the_app_cant_read_still_asks_the_helper() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("update-request");
        let product = Product::new("Seaworthy-Test-Vendor", "asker", "Asker", "stable").unwrap();
        let unreadable = UpdateRequester {
            request_file: Some(file.clone()),
            policy: Some(PolicyDecision {
                policy: UpdatePolicy::Off,
                source: PolicySource::Unreadable("/etc/x/policy.toml: permission denied".into()),
            }),
            ..UpdateRequester::new(product.clone()).interval(Duration::ZERO)
        };
        assert!(matches!(
            unreadable.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::Requested(_)
        ));
        assert!(file.exists());
        // An untrusted `off` is the administrator's `off`: nothing is asked.
        std::fs::remove_file(&file).unwrap();
        let untrusted = UpdateRequester {
            request_file: Some(file.clone()),
            policy: Some(PolicyDecision {
                policy: UpdatePolicy::Off,
                source: PolicySource::Untrusted("writable".into()),
            }),
            ..UpdateRequester::new(product).interval(Duration::ZERO)
        };
        assert!(matches!(
            untrusted.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::NotAuto(_)
        ));
        assert!(!file.exists());
    }

    #[test]
    fn requests_are_throttled_per_interval() {
        // The product's default policy is `notify` and nothing on a test
        // machine names this product, so no request file is written.
        let product = Product::new("Seaworthy-Test-Vendor", "requester", "Requester", "stable")
            .unwrap()
            .with_default_policy(UpdatePolicy::Notify);
        let requester = UpdateRequester::new(product).interval(Duration::from_secs(3600));
        assert!(matches!(
            requester.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::NotAuto(PolicyDecision {
                policy: UpdatePolicy::Notify,
                ..
            })
        ));
        assert!(matches!(
            requester.on_version_mismatch("1.0.0", "1.1.0"),
            RequestOutcome::Throttled { retry_after } if retry_after > Duration::from_secs(3500)
        ));
        let eager = UpdateRequester::new(requester.product().clone()).interval(Duration::ZERO);
        assert!(matches!(
            eager.on_version_mismatch("a", "b"),
            RequestOutcome::NotAuto(_)
        ));
        assert!(matches!(
            eager.on_version_mismatch("a", "b"),
            RequestOutcome::NotAuto(_)
        ));
    }
}
