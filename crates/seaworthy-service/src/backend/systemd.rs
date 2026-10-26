//! systemd backend: drives `systemctl` for the lifecycle of a unit a
//! product's package installed (`start`, `stop`, `status`).
//!
//! Units ship in packages (the seaworthy CLI: the unit text from
//! [`render::systemd`](crate::render::systemd), the lifecycle in the
//! package scripts). The crate installs nothing itself.
//!
//! The shapes worth knowing, by construction:
//!
//! * **`failed` reads as `Stopped`; an unknown `ActiveState` reads as
//!   [`ServiceState::Unknown`]** — neither a start nor a stop wait treats
//!   it as success.
//! * **`systemctl` is resolved by absolute path** (`/usr/bin/systemctl`,
//!   then `/bin/systemctl`; a PATH fallback logs loudly; pin it with
//!   [`SystemdBackend::with_systemctl`]) — a root caller never trusts
//!   `PATH` silently.
//! * **Names are validated first** (`validate_unit_name`): a bad name is
//!   the typed [`ServiceError::InvalidName`] before `systemctl` runs.
//!
//! Shell-outs stay thin: one `Command::output` per `systemctl` verb, stderr
//! captured into [`ServiceError::Platform`] on non-zero exit.

use std::{
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

use crate::{
    ServiceError,
    backend::{DEFAULT_CLOCK_INTERVAL, DEFAULT_TRANSITION_TIMEOUT, ServiceBackend, ServiceState},
    render::systemd::validate_unit_name,
};

// ---------------------------------------------------------------------------

/// Drives a systemd unit, system-wide or per-user (`systemctl --user`).
#[derive(Debug, Clone)]
pub struct SystemdBackend {
    name: String,
    clock_interval: Duration,
    timeout: Duration,
    user: bool,
    systemctl: Option<PathBuf>,
}

impl SystemdBackend {
    /// Backend for a system-wide unit.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            clock_interval: DEFAULT_CLOCK_INTERVAL,
            timeout: DEFAULT_TRANSITION_TIMEOUT,
            user: false,
            systemctl: None,
        }
    }

    /// Backend for a per-user unit (`systemctl --user`).
    pub fn user(name: impl Into<String>) -> Self {
        Self {
            user: true,
            ..Self::new(name)
        }
    }

    /// Override the poll interval / total timeout used by `start` and
    /// `stop`.
    #[must_use]
    pub fn with_poll_timing(mut self, clock_interval: Duration, timeout: Duration) -> Self {
        self.clock_interval = clock_interval;
        self.timeout = timeout;
        self
    }

    /// Pin the `systemctl` executable (an absolute path) — for distributions
    /// that keep it outside `/usr/bin` and `/bin` (NixOS:
    /// `/run/current-system/sw/bin/systemctl`), instead of the loud `PATH`
    /// fallback.
    #[must_use]
    pub fn with_systemctl(mut self, systemctl: impl Into<PathBuf>) -> Self {
        self.systemctl = Some(systemctl.into());
        self
    }

    /// `{name}.service`, unless the name already carries the suffix.
    ///
    /// Fails with [`ServiceError::InvalidName`] for names that cannot be
    /// used as a unit file name or `systemctl` argument.
    fn unit_file_name(&self) -> Result<String, ServiceError> {
        validate_unit_name(&self.name)?;
        Ok(if self.name.ends_with(".service") {
            self.name.clone()
        } else {
            format!("{}.service", self.name)
        })
    }

    /// The `systemctl` executable: the pinned path, else `/usr/bin` or
    /// `/bin`, else a loudly-logged `PATH` lookup.
    fn systemctl_path(&self) -> PathBuf {
        if let Some(path) = &self.systemctl {
            return path.clone();
        }
        for candidate in ["/usr/bin/systemctl", "/bin/systemctl"] {
            if Path::new(candidate).is_file() {
                return PathBuf::from(candidate);
            }
        }
        tracing::warn!(
            "systemctl not found at /usr/bin/systemctl or /bin/systemctl; resolving it through \
             PATH — pin it with SystemdBackend::with_systemctl (a root caller should never \
             trust PATH)"
        );
        PathBuf::from("systemctl")
    }

    fn systemctl(&self) -> Command {
        let mut command = Command::new(self.systemctl_path());
        if self.user {
            command.arg("--user");
        }
        command
    }

    /// Run a `systemctl` verb; non-zero exit becomes `ServiceError::Platform`
    /// with stderr captured.
    fn run_systemctl(&self, args: &[&str]) -> Result<(), ServiceError> {
        let output = self.systemctl().args(args).output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(ServiceError::Platform(format!(
            "systemctl {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }

    /// Poll `status` until `predicate` holds or the timeout elapses.
    fn wait_for(
        &self,
        predicate: impl Fn(Option<ServiceState>) -> bool,
    ) -> Result<bool, ServiceError> {
        let start = Instant::now();
        while start.elapsed() < self.timeout {
            if predicate(self.status()?) {
                return Ok(true);
            }
            sleep(self.clock_interval);
        }
        Ok(false)
    }
}

impl ServiceBackend for SystemdBackend {
    fn start(&self) -> Result<(), ServiceError> {
        self.run_systemctl(&["start", &self.unit_file_name()?])?;
        if self.wait_for(|state| state == Some(ServiceState::Running))? {
            Ok(())
        } else {
            Err(ServiceError::StartTimeout)
        }
    }

    fn stop(&self) -> Result<(), ServiceError> {
        self.run_systemctl(&["stop", &self.unit_file_name()?])?;
        if self.wait_for(|state| state == Some(ServiceState::Stopped))? {
            Ok(())
        } else {
            Err(ServiceError::StopTimeout)
        }
    }

    fn status(&self) -> Result<Option<ServiceState>, ServiceError> {
        let output = self
            .systemctl()
            .args([
                "show",
                &self.unit_file_name()?,
                "--property=LoadState,ActiveState",
            ])
            .output()?;
        if !output.status.success() {
            return Err(ServiceError::Platform(format!(
                "systemctl show failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut load_state = "";
        let mut active_state = "";
        for line in stdout.lines() {
            if let Some(value) = line.strip_prefix("LoadState=") {
                load_state = value;
            } else if let Some(value) = line.strip_prefix("ActiveState=") {
                active_state = value;
            }
        }

        if load_state == "not-found" {
            return Ok(None);
        }
        Ok(Some(map_active_state(active_state)))
    }
}

// ---------------------------------------------------------------------------

/// Map systemd's `ActiveState` onto the lifecycle vocabulary. A state this
/// map does not know (`maintenance` — a `systemctl clean` in progress — or
/// a future addition) is [`ServiceState::Unknown`]: never a hard error that
/// breaks waits after a systemd upgrade, and never read as `Running`, which
/// made `start()` succeed on a state it did not understand. Both
/// waits time out loudly instead.
fn map_active_state(active_state: &str) -> ServiceState {
    match active_state {
        "active" | "reloading" | "refreshing" => ServiceState::Running,
        "activating" => ServiceState::StartPending,
        "deactivating" => ServiceState::StopPending,
        "inactive" | "failed" => ServiceState::Stopped,
        _ => ServiceState::Unknown,
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, fs};

    use super::*;
    use crate::render::systemd::tests::{demo_spec, sandbox, sandboxed_spec};
    use crate::render::systemd::{render_unit, validate_sandbox, validate_spec};

    #[test]
    fn non_utf8_exec_tokens_are_a_typed_error_not_a_silent_mangle() {
        use std::os::unix::ffi::OsStringExt;
        let mut spec = demo_spec();
        spec.arguments = vec![OsString::from_vec(vec![0xff, 0xfe])];
        assert!(matches!(
            render_unit(&spec, false),
            Err(ServiceError::InvalidSpec(_))
        ));
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
    }

    #[test]
    fn program_path_must_be_absolute_modifier_free_and_below_a_directory() {
        for bad in [
            "+/usr/bin/x",
            "@/usr/bin/x",
            "-/usr/bin/x",
            "!/usr/bin/x",
            "!!/usr/bin/x",
            "usr/bin/x",
            "x",
            "/opt/bin/app\ndemo",
            "/opt/bin/app\u{0}demo",
            // Directly in `/`: a package's program has a directory of its
            // own, never the root.
            "/app",
            "/opt/bin/",
        ] {
            let mut spec = demo_spec();
            spec.program = PathBuf::from(bad);
            assert!(
                matches!(validate_spec(&spec), Err(ServiceError::InvalidSpec(_))),
                "{bad:?} must be rejected"
            );
        }
        assert!(validate_spec(&demo_spec()).is_ok());
    }

    #[test]
    fn a_sandbox_value_that_would_inject_a_line_is_refused() {
        let mut spec = sandboxed_spec();
        sandbox(&mut spec).user = "a\nb".to_owned();
        assert!(matches!(
            validate_sandbox(sandbox(&mut spec)),
            Err(ServiceError::InvalidName(_))
        ));
    }

    #[test]
    fn backend_rejects_bad_names_before_touching_the_system() {
        let backend = SystemdBackend::new("../evil");
        assert!(matches!(
            backend.status(),
            Err(ServiceError::InvalidName(_))
        ));
        assert!(matches!(backend.start(), Err(ServiceError::InvalidName(_))));
        assert!(matches!(backend.stop(), Err(ServiceError::InvalidName(_))));
    }

    #[test]
    fn unknown_active_state_is_not_running() {
        assert_eq!(map_active_state("some-future-state"), ServiceState::Unknown);
        assert_eq!(map_active_state("maintenance"), ServiceState::Unknown);
        assert_eq!(map_active_state("active"), ServiceState::Running);
        assert_eq!(map_active_state("reloading"), ServiceState::Running);
        assert_eq!(map_active_state("activating"), ServiceState::StartPending);
        assert_eq!(map_active_state("deactivating"), ServiceState::StopPending);
        assert_eq!(map_active_state("inactive"), ServiceState::Stopped);
        assert_eq!(map_active_state("failed"), ServiceState::Stopped);
    }

    #[test]
    fn systemctl_resolves_by_absolute_path_or_pin() {
        let pinned = SystemdBackend::new("x").with_systemctl("/opt/sd/systemctl");
        assert_eq!(pinned.systemctl_path(), PathBuf::from("/opt/sd/systemctl"));
        let resolved = SystemdBackend::new("x").systemctl_path();
        if Path::new("/usr/bin/systemctl").is_file() || Path::new("/bin/systemctl").is_file() {
            assert!(resolved.is_absolute(), "{}", resolved.display());
        }
    }

    /// The lifecycle against a stub `systemctl` recording its argv: a user
    /// unit's verbs carry `--user`, and `status` maps `systemctl show`.
    #[test]
    fn the_lifecycle_runs_systemctl_verbs_on_the_unit() {
        let dir =
            std::env::temp_dir().join(format!("seaworthy-systemd-stub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        let log = dir.join("systemctl.log");
        let stub = dir.join("systemctl");
        crate::backend::test_support::write_script(
            &stub,
            &format!(
                "#!/bin/sh\necho \"$@\" >> '{}'\n\
                 if [ \"$2\" = show ] || [ \"$1\" = show ]; then \
                 printf 'LoadState=loaded\\nActiveState=active\\n'; fi\n",
                log.display()
            ),
        );
        let backend = SystemdBackend::user("acme-stub")
            .with_systemctl(&stub)
            .with_poll_timing(Duration::from_millis(1), Duration::from_secs(5));
        assert_eq!(
            backend.status().expect("status"),
            Some(ServiceState::Running)
        );
        backend.start().expect("start");
        let calls = fs::read_to_string(&log).expect("log");
        assert!(
            calls.lines().any(|l| l == "--user start acme-stub.service"),
            "{calls}"
        );
        assert!(
            calls
                .lines()
                .any(|l| l == "--user show acme-stub.service --property=LoadState,ActiveState"),
            "{calls}"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// `systemd-analyze security --offline=yes` on the rendered sandboxed
    /// unit stays at the "OK" end (≤ 2.0; 8.3 "EXPOSED" without the
    /// hardening set), and
    /// `systemd-analyze verify` finds no unknown directive. Skips where
    /// systemd-analyze is absent.
    #[test]
    fn the_sandboxed_unit_scores_ok_under_systemd_analyze() {
        let Some(analyze) = [
            "/usr/bin/systemd-analyze",
            "/bin/systemd-analyze",
            "/usr/sbin/systemd-analyze",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file()) else {
            eprintln!("systemd-analyze not present; skipping");
            return;
        };
        let root = std::env::temp_dir().join(format!("seaworthy-analyze-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("scratch");
        let mut spec = sandboxed_spec();
        spec.program = PathBuf::from("/usr/bin/true");
        spec.arguments = vec![];
        sandbox(&mut spec).user = "nobody".to_owned();
        sandbox(&mut spec).group = "nobody".to_owned();
        sandbox(&mut spec).capabilities = vec![];
        let unit_path = root.join("acme-analyze.service");
        fs::write(&unit_path, render_unit(&spec, false).expect("renders")).expect("write");

        let security = Command::new(&analyze)
            .args(["security", "--offline=yes", "--no-pager"])
            .arg(&unit_path)
            .output()
            .expect("run systemd-analyze security");
        let stdout = String::from_utf8_lossy(&security.stdout);
        let score: f64 = stdout
            .lines()
            .find_map(|line| {
                let rest = line.split("Overall exposure level for").nth(1)?;
                rest.split(':')
                    .nth(1)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or_else(|| panic!("no exposure line in: {stdout}\n{:?}", security.stderr));
        eprintln!("systemd-analyze security --offline=yes exposure: {score}");
        assert!(
            score <= 2.0,
            "exposure {score} must stay at the OK end:\n{stdout}"
        );

        let verify = Command::new(&analyze)
            .args(["verify", "--man=no"])
            .arg(&unit_path)
            .output()
            .expect("run systemd-analyze verify");
        let stderr = String::from_utf8_lossy(&verify.stderr);
        assert!(
            !stderr.contains("Unknown key") && !stderr.contains("Unknown section"),
            "verify flagged a directive: {stderr}"
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
