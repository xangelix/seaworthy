//! launchd backend (macOS): drives `launchctl` in the `system` domain for
//! a LaunchDaemon a product's package installed (its plist is
//! [`crate::render::launchd::plist`]'s).
//!
//! Compiled on every unix, so Linux CI runs the lifecycle against a stub
//! `launchctl`; the [`DefaultBackend`](crate::backend::DefaultBackend) on
//! macOS. Packages install and remove daemons (the pkg scripts); the crate
//! installs nothing itself.
//!
//! The shapes worth knowing:
//!
//! * **Loaded is not running.** A daemon whose plist sits in
//!   `/Library/LaunchDaemons` is loaded at boot (`RunAtLoad` starts it).
//!   `stop` signals the process (`launchctl kill SIGTERM`) and leaves the
//!   job loaded: the run loop exits 0 on SIGTERM, and `KeepAlive` restarts
//!   only after a failure, so it stays stopped until `start`
//!   (`launchctl kickstart`) or the next boot. A program that dies of the
//!   signal instead of exiting 0 reads as a failure, and launchd restarts
//!   it. `start` loads a job that isn't loaded from its plist
//!   (`launchctl enable`, then `bootstrap`).
//! * **`launchctl` is resolved by absolute path** (`/bin/launchctl`; pin it
//!   with [`LaunchdBackend::with_launchctl`]) — a root caller never
//!   trusts `PATH`.
//! * **Status reads `launchctl print system/<label>`**: a loaded job's top-
//!   level `state` line ([`crate::render::launchd::state`], unknown states fail
//!   closed); a job that isn't loaded is stopped while its plist exists,
//!   and not installed otherwise. `launchctl print` exits 113 for a job it
//!   doesn't know; any other failure is an error, never a guess.

use std::{
    path::PathBuf,
    process::{Command, Output},
    thread::sleep,
    time::{Duration, Instant},
};

use super::{DEFAULT_CLOCK_INTERVAL, DEFAULT_TRANSITION_TIMEOUT, ServiceBackend, ServiceState};
use crate::ServiceError;
use crate::render::launchd as render;

/// `launchctl print`'s exit status for a service the domain doesn't know.
const NOT_FOUND: i32 = 113;

/// The launchd backend: one LaunchDaemon in the `system` domain.
#[derive(Debug, Clone)]
pub struct LaunchdBackend {
    name: String,
    launchctl: PathBuf,
    daemons: PathBuf,
    clock_interval: Duration,
    timeout: Duration,
}

impl LaunchdBackend {
    /// A backend for the daemon labelled `name`
    /// (`/Library/LaunchDaemons/<name>.plist`).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            launchctl: PathBuf::from("/bin/launchctl"),
            daemons: PathBuf::from(render::LAUNCH_DAEMONS),
            clock_interval: DEFAULT_CLOCK_INTERVAL,
            timeout: DEFAULT_TRANSITION_TIMEOUT,
        }
    }

    /// Poll every `clock_interval`, giving up after `timeout`.
    #[must_use]
    pub fn with_poll_timing(mut self, clock_interval: Duration, timeout: Duration) -> Self {
        self.clock_interval = clock_interval;
        self.timeout = timeout;
        self
    }

    /// Pin the `launchctl` binary.
    #[must_use]
    pub fn with_launchctl(mut self, launchctl: impl Into<PathBuf>) -> Self {
        self.launchctl = launchctl.into();
        self
    }

    #[cfg(test)]
    fn with_daemons(mut self, daemons: PathBuf) -> Self {
        self.daemons = daemons;
        self
    }

    fn plist_path(&self) -> Result<PathBuf, ServiceError> {
        render::validate_label(&self.name)?;
        Ok(self.daemons.join(format!("{}.plist", self.name)))
    }

    fn target(&self) -> Result<String, ServiceError> {
        render::validate_label(&self.name)?;
        Ok(format!("system/{}", self.name))
    }

    fn launchctl(&self, args: &[&str]) -> Result<Output, ServiceError> {
        Ok(Command::new(&self.launchctl).args(args).output()?)
    }

    fn run(&self, args: &[&str]) -> Result<(), ServiceError> {
        let output = self.launchctl(args)?;
        if output.status.success() {
            return Ok(());
        }
        Err(failed(args, &output))
    }

    /// `launchctl print`'s output for a loaded job, `None` for one launchd
    /// doesn't know.
    fn print(&self) -> Result<Option<String>, ServiceError> {
        let target = self.target()?;
        let output = self.launchctl(&["print", &target])?;
        if output.status.success() {
            return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
        }
        if output.status.code() == Some(NOT_FOUND) {
            return Ok(None);
        }
        Err(failed(&["print", &target], &output))
    }

    fn wait_for(
        &self,
        predicate: impl Fn(Option<ServiceState>) -> bool,
    ) -> Result<bool, ServiceError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if predicate(self.status()?) {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            sleep(self.clock_interval);
        }
    }

    /// Load the job from its plist: enabled first (`bootstrap` refuses a
    /// disabled job), then bootstrapped; `RunAtLoad` starts it.
    fn load(&self) -> Result<(), ServiceError> {
        let target = self.target()?;
        let plist = self.plist_path()?;
        let plist = plist.to_str().ok_or_else(|| {
            ServiceError::InvalidSpec(format!("{} is not UTF-8", plist.display()))
        })?;
        self.run(&["enable", &target])?;
        self.run(&["bootstrap", "system", plist])
    }
}

fn failed(args: &[&str], output: &Output) -> ServiceError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout
    } else {
        stderr
    };
    ServiceError::Platform(format!(
        "launchctl {} failed ({}): {}",
        args.join(" "),
        output.status,
        detail.trim()
    ))
}

impl ServiceBackend for LaunchdBackend {
    fn start(&self) -> Result<(), ServiceError> {
        if self.print()?.is_some() {
            self.run(&["kickstart", &self.target()?])?;
        } else if self.plist_path()?.exists() {
            self.load()?;
        } else {
            return Err(ServiceError::DoesNotExist);
        }
        if self.wait_for(|state| state == Some(ServiceState::Running))? {
            Ok(())
        } else {
            Err(ServiceError::StartTimeout)
        }
    }

    fn stop(&self) -> Result<(), ServiceError> {
        match self.status()? {
            None => return Err(ServiceError::DoesNotExist),
            Some(ServiceState::Stopped) => return Ok(()),
            Some(_) => {}
        }
        if let Err(error) = self.run(&["kill", "SIGTERM", &self.target()?]) {
            // Nothing to signal: it stopped meanwhile.
            if self.status()? != Some(ServiceState::Stopped) {
                return Err(error);
            }
        }
        if self.wait_for(|state| state == Some(ServiceState::Stopped))? {
            Ok(())
        } else {
            Err(ServiceError::StopTimeout)
        }
    }

    fn status(&self) -> Result<Option<ServiceState>, ServiceError> {
        match self.print()? {
            Some(text) => Ok(Some(render::state(&text))),
            None if self.plist_path()?.exists() => Ok(Some(ServiceState::Stopped)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{fs, path::Path};

    use super::*;
    use crate::ServiceSpec;

    /// A `launchctl` that keeps its state in files beside it: `loaded`
    /// (bootstrapped) and `running`. Every call is appended to `calls`.
    fn stub_launchctl(dir: &Path) -> PathBuf {
        let stub = dir.join("launchctl");
        let script = r#"#!/bin/sh
here=$(dirname "$0")
echo "$*" >> "$here/calls"
case "$1" in
    print)
        [ -e "$here/loaded" ] || { echo "Could not find service" >&2; exit 113; }
        [ -e "$here/fail-print" ] && { echo "boom" >&2; exit 1; }
        state="not running"; [ -e "$here/running" ] && state=running
        printf '%s = {\n\tactive count = 1\n\tstate = %s\n}\n' "$2" "$state" ;;
    enable) ;;
    bootstrap) touch "$here/loaded" "$here/running" ;;
    bootout) rm -f "$here/loaded" "$here/running" ;;
    kickstart) touch "$here/running" ;;
    kill) [ -e "$here/running" ] || { echo "No process to signal" >&2; exit 3; }
        rm -f "$here/running" ;;
    *) echo "unexpected: $*" >&2; exit 64 ;;
esac
"#;
        crate::backend::test_support::write_script(&stub, script);
        stub
    }

    fn calls(dir: &Path) -> Vec<String> {
        fs::read_to_string(dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    struct Fixture {
        dir: PathBuf,
        backend: LaunchdBackend,
        plist: PathBuf,
    }

    /// A scratch LaunchDaemons directory and a stub launchctl; the daemon's
    /// plist is written as its package writes it.
    fn fixture(tag: &str) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("seaworthy-launchd-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let daemons = dir.join("LaunchDaemons");
        fs::create_dir_all(&daemons).unwrap();
        let stub = stub_launchctl(&dir);
        let backend = LaunchdBackend::new("com.acme.agent")
            .with_launchctl(stub)
            .with_poll_timing(Duration::from_millis(10), Duration::from_secs(2))
            .with_daemons(daemons.clone());
        Fixture {
            plist: daemons.join("com.acme.agent.plist"),
            dir,
            backend,
        }
    }

    /// The package's plist, then loaded as its postinstall does.
    fn packaged(f: &Fixture) {
        let spec = ServiceSpec {
            name: "com.acme.agent".into(),
            display_name: "Acme Agent".into(),
            description: "The Acme agent".into(),
            program: PathBuf::from("/Applications/Acme Agent.app/Contents/MacOS/AcmeAgent"),
            arguments: vec!["service".into()],
            unix_identity: crate::UnixIdentity::Root,
            ..ServiceSpec::default()
        };
        fs::write(&f.plist, render::plist(&spec).unwrap()).unwrap();
        f.backend.start().unwrap();
    }

    #[test]
    fn a_missing_daemon_is_not_installed_and_start_and_stop_say_so() {
        let f = fixture("missing");
        assert_eq!(f.backend.status().unwrap(), None, "not installed");
        let stopped = f.backend.stop();
        assert!(
            matches!(stopped, Err(ServiceError::DoesNotExist)),
            "{stopped:?} (calls: {:?})",
            calls(&f.dir)
        );
        let started = f.backend.start();
        assert!(
            matches!(started, Err(ServiceError::DoesNotExist)),
            "{started:?} (calls: {:?})",
            calls(&f.dir)
        );
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn start_loads_an_unloaded_daemon_from_its_plist() {
        let f = fixture("load");
        packaged(&f);
        assert_eq!(
            calls(&f.dir)[1..],
            [
                "enable system/com.acme.agent".to_owned(),
                format!("bootstrap system {}", f.plist.display()),
                "print system/com.acme.agent".to_owned(),
            ]
        );
        assert_eq!(f.backend.status().unwrap(), Some(ServiceState::Running));
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn stop_signals_and_keeps_it_loaded_start_kickstarts_it() {
        let f = fixture("stop-start");
        packaged(&f);
        f.backend.stop().unwrap();
        assert_eq!(f.backend.status().unwrap(), Some(ServiceState::Stopped));
        assert!(f.dir.join("loaded").exists(), "still loaded");
        assert!(calls(&f.dir).contains(&"kill SIGTERM system/com.acme.agent".to_owned()));
        // Stopping a stopped service is done already: nothing signalled.
        let before = calls(&f.dir).len();
        f.backend.stop().unwrap();
        assert!(
            !calls(&f.dir)[before..]
                .iter()
                .any(|c| c.starts_with("kill")),
            "{:?}",
            calls(&f.dir)
        );
        f.backend.start().unwrap();
        assert_eq!(f.backend.status().unwrap(), Some(ServiceState::Running));
        assert!(calls(&f.dir).contains(&"kickstart system/com.acme.agent".to_owned()));
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn a_booted_out_job_is_stopped_while_its_plist_exists_and_start_loads_it() {
        let f = fixture("unloaded");
        packaged(&f);
        fs::remove_file(f.dir.join("loaded")).unwrap();
        fs::remove_file(f.dir.join("running")).unwrap();
        assert_eq!(f.backend.status().unwrap(), Some(ServiceState::Stopped));
        f.backend.start().unwrap();
        assert_eq!(f.backend.status().unwrap(), Some(ServiceState::Running));
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn a_launchctl_failure_is_an_error_never_a_guess() {
        let f = fixture("print-failure");
        packaged(&f);
        fs::write(f.dir.join("fail-print"), b"").unwrap();
        let err = f.backend.status().unwrap_err().to_string();
        assert!(
            err.contains("launchctl print") && err.contains("boom"),
            "{err}"
        );
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn bad_names_are_refused_before_launchctl_runs() {
        let f = fixture("names");
        let bad = LaunchdBackend::new("../escape").with_launchctl(f.dir.join("launchctl"));
        assert!(matches!(bad.status(), Err(ServiceError::InvalidName(_))));
        assert!(matches!(bad.start(), Err(ServiceError::InvalidName(_))));
        assert!(matches!(bad.stop(), Err(ServiceError::InvalidName(_))));
        assert!(calls(&f.dir).is_empty(), "{:?}", calls(&f.dir));
        fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn launchctl_is_absolute_unless_pinned() {
        assert_eq!(
            LaunchdBackend::new("x").launchctl,
            PathBuf::from("/bin/launchctl")
        );
        assert_eq!(
            LaunchdBackend::new("x").with_launchctl("/opt/l").launchctl,
            PathBuf::from("/opt/l")
        );
    }
}
