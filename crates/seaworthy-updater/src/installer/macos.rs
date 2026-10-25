//! macOS: the package's receipt (`pkgutil --pkg-info`) for the installed
//! release, `installer -pkg` to install.
//!
//! The package's identifier is the product's bundle id
//! ([`Product::macos_package_id`](crate::Product::macos_package_id)):
//! the seaworthy CLI builds it with `pkgbuild --identifier <bundle id> --version
//! <upstream>-<sequence>`, so the receipt reads back as exactly the release
//! ([`Release::from_package_version`] with [`ArtifactFormat::Pkg`]).
//!
//! macOS's installer resolves no dependencies and touches no other
//! package, so there is no plan to check as apt's and pacman's are: the
//! signed manifest binds the file to the product, the release and the
//! format, and the receipt must name the release afterwards, or the install
//! is reported failed. The package's own scripts stop and start the
//! service; they never touch the helper's daemon, which may be the one
//! running the install (the Linux packages' rule too).
//!
//! `installer` isn't transactional: a failed install leaves whatever its
//! preinstall did. The postinstall starts the service however it ends, but
//! an install that fails before it (a payload it couldn't write) leaves
//! the service the preinstall stopped. So after a failed `installer` the
//! helper loads the service's daemon when it isn't loaded
//! ([`MacPkg::with_service`]), and the next run retries after the backoff.
//!
//! Compiled on every unix, so Linux CI drives it against stub tools; only
//! macOS's helper picks it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::{Install, InstallError, Installer};
use crate::ArtifactFormat;
use crate::process::{self, Finished};
use crate::release::Release;

/// How long a receipt query may take.
const QUERY_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the helper waits for `installer`. Past it the install is
/// reported not confirmed, and the next run reads the receipt.
pub const MACOS_INSTALL_WAIT: Duration = Duration::from_secs(900);

/// The longest query output read.
const QUERY_OUTPUT: usize = 1 << 20;

/// The programs the macOS installer runs, by absolute path, and where the
/// system's daemons' property lists live.
#[derive(Debug, Clone)]
pub struct MacTools {
    /// `installer`.
    pub installer: PathBuf,
    /// `pkgutil`.
    pub pkgutil: PathBuf,
    /// `launchctl`.
    pub launchctl: PathBuf,
    /// `/Library/LaunchDaemons`.
    pub launch_daemons: PathBuf,
}

impl Default for MacTools {
    fn default() -> Self {
        Self {
            installer: PathBuf::from("/usr/sbin/installer"),
            pkgutil: PathBuf::from("/usr/sbin/pkgutil"),
            launchctl: PathBuf::from("/bin/launchctl"),
            launch_daemons: PathBuf::from("/Library/LaunchDaemons"),
        }
    }
}

/// macOS's `installer`, for the package with one identifier.
#[derive(Debug, Clone)]
pub struct MacPkg {
    identifier: String,
    service: Option<String>,
    tools: MacTools,
}

impl MacPkg {
    /// The installer for the package `identifier` (the product's bundle
    /// id), with the system's tools.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self::with(identifier, MacTools::default())
    }

    /// The same, with other tool paths.
    #[must_use]
    pub fn with(identifier: impl Into<String>, tools: MacTools) -> Self {
        Self {
            identifier: identifier.into(),
            service: None,
            tools,
        }
    }

    /// The package's service, by its launchd label (the service's name):
    /// after a failed `installer`, its daemon is loaded again when the
    /// package's scripts left it unloaded.
    #[must_use]
    pub fn with_service(mut self, label: impl Into<String>) -> Self {
        self.service = Some(label.into());
        self
    }

    /// After a failed `installer`: loads the service's daemon when it isn't
    /// loaded and its property list is there (`launchctl bootstrap`, which
    /// starts it). Best effort, logged: the run fails either way.
    fn restore_service(&self) {
        let Some(label) = &self.service else {
            return;
        };
        let launchctl = |args: &[&std::ffi::OsStr], what: &str| {
            let mut command = Command::new(&self.tools.launchctl);
            command.args(args);
            process::run(&mut command, what, None, QUERY_TIMEOUT, QUERY_OUTPUT)
        };
        let target = format!("system/{label}");
        match launchctl(&["print".as_ref(), target.as_ref()], "service state") {
            Ok(finished) if finished.status.success() => return,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("after the failed install, {label}'s state is unknown: {e}");
                return;
            }
        }
        let plist = self.tools.launch_daemons.join(format!("{label}.plist"));
        if !plist.is_file() {
            tracing::warn!(
                "the failed install left {label} unloaded, and {} is missing: not starting it",
                plist.display()
            );
            return;
        }
        match launchctl(
            &["bootstrap".as_ref(), "system".as_ref(), plist.as_os_str()],
            "service start",
        ) {
            Ok(finished) if finished.status.success() => {
                tracing::info!("the failed install left {label} unloaded: started it again");
            }
            Ok(finished) => tracing::warn!(
                "the failed install left {label} unloaded, and launchctl bootstrap failed ({}): {}",
                finished.status,
                finished.shown()
            ),
            Err(e) => tracing::warn!(
                "the failed install left {label} unloaded, and launchctl bootstrap failed: {e}"
            ),
        }
    }

    /// The receipt's release, or `None` when there is no receipt.
    fn receipt(&self) -> Result<Option<Release>, InstallError> {
        let mut command = Command::new(&self.tools.pkgutil);
        command.arg("--pkg-info").arg(&self.identifier);
        let finished = process::run(
            &mut command,
            "installed version",
            None,
            QUERY_TIMEOUT,
            QUERY_OUTPUT,
        )
        .map_err(|e| InstallError::Query(e.to_string()))?;
        if !finished.status.success() {
            // `No receipt for '<id>' found at '/'.`, exit 1.
            if finished.status.code() == Some(1) && said(&finished).contains("No receipt for") {
                return Ok(None);
            }
            return Err(InstallError::Query(format!(
                "pkgutil --pkg-info failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        parse_receipt(&String::from_utf8_lossy(&finished.stdout), &self.identifier).map(Some)
    }
}

fn said(finished: &Finished) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&finished.stdout),
        String::from_utf8_lossy(&finished.stderr)
    )
}

/// Reads `pkgutil --pkg-info <id>` output: `package-id:` must be the
/// identifier, and `version:` a release this crate spelled.
pub(crate) fn parse_receipt(output: &str, identifier: &str) -> Result<Release, InstallError> {
    let field = |name: &str| {
        output.lines().find_map(|line| {
            line.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix(':'))
                .map(str::trim)
        })
    };
    if field("package-id") != Some(identifier) {
        return Err(InstallError::Query(format!(
            "pkgutil --pkg-info printed {:?}, not {identifier}'s receipt",
            crate::log::line_safe(output)
        )));
    }
    let version = field("version").unwrap_or_default();
    Release::from_package_version(ArtifactFormat::Pkg, version)
        .map_err(|e| InstallError::Query(format!("the receipt names version {version:?}: {e}")))
}

fn path_arg(path: &Path) -> Result<&str, InstallError> {
    let text = path
        .to_str()
        .ok_or_else(|| InstallError::Install(format!("{} is not valid UTF-8", path.display())))?;
    if !path.is_absolute() || !text.ends_with(".pkg") {
        return Err(InstallError::Install(format!(
            "{} is not an absolute path to a .pkg",
            path.display()
        )));
    }
    Ok(text)
}

impl Installer for MacPkg {
    fn name(&self) -> &'static str {
        "installer"
    }

    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Pkg
    }

    fn installed(&self, _package: &str) -> Result<Option<Release>, InstallError> {
        self.receipt()
    }

    fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
        let file = path_arg(install.file)?;
        let mut command = Command::new(&self.tools.installer);
        command.args(["-pkg", file, "-target", "/"]);
        let finished = process::run(
            &mut command,
            "install",
            None,
            MACOS_INSTALL_WAIT,
            QUERY_OUTPUT,
        )
        .map_err(|e| InstallError::Install(e.to_string()))?;
        if !finished.status.success() {
            self.restore_service();
            return Err(InstallError::Install(format!(
                "installer -pkg failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        match self.receipt()? {
            Some(installed) if installed == *install.release => Ok(()),
            other => Err(InstallError::Install(format!(
                "installer succeeded, but {}'s receipt names {} instead of {}",
                self.identifier,
                other.map_or_else(|| "no release".to_owned(), |r| r.to_string()),
                install.release
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const RECEIPT: &str = "package-id: com.acme.agent\n\
                           version: 1.4.0~rc.2-812\n\
                           volume: /\n\
                           location: /\n\
                           install-time: 1792540000\n";

    #[test]
    fn the_receipt_reads_back_the_release() {
        assert_eq!(
            parse_receipt(RECEIPT, "com.acme.agent").unwrap(),
            Release::new("1.4.0-rc.2", 812).unwrap()
        );
        // Another package's receipt, a version this crate didn't spell, and
        // no version at all are refused: the floor compares against it.
        for (text, id) in [
            (RECEIPT, "com.acme.other"),
            (
                &RECEIPT.replace("1.4.0~rc.2-812", "1.4.0") as &str,
                "com.acme.agent",
            ),
            ("package-id: com.acme.agent\n", "com.acme.agent"),
        ] {
            assert!(
                matches!(parse_receipt(text, id), Err(InstallError::Query(_))),
                "{text:?}"
            );
        }
    }

    /// A stub tool: a shell script answering as the real one does.
    fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        crate::tests_support::write_script(&path, &format!("#!/bin/sh\n{body}\n"));
        path
    }

    #[test]
    fn it_installs_with_installer_and_confirms_with_the_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("log");
        let receipt = dir.path().join("receipt");
        // pkgutil answers from a file the stub installer writes.
        let pkgutil = stub(
            dir.path(),
            "pkgutil",
            &format!(
                "echo \"$@\" >> {log}\n\
                 if [ -f {receipt} ]; then cat {receipt}; else echo \"No receipt for '$2' found at '/'.\" >&2; exit 1; fi",
                log = log.display(),
                receipt = receipt.display()
            ),
        );
        let installer = stub(
            dir.path(),
            "installer",
            &format!(
                "echo \"$@\" >> {log}\nprintf 'package-id: com.acme.agent\\nversion: 2.0.0-7\\n' > {receipt}",
                log = log.display(),
                receipt = receipt.display()
            ),
        );
        let mac = MacPkg::with(
            "com.acme.agent",
            MacTools {
                installer,
                pkgutil: pkgutil.clone(),
                ..MacTools::default()
            },
        );
        assert_eq!(mac.format(), ArtifactFormat::Pkg);
        assert_eq!(mac.installed("acme-agent").unwrap(), None);
        let file = dir.path().join("acme-agent-2.0.0-7.pkg");
        let release = Release::new("2.0.0", 7).unwrap();
        let older = Release::new("1.0.0", 3).unwrap();
        let install = Install {
            package: "acme-agent",
            file: &file,
            signature: None,
            release: &release,
            replaces: &older,
        };
        mac.install(&install).unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains(&format!("-pkg {} -target /", file.display())),
            "{logged}"
        );
        assert_eq!(mac.installed("acme-agent").unwrap(), Some(release.clone()));
        // An installer that "succeeds" without the release's receipt fails.
        let lying = MacPkg::with(
            "com.acme.agent",
            MacTools {
                installer: stub(dir.path(), "lying", "exit 0"),
                pkgutil,
                ..MacTools::default()
            },
        );
        let newer = Release::new("3.0.0", 9).unwrap();
        let err = lying
            .install(&Install {
                release: &newer,
                ..install
            })
            .unwrap_err();
        assert!(
            matches!(&err, InstallError::Install(m) if m.contains("receipt names 2.0.0")),
            "{err}"
        );
        // A failing installer, and a file that isn't an absolute .pkg.
        let failing = MacPkg::with(
            "com.acme.agent",
            MacTools {
                installer: stub(dir.path(), "failing", "echo 'installer: Error' >&2; exit 1"),
                pkgutil: dir.path().join("pkgutil"),
                ..MacTools::default()
            },
        );
        assert!(matches!(
            failing.install(&install),
            Err(InstallError::Install(m)) if m.contains("installer: Error")
        ));
        for bad in [Path::new("relative.pkg"), Path::new("/tmp/x.deb")] {
            assert!(matches!(
                mac.install(&Install {
                    file: bad,
                    ..install
                }),
                Err(InstallError::Install(_))
            ));
        }
        // pkgutil failing any other way is a query error, never "not installed".
        let broken = MacPkg::with(
            "com.acme.agent",
            MacTools {
                installer: dir.path().join("installer"),
                pkgutil: stub(dir.path(), "broken", "echo 'boom' >&2; exit 2"),
                ..MacTools::default()
            },
        );
        assert!(matches!(
            broken.installed("acme-agent"),
            Err(InstallError::Query(_))
        ));
    }

    #[test]
    fn a_failed_install_loads_the_service_the_package_left_unloaded() {
        let dir = tempfile::tempdir().unwrap();
        let daemons = dir.path().join("LaunchDaemons");
        std::fs::create_dir(&daemons).unwrap();
        std::fs::write(daemons.join("AcmeAgent.plist"), "<plist/>").unwrap();
        let log = dir.path().join("launchctl.log");
        // launchctl answers `print` with <loaded>'s exit status.
        let launchctl = |loaded: u8| {
            stub(
                dir.path(),
                &format!("launchctl-{loaded}"),
                &format!(
                    "echo \"$@\" >> {log}\ncase \"$1\" in print) exit {} ;; *) exit 0 ;; esac",
                    if loaded == 0 { 0 } else { 113 },
                    log = log.display()
                ),
            )
        };
        let file = dir.path().join("acme-agent-2.0.0-7.pkg");
        let (release, older) = (
            Release::new("2.0.0", 7).unwrap(),
            Release::new("1.0.0", 3).unwrap(),
        );
        let install = Install {
            package: "acme-agent",
            file: &file,
            signature: None,
            release: &release,
            replaces: &older,
        };
        let failing = |loaded: u8| {
            MacPkg::with(
                "com.acme.agent",
                MacTools {
                    installer: stub(dir.path(), "failing", "echo 'installer: Error' >&2; exit 1"),
                    pkgutil: dir.path().join("pkgutil"),
                    launchctl: launchctl(loaded),
                    launch_daemons: daemons.clone(),
                },
            )
        };
        // Unloaded: bootstrapped again, and the install still fails.
        assert!(matches!(
            failing(1).with_service("AcmeAgent").install(&install),
            Err(InstallError::Install(m)) if m.contains("installer: Error")
        ));
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("print system/AcmeAgent"), "{logged}");
        assert!(
            logged.contains(&format!(
                "bootstrap system {}",
                daemons.join("AcmeAgent.plist").display()
            )),
            "{logged}"
        );
        // Loaded (the postinstall started it): left alone.
        std::fs::remove_file(&log).unwrap();
        assert!(
            failing(0)
                .with_service("AcmeAgent")
                .install(&install)
                .is_err()
        );
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(!logged.contains("bootstrap"), "{logged}");
        // No plist (a service the package never installed), or no service
        // named: nothing to load.
        std::fs::remove_file(&log).unwrap();
        assert!(failing(1).with_service("Other").install(&install).is_err());
        assert!(!std::fs::read_to_string(&log).unwrap().contains("bootstrap"));
        std::fs::remove_file(&log).unwrap();
        assert!(failing(1).install(&install).is_err());
        assert!(!log.exists());
    }
}
