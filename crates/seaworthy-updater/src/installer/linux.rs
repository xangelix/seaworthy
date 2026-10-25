//! apt, dnf and pacman, each installing through a transient systemd unit.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use super::{Install, InstallError, Installer};
use crate::ArtifactFormat;
use crate::process::{self, Finished};
use crate::release::Release;

/// How long a package query or plan may take.
const QUERY_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the helper waits for an install's unit. Waiting is all it
/// limits: the unit has no time limit of its own, because stopping a
/// package manager mid-transaction leaves a half-installed package or a
/// stale lock behind. A helper that stops waiting reports the
/// install as not confirmed, and its next run sees the outcome.
pub const INSTALL_WAIT: Duration = Duration::from_secs(900);

/// The longest query or plan output read.
const QUERY_OUTPUT: usize = 1 << 20;

/// The programs the installers run, by absolute path: the helper never
/// runs whatever `PATH` names.
#[derive(Debug, Clone)]
pub struct Tools {
    /// `apt-get`.
    pub apt_get: PathBuf,
    /// `dpkg-query`.
    pub dpkg_query: PathBuf,
    /// `dnf` (dnf 4 or dnf 5).
    pub dnf: PathBuf,
    /// `rpm`.
    pub rpm: PathBuf,
    /// `pacman`.
    pub pacman: PathBuf,
    /// `pacman-conf` (pacman's resolved configuration).
    pub pacman_conf_tool: PathBuf,
    /// pacman's configuration file.
    pub pacman_conf: PathBuf,
}

impl Tools {
    /// The distribution's own tools under `/usr/bin`, and `/etc/pacman.conf`.
    #[must_use]
    pub fn system() -> Self {
        Self {
            apt_get: PathBuf::from("/usr/bin/apt-get"),
            dpkg_query: PathBuf::from("/usr/bin/dpkg-query"),
            dnf: PathBuf::from("/usr/bin/dnf"),
            rpm: PathBuf::from("/usr/bin/rpm"),
            pacman: PathBuf::from("/usr/bin/pacman"),
            pacman_conf_tool: PathBuf::from("/usr/bin/pacman-conf"),
            pacman_conf: PathBuf::from("/etc/pacman.conf"),
        }
    }
}

impl Default for Tools {
    fn default() -> Self {
        Self::system()
    }
}

/// Where an install runs.
#[derive(Debug, Clone)]
pub struct TransientUnit {
    /// `systemd-run`.
    pub systemd_run: PathBuf,
    /// `journalctl`, for a failed install's last lines.
    pub journalctl: PathBuf,
    /// How long the helper waits for the unit ([`INSTALL_WAIT`]).
    pub wait: Duration,
    /// Run the install directly instead (this crate's tests, which have
    /// no systemd to start units).
    direct: bool,
}

impl Default for TransientUnit {
    fn default() -> Self {
        Self {
            systemd_run: PathBuf::from("/usr/bin/systemd-run"),
            journalctl: PathBuf::from("/usr/bin/journalctl"),
            wait: INSTALL_WAIT,
            direct: false,
        }
    }
}

/// Every install's environment starts with the C locale: its log lines
/// are read back (a failure repeats them), and the manager's environment
/// carries `/etc/locale.conf`'s `LANG`.
const UNIT_ENV: [(&str, &str); 1] = [("LC_ALL", "C")];

impl TransientUnit {
    /// Runs installs as plain child processes: this crate's tests only.
    #[cfg(test)]
    pub(crate) fn direct(wait: Duration) -> Self {
        Self {
            wait,
            direct: true,
            ..Self::default()
        }
    }

    /// The `systemd-run` command running `program args…` with `env` in the
    /// unit `<unit>.service`.
    fn command(
        &self,
        unit: &str,
        env: &[(&str, &str)],
        program: &Path,
        args: &[String],
    ) -> Command {
        if self.direct {
            let mut command = Command::new(program);
            command.args(args).envs(env.iter().copied());
            return command;
        }
        let mut command = Command::new(&self.systemd_run);
        command
            .args(["--wait", "--collect", "--quiet", "--service-type=exec"])
            .arg(format!("--unit={unit}"))
            .arg(format!("--description=Install {unit}"));
        for (key, value) in UNIT_ENV.iter().chain(env) {
            command.arg(format!("--setenv={key}={value}"));
        }
        command.arg("--").arg(program).args(args);
        command
    }

    /// Runs `program args…` in `<unit>.service` and waits for it, up to
    /// [`wait`](Self::wait). Stopping the wait kills `systemd-run` only;
    /// the unit runs on.
    fn run(
        &self,
        unit: &str,
        env: &[(&str, &str)],
        program: &Path,
        args: &[String],
    ) -> Result<(), InstallError> {
        let started = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut command = self.command(unit, env, program, args);
        tracing::info!(unit, "installing: {} {}", program.display(), args.join(" "));
        let finished = process::run(&mut command, "install", None, self.wait, QUERY_OUTPUT)
            .map_err(|e| match e {
                process::ProcessError::Timeout { .. } => InstallError::Install(format!(
                    "{unit}.service didn't finish within {} s; it runs on (journalctl -u {unit}), and the next run sees its outcome",
                    self.wait.as_secs()
                )),
                other => InstallError::Install(other.to_string()),
            })?;
        if finished.status.success() {
            return Ok(());
        }
        let detail = if self.direct {
            finished.shown()
        } else {
            self.journal_tail(unit, started)
                .unwrap_or_else(|| finished.shown())
        };
        Err(InstallError::Install(format!(
            "{} in {unit}.service exited with {} (journalctl -u {unit}): {detail}",
            program.display(),
            finished.status,
        )))
    }

    /// The unit's last journal lines since `started` (seconds since the
    /// epoch), best effort.
    fn journal_tail(&self, unit: &str, started: u64) -> Option<String> {
        let mut command = Command::new(&self.journalctl);
        command
            .arg(format!("--unit={unit}.service"))
            .arg(format!("--since=@{started}"))
            .args(["--lines=15", "--output=cat", "--no-pager", "--quiet"]);
        let text = process::run_ok(&mut command, "install log", QUERY_TIMEOUT).ok()?;
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        (!lines.is_empty()).then(|| crate::log::line_safe(&lines.join(" | ")))
    }
}

/// The install unit's name: `<package>-install` (one at a time: a second
/// helper's `systemd-run` fails while the first's unit exists).
fn unit_name(package: &str) -> String {
    format!("{package}-install")
}

/// Runs a query, returning it (any exit status) or a query error.
fn query(command: &mut Command, what: &str) -> Result<Finished, InstallError> {
    process::run(command, what, None, QUERY_TIMEOUT, QUERY_OUTPUT)
        .map_err(|e| InstallError::Query(e.to_string()))
}

fn path_arg(path: &Path) -> Result<String, InstallError> {
    if !path.is_absolute() {
        return Err(InstallError::Install(format!(
            "{} is not an absolute path",
            path.display()
        )));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| InstallError::Install(format!("{} is not valid UTF-8", path.display())))
}

/// The release's spellings, for the checks against the file's own version.
fn spellings(release: &Release) -> Result<crate::release::PackageVersions, InstallError> {
    release
        .package_versions()
        .map_err(|e| InstallError::Install(format!("release {release}: {e}")))
}

// ---------------------------------------------------------------------------
// apt

/// Debian and Ubuntu: `dpkg-query` for the installed version, `apt-get`
/// to install.
#[derive(Debug, Clone, Default)]
pub struct Apt {
    tools: Tools,
    unit: TransientUnit,
}

impl Apt {
    /// apt with the system's tools, installing in a transient unit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// apt with other tool paths and unit settings.
    #[must_use]
    pub fn with(tools: Tools, unit: TransientUnit) -> Self {
        Self { tools, unit }
    }

    fn install_args(install: &Install<'_>, simulate: bool) -> Result<Vec<String>, InstallError> {
        let mut args: Vec<String> = ["install", "-q", "--no-install-recommends"]
            .map(str::to_owned)
            .into();
        if simulate {
            args.push("-s".to_owned());
        } else {
            args.extend(
                [
                    "-y",
                    "-o",
                    "DPkg::Lock::Timeout=300",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                ]
                .map(str::to_owned),
            );
        }
        if install.is_downgrade() {
            args.push("--allow-downgrades".to_owned());
        }
        args.push(path_arg(install.file)?);
        Ok(args)
    }
}

/// The environment of every apt run: no prompts, no change-log pager, and
/// no needrestart (on Ubuntu it would restart services after the
/// transaction, the helper's own unit included).
const APT_ENV: [(&str, &str); 3] = [
    ("DEBIAN_FRONTEND", "noninteractive"),
    ("NEEDRESTART_SUSPEND", "1"),
    ("APT_LISTCHANGES_FRONTEND", "none"),
];

/// Checks `apt-get install -s` output: exactly one `Inst` of `package`, at
/// `version` (the file's own version must be the release's), and no
/// `Inst`, `Remv` or `Purg` of anything else (nor a removal of ours).
/// These lines aren't translated (apt's catalogue has no entry for them).
pub(crate) fn check_apt_plan(plan: &str, package: &str, version: &str) -> Result<(), InstallError> {
    let refused = |plan: String| InstallError::Plan {
        package: package.to_owned(),
        plan: crate::log::line_safe(&plan),
    };
    let mut ours = Vec::new();
    let mut others = Vec::new();
    for line in plan.lines() {
        let mut words = line.split_whitespace();
        let (Some(action), Some(name)) = (words.next(), words.next()) else {
            continue;
        };
        if !matches!(action, "Inst" | "Remv" | "Purg" | "Conf") {
            continue;
        }
        let name = name.split(':').next().unwrap_or(name);
        if name != package {
            others.push(line.trim().to_owned());
        } else if action == "Inst" {
            // `Inst <name> [<installed>] (<new> <origin> [<arch>])`
            let new = line
                .split_once('(')
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .unwrap_or_default();
            ours.push(new.to_owned());
        } else if action != "Conf" {
            others.push(line.trim().to_owned());
        }
    }
    if !others.is_empty() {
        return Err(refused(others.join("; ")));
    }
    match ours.as_slice() {
        [new] if new == version => Ok(()),
        [new] => Err(refused(format!(
            "the file is version {new}, the release is {version}"
        ))),
        _ => Err(refused(format!(
            "apt plans {} installs of it, not 1",
            ours.len()
        ))),
    }
}

/// Reads `dpkg-query -W -f '${db:Status-Abbrev}|${Version}\n'` output.
pub(crate) fn parse_dpkg_query(output: &str) -> Result<Option<Release>, InstallError> {
    let mut lines = output.lines().filter(|l| !l.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(InstallError::Query(format!(
            "dpkg-query printed {:?}, not one package",
            crate::log::line_safe(output)
        )));
    };
    let (status, version) = line.split_once('|').ok_or_else(|| {
        InstallError::Query(format!(
            "dpkg-query printed {:?}",
            crate::log::line_safe(line)
        ))
    })?;
    // `ii ` installed; `rc ` removed with its configuration left; `un `
    // unknown. Half-installed states mean an interrupted transaction.
    match status.as_bytes().get(1) {
        Some(b'n' | b'c') => Ok(None),
        Some(b'i' | b'W' | b't') => {
            Release::from_package_version(ArtifactFormat::Deb, version.trim())
                .map(Some)
                .map_err(|e| InstallError::Query(format!("dpkg reports version {version:?}: {e}")))
        }
        _ => Err(InstallError::Query(format!(
            "the package is in dpkg state {status:?} (an interrupted install: `dpkg --configure -a` repairs it)"
        ))),
    }
}

impl Installer for Apt {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Deb
    }

    fn installed(&self, package: &str) -> Result<Option<Release>, InstallError> {
        let mut command = Command::new(&self.tools.dpkg_query);
        command
            .args(["-W", "-f", "${db:Status-Abbrev}|${Version}\\n", "--"])
            .arg(package);
        let finished = query(&mut command, "installed version")?;
        if !finished.status.success() {
            let stderr = String::from_utf8_lossy(&finished.stderr);
            if finished.status.code() == Some(1) && stderr.contains("no packages found") {
                return Ok(None);
            }
            return Err(InstallError::Query(format!(
                "dpkg-query failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        parse_dpkg_query(&String::from_utf8_lossy(&finished.stdout))
    }

    fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
        let mut plan = Command::new(&self.tools.apt_get);
        plan.args(Self::install_args(install, true)?).envs(APT_ENV);
        let finished = query(&mut plan, "install plan")?;
        if !finished.status.success() {
            return Err(InstallError::Install(format!(
                "apt-get install -s failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        check_apt_plan(
            &String::from_utf8_lossy(&finished.stdout),
            install.package,
            &spellings(install.release)?.deb,
        )?;
        self.unit.run(
            &unit_name(install.package),
            &APT_ENV,
            &self.tools.apt_get,
            &Self::install_args(install, false)?,
        )
    }
}

// ---------------------------------------------------------------------------
// dnf

/// RHEL and Fedora: `rpm -q` for the installed version, `dnf upgrade` (or
/// `dnf downgrade`, only when the helper's floor allows one) with every
/// repository disabled to install. Each refuses the other direction, so
/// a package upgraded by someone else during the run is never quietly
/// downgraded. dnf 4 and dnf 5 alike.
#[derive(Debug, Clone, Default)]
pub struct Dnf {
    tools: Tools,
    unit: TransientUnit,
}

impl Dnf {
    /// dnf with the system's tools, installing in a transient unit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// dnf with other tool paths and unit settings.
    #[must_use]
    pub fn with(tools: Tools, unit: TransientUnit) -> Self {
        Self { tools, unit }
    }

    fn install_args(install: &Install<'_>) -> Result<Vec<String>, InstallError> {
        let command = if install.is_downgrade() {
            "downgrade"
        } else {
            "upgrade"
        };
        Ok([
            command,
            "-y",
            "-q",
            "--disablerepo=*",
            "--setopt=install_weak_deps=False",
        ]
        .map(str::to_owned)
        .into_iter()
        .chain([path_arg(install.file)?])
        .collect())
    }
}

/// The rpm query format: the epoch (when set) is part of the version, so a
/// package with one is refused rather than read without it.
const RPM_VERSION_FORMAT: &str = "%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\\n";

/// Reads `rpm -q --qf '<RPM_VERSION_FORMAT>'` output (one line: several
/// installed versions of the product's package is a state the helper won't
/// guess about).
pub(crate) fn parse_rpm_query(output: &str) -> Result<Release, InstallError> {
    let mut lines = output.lines().filter(|l| !l.trim().is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(InstallError::Query(format!(
            "rpm printed {:?}, not one installed version",
            crate::log::line_safe(output)
        )));
    };
    Release::from_package_version(ArtifactFormat::Rpm, line.trim())
        .map_err(|e| InstallError::Query(format!("rpm reports version {line:?}: {e}")))
}

impl Installer for Dnf {
    fn name(&self) -> &'static str {
        "dnf"
    }

    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Rpm
    }

    fn installed(&self, package: &str) -> Result<Option<Release>, InstallError> {
        let mut command = Command::new(&self.tools.rpm);
        command
            .args(["-q", "--qf", RPM_VERSION_FORMAT, "--"])
            .arg(package);
        let finished = query(&mut command, "installed version")?;
        let stdout = String::from_utf8_lossy(&finished.stdout);
        if !finished.status.success() {
            if finished.status.code() == Some(1) && stdout.contains("is not installed") {
                return Ok(None);
            }
            return Err(InstallError::Query(format!(
                "rpm -q failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        parse_rpm_query(&stdout).map(Some)
    }

    fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
        // The file's own name and version must be the release's.
        let mut header = Command::new(&self.tools.rpm);
        header
            .args([
                "-qp",
                "--qf",
                &format!("%{{NAME}}|{RPM_VERSION_FORMAT}"),
                "--",
            ])
            .arg(install.file);
        let finished = query(&mut header, "package header")?;
        let spelled = spellings(install.release)?;
        let expected = format!(
            "{}|{}-{}",
            install.package, spelled.rpm_version, spelled.rpm_release
        );
        let found = String::from_utf8_lossy(&finished.stdout).trim().to_owned();
        if !finished.status.success() || found != expected {
            return Err(InstallError::Plan {
                package: install.package.to_owned(),
                plan: crate::log::line_safe(&format!(
                    "the file is {found:?}, the release is {expected:?}"
                )),
            });
        }
        self.unit.run(
            &unit_name(install.package),
            &[],
            &self.tools.dnf,
            &Self::install_args(install)?,
        )
    }
}

// ---------------------------------------------------------------------------
// pacman

/// Arch: `pacman -Q` for the installed version, `pacman -U` to install.
#[derive(Debug, Clone, Default)]
pub struct Pacman {
    tools: Tools,
    unit: TransientUnit,
}

impl Pacman {
    /// pacman with the system's tools, installing in a transient unit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// pacman with other tool paths and unit settings.
    #[must_use]
    pub fn with(tools: Tools, unit: TransientUnit) -> Self {
        Self { tools, unit }
    }
}

/// Reads `pacman -Q <package>` output (`<name> <pkgver>-<pkgrel>`).
pub(crate) fn parse_pacman_query(output: &str, package: &str) -> Result<Release, InstallError> {
    let line = output
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default();
    match line.split_whitespace().collect::<Vec<_>>().as_slice() {
        [name, version] if *name == package => {
            Release::from_package_version(ArtifactFormat::Pacman, version).map_err(|e| {
                InstallError::Query(format!("pacman reports version {version:?}: {e}"))
            })
        }
        _ => Err(InstallError::Query(format!(
            "pacman -Q printed {:?}",
            crate::log::line_safe(line)
        ))),
    }
}

/// Removes a file at drop (the signature placed beside a package).
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn remove_if_present(path: &Path) -> Result<(), InstallError> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(InstallError::Install(format!("{}: {e}", path.display())))
        }
        _ => Ok(()),
    }
}

impl Installer for Pacman {
    fn name(&self) -> &'static str {
        "pacman"
    }

    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Pacman
    }

    fn installed(&self, package: &str) -> Result<Option<Release>, InstallError> {
        let mut command = Command::new(&self.tools.pacman);
        command.args(["-Q", "--"]).arg(package);
        let finished = query(&mut command, "installed version")?;
        if !finished.status.success() {
            let stderr = String::from_utf8_lossy(&finished.stderr);
            if finished.status.code() == Some(1) && stderr.contains("was not found") {
                return Ok(None);
            }
            return Err(InstallError::Query(format!(
                "pacman -Q failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        parse_pacman_query(&String::from_utf8_lossy(&finished.stdout), package).map(Some)
    }

    fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
        let file = path_arg(install.file)?;
        // The signature goes beside the package before pacman reads it at
        // all: under a Required level even the plan refuses a package
        // without one. It goes there only then: with a signature
        // present, pacman checks it against its own keyring at any level
        // but Never, and fails on a key it doesn't hold. The helper has
        // checked it against the product's pinned keys either way.
        let conf = crate::pacman_conf::read(&self.tools.pacman_conf_tool, &self.tools.pacman_conf)
            .map_err(InstallError::Install)?;
        let beside = PathBuf::from(format!("{file}.sig"));
        remove_if_present(&beside)?;
        let _placed = RemoveOnDrop(beside.clone());
        if let (Some(signature), true) = (install.signature, conf.local_file_signature_required()) {
            std::fs::copy(signature, &beside)
                .map_err(|e| InstallError::Install(format!("{}: {e}", beside.display())))?;
        }
        let mut plan = Command::new(&self.tools.pacman);
        plan.args(["-U", "--print", "--print-format", "%n %v", "--"])
            .arg(&file);
        let finished = query(&mut plan, "install plan")?;
        if !finished.status.success() {
            return Err(InstallError::Install(format!(
                "pacman -Up failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        let spelled = spellings(install.release)?;
        let expected = format!(
            "{} {}-{}",
            install.package, spelled.pacman_pkgver, spelled.pacman_pkgrel
        );
        let stdout = String::from_utf8_lossy(&finished.stdout);
        let targets: Vec<&str> = stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        if targets != [expected.as_str()] {
            return Err(InstallError::Plan {
                package: install.package.to_owned(),
                plan: crate::log::line_safe(&format!(
                    "pacman plans {:?}, the release is {expected:?}",
                    targets.join(", ")
                )),
            });
        }
        self.unit.run(
            &unit_name(install.package),
            &[],
            &self.tools.pacman,
            &[
                "-U".to_owned(),
                "--noconfirm".to_owned(),
                "--".to_owned(),
                file,
            ],
        )
    }
}

// ---------------------------------------------------------------------------
// Which one

/// The installer that installed `package` on this machine: whichever of
/// apt, dnf and pacman (with their tools present) reports it installed.
/// A package manager whose query fails is skipped with a warning (a
/// Debian host with pacman's tools but no pacman database, say).
///
/// # Errors
/// [`InstallError::Unsupported`] when none reports it (a tarball install,
/// or a package installed some other way), or more than one does;
/// [`InstallError::Query`] when none reports it and a query failed.
pub fn detect(package: &str, tools: &Tools) -> Result<Box<dyn Installer>, InstallError> {
    let candidates: Vec<(Box<dyn Installer>, [&PathBuf; 2])> = vec![
        (
            Box::new(Apt::with(tools.clone(), TransientUnit::default())),
            [&tools.dpkg_query, &tools.apt_get],
        ),
        (
            Box::new(Dnf::with(tools.clone(), TransientUnit::default())),
            [&tools.rpm, &tools.dnf],
        ),
        (
            Box::new(Pacman::with(tools.clone(), TransientUnit::default())),
            [&tools.pacman, &tools.pacman_conf_tool],
        ),
    ];
    let mut found = Vec::new();
    let mut failures = Vec::new();
    for (installer, programs) in candidates {
        if !programs.iter().all(|p| p.is_file()) {
            continue;
        }
        match installer.installed(package) {
            Ok(Some(_)) => found.push(installer),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!("{}: {error}; skipping it", installer.name());
                failures.push(format!("{}: {error}", installer.name()));
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 if !failures.is_empty() => Err(InstallError::Query(format!(
            "{package} isn't reported installed, and {}",
            failures.join("; ")
        ))),
        0 => Err(InstallError::Unsupported(format!(
            "{package} is not installed by apt, dnf or pacman (the helper updates package installs only)"
        ))),
        _ => Err(InstallError::Unsupported(format!(
            "{package} is installed by more than one package manager ({})",
            found
                .iter()
                .map(|i| i.name())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "linux_tests.rs"]
mod tests;
