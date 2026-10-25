//! Installers: how the update helper hands a verified package to the
//! operating system's own package manager.
//!
//! An [`Installer`] answers two questions and does one thing: which
//! release of a package is installed, and which package format it
//! installs; and install one verified file. The helper never installs
//! anything an installer didn't plan to install, and the installers never
//! refresh repository indexes, upgrade the system, or install a package
//! other than the product's own:
//!
//! | Installer | Installs with | Only our package, at the release's version, because |
//! | --- | --- | --- |
//! | [`Apt`] | `apt-get install -y --no-install-recommends ./<file>.deb` (`DEBIAN_FRONTEND=noninteractive`, `NEEDRESTART_SUSPEND=1`, `--force-confold`, a 300 s lock wait; `--allow-downgrades` only for a downgrade the floor allowed) | its plan (`apt-get install -s`) must install exactly our package, at the release's version, and touch nothing else |
//! | [`Dnf`] | `dnf upgrade -y --disablerepo=* ./<file>.rpm` (`dnf downgrade` for an allowed downgrade; dnf 4 and 5) | no repository is enabled, the file's header (`rpm -qp`) names our package at the release's version, and each command refuses the other direction |
//! | [`Pacman`] | `pacman -U --noconfirm <file>` | its plan (`pacman -Up --print-format '%n %v'`) must be exactly our package at the release's version |
//! | [`MacPkg`] (macOS) | `installer -pkg <file> -target /` | macOS's installer resolves no dependencies; afterwards the package's receipt (`pkgutil --pkg-info <bundle id>`) must name the release |
//! | `Msi` (Windows) | `msiexec /i <file> /qn /norestart /l*v <log>`, handed off ([`Installer::hands_off`]) | an MSI installs only itself; its major upgrade replaces only the product's own release, which the next run reads back from the MSI's `Release` value |
//!
//! Every program runs in the C locale, since their output is parsed
//! ([`crate::process`]). The installed release is read back only in the
//! exact spelling the seaworthy CLI writes ([`Release::from_package_version`]);
//! rpm's query includes the epoch so an epoch is refused, not dropped.
//!
//! On Linux every install runs in its own transient systemd unit
//! (`systemd-run --wait --collect`), outside the helper's unit and cgroup:
//! package scripts may restart services, and an upgrade must never be able
//! to kill the package manager mid-transaction by stopping the helper. The
//! unit has no time limit of its own (stopping a package manager
//! mid-transaction is exactly what the unit avoids); the helper
//! waits for it up to [`INSTALL_WAIT`] and reads its exit status. The
//! install's output goes to the journal under the unit's name
//! (`journalctl -u <package>-install`), and a failure repeats its last
//! lines.
//!
//! pacman's settings come from `pacman-conf`, which resolves `Include`d
//! files and repeated lines as pacman does. The package's detached
//! signature goes beside it, before pacman reads the file, only when the
//! effective local-file level is `Required`: with a signature present,
//! pacman checks it against its own keyring at any level but `Never`, and
//! fails on a key it doesn't hold.
//!
//! On Windows the MSI replaces the helper's own binary, so the helper
//! starts msiexec detached and exits (the `msi` module's docs): its
//! installer [hands the install off](Installer::hands_off), and the next
//! run confirms it. The macOS installer ([`MacPkg`]) compiles on every
//! unix, so Linux CI drives it against stub tools; the helper picks it on
//! macOS only. Callers with their own package manager implement
//! [`Installer`].

use std::fmt;
use std::path::Path;

use crate::ArtifactFormat;
use crate::release::Release;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{Apt, Dnf, INSTALL_WAIT, Pacman, Tools, TransientUnit, detect};

#[cfg(unix)]
mod macos;

mod msi;

#[cfg(unix)]
pub use macos::{MACOS_INSTALL_WAIT, MacPkg, MacTools};

#[cfg(windows)]
pub use msi::Msi;
pub use msi::{MSIEXEC_LOG, msiexec_arguments};
pub use seaworthy_formats::MSI_RELEASE_VALUE;

/// Why an installer couldn't answer or install.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// Asking the package manager what's installed failed, or its answer
    /// isn't a release this crate wrote.
    #[error("package query failed: {0}")]
    Query(String),
    /// The install's plan would touch more than the product's package.
    #[error("the package manager's plan installs or removes more than {package}: {plan}")]
    Plan {
        /// The product's package.
        package: String,
        /// The offending plan lines.
        plan: String,
    },
    /// The install ran and failed (or didn't finish in time).
    #[error("install failed: {0}")]
    Install(String),
    /// No installer applies to this machine (no supported package manager
    /// has the product installed).
    #[error("no installer: {0}")]
    Unsupported(String),
}

/// One install: a verified package file and what it is.
#[derive(Debug, Clone, Copy)]
pub struct Install<'a> {
    /// The product's package name (`acme-agent`).
    pub package: &'a str,
    /// The verified file, in the helper's root-only staging directory
    /// (an absolute path ending in the format's extension).
    pub file: &'a Path,
    /// The file's detached OpenPGP signature, when the format has one
    /// (pacman) and the helper verified it.
    pub signature: Option<&'a Path>,
    /// The release the file is.
    pub release: &'a Release,
    /// The installed release, which this one replaces.
    pub replaces: &'a Release,
}

impl Install<'_> {
    /// Whether this install goes back to an older release (only when the
    /// helper's floor allows downgrades).
    #[must_use]
    pub fn is_downgrade(&self) -> bool {
        self.release < self.replaces
    }
}

/// A package manager the helper installs through.
///
/// The methods block (they run programs): the helper calls them from a
/// blocking task.
pub trait Installer: Send + Sync + fmt::Debug {
    /// Its name, for logs (`apt`).
    fn name(&self) -> &'static str;

    /// The package format it installs: the manifest the helper fetches
    /// must name it.
    fn format(&self) -> ArtifactFormat;

    /// The release of `package` that is installed, or `None` when it
    /// isn't.
    ///
    /// # Errors
    /// [`InstallError::Query`] when the package manager can't be asked, or
    /// reports a version this crate's spellings don't produce
    /// ([`Release::from_package_version`]): the version floor can't compare
    /// against a version it can't read.
    fn installed(&self, package: &str) -> Result<Option<Release>, InstallError>;

    /// Installs `install.file`.
    ///
    /// # Errors
    /// [`InstallError::Plan`] when the install would touch another package;
    /// [`InstallError::Install`] when it fails.
    fn install(&self, install: &Install<'_>) -> Result<(), InstallError>;

    /// Whether [`install`](Self::install) only starts the install and
    /// returns before it ends (Windows' msiexec, which replaces the
    /// helper's own binary). The helper then leaves the staged file for
    /// the installer, doesn't wait for the release to appear, and reports
    /// [`HelperOutcome::HandedOff`](crate::helper::HelperOutcome::HandedOff);
    /// the next run confirms it. `false` by default: the helper confirms
    /// the release before it reports an install.
    fn hands_off(&self) -> bool {
        false
    }
}
