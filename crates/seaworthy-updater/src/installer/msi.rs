//! The MSI installer (Windows): `msiexec /i <file> /qn /norestart`,
//! handed off.
//!
//! On Windows the MSI replaces the helper's own binary and stops and
//! removes its service on an upgrade (the seaworthy CLI's MSI controls the
//! helper's service), so the helper can't wait for the install it starts:
//! it starts msiexec detached and exits, and isn't running when Windows
//! Installer replaces its files. [`Msi::hands_off`]
//! says so: the helper keeps the staged package for msiexec, reports
//! [`HelperOutcome::HandedOff`](crate::helper::HelperOutcome::HandedOff),
//! and the next run confirms the release ([`Msi::installed`]) or, past the
//! failure memo's backoff, tries again.
//!
//! msiexec starts in a new process group with no console and outside any
//! job object that allows breaking away (Restart Manager restarts a closed
//! app from msiexec's client process, so nothing may kill it when the
//! helper exits). Its verbose log goes to [`MSIEXEC_LOG`] in the
//! staging directory, which the next run keeps.
//!
//! The installed release is the MSI's [`MSI_RELEASE_VALUE`] under the
//! product's install key (`HKLM\SOFTWARE\<Vendor>\<Directory>`), which
//! the seaworthy CLI's MSI writes in deb's spelling
//! ([`PackageVersions::msi_release`](crate::release::PackageVersions::msi_release)):
//! ProductVersion holds neither a pre-release nor the sequence. The key is
//! read only when nobody but SYSTEM, Administrators or TrustedInstaller
//! could have written it, as the update policy is.

use std::ffi::OsString;
use std::path::Path;

#[cfg(windows)]
use seaworthy_formats::MSI_RELEASE_VALUE;

/// msiexec's verbose log of the last install, in the staging directory.
pub const MSIEXEC_LOG: &str = "msiexec-last.log";

/// msiexec's arguments for installing `file` silently, logging to `log`:
/// `/i <file> /qn /norestart /l*v <log>`. A major upgrade (the seaworthy
/// CLI's MSI) removes the installed release first; `/norestart`
/// leaves a reboot to the administrator (msiexec then exits 3010).
#[must_use]
pub fn msiexec_arguments(file: &Path, log: &Path) -> Vec<OsString> {
    vec![
        "/i".into(),
        file.as_os_str().to_owned(),
        "/qn".into(),
        "/norestart".into(),
        "/l*v".into(),
        log.as_os_str().to_owned(),
    ]
}

#[cfg(windows)]
pub use windows::Msi;

#[cfg(windows)]
mod windows {
    use std::os::windows::process::CommandExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use super::{MSI_RELEASE_VALUE, MSIEXEC_LOG, msiexec_arguments};
    use crate::ArtifactFormat;
    use crate::installer::{Install, InstallError, Installer};
    use crate::release::Release;

    /// No console window.
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    /// Its own process group: no console control event reaches it.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    /// Out of the helper's job object, when it's in one that allows it.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    /// `ERROR_ACCESS_DENIED`: the job doesn't allow breaking away.
    const ACCESS_DENIED: i32 = 5;

    /// Installs MSIs through msiexec and reads the installed release from
    /// the product's install key (see the module docs).
    #[derive(Debug, Clone)]
    pub struct Msi {
        install_key: String,
    }

    impl Msi {
        /// The installer for the product whose install key is
        /// `install_key` ([`Product::install_key`](crate::Product::install_key)).
        #[must_use]
        pub fn new(install_key: impl Into<String>) -> Self {
            Self {
                install_key: install_key.into(),
            }
        }
    }

    /// `%SystemRoot%\System32\msiexec.exe`, from the system's own answer
    /// rather than the environment or `PATH`.
    fn msiexec() -> Result<PathBuf, InstallError> {
        let mut buffer = [0u16; 512];
        #[allow(unsafe_code, reason = "GetSystemDirectoryW through windows-sys")]
        // SAFETY: `buffer` holds 512 UTF-16 units, the length passed.
        let len = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        } as usize;
        if len == 0 || len >= buffer.len() {
            return Err(InstallError::Install(format!(
                "can't find the system directory: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(PathBuf::from(String::from_utf16_lossy(
            buffer.get(..len).unwrap_or_default(),
        ))
        .join("msiexec.exe"))
    }

    impl Installer for Msi {
        fn name(&self) -> &'static str {
            "msiexec"
        }

        fn format(&self) -> ArtifactFormat {
            ArtifactFormat::Msi
        }

        fn hands_off(&self) -> bool {
            true
        }

        fn installed(&self, _package: &str) -> Result<Option<Release>, InstallError> {
            let text =
                crate::policy::windows::read_install_value(&self.install_key, MSI_RELEASE_VALUE)
                    .map_err(InstallError::Query)?;
            text.map(|text| {
                Release::from_package_version(ArtifactFormat::Msi, &text).map_err(|_| {
                    InstallError::Query(format!(
                        "HKLM\\{}\\{MSI_RELEASE_VALUE} is {:?}, not a release seaworthy wrote",
                        self.install_key,
                        crate::log::line_safe(&text)
                    ))
                })
            })
            .transpose()
        }

        fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
            let staging = install.file.parent().ok_or_else(|| {
                InstallError::Install(format!("{} has no directory", install.file.display()))
            })?;
            let log = staging.join(MSIEXEC_LOG);
            let _ = std::fs::remove_file(&log);
            let program = msiexec()?;
            let start = |flags: u32| {
                Command::new(&program)
                    .args(msiexec_arguments(install.file, &log))
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .creation_flags(flags)
                    .spawn()
            };
            let detached = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
            let child = match start(detached | CREATE_BREAKAWAY_FROM_JOB) {
                Err(e) if e.raw_os_error() == Some(ACCESS_DENIED) => start(detached),
                other => other,
            }
            .map_err(|e| InstallError::Install(format!("starting {}: {e}", program.display())))?;
            tracing::info!(
                "handed {} {} to msiexec (log: {}); the next run confirms it",
                install.package,
                install.release,
                log.display()
            );
            tracing::debug!("msiexec runs as process {}", child.id());
            // Dropping the handle neither waits for nor kills msiexec.
            drop(child);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msiexec_installs_silently_without_a_reboot_and_logs() {
        let args = msiexec_arguments(
            Path::new(r"C:\ProgramData\Acme\Agent\updates\acme-agent-1.4.0-812.msi"),
            Path::new(r"C:\ProgramData\Acme\Agent\updates\msiexec-last.log"),
        );
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "/i",
                r"C:\ProgramData\Acme\Agent\updates\acme-agent-1.4.0-812.msi",
                "/qn",
                "/norestart",
                "/l*v",
                r"C:\ProgramData\Acme\Agent\updates\msiexec-last.log",
            ]
        );
    }
}
