//! A desktop app around its own update: the release installed now, and the
//! app back once the helper has installed a newer one.
//!
//! The helper takes no input and reports nothing back to the app
//! ([`request_update`](crate::request_update) returns once it's asked), so
//! the one signal is the installed release changing ([`installed_release`]):
//! the MSI's `Release` value on Windows, the package database on Linux, the
//! package receipt on macOS.
//!
//! - **Windows:** msiexec replaces the app's own files, so the app closes
//!   before the install (the update prompt does) and can't wait for it.
//!   `spawn_relaunch_watcher` (Windows only) first starts a watcher in the user's
//!   session, as the user: Windows PowerShell from the system directory,
//!   so it holds no file the install replaces, and only cmdlets Constrained
//!   Language Mode allows. It polls `Release` until it differs from the
//!   release the app saw, lets msiexec finish ([`SETTLE_SECS`]), and starts the
//!   app again unless it already runs in that session. After the timeout it
//!   starts the app anyway. The app learns which it was from
//!   [`UPDATE_RESULT_VAR`] ([`UpdateResult`]). The app doesn't register
//!   with Restart Manager (`RegisterApplicationRestart`): Restart Manager
//!   may restart it in another session or as SYSTEM, which the
//!   cross-session spike has yet to rule out.
//! - **Linux:** the package manager replaces the files under the running
//!   app, which keeps working. The app polls [`installed_release`] and, once
//!   it changes, offers a restart: [`relaunch`] of [`current_launcher`]
//!   (the path, captured before the replacement).

use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;

use crate::Product;
use crate::installer::InstallError;
use crate::release::Release;

/// The environment variable a relaunched app reads: [`UpdateResult`]'s
/// spelling.
pub const UPDATE_RESULT_VAR: &str = "SEAWORTHY_UPDATE_RESULT";

/// How long the Windows watcher lets msiexec finish once `Release` has
/// changed: the value is written after the files, before the services
/// start and the product is registered.
pub const SETTLE_SECS: u64 = 15;

/// [`SETTLE_SECS`] as a duration.
#[cfg(windows)]
pub const SETTLE: Duration = Duration::from_secs(SETTLE_SECS);

/// What a relaunched app was relaunched after ([`UPDATE_RESULT_VAR`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateResult {
    /// The installed release changed: this is the new one.
    Installed,
    /// The watcher gave up waiting: the update failed, or is still running.
    TimedOut,
}

impl UpdateResult {
    /// The value [`UPDATE_RESULT_VAR`] carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::TimedOut => "timeout",
        }
    }

    /// The result this process was relaunched after, if it was (reads
    /// [`UPDATE_RESULT_VAR`]).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        // allow-std-env: the watcher's one-word signal to the app it starts, not configuration
        Self::parse(&std::env::var(UPDATE_RESULT_VAR).ok()?)
    }

    /// The result [`as_str`](Self::as_str) spells as `value`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::Installed, Self::TimedOut]
            .into_iter()
            .find(|result| result.as_str() == value)
    }
}

/// Why the watcher couldn't be started.
#[derive(Debug, thiserror::Error)]
pub enum RelaunchError {
    /// A name the watcher's script would carry holds a control character.
    #[error("{0}")]
    Refused(String),
    /// Starting the watcher failed.
    #[error("starting the relaunch watcher: {0}")]
    Spawn(String),
}

/// The release of `product` installed now, or `None` when it isn't
/// installed through its package (a portable copy, a development build).
///
/// Blocking: it may run the package manager's query.
///
/// # Errors
/// [`InstallError::Query`] when the package manager or the install key
/// can't be read, or holds a release seaworthy didn't write.
pub fn installed_release(product: &Product) -> Result<Option<Release>, InstallError> {
    #[cfg(any(windows, target_os = "macos"))]
    use crate::installer::Installer as _;
    let package = product.package();
    #[cfg(windows)]
    {
        crate::installer::Msi::new(product.install_key()).installed(&package)
    }
    #[cfg(target_os = "macos")]
    {
        let identifier = product.macos_package_id().ok_or_else(|| {
            InstallError::Query(format!(
                "product {package} has no [product.<id>.macos] bundle-id: no receipt to read"
            ))
        })?;
        crate::installer::MacPkg::new(identifier).installed(&package)
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        crate::installer::detect(&package, &crate::installer::Tools::system())?.installed(&package)
    }
}

/// This app's launcher, to start again after an update: the running
/// executable's path. On Linux, once the package manager has replaced the
/// file, the kernel reports it with a ` (deleted)` suffix; the path itself
/// names the new file, so the suffix is dropped.
///
/// # Errors
/// As [`std::env::current_exe`].
pub fn current_launcher() -> std::io::Result<PathBuf> {
    let path = std::env::current_exe()?;
    Ok(
        match path.to_str().and_then(|p| p.strip_suffix(" (deleted)")) {
            Some(stripped) => PathBuf::from(stripped),
            None => path,
        },
    )
}

/// Starts `launcher` detached from this process (its own process group, no
/// inherited standard streams), for an app that closes right after.
///
/// # Errors
/// As [`std::process::Command::spawn`].
pub fn relaunch(launcher: &Path) -> std::io::Result<()> {
    let mut command = std::process::Command::new(launcher);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(dir) = launcher.parent() {
        command.current_dir(dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(windows::CREATE_NEW_PROCESS_GROUP);
    }
    // Dropping the handle neither waits for nor kills it.
    drop(command.spawn()?);
    Ok(())
}

/// Starts the Windows relaunch watcher (see the module docs): once the
/// MSI's `Release` value differs from `seen` (the value as installed when
/// the app asked; `None` when there was none), and after [`SETTLE`], or
/// after `timeout`, it starts `launcher` again in this session, unless an
/// instance already runs there.
///
/// # Errors
/// [`RelaunchError::Refused`] for a name with a control character;
/// [`RelaunchError::Spawn`] when PowerShell can't be started.
#[cfg(windows)]
pub fn spawn_relaunch_watcher(
    product: &Product,
    launcher: &Path,
    seen: Option<&Release>,
    timeout: Duration,
) -> Result<(), RelaunchError> {
    let seen = match seen {
        Some(release) => {
            release
                .package_versions()
                .map_err(|e| RelaunchError::Refused(e.to_string()))?
                .msi_release
        }
        None => String::new(),
    };
    let launcher = launcher.to_str().ok_or_else(|| {
        RelaunchError::Refused(format!(
            "the launcher's path {} isn't UTF-8",
            launcher.display()
        ))
    })?;
    let script = watcher_script(&WatcherSpec {
        install_key: &product.install_key(),
        seen: &seen,
        launcher,
        timeout_secs: timeout.as_secs(),
    })?;
    windows::spawn_powershell(&script)
}

/// What the Windows watcher's script is built from.
#[derive(Debug, Clone, Copy)]
pub struct WatcherSpec<'a> {
    /// `HKLM\<install_key>` holds `Release` ([`Product::install_key`]).
    pub install_key: &'a str,
    /// `Release` as the app saw it: the watcher waits for anything else.
    pub seen: &'a str,
    /// The app's launcher, started again: a Windows path
    /// (`C:\Program Files\…\App.exe`), split here on `\`.
    pub launcher: &'a str,
    /// How long the watcher waits for `Release` to change.
    pub timeout_secs: u64,
}

/// The Windows watcher's PowerShell script: one line (statements joined by
/// `;`), every value a single-quoted literal (`'` doubled), no double
/// quote anywhere, so it passes through `-Command` as one argument intact.
/// Only cmdlets Constrained Language Mode allows (`Get-ItemProperty`,
/// `Get-Process`, `Start-Sleep`, `Start-Process`, `$env:`).
///
/// # Errors
/// [`RelaunchError::Refused`] when a value holds a control character, or
/// the launcher isn't a file in a folder.
pub fn watcher_script(spec: &WatcherSpec<'_>) -> Result<String, RelaunchError> {
    let launcher = spec.launcher;
    let (directory, file) = launcher
        .rsplit_once('\\')
        .filter(|(directory, file)| !directory.is_empty() && !file.is_empty())
        .ok_or_else(|| {
            RelaunchError::Refused(format!("the launcher {launcher} isn't a file in a folder"))
        })?;
    // Get-Process names a process by its image's file name without `.exe`.
    let stem = match file.len().checked_sub(4) {
        Some(at) if file.is_char_boundary(at) && file[at..].eq_ignore_ascii_case(".exe") => {
            &file[..at]
        }
        _ => file,
    };
    let quote = |what: &str, value: &str| -> Result<String, RelaunchError> {
        if value.chars().any(char::is_control) {
            return Err(RelaunchError::Refused(format!(
                "the relaunch watcher's {what} holds a control character"
            )));
        }
        Ok(format!("'{}'", value.replace('\'', "''")))
    };
    let key = quote("install key", &format!("HKLM:\\{}", spec.install_key))?;
    let seen = quote("installed release", spec.seen)?;
    let launcher = quote("launcher", launcher)?;
    let stem = quote("launcher name", stem)?;
    let directory = quote("launcher folder", directory)?;
    let (timeout, settle, var) = (spec.timeout_secs, SETTLE_SECS, UPDATE_RESULT_VAR);
    let (installed, timed_out) = (
        UpdateResult::Installed.as_str(),
        UpdateResult::TimedOut.as_str(),
    );
    Ok([
        format!("$deadline = (Get-Date).AddSeconds({timeout})"),
        format!("$result = '{timed_out}'"),
        format!(
            "while ((Get-Date) -lt $deadline) {{ \
             $now = (Get-ItemProperty -LiteralPath {key} -Name Release -ErrorAction SilentlyContinue).Release; \
             if ($now -and $now -ne {seen}) {{ $result = '{installed}'; break }}; \
             Start-Sleep -Seconds 2 }}"
        ),
        format!("if ($result -eq '{installed}') {{ Start-Sleep -Seconds {settle} }}"),
        "$session = (Get-Process -Id $PID).SessionId".to_owned(),
        format!(
            "$running = @(Get-Process -Name {stem} -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.SessionId -eq $session }})"
        ),
        format!(
            "if ($running.Count -eq 0) {{ $env:{var} = $result; \
             Start-Process -FilePath {launcher} -WorkingDirectory {directory} }}"
        ),
    ]
    .join("; "))
}

#[cfg(windows)]
mod windows {
    use std::os::windows::process::CommandExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    use super::RelaunchError;

    /// No console window for a console program (PowerShell).
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// Its own process group: no console control event reaches it.
    pub(super) const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    /// Out of the app's job object, when it's in one that allows it.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    /// `ERROR_ACCESS_DENIED`: the job doesn't allow breaking away.
    const ACCESS_DENIED: i32 = 5;

    /// Windows PowerShell 5.1, from the system directory.
    fn powershell() -> Result<PathBuf, RelaunchError> {
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
            return Err(RelaunchError::Spawn(format!(
                "can't find the system directory: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(PathBuf::from(String::from_utf16_lossy(
            buffer.get(..len).unwrap_or_default(),
        ))
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
    }

    /// Starts `script` in a hidden, detached PowerShell that outlives this
    /// process.
    pub(super) fn spawn_powershell(script: &str) -> Result<(), RelaunchError> {
        let program = powershell()?;
        let start = |flags: u32| {
            Command::new(&program)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    script,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(flags)
                .spawn()
        };
        let detached = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
        let child = match start(detached | CREATE_BREAKAWAY_FROM_JOB) {
            Err(e) if e.raw_os_error() == Some(ACCESS_DENIED) => start(detached),
            other => other,
        }
        .map_err(|e| RelaunchError::Spawn(format!("{}: {e}", program.display())))?;
        // Dropping the handle neither waits for nor kills it.
        drop(child);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn spec<'a>(launcher: &'a str, seen: &'a str) -> WatcherSpec<'a> {
        WatcherSpec {
            install_key: "SOFTWARE\\Acme\\Console",
            seen,
            launcher,
            timeout_secs: 900,
        }
    }

    #[test]
    fn the_watcher_waits_for_release_to_change_then_starts_the_launcher_once() {
        let launcher = r"C:\Program Files\Acme\Console\AcmeConsole.exe";
        let script = watcher_script(&spec(launcher, "1.4.0-812")).unwrap();
        assert!(!script.contains('"'), "no double quote: {script}");
        assert!(!script.contains('\n'), "one line: {script}");
        assert!(script.contains("$deadline = (Get-Date).AddSeconds(900)"));
        assert!(script.contains(
            "(Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Acme\\Console' -Name Release -ErrorAction SilentlyContinue).Release"
        ));
        assert!(
            script.contains("if ($now -and $now -ne '1.4.0-812') { $result = 'installed'; break }")
        );
        assert!(script.contains(&format!(
            "if ($result -eq 'installed') {{ Start-Sleep -Seconds {SETTLE_SECS} }}"
        )));
        assert!(script.contains(
            "Get-Process -Name 'AcmeConsole' -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $session }"
        ));
        assert!(script.contains(
            "if ($running.Count -eq 0) { $env:SEAWORTHY_UPDATE_RESULT = $result; Start-Process -FilePath 'C:\\Program Files\\Acme\\Console\\AcmeConsole.exe' -WorkingDirectory 'C:\\Program Files\\Acme\\Console' }"
        ));
        // Timed out unless the loop saw a change.
        assert!(script.find("$result = 'timeout'").unwrap() < script.find("while").unwrap());
    }

    #[test]
    fn the_watcher_quotes_every_value_and_refuses_control_characters() {
        let launcher = r"C:\O'Brien Tools\Console\Con'sole.exe";
        let script = watcher_script(&spec(launcher, "")).unwrap();
        assert!(script.contains("-FilePath 'C:\\O''Brien Tools\\Console\\Con''sole.exe'"));
        assert!(script.contains("-Name 'Con''sole'"));
        // No release installed before: any value is a change.
        assert!(script.contains("$now -ne ''"));
        for bad in ["1.4.0\n-812", "1.4.0\u{1b}"] {
            assert!(matches!(
                watcher_script(&spec(launcher, bad)),
                Err(RelaunchError::Refused(_))
            ));
        }
        let mut with_bad_key = spec(launcher, "1");
        with_bad_key.install_key = "SOFTWARE\\Acme\r\\Console";
        assert!(matches!(
            watcher_script(&with_bad_key),
            Err(RelaunchError::Refused(_))
        ));
        assert!(matches!(
            watcher_script(&spec("Console.exe", "1")),
            Err(RelaunchError::Refused(_))
        ));
    }

    #[test]
    fn the_update_result_round_trips_through_its_spelling() {
        for result in [UpdateResult::Installed, UpdateResult::TimedOut] {
            assert_eq!(UpdateResult::parse(result.as_str()), Some(result));
        }
        assert_eq!(UpdateResult::parse("Installed"), None);
        assert_eq!(UpdateResult::parse(""), None);
    }
}
