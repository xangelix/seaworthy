//! The helper's Windows half: `%ProgramData%`, the privilege check, the
//! staging directory's audit, and the run under the Service Control
//! Manager.
//!
//! **Privileges.** The helper runs as LocalSystem (the MSI installs it as
//! the `<service>-update` service). An elevated administrator may run it
//! from a console too: both may install an MSI. Anyone else is refused
//! before anything is read.
//!
//! **The staging directory**, `%ProgramData%\<Vendor>\<Directory>\updates`,
//! which the MSI creates with a protected DACL (SYSTEM and Administrators
//! only), as it does the two directories above it. Before a run uses it,
//! it and each directory above it up to `%ProgramData%` must be a
//! directory, not a reparse point (a junction or a symlink could send the
//! download elsewhere), owned by SYSTEM, Administrators or
//! TrustedInstaller, and writable by no one else
//! ([`crate::policy::acl::untrusted_writer_of`] with the directory rights).
//! `%ProgramData%` itself lets any user create a directory, so a user can
//! create `<Vendor>` before the product is installed and own it: the run is
//! then refused, which is safe (taking the owner back is the installer's
//! job). A missing directory is created with the same protected DACL, as
//! the MSI would.
//!
//! **The log** ([`open_log`]), `%ProgramData%\<Vendor>\<Directory>\
//! update-logs\<stem>.log`: the helper's own directory (the MSI's guard
//! gives it SYSTEM and Administrators alone), made or audited as the
//! staging directory is; the file opened without following a reparse point
//! and refused unless the handle is a regular file with one link, at the
//! path asked for, owned and writable only by SYSTEM, Administrators or
//! TrustedInstaller. The service's account may write `logs`, so an append
//! there as LocalSystem could be redirected.
//!
//! **The service.** [`main`] starts the dispatcher. Under the SCM the
//! service reports `Running` at once, accepts STOP and SHUTDOWN (each ends
//! the run; an install already handed to msiexec runs on), and reports
//! `Stopped` with exit code 0 when the run succeeded for the exit status,
//! else the service-specific code 1. Started from a console, the
//! dispatcher answers 1063 (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`) and
//! the run happens in the foreground.

// No FFI of its own: the token, the known folder, handles, security
// descriptors and the audits are seaworthy-fsguard's.

use std::os::windows::fs::MetadataExt as _;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use seaworthy_fsguard::windows::{
    FileAccess, KnownFolder, SecurityDescriptor, attributes, create_directory, final_path,
    known_folder, link_count, named_security, open_file, process_elevated, process_user, security,
};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;

use super::{HelperConfig, HelperError};
use crate::policy::acl::{DIRECTORY_WRITE_RIGHTS, untrusted_writer_of};

/// LocalSystem's SID.
const LOCAL_SYSTEM: &str = seaworthy_fsguard::acl::LOCAL_SYSTEM;

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a junction, a symlink or another
/// reparse point.
const REPARSE_POINT: u32 = 0x0000_0400;

/// The DACL of a staging directory the helper creates: protected, SYSTEM
/// and Administrators full control (inherited by what it holds), as the
/// MSI gives its own.
const CREATED_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// `%ProgramData%`, from the system's known folder rather than the
/// environment.
pub(super) fn program_data() -> Result<PathBuf, String> {
    Ok(known_folder(KnownFolder::ProgramData)?)
}

/// Refuses a process that is neither LocalSystem nor elevated.
pub(super) fn check_privileges() -> Result<(), HelperError> {
    let refuse = |e: seaworthy_fsguard::Error| HelperError::NotElevated(e.into());
    let sid = process_user().map_err(refuse)?;
    if sid.as_deref() == Some(LOCAL_SYSTEM) {
        return Ok(());
    }
    if process_elevated().map_err(refuse)? {
        return Ok(());
    }
    Err(HelperError::NotElevated(format!(
        "started as {}, not elevated",
        sid.as_deref().unwrap_or("an unreadable SID")
    )))
}

/// Creates `dir` with [`CREATED_DIR_SDDL`] (its parent must exist).
fn create_private_dir(dir: &Path) -> Result<(), String> {
    let descriptor = SecurityDescriptor::from_sddl(CREATED_DIR_SDDL)
        .map_err(|e| format!("can't build the staging directory's DACL ({e})"))?;
    create_directory(dir, &descriptor).map_err(|e| format!("can't create {}: {e}", dir.display()))
}

/// See the module docs. `require_root` off (a test run) skips the audit.
pub(super) fn prepare_staging(dir: &Path, require_root: bool) -> Result<(), HelperError> {
    let staging = HelperError::Staging;
    if !dir.is_absolute() {
        return Err(staging(format!("{} is not absolute", dir.display())));
    }
    if !require_root {
        return std::fs::create_dir_all(dir)
            .map_err(|e| staging(format!("can't create {}: {e}", dir.display())));
    }
    // The audit stops at %ProgramData% (any user may create a directory
    // there; what's below it is the product's), or at the volume root for
    // a staging directory elsewhere.
    let root = program_data().map_err(staging)?;
    let stop = |path: &Path| path == root || path.parent().is_none();
    let mut missing = Vec::new();
    let mut current = Some(dir);
    while let Some(path) = current.filter(|p| !stop(p)) {
        if std::fs::symlink_metadata(path).is_ok() {
            break;
        }
        missing.push(path.to_owned());
        current = path.parent();
    }
    for path in missing.iter().rev() {
        create_private_dir(path).map_err(staging)?;
        tracing::info!("created {}", path.display());
    }
    let mut current = Some(dir);
    while let Some(path) = current.filter(|p| !stop(p)) {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| staging(format!("{}: {e}", path.display())))?;
        if metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(staging(format!(
                "{} is a reparse point (a junction or a link)",
                path.display()
            )));
        }
        if !metadata.is_dir() {
            return Err(staging(format!("{} is not a directory", path.display())));
        }
        audit_trusted(path).map_err(staging)?;
        current = path.parent();
    }
    Ok(())
}

/// `path` (a directory or a file) is owned by SYSTEM, Administrators or
/// TrustedInstaller and writable by no one else (the directory rights,
/// whose bits are the matching file rights on a file).
fn audit_trusted(path: &Path) -> Result<(), String> {
    let found = named_security(path)?;
    match untrusted_writer_of(
        &path.display().to_string(),
        found.owner.as_deref(),
        found.dacl.as_deref(),
        DIRECTORY_WRITE_RIGHTS,
    ) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

/// A log file's stem: `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 100 bytes, so
/// `<stem>.log` names a file in the log directory and nothing else.
fn is_log_stem(stem: &str) -> bool {
    stem.len() <= 100
        && stem
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// [`super::log_file`]: the log directory made or audited as the staging
/// directory is, then `<stem>.log` opened to append without following a
/// reparse point and kept only if the open handle is a regular file with
/// one link, at the path asked for, owned and writable only by SYSTEM,
/// Administrators or TrustedInstaller.
pub(super) fn open_log(dir: &Path, stem: &str) -> Result<std::fs::File, String> {
    if !is_log_stem(stem) {
        return Err(format!("{stem:?} is not a plain file name"));
    }
    prepare_staging(dir, true).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{stem}.log"));
    let file = open_file(&path, FileAccess::Append, true)?;
    let handle = file.as_handle();
    let found = attributes(handle, &path)?;
    if found.is_reparse_point() {
        return Err(format!(
            "{} is a reparse point (a junction or a link)",
            path.display()
        ));
    }
    if found.is_directory() {
        return Err(format!("{} is not a file", path.display()));
    }
    let links = link_count(handle, &path)?;
    if links != 1 {
        return Err(format!(
            "{} has {links} names (a hard link to another file)",
            path.display()
        ));
    }
    let directory = open_file(dir, FileAccess::ReadAttributes, false)?;
    let wanted = format!(
        "{}\\{stem}.log",
        final_path(directory.as_handle(), dir)?.trim_end_matches('\\')
    );
    let found = final_path(handle, &path)?;
    if !found.eq_ignore_ascii_case(&wanted) {
        return Err(format!(
            "{} is not where it was asked for (it is {found})",
            path.display()
        ));
    }
    let what = path.display().to_string();
    let object = security(handle, &what)?;
    if let Some(why) = untrusted_writer_of(
        &what,
        object.owner.as_deref(),
        object.dacl.as_deref(),
        DIRECTORY_WRITE_RIGHTS,
    ) {
        return Err(why);
    }
    Ok(file)
}

/// [`super::read_protected_file`]: the file and each directory above it up
/// to `%ProgramData%` audited as the staging directory is, then read.
pub(super) fn read_protected_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read as _;
    if !path.is_absolute() {
        return Err(format!("{} is not absolute", path.display()));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if metadata.file_attributes() & REPARSE_POINT != 0 {
        return Err(format!(
            "{} is a reparse point (a junction or a link): refused",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!("{} isn't a regular file: refused", path.display()));
    }
    audit_trusted(path)?;
    let root = program_data()?;
    let mut current = path.parent();
    while let Some(dir) = current.filter(|p| *p != root && p.parent().is_some()) {
        let metadata =
            std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a reparse point (a junction or a link): refused",
                dir.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory: refused", dir.display()));
        }
        audit_trusted(dir)?;
        current = dir.parent();
    }
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{} holds more than {max_bytes} bytes: refused",
            path.display()
        ));
    }
    Ok(Some(bytes))
}

/// The configuration and the result channel, stashed for the SCM-invoked
/// service main (the dispatcher takes only a plain function).
type Stash = (HelperConfig, mpsc::Sender<bool>);

static STASH: Mutex<Option<Stash>> = Mutex::new(None);

/// Runs the helper as its service, or in the foreground outside the SCM;
/// `true` when the run succeeded for the exit status.
pub(super) fn main(config: HelperConfig) -> bool {
    let name = service_name(&config);
    let (sender, receiver) = mpsc::channel();
    *STASH.lock().unwrap_or_else(PoisonError::into_inner) = Some((config, sender));
    match service_dispatcher::start(&name, service_main) {
        Ok(()) => receiver.recv().unwrap_or_else(|_| {
            tracing::error!("the helper's service ended without a result");
            false
        }),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32) =>
        {
            // Not under the SCM: a console run.
            let Some((config, _)) = STASH.lock().unwrap_or_else(PoisonError::into_inner).take()
            else {
                return false;
            };
            super::run_once(&config, std::future::pending())
        }
        Err(e) => {
            tracing::error!("the helper can't start its service dispatcher: {e}");
            false
        }
    }
}

/// The helper's service name: `<service>-update`, else `<package>-update`
/// (unchecked by the SCM for a service in its own process).
fn service_name(config: &HelperConfig) -> String {
    config
        .product()
        .helper_service()
        .unwrap_or_else(|| format!("{}-update", config.product().package()))
}

/// The service main the SCM calls on its own thread.
extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    // No panic may cross this frame; a missing stash (a second call) is
    // logged and ignored.
    let Some((config, sender)) = STASH.lock().unwrap_or_else(PoisonError::into_inner).take() else {
        tracing::error!("the SCM called the helper's service main twice");
        return;
    };
    let ok = run_service(&config);
    let _ = sender.send(ok);
}

fn status(
    state: ServiceState,
    accept: ServiceControlAccept,
    exit: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    }
}

/// `Running` at once, the run raced against STOP and SHUTDOWN, then
/// `Stopped` with the run's exit status.
fn run_service(config: &HelperConfig) -> bool {
    let stop = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&stop);
    let handle =
        match service_control_handler::register(
            service_name(config),
            move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    signal.notify_one();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        ) {
            Ok(handle) => handle,
            Err(e) => {
                tracing::error!("the helper can't register its service control handler: {e}");
                return false;
            }
        };
    let accept = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
    if let Err(e) = handle.set_service_status(status(
        ServiceState::Running,
        accept,
        ServiceExitCode::Win32(0),
    )) {
        tracing::warn!("the helper couldn't report Running: {e}");
    }
    let ok = super::run_once(config, async move { stop.notified().await });
    let exit = if ok {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    if let Err(e) = handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    )) {
        tracing::warn!("the helper couldn't report Stopped: {e}");
    }
    ok
}
