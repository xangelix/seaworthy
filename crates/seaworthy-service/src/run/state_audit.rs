//! A service's own state directory, audited before it runs: the directory
//! and everything below it (bounded) must be what an administrator or the
//! service itself made, or the service refuses to start.
//!
//! The installer makes the state directory safe (on Windows, the seaworthy
//! CLI's MSI takes `%ProgramData%\<Vendor>\<Directory>\state` back from
//! anyone who created it first and refuses an install over planted
//! content); this is the run-time half, for whatever changed since:
//!
//! - **Windows.** The directory is opened without following a reparse
//!   point and must be a directory whose final path is the one asked for
//!   (so no folder above it is a junction either; `%ProgramData%` itself
//!   may be redirected by its administrator). It and every object below it
//!   must be no reparse point, owned by SYSTEM, Administrators,
//!   TrustedInstaller or the service's own account (the process token's
//!   user: `NT SERVICE\<name>` for a virtual account), and writable by no
//!   one else. `run_windows_service` runs this on the MSI's state
//!   directory before `init` (a service installed under
//!   `%ProgramFiles%\<Vendor>\<Directory>`), failing the start as a fatal
//!   error.
//! - **Unix.** The path must be absolute and its own canonical form (no
//!   symlink on the way); it and every object below it must be no symlink,
//!   owned by root or the service's effective user, and not writable by
//!   group or others. A service calls [`audit_state_directory`] itself
//!   (systemd's `StateDirectory=` makes the directory the service's).
//!
//! At most [`MAX_ENTRIES`] objects, [`MAX_DEPTH`] levels deep: a larger
//! tree is refused too.
//!
//! The rules and the walks are `seaworthy-fsguard`'s (shared with the
//! update helper and the MSI's install-time guard); this module holds the
//! service's policy: who besides SYSTEM, Administrators and
//! TrustedInstaller (root on Unix) may own and write its state.

use std::path::Path;

#[cfg(any(windows, test))]
use seaworthy_fsguard::acl::{DIRECTORY_WRITE_RIGHTS, WriterPolicy};
#[cfg(any(unix, test))]
use seaworthy_fsguard::mode::Owners;
#[cfg(test)]
use seaworthy_fsguard::{acl, mode};

use crate::ServiceError;

/// The most objects the audit visits below the state directory.
pub const MAX_ENTRIES: usize = seaworthy_fsguard::MAX_ENTRIES;
/// The deepest the audit descends below the state directory.
pub const MAX_DEPTH: usize = seaworthy_fsguard::MAX_DEPTH;

/// Audits the state directory at `path` (see the module docs).
///
/// # Errors
/// [`ServiceError::UntrustedState`] naming the first object that isn't
/// trusted and why (an object that can't be read counts as untrusted).
pub fn audit_state_directory(path: &Path) -> Result<(), ServiceError> {
    platform::audit(path).map_err(ServiceError::UntrustedState)
}

/// Windows: the MSI's state directory of the running service, when the
/// program was installed as the seaworthy CLI's MSI installs it
/// (`%ProgramFiles%\<Vendor>\<Directory>\<program>`, the state in
/// `%ProgramData%\<Vendor>\<Directory>\state`) and that directory exists,
/// audited; `Ok` otherwise (another layout, a developer build).
#[cfg(windows)]
pub(crate) fn audit_installed_state() -> Result<(), String> {
    match platform::installed_state_directory()? {
        Some(state) => platform::audit(&state),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The service's policy (the rules themselves are seaworthy-fsguard's, pure
// and tested everywhere)

/// Windows: who may own and write the state. SYSTEM, Administrators,
/// TrustedInstaller and the service's own account (`account`: the process
/// token's user); every right that changes a directory or a file counts as
/// a write; OWNER RIGHTS grants the owner, whom the rule checks itself.
#[cfg(any(windows, test))]
fn writer_policy<'a>(account: &'a [&'a str]) -> WriterPolicy<'a> {
    WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS)
        .with_accounts(account, "the service's account")
        .trusting_owner_rights()
}

/// Unix: who may own the state. Root or the service's effective user.
#[cfg(any(unix, test))]
fn owners(euid: u32) -> Owners<'static> {
    Owners::RootOr {
        uid: euid,
        named: "the service's user",
    }
}

/// Why `what` (owned by `owner`, with `dacl`; `None` for a NULL DACL) could
/// be changed by someone other than SYSTEM, Administrators,
/// TrustedInstaller or `account`, or `None` when it can't.
#[cfg(test)]
fn untrusted(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[acl::Ace]>,
    account: &str,
) -> Option<String> {
    acl::untrusted(what, owner, dacl, &writer_policy(&[account]))
}

/// The Unix rule for one object: owned by root or `euid`, not writable by
/// group or others, no symlink.
#[cfg(test)]
fn unix_untrusted(what: &str, uid: u32, mode: u32, symlink: bool, euid: u32) -> Option<String> {
    mode::untrusted(what, uid, mode, symlink, owners(euid))
}

// ---------------------------------------------------------------------------
// Unix

#[cfg(unix)]
mod platform {
    use std::path::Path;

    use seaworthy_fsguard::unix::{audit_directory, effective_uid};

    pub(super) fn audit(path: &Path) -> Result<(), String> {
        Ok(audit_directory(path, super::owners(effective_uid()))?)
    }
}

// ---------------------------------------------------------------------------
// Windows

#[cfg(windows)]
mod platform {
    use std::path::{Path, PathBuf};

    use seaworthy_fsguard::windows::{KnownFolder, audit_directory, known_folder, process_user};

    pub(super) fn audit(path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("{} is not absolute", path.display()));
        }
        let account =
            process_user()?.ok_or_else(|| "can't read the process token's user".to_owned())?;
        let accounts = [account.as_str()];
        Ok(audit_directory(path, &super::writer_policy(&accounts))?)
    }

    /// The MSI's state directory for the running program (see
    /// [`super::audit_installed_state`]).
    pub(super) fn installed_state_directory() -> Result<Option<PathBuf>, String> {
        let Ok(exe) = std::env::current_exe() else {
            return Ok(None);
        };
        let Some(product) = exe.parent() else {
            return Ok(None);
        };
        let (Some(directory), Some(vendor_dir)) = (product.file_name(), product.parent()) else {
            return Ok(None);
        };
        let (Some(vendor), Some(program_files)) = (vendor_dir.file_name(), vendor_dir.parent())
        else {
            return Ok(None);
        };
        let installed = known_folder(KnownFolder::ProgramFiles)?;
        if !program_files
            .as_os_str()
            .eq_ignore_ascii_case(installed.as_os_str())
        {
            return Ok(None);
        }
        let state = known_folder(KnownFolder::ProgramData)?
            .join(vendor)
            .join(directory)
            .join("state");
        Ok(std::fs::symlink_metadata(&state).is_ok().then_some(state))
    }
}

#[cfg(test)]
mod tests {
    use seaworthy_fsguard::acl::{Ace, CREATOR_OWNER, OWNER_RIGHTS};

    use super::*;

    const SY: &str = "S-1-5-18";
    const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
    const USER: &str = "S-1-5-21-1-2-3-1001";

    fn ace(sid: &str, mask: u32) -> Ace {
        Ace {
            allow: true,
            inherit_only: false,
            mask,
            sid: Some(sid.to_owned()),
        }
    }

    #[test]
    fn the_service_s_own_objects_and_the_administrators_pass() {
        let what = "C:\\ProgramData\\Acme\\Agent\\state\\x";
        let state = [
            ace(SY, 0x001F_01FF),
            ace("S-1-5-32-544", 0x001F_01FF),
            ace(OWNER_RIGHTS, 0x0002_0000),
            ace(SERVICE, 0x0013_01BF),
        ];
        for owner in [SY, "S-1-5-32-544", SERVICE] {
            assert_eq!(untrusted(what, Some(owner), Some(&state), SERVICE), None);
        }
        // Another service's account, or a user: neither owns nor writes.
        let why = untrusted(what, Some(USER), Some(&state), SERVICE).expect("refused");
        assert!(why.contains("is owned by"), "{why}");
        assert!(untrusted(what, Some(SERVICE), Some(&state), "S-1-5-80-9-9-9-9-9").is_some());
        let mut planted = state.to_vec();
        planted.push(ace(USER, 0x0000_0002));
        let why = untrusted(what, Some(SY), Some(&planted), SERVICE).expect("refused");
        assert!(why.contains(USER), "{why}");
        assert!(untrusted(what, Some(SY), None, SERVICE).is_some());
        // Read access and inherit-only or deny entries change nothing.
        let harmless = [
            ace(SY, 0x001F_01FF),
            ace("S-1-5-32-545", 0x0012_00A9),
            Ace {
                inherit_only: true,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            Ace {
                allow: false,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            ace(CREATOR_OWNER, 0x1000_0000),
        ];
        assert_eq!(untrusted(what, Some(SY), Some(&harmless), SERVICE), None);
    }

    #[test]
    fn the_unix_rule_wants_root_or_the_service_and_no_shared_write() {
        assert_eq!(unix_untrusted("x", 0, 0o40700, false, 990), None);
        assert_eq!(unix_untrusted("x", 990, 0o100600, false, 990), None);
        assert_eq!(unix_untrusted("x", 990, 0o100644, false, 990), None);
        assert!(unix_untrusted("x", 1000, 0o100600, false, 990).is_some());
        assert!(unix_untrusted("x", 990, 0o100620, false, 990).is_some());
        assert!(unix_untrusted("x", 990, 0o40777, false, 990).is_some());
        assert!(unix_untrusted("x", 0, 0o120777, true, 990).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_state_directory_is_audited_whole() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = std::env::temp_dir().join(format!("seaworthy-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        let state = scratch.join("state");
        std::fs::create_dir_all(state.join("keys")).unwrap();
        let state = std::fs::canonicalize(&state).unwrap();
        for dir in [&state, &state.join("keys")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(state.join("keys/enrollment"), b"x").unwrap();
        std::fs::set_permissions(
            state.join("keys/enrollment"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(audit_state_directory(&state).is_ok());
        // Reached through a symlink: refused.
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        let err = audit_state_directory(&link).unwrap_err().to_string();
        assert!(err.contains("through a symlink"), "{err}");
        // A symlink inside, a group-writable file: refused.
        std::os::unix::fs::symlink("/etc/passwd", state.join("keys/planted")).unwrap();
        let err = audit_state_directory(&state).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");
        std::fs::remove_file(state.join("keys/planted")).unwrap();
        std::fs::set_permissions(
            state.join("keys/enrollment"),
            std::fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        let err = audit_state_directory(&state).unwrap_err().to_string();
        assert!(err.contains("writable by group or others"), "{err}");
        assert!(audit_state_directory(Path::new("relative/state")).is_err());
        std::fs::remove_dir_all(&scratch).unwrap();
    }
}
