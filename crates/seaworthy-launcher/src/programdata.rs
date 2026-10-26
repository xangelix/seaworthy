//! The product's `%ProgramData%` folders, made safe at install time (the
//! seaworthy CLI's MSI runs this as a deferred, no-impersonate custom
//! action: the launcher started as LocalSystem with [`FLAG`]).
//!
//! `%ProgramData%` lets any user create a directory, so before a product is
//! installed a local user can create `<Vendor>`, `<Vendor>\<Directory>` or
//! its `state` and fill them: children with protected DACLs keep their
//! owner and their grants when an installer later locks the parent, and a
//! junction in place of a folder sends the installer's own writes (and its
//! ACL writes) somewhere else. Windows Installer's `CreateFolder` and
//! `MsiLockPermissionsEx` work by path and follow junctions, so the MSI
//! leaves these folders to this guard, which works by handle:
//!
//! 1. **Each folder, top down** (`<Vendor>`, `<Vendor>\<Directory>`, then
//!    each of the product's folders below it): created with its security
//!    descriptor (owner SYSTEM, protected DACL), so it is locked at birth;
//!    or, when it exists, opened without following a reparse point, refused
//!    if it is one or isn't a directory, and taken back on the handle (owner
//!    SYSTEM, its DACL replaced, nothing propagated yet). Its final path
//!    must then be where it was asked for: a folder renamed away during the
//!    take-back is refused.
//! 2. **Everything below `<Vendor>\<Directory>`**, now that nobody but
//!    SYSTEM and Administrators can change it, is audited (bounded): no
//!    reparse point anywhere, every object owned by SYSTEM, Administrators,
//!    TrustedInstaller or an account its folder's descriptor lets write
//!    (the service's account in `state` and `logs`), and writable by no one
//!    else. Anything else refuses the install: nothing a user planted
//!    survives as trusted, and nothing is rewritten recursively.
//! 3. **The descriptors propagate** to what the folders already hold
//!    (leftovers of a previous version), from `<Vendor>\<Directory>` down,
//!    which the audit has just shown to hold no reparse point. `<Vendor>`
//!    itself, which other products and users may share, is only ever
//!    changed on its own handle.
//!
//! A refusal names the object and why on stderr and in the Application
//! event log, and the custom action's exit status fails the install.

use seaworthy_fsguard::acl::{self, Ace, DIRECTORY_WRITE_RIGHTS, WriterPolicy};

/// The argument the MSI's custom action starts the launcher with:
/// `--seaworthy-install-programdata <Vendor> <Directory> <account>
/// [<folder>[:account]]...`, where `<account>` is the service's virtual
/// account SID (`S-1-5-80-…`) or `-`, and a folder marked `:account` grants
/// that account Modify (the service's `state` and `logs`). Short on
/// purpose: the command sits in the MSI's `CustomAction` table, whose
/// target column holds 255 characters. Reserved: a launcher on Windows
/// never passes it to its core.
pub(crate) const FLAG: &str = "--seaworthy-install-programdata";

/// The descriptor of every folder: owner SYSTEM, a protected DACL of
/// SYSTEM and Administrators full control (inherited) and OWNER RIGHTS
/// read-control only, which strips an owner's implicit `WRITE_DAC` (the
/// seaworthy-service renderer's `data_dir_sddl`, `updates_dir_sddl` and
/// `helper_log_dir_sddl`).
pub(crate) const FOLDER_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)";

/// Modify (read, write, create, delete; never `WRITE_DAC` or
/// `WRITE_OWNER`), inherited: what a `:account` folder grants the account
/// (the renderer's `state_dir_sddl`).
const ACCOUNT_RIGHTS: &str = "0x1301bf";

/// The guard's exit status when the arguments are malformed (sysexits
/// `EX_USAGE`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const EXIT_USAGE: i32 = 64;
/// The guard's exit status when it refuses (sysexits `EX_NOPERM`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const EXIT_REFUSED: i32 = 77;

/// LocalSystem's SID.
#[cfg_attr(not(windows), allow(dead_code))]
const LOCAL_SYSTEM: &str = seaworthy_fsguard::acl::LOCAL_SYSTEM;

/// One folder the guard makes or takes back: its components below
/// `%ProgramData%` and its security descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Level {
    /// `[<Vendor>]`, `[<Vendor>, <Directory>]` or `[<Vendor>, <Directory>,
    /// <folder>]`.
    pub(crate) components: Vec<String>,
    /// The descriptor, as SDDL: owner SYSTEM, a protected DACL.
    pub(crate) sddl: String,
}

/// What the custom action asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    /// The folders, top down.
    pub(crate) levels: Vec<Level>,
}

/// A vendor or product directory name: `[A-Za-z0-9][A-Za-z0-9._-]*`, at
/// most 100 bytes, no `..` (the seaworthy CLI's rule).
fn is_directory_name(name: &str) -> bool {
    name.len() <= 100
        && !name.contains("..")
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A folder's name below the product's: `[a-z][a-z0-9-]*`, at most 32
/// bytes (`state`, `logs`, `updates`, `update-logs`).
fn is_folder_name(name: &str) -> bool {
    name.len() <= 32
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A virtual account's SID: `S-1-5-80-` and five 32-bit numbers.
fn is_virtual_account(sid: &str) -> bool {
    sid.strip_prefix("S-1-5-80-").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('-').collect();
        parts.len() == 5
            && parts.iter().all(|part| {
                !part.is_empty()
                    && part.bytes().all(|b| b.is_ascii_digit())
                    && part.parse::<u32>().is_ok()
            })
    })
}

/// The request in the arguments after [`FLAG`].
pub(crate) fn parse(args: &[String]) -> Result<Request, String> {
    let [vendor, directory, account, folders @ ..] = args else {
        return Err(format!(
            "usage: {FLAG} <Vendor> <Directory> <account SID or -> [<folder>[:account]]..."
        ));
    };
    for name in [vendor, directory] {
        if !is_directory_name(name) {
            return Err(format!(
                "{name:?} is not a directory name ([A-Za-z0-9][A-Za-z0-9._-]*, no \"..\")"
            ));
        }
    }
    let account = match account.as_str() {
        "-" => None,
        sid if is_virtual_account(sid) => Some(sid),
        other => {
            return Err(format!(
                "{other:?} is not a virtual account's SID (S-1-5-80-…) or -"
            ));
        }
    };
    let mut levels = vec![
        Level {
            components: vec![vendor.clone()],
            sddl: FOLDER_SDDL.to_owned(),
        },
        Level {
            components: vec![vendor.clone(), directory.clone()],
            sddl: FOLDER_SDDL.to_owned(),
        },
    ];
    for folder in folders {
        let (name, sddl) = match folder.split_once(':') {
            None => (folder.as_str(), FOLDER_SDDL.to_owned()),
            Some((name, "account")) => {
                let sid = account.ok_or_else(|| {
                    format!("{folder:?} grants the account, but the request names none")
                })?;
                (
                    name,
                    format!("{FOLDER_SDDL}(A;OICI;{ACCOUNT_RIGHTS};;;{sid})"),
                )
            }
            Some(_) => return Err(format!("{folder:?} is not <folder> or <folder>:account")),
        };
        if !is_folder_name(name) {
            return Err(format!(
                "{name:?} is not a folder name ([a-z][a-z0-9-]*, at most 32 bytes)"
            ));
        }
        if levels
            .iter()
            .skip(2)
            .any(|level| level.components.last().is_some_and(|last| last == name))
        {
            return Err(format!("the folder {name:?} is named twice"));
        }
        levels.push(Level {
            components: vec![vendor.clone(), directory.clone(), name.to_owned()],
            sddl,
        });
    }
    Ok(Request { levels })
}

/// Who may own and write below `<Vendor>\<Directory>`: SYSTEM,
/// Administrators, TrustedInstaller and `also`, the accounts the object's
/// folder's own descriptor lets write ([`writers`]); every right that
/// changes a directory or a file counts as a write; OWNER RIGHTS grants
/// the owner, whom the rule checks itself.
#[cfg_attr(not(windows), allow(dead_code))]
fn writer_policy<'a>(also: &'a [&'a str]) -> WriterPolicy<'a> {
    WriterPolicy::administrators(DIRECTORY_WRITE_RIGHTS)
        .with_accounts(also, "its folder's account")
        .trusting_owner_rights()
}

/// The SIDs an object may be owned and written by besides SYSTEM,
/// Administrators and TrustedInstaller: the ones its folder's own
/// descriptor grants a write (`dacl`, reduced).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn writers(dacl: &[Ace]) -> Vec<String> {
    acl::writers(dacl, DIRECTORY_WRITE_RIGHTS)
}

/// Why `what` (owned by `owner`, with `dacl`; `None` for a NULL DACL) could
/// be changed by someone other than SYSTEM, Administrators,
/// TrustedInstaller or `also`, or `None` when it can't.
#[cfg(test)]
pub(crate) fn untrusted(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
    also: &[String],
) -> Option<String> {
    let also: Vec<&str> = also.iter().map(String::as_str).collect();
    acl::untrusted(what, owner, dacl, &writer_policy(&also))
}

/// Whether two final paths name the same object: the same API produced
/// both, so only the case of a component this guard named can differ (NTFS
/// compares names without case; the names here are ASCII).
#[cfg_attr(not(windows), allow(dead_code))]
fn same_path(found: &str, wanted: &str) -> bool {
    found.eq_ignore_ascii_case(wanted)
}

/// On Windows, when the launcher was started with [`FLAG`]: runs the guard
/// and returns its exit status. `None` otherwise (and on every other
/// platform, where the argument reaches the core like any other).
pub(crate) fn intercept() -> Option<i32> {
    #[cfg(windows)]
    {
        let mut args = std::env::args_os().skip(1);
        if args.next()? != FLAG {
            return None;
        }
        let rest: Option<Vec<String>> = args.map(|a| a.into_string().ok()).collect();
        let request = match rest.ok_or_else(|| "an argument is not UTF-8".to_owned()) {
            Ok(rest) => parse(&rest),
            Err(e) => Err(e),
        };
        let request = match request {
            Ok(request) => request,
            Err(why) => {
                eprintln!("{FLAG}: {why}");
                return Some(EXIT_USAGE);
            }
        };
        Some(match win::run(&request) {
            Ok(()) => 0,
            Err(why) => {
                let message = format!(
                    "the %ProgramData% folders of this product can't be trusted, so the install is refused: {why}. A local user may have created them before the install; an administrator should inspect and remove them, then install again."
                );
                eprintln!("{FLAG}: {message}");
                win::report_event(&request, &message);
                EXIT_REFUSED
            }
        })
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
mod win {
    //! The guard's steps, on seaworthy-fsguard's handle-based primitives
    //! (the token, privileges, the known folder, directory handles,
    //! security descriptors, listings and the audit itself); the event log
    //! is the only FFI here, each `unsafe` block allowed on its own with
    //! the invariant it relies on.

    use std::ffi::OsString;
    use std::os::windows::io::{AsHandle as _, OwnedHandle};
    use std::path::{Path, PathBuf};

    use seaworthy_fsguard::windows::{
        Access, KnownFolder, SecurityDescriptor, attributes, audit_object, audit_tree,
        create_directory, enable_privileges, final_path, is_protected, known_folder, list, open,
        process_user, propagate, take_back,
    };
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };

    use super::{LOCAL_SYSTEM, Level, Request, same_path, writer_policy, writers};

    fn wide_str(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// One folder, made or taken back (step 1 of the module docs); its
    /// handle, open for the descriptor's later propagation.
    fn ensure(
        path: &Path,
        wanted_final: &str,
        sd: &SecurityDescriptor,
        what: &str,
    ) -> Result<OwnedHandle, String> {
        let created = match create_directory(path, sd) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) => false,
            Err(error) => return Err(format!("can't create {what} ({error})")),
        };
        let handle = open(path, Access::TakeBack, false)?;
        let attributes = attributes(handle.as_handle(), path)?;
        if attributes.is_reparse_point() {
            return Err(format!("{what} is a reparse point (a junction or a link)"));
        }
        if !attributes.is_directory() {
            return Err(format!("{what} is not a directory"));
        }
        if !created {
            take_back(handle.as_handle(), sd, what)?;
        }
        let found = final_path(handle.as_handle(), path)?;
        if !same_path(&found, wanted_final) {
            return Err(format!(
                "{what} is not where it was asked for (it is {found}): moved while it was taken back"
            ));
        }
        Ok(handle)
    }

    /// The guard (see the module docs).
    pub(super) fn run(request: &Request) -> Result<(), String> {
        let user =
            process_user()?.ok_or_else(|| "can't read the process token's user".to_owned())?;
        if user != LOCAL_SYSTEM {
            return Err(format!(
                "it must run as LocalSystem (the MSI's deferred custom action), not {user}"
            ));
        }
        enable_privileges(&[
            "SeTakeOwnershipPrivilege",
            "SeRestorePrivilege",
            "SeBackupPrivilege",
        ])?;
        let root = known_folder(KnownFolder::ProgramData)?;
        // %ProgramData% may itself be redirected by its administrator:
        // then name where it leads.
        let root_handle = open(&root, Access::ReadAttributes, false)
            .or_else(|_| open(&root, Access::ReadAttributes, true))?;
        let root_final = final_path(root_handle.as_handle(), &root)?;
        drop(root_handle);

        // Step 1: each folder, top down.
        let mut opened: Vec<(&Level, PathBuf, OwnedHandle, SecurityDescriptor)> = Vec::new();
        for level in &request.levels {
            let path = level
                .components
                .iter()
                .fold(root.clone(), |path, component| path.join(component));
            let wanted = format!(
                "{}\\{}",
                root_final.trim_end_matches('\\'),
                level.components.join("\\")
            );
            let what = path.display().to_string();
            let sd = SecurityDescriptor::from_sddl(&level.sddl)
                .map_err(|e| format!("{:?} isn't a security descriptor ({e})", level.sddl))?;
            let handle = ensure(&path, &wanted, &sd, &what)?;
            opened.push((level, path, handle, sd));
        }

        // Step 2: everything below <Vendor>\<Directory>. A folder the
        // request names admits the writers its descriptor names; anything
        // else below the product's directory, only SYSTEM, Administrators
        // and TrustedInstaller.
        let Some((_, data_path, _, _)) = opened
            .iter()
            .find(|(level, ..)| level.components.len() == 2)
        else {
            return Err("no product directory in the request".to_owned());
        };
        let mut visited = 0usize;
        for entry in list(data_path)? {
            let name = entry.name();
            let path = data_path.join(name);
            let named = opened.iter().find(|(level, ..)| {
                level.components.len() == 3
                    && level
                        .components
                        .last()
                        .is_some_and(|last| OsString::from(last).eq_ignore_ascii_case(name))
            });
            let also = match named {
                Some((_, _, _, sd)) => writers(&sd.dacl(&path.display().to_string())?),
                None => Vec::new(),
            };
            let also: Vec<&str> = also.iter().map(String::as_str).collect();
            let policy = writer_policy(&also);
            visited = visited.saturating_add(1);
            if entry.attributes().is_reparse_point() {
                return Err(format!(
                    "{} is a reparse point (a junction or a link)",
                    path.display()
                ));
            }
            if audit_object(&path, &policy)?.is_directory() {
                audit_tree(&path, &policy, 1, &mut visited)?;
            }
        }

        // Step 3: the descriptors propagate from the product's directory
        // down; <Vendor> keeps its own handle's change alone.
        for (level, path, handle, sd) in &opened {
            let what = path.display().to_string();
            if level.components.len() >= 2 {
                propagate(handle.as_handle(), sd, &what)?;
            } else if !is_protected(handle.as_handle(), &what)? {
                eprintln!(
                    "{}: {what}'s DACL isn't marked protected; it is locked, and the product's own directory below it is",
                    super::FLAG
                );
            }
        }
        Ok(())
    }

    /// Writes `message` to the Application event log, best effort, as
    /// `<Vendor> <Directory> installer`.
    pub(super) fn report_event(request: &Request, message: &str) {
        let source = request
            .levels
            .iter()
            .find(|level| level.components.len() == 2)
            .map_or_else(
                || "seaworthy installer".to_owned(),
                |level| format!("{} installer", level.components.join(" ")),
            );
        let source = wide_str(&source);
        let text = wide_str(message);
        // SAFETY: the local machine (NULL) and a NUL-terminated source
        // name; the handle is deregistered below.
        #[allow(unsafe_code, reason = "opens the event log")]
        let log = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
        if log.is_null() {
            return;
        }
        let strings = [text.as_ptr()];
        // SAFETY: the event source handle, one NUL-terminated string in a
        // live array, no SID, no raw data.
        #[allow(unsafe_code, reason = "writes an event")]
        let _ = unsafe {
            ReportEventW(
                log,
                EVENTLOG_ERROR_TYPE,
                0,
                1,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        // SAFETY: the handle RegisterEventSourceW returned, closed once.
        #[allow(unsafe_code, reason = "closes the event log")]
        let _ = unsafe { DeregisterEventSource(log) };
    }
}

#[cfg(test)]
mod tests {
    use seaworthy_fsguard::acl::{CREATOR_OWNER, OWNER_RIGHTS};

    use super::*;

    const SY: &str = "S-1-5-18";
    const BA: &str = "S-1-5-32-544";
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

    fn args(text: &[&str]) -> Vec<String> {
        text.iter().map(|t| (*t).to_owned()).collect()
    }

    const DATA: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)";
    const STATE: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)";

    #[test]
    fn the_request_names_the_folders_top_down() {
        let request = parse(&args(&[
            "Acme",
            "Agent",
            SERVICE,
            "state:account",
            "logs:account",
            "updates",
            "update-logs",
        ]))
        .expect("parses");
        let components: Vec<String> = request
            .levels
            .iter()
            .map(|level| level.components.join("\\"))
            .collect();
        assert_eq!(
            components,
            [
                "Acme",
                "Acme\\Agent",
                "Acme\\Agent\\state",
                "Acme\\Agent\\logs",
                "Acme\\Agent\\updates",
                "Acme\\Agent\\update-logs"
            ]
        );
        // The descriptors seaworthy-service renders for these folders
        // (data_dir_sddl, state_dir_sddl for a virtual account,
        // updates_dir_sddl, helper_log_dir_sddl), byte for byte.
        let sddls: Vec<&str> = request.levels.iter().map(|l| l.sddl.as_str()).collect();
        assert_eq!(sddls, [DATA, DATA, STATE, STATE, DATA, DATA]);
        // A desktop product's helper: no account.
        let desktop = parse(&args(&["Acme", "Console", "-", "updates", "update-logs"])).unwrap();
        assert_eq!(desktop.levels.len(), 4);
        assert!(desktop.levels.iter().all(|l| l.sddl == DATA));
    }

    #[test]
    fn a_request_that_could_reach_elsewhere_is_refused() {
        for bad in [
            &["Acme", "Agent"][..],
            &["..", "Agent", "-"],
            &["Acme", "a..b", "-"],
            &["Acme", "Agent\\..", "-"],
            &["Acme", "Ag ent", "-"],
            &["Acme", "Agent", "-", "../x"],
            &["Acme", "Agent", "-", "State"],
            &["Acme", "Agent", "-", "state:account"],
            &["Acme", "Agent", SERVICE, "state:admin"],
            // Only a virtual account's own SID: never a shared or broad one.
            &["Acme", "Agent", "S-1-5-19", "state:account"],
            &["Acme", "Agent", "S-1-1-0", "state:account"],
            &["Acme", "Agent", "WD", "state:account"],
            &["Acme", "Agent", "S-1-5-80-1-2-3-4", "state:account"],
            &[
                "Acme",
                "Agent",
                "S-1-5-80-1-2-3-4-99999999999",
                "state:account",
            ],
            // A folder named twice.
            &["Acme", "Agent", "-", "state", "state"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_trusted_owners_and_writers_pass() {
        let what = "C:\\ProgramData\\Acme\\Agent\\state\\x";
        let locked = [
            ace(SY, 0x001F_01FF),
            ace(BA, 0x001F_01FF),
            ace(OWNER_RIGHTS, 0x0002_0000),
        ];
        assert_eq!(untrusted(what, Some(SY), Some(&locked), &[]), None);
        assert_eq!(untrusted(what, Some(BA), Some(&locked), &[]), None);
        // A user who created it first: their ownership survives a parent's
        // lock, and so does their own grant on a protected child.
        let why = untrusted(what, Some(USER), Some(&locked), &[]).expect("refused");
        assert!(why.contains("is owned by"), "{why}");
        let mut granted = locked.to_vec();
        granted.push(ace(USER, 0x001F_01FF));
        let why = untrusted(what, Some(SY), Some(&granted), &[]).expect("refused");
        assert!(why.contains(USER), "{why}");
        // Users' create-files right inherited from %ProgramData%.
        let mut users = locked.to_vec();
        users.push(ace("S-1-5-32-545", 0x0000_0116));
        assert!(untrusted(what, Some(SY), Some(&users), &[]).is_some());
        // A NULL DACL, an unreadable owner or trustee.
        assert!(untrusted(what, Some(SY), None, &[]).is_some());
        assert!(untrusted(what, None, Some(&locked), &[]).is_some());
        let unknown = Ace {
            sid: None,
            ..ace(SY, 0x2)
        };
        assert!(untrusted(what, Some(SY), Some(&[unknown]), &[]).is_some());
        // The service's own files in its state: owned by and writable by
        // its account, which its folder's descriptor names.
        let service = [ace(SY, 0x001F_01FF), ace(SERVICE, 0x0013_01BF)];
        assert!(untrusted(what, Some(SERVICE), Some(&service), &[]).is_some());
        let also = vec![SERVICE.to_owned()];
        assert_eq!(untrusted(what, Some(SERVICE), Some(&service), &also), None);
        // Read and execute, deny ACEs, inherit-only grants and CREATOR
        // OWNER change nothing.
        let harmless = [
            ace(SY, 0x001F_01FF),
            ace("S-1-5-32-545", 0x0012_00A9),
            Ace {
                allow: false,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            Ace {
                inherit_only: true,
                ..ace("S-1-1-0", 0x001F_01FF)
            },
            ace(CREATOR_OWNER, 0x1000_0000),
        ];
        assert_eq!(untrusted(what, Some(SY), Some(&harmless), &[]), None);
    }

    #[test]
    fn a_folders_writers_are_what_its_descriptor_lets_write() {
        let state = [
            ace(SY, 0x001F_01FF),
            ace(BA, 0x001F_01FF),
            ace(OWNER_RIGHTS, 0x0002_0000),
            ace(SERVICE, 0x0013_01BF),
            ace("S-1-5-32-545", 0x0012_00A9),
        ];
        assert_eq!(writers(&state), [SERVICE]);
        assert!(writers(&state[..3]).is_empty());
    }

    #[test]
    fn final_paths_compare_without_case() {
        assert!(same_path(
            "\\\\?\\C:\\ProgramData\\Acme\\Agent",
            "\\\\?\\C:\\ProgramData\\acme\\AGENT"
        ));
        assert!(!same_path(
            "\\\\?\\C:\\Users\\mallory\\Agent",
            "\\\\?\\C:\\ProgramData\\Acme\\Agent"
        ));
    }

    #[test]
    fn the_flag_is_not_intercepted_off_windows() {
        if !cfg!(windows) {
            assert_eq!(intercept(), None);
        }
    }
}
