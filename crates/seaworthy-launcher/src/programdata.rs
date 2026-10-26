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

/// The most objects the audit visits below `<Vendor>\<Directory>`.
const MAX_ENTRIES: usize = 100_000;
/// The deepest the audit descends below `<Vendor>\<Directory>`.
const MAX_DEPTH: usize = 32;

/// LocalSystem's SID.
const LOCAL_SYSTEM: &str = "S-1-5-18";
/// The principals that may always own or write: LocalSystem,
/// BUILTIN\Administrators and TrustedInstaller.
const TRUSTED: [&str; 3] = [
    LOCAL_SYSTEM,
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
/// CREATOR OWNER: in an effective ACE it matches no token.
const CREATOR_OWNER: &str = "S-1-3-0";
/// OWNER RIGHTS: the object's owner, whom the rule checks itself.
const OWNER_RIGHTS: &str = "S-1-3-4";

/// Access rights that change a directory or a file: add file / write data,
/// add subdirectory / append, write extended attributes, delete child,
/// write attributes, delete, write DAC, write owner, generic write, generic
/// all, maximum allowed.
const WRITE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000
    | 0x0200_0000;

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

/// One ACE, reduced to what the rule needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ace {
    /// An allow ACE of any kind; deny ACEs are skipped (the rule asks
    /// whether anything grants a write).
    pub(crate) allow: bool,
    /// `INHERIT_ONLY_ACE`: for children only, not this object.
    pub(crate) inherit_only: bool,
    /// The access mask.
    pub(crate) mask: u32,
    /// The trustee as a string SID; `None` when it couldn't be read
    /// (untrusted).
    pub(crate) sid: Option<String>,
}

/// Whether `ace` grants a write right (to this object).
fn grants_write(ace: &Ace) -> bool {
    ace.allow && !ace.inherit_only && ace.mask & WRITE_RIGHTS != 0
}

/// The SIDs an object may be owned and written by besides [`TRUSTED`]:
/// the ones its folder's own descriptor grants a write (`dacl`, reduced).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn writers(dacl: &[Ace]) -> Vec<String> {
    let mut sids: Vec<String> = dacl
        .iter()
        .filter(|ace| ace.allow && ace.mask & WRITE_RIGHTS != 0)
        .filter_map(|ace| ace.sid.clone())
        .filter(|sid| {
            !TRUSTED.contains(&sid.as_str()) && sid != CREATOR_OWNER && sid != OWNER_RIGHTS
        })
        .collect();
    sids.sort();
    sids.dedup();
    sids
}

/// Why `what` (owned by `owner`, with `dacl`; `None` for a NULL DACL) could
/// be changed by someone other than [`TRUSTED`] or `also`, or `None` when it
/// can't.
pub(crate) fn untrusted(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
    also: &[String],
) -> Option<String> {
    let allowed = |sid: &str| TRUSTED.contains(&sid) || also.iter().any(|a| a == sid);
    match owner {
        Some(owner) if allowed(owner) => {}
        other => {
            return Some(format!(
                "{what} is owned by {}, not SYSTEM, Administrators, TrustedInstaller or its folder's account",
                other.unwrap_or("an unreadable SID")
            ));
        }
    }
    let Some(dacl) = dacl else {
        return Some(format!("{what} has no DACL (everyone has full access)"));
    };
    dacl.iter()
        .filter(|ace| grants_write(ace))
        .find(|ace| {
            !ace.sid
                .as_deref()
                .is_some_and(|sid| allowed(sid) || sid == CREATOR_OWNER || sid == OWNER_RIGHTS)
        })
        .map(|ace| {
            format!(
                "{what} grants {} write access (mask {:#010x})",
                ace.sid.as_deref().unwrap_or("an unreadable trustee"),
                ace.mask
            )
        })
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
    //! The guard's FFI: token, privileges, the known folder, directory
    //! handles, security descriptors, enumeration and the event log, through
    //! windows-sys. Each `unsafe` block is allowed on its own, with the
    //! invariant it relies on.

    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, HANDLE,
        INVALID_HANDLE_VALUE, LUID, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetAce,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        GetTokenInformation, INHERIT_ONLY_ACE, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES,
        SetKernelObjectSecurity, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FIND_FIRST_EX_LARGE_FETCH, FileAttributeTagInfo, FindClose, FindExInfoBasic,
        FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS,
        WIN32_FIND_DATAW, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

    use super::{
        Ace, LOCAL_SYSTEM, Level, MAX_DEPTH, MAX_ENTRIES, Request, same_path, untrusted, writers,
    };

    /// ACE types that grant access: plain, object, callback, callback
    /// object.
    const ALLOW_ACE_TYPES: [u8; 4] = [0, 5, 9, 11];
    /// ACE types whose trustee SID directly follows the mask.
    const PLAIN_SID_ACE_TYPES: [u8; 2] = [0, 9];

    /// A handle, closed on drop.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a handle this module opened, closed once, here.
            #[allow(unsafe_code, reason = "closes a handle")]
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    /// A security descriptor from `LocalAlloc` (SDDL conversion,
    /// `GetSecurityInfo`), freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the call that produced it, freed
                // once, here.
                #[allow(unsafe_code, reason = "frees a security descriptor")]
                let _ = unsafe { LocalFree(self.0) };
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn wide_str(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The UTF-16 units of a NUL-terminated wide string.
    ///
    /// # Safety
    /// `text` must point to a readable, NUL-terminated UTF-16 string that
    /// stays alive and unchanged for `'a`.
    #[allow(unsafe_code, reason = "reads a C wide string")]
    unsafe fn wide_units<'a>(text: *const u16) -> &'a [u16] {
        let mut len = 0usize;
        loop {
            // SAFETY: the caller's string is terminated, so every unit up
            // to and including the terminator is readable.
            #[allow(unsafe_code, reason = "reads one unit")]
            let unit = unsafe { text.wrapping_add(len).read() };
            if unit == 0 {
                break;
            }
            len = len.saturating_add(1);
        }
        // SAFETY: `len` readable units precede the terminator (the
        // caller's contract); u16 has no invalid bit patterns.
        #[allow(unsafe_code, reason = "views the string")]
        unsafe {
            std::slice::from_raw_parts(text, len)
        }
    }

    /// A SID as its string form (`S-1-5-18`).
    fn sid_string(sid: PSID) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` points into a descriptor or token buffer the caller
        // holds; the string is allocated by the call and freed below.
        #[allow(unsafe_code, reason = "renders a SID")]
        let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
        if converted == 0 || text.is_null() {
            return None;
        }
        // SAFETY: the NUL-terminated string the call allocated, alive
        // until the LocalFree below (after the copy).
        #[allow(unsafe_code, reason = "reads the rendered SID")]
        let result = String::from_utf16(unsafe { wide_units(text) }).ok();
        // SAFETY: allocated by ConvertSidToStringSidW, freed once.
        #[allow(unsafe_code, reason = "frees the rendered SID")]
        let _ = unsafe { LocalFree(text.cast()) };
        result
    }

    fn process_token(access: u32) -> Result<Handle, String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess takes nothing and can't fail; its
        // pseudo handle needs no closing.
        #[allow(unsafe_code, reason = "this process's pseudo handle")]
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the pseudo handle, an access mask and a valid out
        // pointer; the token is closed by `Handle`'s drop.
        #[allow(unsafe_code, reason = "opens this process's token")]
        let opened = unsafe { OpenProcessToken(process, access, &mut token) };
        if opened == 0 {
            return Err(format!(
                "can't open the process token ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Handle(token))
    }

    /// The process token's user, as a string SID.
    fn token_user() -> Result<String, String> {
        let token = process_token(TOKEN_QUERY)?;
        let mut size = 0u32;
        // SAFETY: a size query with a NULL buffer and a valid size pointer.
        #[allow(unsafe_code, reason = "sizes the token's user")]
        let _ =
            unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size) };
        if size == 0 {
            return Err(format!(
                "can't read the process token ({})",
                std::io::Error::last_os_error()
            ));
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` holds at least `size` bytes, 8-byte aligned;
        // `size` is a valid in/out pointer.
        #[allow(unsafe_code, reason = "reads the token's user")]
        let read = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                size,
                &mut size,
            )
        };
        if read == 0 {
            return Err(format!(
                "can't read the process token ({})",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: TokenUser filled the aligned buffer with a TOKEN_USER
        // whose SID follows it in the buffer, which outlives the read.
        #[allow(unsafe_code, reason = "reads the TOKEN_USER")]
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        sid_string(sid).ok_or_else(|| "can't read the process token's user".to_owned())
    }

    /// Enables `names` in the process token (LocalSystem holds them all).
    fn enable_privileges(names: &[&str]) -> Result<(), String> {
        let token = process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
        for name in names {
            let mut luid = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            let wide_name = wide_str(name);
            // SAFETY: the local system (NULL), a NUL-terminated name and a
            // valid out pointer.
            #[allow(unsafe_code, reason = "looks a privilege up")]
            let found =
                unsafe { LookupPrivilegeValueW(std::ptr::null(), wide_name.as_ptr(), &mut luid) };
            if found == 0 {
                return Err(format!(
                    "can't look up {name} ({})",
                    std::io::Error::last_os_error()
                ));
            }
            let state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            // SAFETY: the token opened with TOKEN_ADJUST_PRIVILEGES, one
            // privilege in a valid TOKEN_PRIVILEGES, no previous state
            // wanted.
            #[allow(unsafe_code, reason = "enables a privilege")]
            let adjusted = unsafe {
                AdjustTokenPrivileges(
                    token.0,
                    0,
                    &state,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            let error = std::io::Error::last_os_error();
            if adjusted == 0 || error.raw_os_error() == Some(ERROR_NOT_ALL_ASSIGNED as i32) {
                return Err(format!("can't enable {name} ({error})"));
            }
        }
        Ok(())
    }

    /// `%ProgramData%`, from the system's known folder.
    fn program_data() -> Result<PathBuf, String> {
        let mut path: *mut u16 = std::ptr::null_mut();
        // SAFETY: a known folder id, no flags, the default user (NULL) and
        // a valid out pointer; the string is freed below, whatever the
        // result.
        #[allow(unsafe_code, reason = "looks the ProgramData known folder up")]
        let status = unsafe {
            SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut path)
        };
        let result = if status < 0 || path.is_null() {
            Err(format!("can't find %ProgramData% (HRESULT {status:#010x})"))
        } else {
            // SAFETY: the NUL-terminated string from the call, alive until
            // the CoTaskMemFree below (after the copy).
            #[allow(unsafe_code, reason = "reads the known folder's path")]
            let units = unsafe { wide_units(path) };
            Ok(PathBuf::from(OsString::from_wide(units)))
        };
        // SAFETY: allocated by SHGetKnownFolderPath (NULL is allowed),
        // freed once.
        #[allow(unsafe_code, reason = "frees the known folder's path")]
        unsafe {
            CoTaskMemFree(path.cast_const().cast());
        }
        result
    }

    fn descriptor(sddl: &str) -> Result<Descriptor, String> {
        let text = wide_str(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string and a valid out pointer; the
        // descriptor is freed by `Descriptor`'s drop.
        #[allow(unsafe_code, reason = "builds a security descriptor")]
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if converted == 0 || sd.is_null() {
            return Err(format!(
                "{sddl:?} isn't a security descriptor ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Descriptor(sd))
    }

    /// A descriptor's owner and DACL pointers (into the descriptor).
    fn owner_and_dacl_of(sd: &Descriptor) -> Result<(PSID, *mut ACL), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: a valid descriptor and valid out pointers.
        #[allow(unsafe_code, reason = "reads a descriptor's owner")]
        let read = unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) };
        if read == 0 {
            return Err("can't read a descriptor's owner".to_owned());
        }
        let mut present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above.
        #[allow(unsafe_code, reason = "reads a descriptor's DACL")]
        let read =
            unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err("a descriptor without a DACL".to_owned());
        }
        Ok((owner, dacl))
    }

    /// An ACL's entries, reduced for [`untrusted`].
    fn aces(dacl: *const ACL, what: &str) -> Result<Vec<Ace>, String> {
        // SAFETY: `dacl` is a non-null ACL inside a descriptor the caller
        // holds.
        #[allow(unsafe_code, reason = "reads the ACL's header")]
        let count = unsafe { (*dacl).AceCount };
        let mut out = Vec::with_capacity(usize::from(count));
        for index in 0..u32::from(count) {
            let mut entry: *mut c_void = std::ptr::null_mut();
            // SAFETY: a valid ACL, an index below its count, a valid out
            // pointer.
            #[allow(unsafe_code, reason = "reads one ACE")]
            let found = unsafe { GetAce(dacl, index, &mut entry) };
            if found == 0 || entry.is_null() {
                return Err(format!("{what}: can't read ACE {index}"));
            }
            // SAFETY: every ACE starts with an ACE_HEADER, inside the
            // caller's descriptor.
            #[allow(unsafe_code, reason = "reads an ACE's header")]
            let header = unsafe { entry.cast::<ACE_HEADER>().read_unaligned() };
            if !ALLOW_ACE_TYPES.contains(&header.AceType) {
                continue;
            }
            let mask_at = std::mem::size_of::<ACE_HEADER>();
            // SAFETY: every allow ACE type read here continues its header
            // with a 32-bit access mask, inside the ACE.
            #[allow(unsafe_code, reason = "reads an allow ACE's mask")]
            let mask = unsafe {
                entry
                    .cast::<u8>()
                    .wrapping_add(mask_at)
                    .cast::<u32>()
                    .read_unaligned()
            };
            let sid = if PLAIN_SID_ACE_TYPES.contains(&header.AceType) {
                sid_string(
                    entry
                        .cast::<u8>()
                        .wrapping_add(mask_at.saturating_add(4))
                        .cast(),
                )
            } else {
                None
            };
            out.push(Ace {
                allow: true,
                inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
                mask,
                sid,
            });
        }
        Ok(out)
    }

    /// Opens `path` itself (never what a reparse point names), for
    /// `access`, as a directory or a file.
    fn open(path: &Path, access: u32) -> Result<Handle, String> {
        let name = wide(path);
        // SAFETY: a NUL-terminated path, no security attributes, no
        // template; the handle is closed by `Handle`'s drop.
        #[allow(unsafe_code, reason = "opens a file system object")]
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(format!(
                "can't open {} ({})",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(Handle(handle))
    }

    /// The open object's attributes.
    fn attributes(handle: &Handle, path: &Path) -> Result<u32, String> {
        let mut info = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: 0,
            ReparseTag: 0,
        };
        // SAFETY: an open handle and a buffer of the class's own type and
        // size.
        #[allow(unsafe_code, reason = "reads an object's attributes")]
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileAttributeTagInfo,
                (&raw mut info).cast(),
                u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(0),
            )
        };
        if read == 0 {
            return Err(format!(
                "can't read {}'s attributes ({})",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(info.FileAttributes)
    }

    /// The open object's final path (`\\?\C:\…`).
    fn final_path(handle: &Handle, path: &Path) -> Result<String, String> {
        let mut buffer = vec![0u16; 1024];
        loop {
            let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            // SAFETY: an open handle and a buffer of `capacity` units.
            #[allow(unsafe_code, reason = "reads an object's final path")]
            let length = unsafe {
                GetFinalPathNameByHandleW(handle.0, buffer.as_mut_ptr(), capacity, VOLUME_NAME_DOS)
            } as usize;
            if length == 0 {
                return Err(format!(
                    "can't read {}'s final path ({})",
                    path.display(),
                    std::io::Error::last_os_error()
                ));
            }
            if length < buffer.len() {
                return String::from_utf16(buffer.get(..length).unwrap_or_default())
                    .map_err(|_| format!("{}'s final path isn't UTF-16", path.display()));
            }
            if length > 32_768 {
                return Err(format!("{}'s final path is too long", path.display()));
            }
            buffer.resize(length.saturating_add(1), 0);
        }
    }

    /// The open object's owner and DACL, reduced.
    fn security(handle: &Handle, what: &str) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: an open handle with READ_CONTROL, valid out pointers; the
        // descriptor is allocated by the call and freed by `Descriptor`.
        #[allow(unsafe_code, reason = "reads an object's security")]
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        let sd = Descriptor(sd);
        if status != ERROR_SUCCESS || sd.0.is_null() {
            return Err(format!(
                "{what}: can't read its security descriptor ({})",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let owner = sid_string(owner);
        let dacl = if dacl.is_null() {
            None
        } else {
            Some(aces(dacl, what)?)
        };
        drop(sd);
        Ok((owner, dacl))
    }

    /// Whether the open object's DACL is protected.
    fn protected(handle: &Handle, what: &str) -> Result<bool, String> {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: as in `security`, the DACL only.
        #[allow(unsafe_code, reason = "reads an object's DACL")]
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        let sd = Descriptor(sd);
        if status != ERROR_SUCCESS || sd.0.is_null() {
            return Err(format!(
                "{what}: can't read its DACL ({})",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: a valid descriptor and valid out pointers.
        #[allow(unsafe_code, reason = "reads a descriptor's control bits")]
        let read = unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) };
        if read == 0 {
            return Err(format!("{what}: can't read its descriptor's control bits"));
        }
        Ok(control & SE_DACL_PROTECTED != 0)
    }

    /// Replaces the open object's owner and DACL with `sd`'s, on this
    /// object alone: the kernel's own call, which propagates nothing to
    /// children (nothing below has been audited yet). The DACL's
    /// protection is marked by [`propagate`], or checked for `<Vendor>`.
    fn take_back(handle: &Handle, sd: &Descriptor, what: &str) -> Result<(), String> {
        // SAFETY: an open handle with WRITE_OWNER and WRITE_DAC, a valid
        // descriptor.
        #[allow(unsafe_code, reason = "sets an object's owner and DACL")]
        let set = unsafe {
            SetKernelObjectSecurity(
                handle.0,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                sd.0,
            )
        };
        if set == 0 {
            return Err(format!(
                "{what}: can't take it back ({})",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /// Sets `sd`'s owner and protected DACL on the open object and
    /// propagates its inheritable entries to what the object holds.
    fn propagate(handle: &Handle, sd: &Descriptor, what: &str) -> Result<(), String> {
        let (owner, dacl) = owner_and_dacl_of(sd)?;
        // SAFETY: an open handle with WRITE_OWNER and WRITE_DAC; the owner
        // and DACL point into `sd`, alive for the call.
        #[allow(unsafe_code, reason = "sets and propagates an object's DACL")]
        let status = unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "{what}: can't apply its descriptor ({})",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        Ok(())
    }

    /// The entries of `dir` (but `.` and `..`), with their attributes.
    fn children(dir: &Path) -> Result<Vec<(OsString, u32)>, String> {
        let pattern = wide(&dir.join("*"));
        // SAFETY: WIN32_FIND_DATAW is plain data; all zeroes is a valid
        // value, overwritten by the calls below.
        #[allow(unsafe_code, reason = "a zeroed find buffer")]
        let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated pattern, the basic info level, a buffer
        // of the level's type, no filter; the handle is closed below.
        #[allow(unsafe_code, reason = "starts a directory listing")]
        let find = unsafe {
            FindFirstFileExW(
                pattern.as_ptr(),
                FindExInfoBasic,
                (&raw mut data).cast(),
                FindExSearchNameMatch,
                std::ptr::null(),
                FIND_FIRST_EX_LARGE_FETCH,
            )
        };
        if find == INVALID_HANDLE_VALUE {
            return Err(format!(
                "can't list {} ({})",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        let mut out = Vec::new();
        let mut result = Ok(());
        loop {
            let len = data
                .cFileName
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(data.cFileName.len());
            let name = OsString::from_wide(data.cFileName.get(..len).unwrap_or_default());
            if name != "." && name != ".." {
                out.push((name, data.dwFileAttributes));
            }
            if out.len() > super::MAX_ENTRIES {
                result = Err(format!(
                    "{} holds more than {} entries",
                    dir.display(),
                    super::MAX_ENTRIES
                ));
                break;
            }
            // SAFETY: the open find handle and the same buffer.
            #[allow(unsafe_code, reason = "continues the listing")]
            let more = unsafe { FindNextFileW(find, &mut data) };
            if more == 0 {
                let error = std::io::Error::last_os_error();
                // ERROR_NO_MORE_FILES (18) ends a listing.
                if error.raw_os_error() != Some(18) {
                    result = Err(format!("can't list {} ({error})", dir.display()));
                }
                break;
            }
        }
        // SAFETY: the find handle FindFirstFileExW returned, closed once.
        #[allow(unsafe_code, reason = "ends the listing")]
        let _ = unsafe { FindClose(find) };
        result.map(|()| out)
    }

    /// The audit of everything below `dir` (see the module docs): no
    /// reparse point, every object trusted for `also`, bounded by
    /// [`MAX_ENTRIES`] and [`MAX_DEPTH`].
    fn audit_tree(
        dir: &Path,
        also: &[String],
        depth: usize,
        visited: &mut usize,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!(
                "{} is nested deeper than {MAX_DEPTH} levels",
                dir.display()
            ));
        }
        for (name, listed) in children(dir)? {
            *visited = visited.saturating_add(1);
            if *visited > MAX_ENTRIES {
                return Err(format!("more than {MAX_ENTRIES} objects to audit"));
            }
            let path = dir.join(&name);
            if listed & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "{} is a reparse point (a junction or a link)",
                    path.display()
                ));
            }
            let handle = open(&path, READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE)?;
            let attributes = attributes(&handle, &path)?;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "{} is a reparse point (a junction or a link)",
                    path.display()
                ));
            }
            let what = path.display().to_string();
            let (owner, dacl) = security(&handle, &what)?;
            if let Some(why) = untrusted(&what, owner.as_deref(), dacl.as_deref(), also) {
                return Err(why);
            }
            drop(handle);
            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                audit_tree(&path, also, depth.saturating_add(1), visited)?;
            }
        }
        Ok(())
    }

    /// One folder, made or taken back (step 1 of the module docs); its
    /// handle, open for the descriptor's later propagation.
    fn ensure(
        path: &Path,
        wanted_final: &str,
        sd: &Descriptor,
        what: &str,
    ) -> Result<Handle, String> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let name = wide(path);
        // SAFETY: a NUL-terminated path and attributes holding a valid
        // descriptor, both alive for the call.
        #[allow(unsafe_code, reason = "creates a folder with its descriptor")]
        let created = unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } != 0;
        if !created {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(format!("can't create {what} ({error})"));
            }
        }
        let handle = open(
            path,
            READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )?;
        let attributes = self::attributes(&handle, path)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{what} is a reparse point (a junction or a link)"));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(format!("{what} is not a directory"));
        }
        if !created {
            take_back(&handle, sd, what)?;
        }
        let found = final_path(&handle, path)?;
        if !same_path(&found, wanted_final) {
            return Err(format!(
                "{what} is not where it was asked for (it is {found}): moved while it was taken back"
            ));
        }
        Ok(handle)
    }

    /// The guard (see the module docs).
    pub(super) fn run(request: &Request) -> Result<(), String> {
        let user = token_user()?;
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
        let root = program_data()?;
        let root_handle = open(&root, FILE_READ_ATTRIBUTES | SYNCHRONIZE).or_else(|_| {
            // %ProgramData% may itself be redirected by its
            // administrator: then name where it leads.
            let name = wide(&root);
            // SAFETY: as in `open`, following a reparse point.
            #[allow(unsafe_code, reason = "opens %ProgramData%")]
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                Err(format!(
                    "can't open {} ({})",
                    root.display(),
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(Handle(handle))
            }
        })?;
        let root_final = final_path(&root_handle, &root)?;
        drop(root_handle);

        // Step 1: each folder, top down.
        let mut opened: Vec<(&Level, PathBuf, Handle, Descriptor)> = Vec::new();
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
            let sd = descriptor(&level.sddl)?;
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
        for (name, listed) in children(data_path)? {
            let path = data_path.join(&name);
            let named = opened.iter().find(|(level, ..)| {
                level.components.len() == 3
                    && level
                        .components
                        .last()
                        .is_some_and(|last| OsString::from(last).eq_ignore_ascii_case(&name))
            });
            let also = match named {
                Some((_, _, _, sd)) => {
                    let (_, dacl) = owner_and_dacl_of(sd)?;
                    writers(&aces(dacl, &path.display().to_string())?)
                }
                None => Vec::new(),
            };
            visited = visited.saturating_add(1);
            if listed & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "{} is a reparse point (a junction or a link)",
                    path.display()
                ));
            }
            let handle = open(&path, READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE)?;
            let attributes = attributes(&handle, &path)?;
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "{} is a reparse point (a junction or a link)",
                    path.display()
                ));
            }
            let what = path.display().to_string();
            let (owner, dacl) = security(&handle, &what)?;
            if let Some(why) = untrusted(&what, owner.as_deref(), dacl.as_deref(), &also) {
                return Err(why);
            }
            drop(handle);
            if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                audit_tree(&path, &also, 1, &mut visited)?;
            }
        }

        // Step 3: the descriptors propagate from the product's directory
        // down; <Vendor> keeps its own handle's change alone.
        for (level, path, handle, sd) in &opened {
            let what = path.display().to_string();
            if level.components.len() >= 2 {
                propagate(handle, sd, &what)?;
            } else if !protected(handle, &what)? {
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
