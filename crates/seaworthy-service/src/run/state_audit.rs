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

use std::path::Path;

use crate::ServiceError;

/// The most objects the audit visits below the state directory.
pub const MAX_ENTRIES: usize = 100_000;
/// The deepest the audit descends below the state directory.
pub const MAX_DEPTH: usize = 32;

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
// The rule (pure, tested everywhere)

/// The principals that may always own or write: LocalSystem,
/// BUILTIN\Administrators and TrustedInstaller.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const TRUSTED: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
/// CREATOR OWNER: in an effective ACE it matches no token.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const CREATOR_OWNER: &str = "S-1-3-0";
/// OWNER RIGHTS: the object's owner, whom the rule checks itself.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const OWNER_RIGHTS: &str = "S-1-3-4";

/// Access rights that change a directory or a file: add file / write data,
/// add subdirectory / append, write extended attributes, delete child,
/// write attributes, delete, write DAC, write owner, generic write, generic
/// all, maximum allowed.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
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

/// One ACE, reduced to what the rule needs.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ace {
    /// An allow ACE of any kind; deny ACEs are skipped.
    allow: bool,
    /// `INHERIT_ONLY_ACE`: for children only.
    inherit_only: bool,
    /// The access mask.
    mask: u32,
    /// The trustee as a string SID; `None` when unreadable (untrusted).
    sid: Option<String>,
}

/// Why `what` (owned by `owner`, with `dacl`; `None` for a NULL DACL) could
/// be changed by someone other than [`TRUSTED`] or `account`, or `None`
/// when it can't.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn untrusted(
    what: &str,
    owner: Option<&str>,
    dacl: Option<&[Ace]>,
    account: &str,
) -> Option<String> {
    let allowed = |sid: &str| TRUSTED.contains(&sid) || sid == account;
    match owner {
        Some(owner) if allowed(owner) => {}
        other => {
            return Some(format!(
                "{what} is owned by {}, not SYSTEM, Administrators, TrustedInstaller or the service's account",
                other.unwrap_or("an unreadable SID")
            ));
        }
    }
    let Some(dacl) = dacl else {
        return Some(format!("{what} has no DACL (everyone has full access)"));
    };
    dacl.iter()
        .filter(|ace| ace.allow && !ace.inherit_only && ace.mask & WRITE_RIGHTS != 0)
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

/// The Unix rule for one object: owned by root or `euid`, not writable by
/// group or others, no symlink.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
fn unix_untrusted(what: &str, uid: u32, mode: u32, symlink: bool, euid: u32) -> Option<String> {
    if symlink {
        return Some(format!("{what} is a symlink"));
    }
    if uid != 0 && uid != euid {
        return Some(format!(
            "{what} is owned by uid {uid}, not root or the service's user ({euid})"
        ));
    }
    if mode & 0o022 != 0 {
        return Some(format!(
            "{what} is writable by group or others (mode {:o})",
            mode & 0o7777
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Unix

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;

    use super::{MAX_DEPTH, MAX_ENTRIES, unix_untrusted};

    pub(super) fn audit(path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("{} is not absolute", path.display()));
        }
        let real = std::fs::canonicalize(path)
            .map_err(|e| format!("can't resolve {}: {e}", path.display()))?;
        if real != path {
            return Err(format!(
                "{} is reached through a symlink (it is {})",
                path.display(),
                real.display()
            ));
        }
        // SAFETY: geteuid takes no arguments and can't fail.
        #[allow(unsafe_code, reason = "FFI: geteuid")]
        let euid = unsafe { libc::geteuid() };
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("can't inspect {}: {e}", path.display()))?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", path.display()));
        }
        let what = path.display().to_string();
        if let Some(why) = unix_untrusted(&what, metadata.uid(), metadata.mode(), false, euid) {
            return Err(why);
        }
        let mut visited = 0usize;
        walk(path, euid, 1, &mut visited)
    }

    fn walk(dir: &Path, euid: u32, depth: usize, visited: &mut usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(format!(
                "{} is nested deeper than {MAX_DEPTH} levels",
                dir.display()
            ));
        }
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("can't list {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("can't list {}: {e}", dir.display()))?;
            *visited = visited.saturating_add(1);
            if *visited > MAX_ENTRIES {
                return Err(format!("more than {MAX_ENTRIES} objects to audit"));
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("can't inspect {}: {e}", path.display()))?;
            let what = path.display().to_string();
            if let Some(why) = unix_untrusted(
                &what,
                metadata.uid(),
                metadata.mode(),
                metadata.file_type().is_symlink(),
                euid,
            ) {
                return Err(why);
            }
            if metadata.is_dir() {
                walk(&path, euid, depth.saturating_add(1), visited)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windows

#[cfg(windows)]
mod platform {
    //! The audit's FFI through windows-sys: the token's user, known
    //! folders, handles opened without following reparse points, their
    //! final paths and security descriptors, directory listings. Each
    //! `unsafe` block is allowed on its own, with the invariant it relies
    //! on.

    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation, INHERIT_ONLY_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FIND_FIRST_EX_LARGE_FETCH, FileAttributeTagInfo, FindClose, FindExInfoBasic,
        FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS,
        WIN32_FIND_DATAW,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
    };
    use windows_sys::core::GUID;

    use super::{Ace, MAX_DEPTH, MAX_ENTRIES, untrusted};

    /// ACE types that grant access: plain, object, callback, callback
    /// object.
    const ALLOW_ACE_TYPES: [u8; 4] = [0, 5, 9, 11];
    /// ACE types whose trustee SID directly follows the mask.
    const PLAIN_SID_ACE_TYPES: [u8; 2] = [0, 9];
    /// `ERROR_NO_MORE_FILES`: the end of a listing.
    const NO_MORE_FILES: i32 = 18;

    /// A handle, closed on drop.
    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a handle this module opened, closed once, here.
            #[allow(unsafe_code, reason = "closes a handle")]
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
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

    /// A SID as its string form.
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

    /// The process token's user (the service's account), as a string SID.
    fn token_user() -> Result<String, String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess takes nothing and can't fail; its
        // pseudo handle needs no closing.
        #[allow(unsafe_code, reason = "this process's pseudo handle")]
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the pseudo handle, a query right and a valid out pointer;
        // the token is closed by `Handle`'s drop.
        #[allow(unsafe_code, reason = "opens this process's token")]
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(format!(
                "can't open the process token ({})",
                std::io::Error::last_os_error()
            ));
        }
        let token = Handle(token);
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

    /// A known folder's path.
    fn known_folder(id: &GUID, name: &str) -> Result<PathBuf, String> {
        let mut path: *mut u16 = std::ptr::null_mut();
        // SAFETY: a known folder id, no flags, the default user (NULL) and
        // a valid out pointer; the string is freed below, whatever the
        // result.
        #[allow(unsafe_code, reason = "looks a known folder up")]
        let status = unsafe { SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut path) };
        let result = if status < 0 || path.is_null() {
            Err(format!("can't find {name} (HRESULT {status:#010x})"))
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

    /// Opens `path` for reading its attributes and security, never through
    /// a reparse point unless `follow`.
    fn open(path: &Path, follow: bool) -> Result<Handle, String> {
        let name = wide(path);
        let flags = if follow {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
        };
        // SAFETY: a NUL-terminated path, no security attributes, no
        // template; the handle is closed by `Handle`'s drop.
        #[allow(unsafe_code, reason = "opens a file system object")]
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                flags,
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

    /// The open object's owner and DACL, reduced for [`untrusted`].
    fn security(handle: &Handle, what: &str) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: an open handle with READ_CONTROL and valid out pointers;
        // the descriptor is allocated by the call and freed below; `owner`
        // and `dacl` point into it.
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
        if status != ERROR_SUCCESS || sd.is_null() {
            return Err(format!(
                "{what}: can't read its security descriptor ({})",
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        let result = (|| {
            let owner = sid_string(owner);
            if dacl.is_null() {
                return Ok((owner, None));
            }
            // SAFETY: a non-null ACL inside the descriptor, alive until the
            // LocalFree below.
            #[allow(unsafe_code, reason = "reads the ACL's header")]
            let count = unsafe { (*dacl).AceCount };
            let mut aces = Vec::with_capacity(usize::from(count));
            for index in 0..u32::from(count) {
                let mut entry: *mut c_void = std::ptr::null_mut();
                // SAFETY: a valid ACL, an index below its count, a valid
                // out pointer.
                #[allow(unsafe_code, reason = "reads one ACE")]
                let found = unsafe { GetAce(dacl, index, &mut entry) };
                if found == 0 || entry.is_null() {
                    return Err(format!("{what}: can't read ACE {index}"));
                }
                // SAFETY: every ACE starts with an ACE_HEADER, inside the
                // descriptor.
                #[allow(unsafe_code, reason = "reads an ACE's header")]
                let header = unsafe { entry.cast::<ACE_HEADER>().read_unaligned() };
                if !ALLOW_ACE_TYPES.contains(&header.AceType) {
                    continue;
                }
                let mask_at = std::mem::size_of::<ACE_HEADER>();
                // SAFETY: every allow ACE type read here continues its
                // header with a 32-bit access mask, inside the ACE.
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
                aces.push(Ace {
                    allow: true,
                    inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
                    mask,
                    sid,
                });
            }
            Ok((owner, Some(aces)))
        })();
        // SAFETY: allocated by GetSecurityInfo, freed once, after the read.
        #[allow(unsafe_code, reason = "frees the descriptor")]
        let _ = unsafe { LocalFree(sd) };
        result
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
            if out.len() > MAX_ENTRIES {
                result = Err(format!(
                    "{} holds more than {MAX_ENTRIES} entries",
                    dir.display()
                ));
                break;
            }
            // SAFETY: the open find handle and the same buffer.
            #[allow(unsafe_code, reason = "continues the listing")]
            let more = unsafe { FindNextFileW(find, &mut data) };
            if more == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(NO_MORE_FILES) {
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

    /// One object: no reparse point, trusted; its attributes.
    fn check(path: &Path, account: &str) -> Result<u32, String> {
        let handle = open(path, false)?;
        let attributes = attributes(&handle, path)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a reparse point (a junction or a link)",
                path.display()
            ));
        }
        let what = path.display().to_string();
        let (owner, dacl) = security(&handle, &what)?;
        if let Some(why) = untrusted(&what, owner.as_deref(), dacl.as_deref(), account) {
            return Err(why);
        }
        Ok(attributes)
    }

    fn walk(dir: &Path, account: &str, depth: usize, visited: &mut usize) -> Result<(), String> {
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
            if check(&path, account)? & FILE_ATTRIBUTE_DIRECTORY != 0 {
                walk(&path, account, depth.saturating_add(1), visited)?;
            }
        }
        Ok(())
    }

    /// What `path`'s final path must be: under `%ProgramData%`, that
    /// folder's own final path (its administrator may have redirected it)
    /// and the rest; elsewhere, `\\?\` and the path.
    fn wanted_final(path: &Path) -> Result<String, String> {
        let program_data = known_folder(&FOLDERID_ProgramData, "%ProgramData%")?;
        let text = path.display().to_string().replace('/', "\\");
        let root = program_data.display().to_string();
        let below = text
            .get(..root.len())
            .filter(|head| head.eq_ignore_ascii_case(&root))
            .and_then(|_| text.get(root.len()..))
            .filter(|rest| rest.starts_with('\\'));
        match below {
            Some(rest) => {
                let handle = open(&program_data, true)?;
                let root_final = final_path(&handle, &program_data)?;
                Ok(format!("{}{rest}", root_final.trim_end_matches('\\')))
            }
            None => Ok(format!("\\\\?\\{}", text.trim_end_matches('\\'))),
        }
    }

    pub(super) fn audit(path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err(format!("{} is not absolute", path.display()));
        }
        let account = token_user()?;
        let handle = open(path, false)?;
        let attributes = attributes(&handle, path)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{} is a reparse point (a junction or a link)",
                path.display()
            ));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(format!("{} is not a directory", path.display()));
        }
        let found = final_path(&handle, path)?;
        let wanted = wanted_final(path)?;
        if !found.eq_ignore_ascii_case(&wanted) {
            return Err(format!(
                "{} leads to {found}: a folder on its way is a junction or a link",
                path.display()
            ));
        }
        let what = path.display().to_string();
        let (owner, dacl) = security(&handle, &what)?;
        if let Some(why) = untrusted(&what, owner.as_deref(), dacl.as_deref(), &account) {
            return Err(why);
        }
        drop(handle);
        let mut visited = 0usize;
        walk(path, &account, 1, &mut visited)
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
        let installed = known_folder(&FOLDERID_ProgramFiles, "%ProgramFiles%")?;
        if !program_files
            .as_os_str()
            .eq_ignore_ascii_case(installed.as_os_str())
        {
            return Ok(None);
        }
        let state = known_folder(&FOLDERID_ProgramData, "%ProgramData%")?
            .join(vendor)
            .join(directory)
            .join("state");
        Ok(std::fs::symlink_metadata(&state).is_ok().then_some(state))
    }
}

#[cfg(test)]
mod tests {
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
