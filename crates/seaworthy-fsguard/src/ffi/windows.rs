//! The Windows calls, through windows-sys: the process token and its
//! privileges, known folders, handles opened without following reparse
//! points, their attributes, link counts, final paths and security
//! descriptors (read, made from SDDL, replaced, propagated), directories
//! created with a descriptor, and directory listings.
//!
//! Handles cross the API as std's I/O-safe [`OwnedHandle`] and
//! [`BorrowedHandle`]; descriptors made here as [`SecurityDescriptor`],
//! freed on drop. Errors name the object (the caller's `path` or `what`)
//! and the system's reason.

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, INHERIT_ONLY_ACE, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, SetKernelObjectSecurity,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES,
    TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FIND_FIRST_EX_LARGE_FETCH, FileAttributeTagInfo, FindClose, FindExInfoBasic,
    FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, OPEN_ALWAYS, OPEN_EXISTING,
    READ_CONTROL, SYNCHRONIZE, VOLUME_NAME_DOS, WIN32_FIND_DATAW, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

use crate::acl::Ace;
use crate::{Error, MAX_ENTRIES};

/// ACE types that grant access: plain, object, callback, callback object.
const ALLOW_ACE_TYPES: [u8; 4] = [0, 5, 9, 11];
/// ACE types whose trustee SID directly follows the mask.
const PLAIN_SID_ACE_TYPES: [u8; 2] = [0, 9];
/// `ERROR_NO_MORE_FILES`: the end of a listing.
const NO_MORE_FILES: i32 = 18;
/// The longest final path read, in UTF-16 units.
const MAX_FINAL_PATH: usize = 32_768;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_str(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// A status a security API returned, as an I/O error. Win32 error codes
/// fit an `i32` (they are below 0x10000).
fn status_error(status: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX))
}

/// The UTF-16 units of a NUL-terminated wide string, without its
/// terminator.
///
/// # Safety
/// `text` must point to a readable, NUL-terminated UTF-16 string that stays
/// alive and unchanged for `'a`.
#[allow(unsafe_code, reason = "reads a C wide string")]
unsafe fn wide_units<'a>(text: *const u16) -> &'a [u16] {
    let mut len = 0usize;
    loop {
        // SAFETY: the caller's string is terminated, so every unit up to
        // and including the terminator is readable; the loop stops at it.
        #[allow(unsafe_code, reason = "reads one unit")]
        let unit = unsafe { text.wrapping_add(len).read() };
        if unit == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    // SAFETY: `len` readable units precede the terminator, alive for `'a`
    // (the caller's contract); u16 has no invalid bit patterns.
    #[allow(unsafe_code, reason = "views the string")]
    unsafe {
        std::slice::from_raw_parts(text, len)
    }
}

/// A SID as its string form (`S-1-5-18`); `None` for a null or unreadable
/// one.
///
/// # Safety
/// `sid` must be null or point to a valid SID that stays alive for the
/// call (inside a descriptor, an ACE or a token buffer the caller holds).
#[allow(unsafe_code, reason = "renders a caller's SID")]
unsafe fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID (the caller's contract) and a valid out pointer;
    // the string is allocated by the call and freed below.
    #[allow(unsafe_code, reason = "renders a SID")]
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    if converted == 0 || text.is_null() {
        return None;
    }
    // SAFETY: the NUL-terminated string the call allocated, alive until the
    // LocalFree below (after the copy).
    #[allow(unsafe_code, reason = "reads the rendered SID")]
    let result = String::from_utf16(unsafe { wide_units(text) }).ok();
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    #[allow(unsafe_code, reason = "frees the rendered SID")]
    let _ = unsafe { LocalFree(text.cast()) };
    result
}

// ---------------------------------------------------------------------------
// The process token

/// This process's token, opened for `access`.
fn process_token(access: u32) -> Result<OwnedHandle, Error> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess takes nothing and can't fail; its pseudo
    // handle needs no closing.
    #[allow(unsafe_code, reason = "this process's pseudo handle")]
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo handle, an access mask and a valid out pointer.
    #[allow(unsafe_code, reason = "opens this process's token")]
    let opened = unsafe { OpenProcessToken(process, access, &mut token) };
    if opened == 0 || token.is_null() {
        return Err(Error::new(format!(
            "can't open the process token ({})",
            last_error()
        )));
    }
    // SAFETY: a token handle OpenProcessToken just returned, owned by
    // nothing else; CloseHandle is all it needs, once, when the
    // OwnedHandle drops.
    #[allow(unsafe_code, reason = "takes ownership of the token")]
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// `GetTokenInformation` for `class`, into a pointer-aligned buffer.
fn token_information(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u64>, Error> {
    let mut size = 0u32;
    // SAFETY: an open token, a size query with a NULL buffer and a valid
    // size pointer.
    #[allow(unsafe_code, reason = "sizes a token information class")]
    let _ = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            std::ptr::null_mut(),
            0,
            &mut size,
        )
    };
    if size == 0 {
        return Err(Error::new(format!(
            "can't read the process token ({})",
            last_error()
        )));
    }
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `buffer` holds at least `size` bytes, 8-byte aligned; `size`
    // is a valid in/out pointer.
    #[allow(unsafe_code, reason = "reads a token information class")]
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            buffer.as_mut_ptr().cast::<c_void>(),
            size,
            &mut size,
        )
    };
    if read == 0 {
        return Err(Error::new(format!(
            "can't read the process token ({})",
            last_error()
        )));
    }
    Ok(buffer)
}

/// The process token's user, as a string SID (`S-1-5-18` for
/// LocalSystem, `S-1-5-80-…` for a service's virtual account); `Ok(None)`
/// when its SID can't be rendered.
///
/// # Errors
/// The token can't be opened or read.
pub fn process_user() -> Result<Option<String>, Error> {
    let token = process_token(TOKEN_QUERY)?;
    let buffer = token_information(&token, TokenUser)?;
    // SAFETY: TokenUser filled the 8-byte-aligned buffer with a TOKEN_USER
    // whose SID follows it in the buffer, which outlives the read.
    #[allow(unsafe_code, reason = "reads the TOKEN_USER")]
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: the SID inside `buffer`, alive for the call.
    #[allow(unsafe_code, reason = "renders the token's user")]
    let user = unsafe { sid_string(sid) };
    Ok(user)
}

/// Whether the process token is elevated (an administrator's elevated
/// token, LocalSystem and the service accounts).
///
/// # Errors
/// The token can't be opened or read.
pub fn process_elevated() -> Result<bool, Error> {
    let token = process_token(TOKEN_QUERY)?;
    let buffer = token_information(&token, TokenElevation)?;
    // SAFETY: TokenElevation filled the 8-byte-aligned buffer with a
    // TOKEN_ELEVATION.
    #[allow(unsafe_code, reason = "reads the token's elevation")]
    let elevated = unsafe { (*buffer.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated };
    Ok(elevated != 0)
}

/// Enables `names` (`SeTakeOwnershipPrivilege`, …) in the process token;
/// LocalSystem holds them all.
///
/// # Errors
/// A name isn't a privilege, or the token doesn't hold it.
pub fn enable_privileges(names: &[&str]) -> Result<(), Error> {
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
            return Err(Error::new(format!(
                "can't look up {name} ({})",
                last_error()
            )));
        }
        let state = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: the token opened with TOKEN_ADJUST_PRIVILEGES, one
        // privilege in a valid TOKEN_PRIVILEGES, no previous state wanted.
        #[allow(unsafe_code, reason = "enables a privilege")]
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let error = last_error();
        if adjusted == 0 || error.raw_os_error() == i32::try_from(ERROR_NOT_ALL_ASSIGNED).ok() {
            return Err(Error::new(format!("can't enable {name} ({error})")));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Known folders

/// A known folder, located through the shell's known-folder API (never the
/// environment, which the caller controls).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    /// `%ProgramData%`.
    ProgramData,
    /// `%ProgramFiles%` (the native one).
    ProgramFiles,
}

impl KnownFolder {
    fn id(self) -> GUID {
        match self {
            Self::ProgramData => FOLDERID_ProgramData,
            Self::ProgramFiles => FOLDERID_ProgramFiles,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::ProgramData => "%ProgramData%",
            Self::ProgramFiles => "%ProgramFiles%",
        }
    }
}

/// The path of `folder`.
///
/// # Errors
/// The shell can't locate it.
pub fn known_folder(folder: KnownFolder) -> Result<PathBuf, Error> {
    let id = folder.id();
    let mut path: *mut u16 = std::ptr::null_mut();
    // SAFETY: a known folder id, no flags, the default user (NULL) and a
    // valid out pointer; the string is freed below, whatever the result.
    #[allow(unsafe_code, reason = "looks a known folder up")]
    let status = unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut path) };
    let result = if status < 0 || path.is_null() {
        Err(Error::new(format!(
            "can't find {} (HRESULT {status:#010x})",
            folder.name()
        )))
    } else {
        // SAFETY: the NUL-terminated string from the call, alive until the
        // CoTaskMemFree below (after the copy).
        #[allow(unsafe_code, reason = "reads the known folder's path")]
        let units = unsafe { wide_units(path) };
        Ok(PathBuf::from(OsString::from_wide(units)))
    };
    // SAFETY: allocated by SHGetKnownFolderPath (NULL is allowed), freed
    // once.
    #[allow(unsafe_code, reason = "frees the known folder's path")]
    unsafe {
        CoTaskMemFree(path.cast_const().cast());
    }
    result
}

// ---------------------------------------------------------------------------
// Handles

/// What an audit's handle may do. Every handle also has `SYNCHRONIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read the attributes and the final path.
    ReadAttributes,
    /// Also read the security descriptor (`READ_CONTROL`).
    ReadSecurity,
    /// Also replace the owner and the DACL (`WRITE_OWNER`, `WRITE_DAC`).
    TakeBack,
}

impl Access {
    fn mask(self) -> u32 {
        match self {
            Self::ReadAttributes => FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Self::ReadSecurity => READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Self::TakeBack => {
                READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_READ_ATTRIBUTES | SYNCHRONIZE
            }
        }
    }
}

/// Opens the file or directory at `path` for `access`, sharing it fully
/// (an audit disturbs nobody), never through a reparse point unless
/// `follow`: without it, a junction or a link is opened itself, so its
/// attributes say what it is.
///
/// # Errors
/// It can't be opened.
pub fn open(path: &Path, access: Access, follow: bool) -> Result<OwnedHandle, Error> {
    let name = wide(path);
    let flags = if follow {
        FILE_FLAG_BACKUP_SEMANTICS
    } else {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    };
    // SAFETY: a NUL-terminated path, no security attributes, no template.
    #[allow(unsafe_code, reason = "opens a file system object")]
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access.mask(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(Error::new(format!(
            "can't open {} ({})",
            path.display(),
            last_error()
        )));
    }
    // SAFETY: a valid handle CreateFileW just returned, owned by nothing
    // else; CloseHandle is all it needs, once, when the OwnedHandle drops.
    #[allow(unsafe_code, reason = "takes ownership of the handle")]
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// What a file a caller keeps open may do. Every handle also has
/// `READ_CONTROL` when it appends, and `SYNCHRONIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    /// Read the attributes and the final path.
    ReadAttributes,
    /// Append data; read the attributes, the final path and the security
    /// descriptor.
    Append,
}

impl FileAccess {
    fn mask(self) -> u32 {
        match self {
            Self::ReadAttributes => FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            Self::Append => FILE_APPEND_DATA | READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        }
    }
}

/// Opens the file (or directory) at `path` for `access`, never through a
/// reparse point, shared for reading only (nobody else writes, renames or
/// deletes it while it is open), creating a file when `create` (its
/// directory's inheritable DACL then applies).
///
/// # Errors
/// It can't be opened (or created).
pub fn open_file(path: &Path, access: FileAccess, create: bool) -> Result<std::fs::File, Error> {
    let name = wide(path);
    let disposition = if create { OPEN_ALWAYS } else { OPEN_EXISTING };
    // SAFETY: a NUL-terminated path, no security attributes, no template.
    #[allow(unsafe_code, reason = "opens a file without following a reparse point")]
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access.mask(),
            FILE_SHARE_READ,
            std::ptr::null(),
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(Error::new(format!(
            "can't open {} ({})",
            path.display(),
            last_error()
        )));
    }
    // SAFETY: a valid handle CreateFileW just returned, owned by nothing
    // else: the File closes it.
    #[allow(unsafe_code, reason = "takes ownership of the handle")]
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

/// An object's attributes (`FILE_ATTRIBUTE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes(u32);

impl Attributes {
    /// A reparse point: a junction, a symbolic link, or another kind.
    #[must_use]
    pub const fn is_reparse_point(self) -> bool {
        self.0 & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// A directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.0 & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// The raw `FILE_ATTRIBUTE_*` bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// The open object's attributes; `path` names it in errors.
///
/// # Errors
/// They can't be read.
pub fn attributes(handle: BorrowedHandle<'_>, path: &Path) -> Result<Attributes, Error> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: an open handle and a buffer of the class's own type and size.
    #[allow(unsafe_code, reason = "reads an object's attributes")]
    let read = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileAttributeTagInfo,
            (&raw mut info).cast(),
            u32::try_from(size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(0),
        )
    };
    if read == 0 {
        return Err(Error::new(format!(
            "can't read {}'s attributes ({})",
            path.display(),
            last_error()
        )));
    }
    Ok(Attributes(info.FileAttributes))
}

/// How many names (hard links) the open file has; `path` names it in
/// errors.
///
/// # Errors
/// They can't be read.
pub fn link_count(handle: BorrowedHandle<'_>, path: &Path) -> Result<u32, Error> {
    // SAFETY: BY_HANDLE_FILE_INFORMATION is plain data; all zeroes is a
    // valid value, overwritten by the call below.
    #[allow(unsafe_code, reason = "a zeroed information buffer")]
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open handle and a buffer of the call's type.
    #[allow(unsafe_code, reason = "reads the open file's link count")]
    let read = unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) };
    if read == 0 {
        return Err(Error::new(format!(
            "can't read {}'s links ({})",
            path.display(),
            last_error()
        )));
    }
    Ok(info.nNumberOfLinks)
}

/// The open object's final path (`\\?\C:\…`), every junction and link on
/// its way resolved; `path` names it in errors.
///
/// # Errors
/// It can't be read, isn't UTF-16, or is longer than 32,768 units.
pub fn final_path(handle: BorrowedHandle<'_>, path: &Path) -> Result<String, Error> {
    let mut buffer = vec![0u16; 1024];
    loop {
        let capacity = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: an open handle and a buffer of `capacity` units.
        #[allow(unsafe_code, reason = "reads an object's final path")]
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle(),
                buffer.as_mut_ptr(),
                capacity,
                VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 {
            return Err(Error::new(format!(
                "can't read {}'s final path ({})",
                path.display(),
                last_error()
            )));
        }
        if length < buffer.len() {
            return String::from_utf16(buffer.get(..length).unwrap_or_default())
                .map_err(|_| Error::new(format!("{}'s final path isn't UTF-16", path.display())));
        }
        if length > MAX_FINAL_PATH {
            return Err(Error::new(format!(
                "{}'s final path is too long",
                path.display()
            )));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}

// ---------------------------------------------------------------------------
// Security descriptors

/// An object's owner and DACL, reduced for [`crate::acl::untrusted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSecurity {
    /// The owner as a string SID; `None` when unreadable (untrusted).
    pub owner: Option<String>,
    /// The DACL's allow entries; `None` for a NULL or absent DACL
    /// (everyone has full access).
    pub dacl: Option<Vec<Ace>>,
}

/// A security descriptor from `LocalAlloc`, freed on drop.
struct Allocated(PSECURITY_DESCRIPTOR);

impl Drop for Allocated {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by the call that produced it (SDDL
            // conversion, GetSecurityInfo, GetNamedSecurityInfoW), freed
            // once, here.
            #[allow(unsafe_code, reason = "frees a security descriptor")]
            let _ = unsafe { LocalFree(self.0) };
        }
    }
}

/// An ACL's allow entries, reduced (deny and audit entries are skipped:
/// the rule asks whether anything grants a write).
///
/// # Safety
/// `dacl` must point to a valid ACL inside a descriptor that stays alive
/// for the call.
#[allow(unsafe_code, reason = "walks a caller's ACL")]
unsafe fn aces(dacl: *const ACL, what: &str) -> Result<Vec<Ace>, Error> {
    // SAFETY: a valid ACL (the caller's contract).
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
            return Err(Error::new(format!("{what}: can't read ACE {index}")));
        }
        // SAFETY: every ACE GetAce returns starts with an ACE_HEADER,
        // inside the caller's descriptor.
        #[allow(unsafe_code, reason = "reads an ACE's header")]
        let header = unsafe { entry.cast::<ACE_HEADER>().read_unaligned() };
        if !ALLOW_ACE_TYPES.contains(&header.AceType) {
            continue;
        }
        let mask_at = size_of::<ACE_HEADER>();
        // SAFETY: every allow ACE type read here continues its header with
        // a 32-bit access mask (ACCESS_ALLOWED_ACE.Mask and the object and
        // callback forms), inside the ACE.
        #[allow(unsafe_code, reason = "reads an allow ACE's mask")]
        let mask = unsafe {
            entry
                .cast::<u8>()
                .wrapping_add(mask_at)
                .cast::<u32>()
                .read_unaligned()
        };
        let sid = if PLAIN_SID_ACE_TYPES.contains(&header.AceType) {
            // SAFETY: plain and callback allow ACEs hold their trustee's SID
            // right after the mask (ACCESS_ALLOWED_ACE.SidStart), inside
            // the ACE and the caller's descriptor.
            #[allow(unsafe_code, reason = "renders an ACE's trustee")]
            unsafe {
                sid_string(
                    entry
                        .cast::<u8>()
                        .wrapping_add(mask_at.saturating_add(4))
                        .cast(),
                )
            }
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

/// A security descriptor's owner and DACL, reduced for
/// [`crate::acl::untrusted`]; `what` names its object in errors. For a
/// descriptor the caller read itself (a registry key's, from
/// `RegGetKeySecurity`).
///
/// # Errors
/// The owner, the DACL or an entry can't be read.
///
/// # Safety
/// `descriptor` must point to a valid security descriptor (absolute or
/// self-relative) that stays alive and unchanged for the call.
#[allow(unsafe_code, reason = "walks a caller's security descriptor")]
pub unsafe fn descriptor_security(
    descriptor: *const c_void,
    what: &str,
) -> Result<ObjectSecurity, Error> {
    let descriptor: PSECURITY_DESCRIPTOR = descriptor.cast_mut();
    let mut owner: PSID = std::ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: the caller's valid descriptor; valid out pointers.
    #[allow(unsafe_code, reason = "reads the descriptor's owner")]
    let read = unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) };
    if read == 0 {
        return Err(Error::new(format!("{what}: can't read its owner")));
    }
    // SAFETY: the owner SID inside the caller's descriptor.
    #[allow(unsafe_code, reason = "renders the owner")]
    let owner = unsafe { sid_string(owner) };
    let mut present = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: as above.
    #[allow(unsafe_code, reason = "reads the descriptor's DACL")]
    let read =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if read == 0 {
        return Err(Error::new(format!("{what}: can't read its DACL")));
    }
    if present == 0 || dacl.is_null() {
        return Ok(ObjectSecurity { owner, dacl: None });
    }
    // SAFETY: a non-null ACL inside the caller's descriptor.
    #[allow(unsafe_code, reason = "reduces the DACL")]
    let entries = unsafe { aces(dacl, what) }?;
    Ok(ObjectSecurity {
        owner,
        dacl: Some(entries),
    })
}

/// The open object's owner and DACL, read through the handle (so what was
/// opened is what is judged); `what` names it in errors. The handle needs
/// `READ_CONTROL` ([`Access::ReadSecurity`]).
///
/// # Errors
/// The descriptor can't be read.
pub fn security(handle: BorrowedHandle<'_>, what: &str) -> Result<ObjectSecurity, Error> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: an open handle with READ_CONTROL and a valid out pointer; the
    // descriptor is allocated by the call and freed by `Allocated`.
    #[allow(unsafe_code, reason = "reads an object's security")]
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let sd = Allocated(sd);
    if status != ERROR_SUCCESS || sd.0.is_null() {
        return Err(Error::new(format!(
            "{what}: can't read its security descriptor ({})",
            status_error(status)
        )));
    }
    // SAFETY: the descriptor GetSecurityInfo returned, freed only when
    // `sd` drops, after this read.
    #[allow(unsafe_code, reason = "reduces the descriptor just read")]
    unsafe {
        descriptor_security(sd.0, what)
    }
}

/// The owner and DACL of the object at `path`, read by name (a reparse
/// point there is followed: check the path's attributes first).
///
/// # Errors
/// The descriptor can't be read.
pub fn named_security(path: &Path) -> Result<ObjectSecurity, Error> {
    let name = wide(path);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call; the out
    // pointer is valid. The descriptor is allocated by the call and freed
    // by `Allocated`.
    #[allow(unsafe_code, reason = "reads a file's security descriptor")]
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let sd = Allocated(sd);
    if status != ERROR_SUCCESS || sd.0.is_null() {
        return Err(Error::new(format!(
            "{}: can't read its security descriptor ({})",
            path.display(),
            status_error(status)
        )));
    }
    // SAFETY: the descriptor GetNamedSecurityInfoW returned, freed only
    // when `sd` drops, after this read.
    #[allow(unsafe_code, reason = "reduces the descriptor just read")]
    unsafe {
        descriptor_security(sd.0, &path.display().to_string())
    }
}

/// Whether the open object's DACL is protected (inherits nothing); `what`
/// names it in errors.
///
/// # Errors
/// The DACL can't be read.
pub fn is_protected(handle: BorrowedHandle<'_>, what: &str) -> Result<bool, Error> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: as in `security`, the DACL only.
    #[allow(unsafe_code, reason = "reads an object's DACL")]
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    let sd = Allocated(sd);
    if status != ERROR_SUCCESS || sd.0.is_null() {
        return Err(Error::new(format!(
            "{what}: can't read its DACL ({})",
            status_error(status)
        )));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: a valid descriptor and valid out pointers.
    #[allow(unsafe_code, reason = "reads a descriptor's control bits")]
    let read = unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) };
    if read == 0 {
        return Err(Error::new(format!(
            "{what}: can't read its descriptor's control bits"
        )));
    }
    Ok(control & SE_DACL_PROTECTED != 0)
}

/// A security descriptor made from SDDL, freed on drop: what a folder is
/// created with, or taken back to.
pub struct SecurityDescriptor(Allocated);

impl std::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecurityDescriptor")
    }
}

impl SecurityDescriptor {
    /// The descriptor `sddl` describes (`O:SYD:P(A;OICI;FA;;;SY)…`).
    ///
    /// # Errors
    /// The system's reason the text isn't a descriptor.
    pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let text = wide_str(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string and a valid out pointer; the
        // descriptor is freed by `Allocated`'s drop.
        #[allow(unsafe_code, reason = "builds a security descriptor")]
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        let error = last_error();
        let sd = Allocated(sd);
        if converted == 0 || sd.0.is_null() {
            return Err(error);
        }
        Ok(Self(sd))
    }

    /// The descriptor's owner and DACL pointers (into the descriptor).
    fn owner_and_dacl(&self) -> Result<(PSID, *mut ACL), Error> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: a valid descriptor and valid out pointers.
        #[allow(unsafe_code, reason = "reads a descriptor's owner")]
        let read = unsafe { GetSecurityDescriptorOwner(self.0.0, &mut owner, &mut defaulted) };
        if read == 0 {
            return Err(Error::new("can't read a descriptor's owner"));
        }
        let mut present = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: as above.
        #[allow(unsafe_code, reason = "reads a descriptor's DACL")]
        let read =
            unsafe { GetSecurityDescriptorDacl(self.0.0, &mut present, &mut dacl, &mut defaulted) };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err(Error::new("a descriptor without a DACL"));
        }
        Ok((owner, dacl))
    }

    /// The descriptor's DACL, reduced (for [`crate::acl::writers`]); `what`
    /// names the object it is for in errors.
    ///
    /// # Errors
    /// The descriptor has no owner or no DACL, or an entry can't be read.
    pub fn dacl(&self, what: &str) -> Result<Vec<Ace>, Error> {
        let (_, dacl) = self.owner_and_dacl()?;
        // SAFETY: a non-null ACL inside this descriptor, alive while `self`
        // is.
        #[allow(unsafe_code, reason = "reduces the descriptor's DACL")]
        unsafe {
            aces(dacl, what)
        }
    }
}

/// Creates the directory `path` with `descriptor` (its parent must exist),
/// so it is locked from its first moment.
///
/// # Errors
/// The system's reason, `ERROR_ALREADY_EXISTS` (183) included.
pub fn create_directory(path: &Path, descriptor: &SecurityDescriptor) -> std::io::Result<()> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: 0,
    };
    let name = wide(path);
    // SAFETY: a NUL-terminated path and attributes holding a valid
    // descriptor, both alive for the call.
    #[allow(unsafe_code, reason = "creates a directory with its descriptor")]
    let created = unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } != 0;
    if created { Ok(()) } else { Err(last_error()) }
}

/// Replaces the open object's owner and DACL with `descriptor`'s, on this
/// object alone: the kernel's own call, which propagates nothing to what
/// the object holds. The handle needs [`Access::TakeBack`]; `what` names it
/// in errors.
///
/// # Errors
/// The system refuses.
pub fn take_back(
    handle: BorrowedHandle<'_>,
    descriptor: &SecurityDescriptor,
    what: &str,
) -> Result<(), Error> {
    // SAFETY: an open handle (the caller's, with WRITE_OWNER and WRITE_DAC
    // or the call fails) and a valid descriptor.
    #[allow(unsafe_code, reason = "sets an object's owner and DACL")]
    let set = unsafe {
        SetKernelObjectSecurity(
            handle.as_raw_handle(),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor.0.0,
        )
    };
    if set == 0 {
        return Err(Error::new(format!(
            "{what}: can't take it back ({})",
            last_error()
        )));
    }
    Ok(())
}

/// Sets `descriptor`'s owner and protected DACL on the open object and
/// propagates its inheritable entries to everything the object holds. The
/// handle needs [`Access::TakeBack`]; `what` names it in errors. Audit what
/// it holds first: propagation follows no reparse point, but rewrites
/// every object below.
///
/// # Errors
/// The descriptor has no owner or DACL, or the system refuses.
pub fn propagate(
    handle: BorrowedHandle<'_>,
    descriptor: &SecurityDescriptor,
    what: &str,
) -> Result<(), Error> {
    let (owner, dacl) = descriptor.owner_and_dacl()?;
    // SAFETY: an open handle (the caller's, with WRITE_OWNER and WRITE_DAC
    // or the call fails); the owner and DACL point into `descriptor`,
    // alive for the call.
    #[allow(unsafe_code, reason = "sets and propagates an object's DACL")]
    let status = unsafe {
        SetSecurityInfo(
            handle.as_raw_handle(),
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
        return Err(Error::new(format!(
            "{what}: can't apply its descriptor ({})",
            status_error(status)
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listings

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    name: OsString,
    attributes: Attributes,
}

impl Entry {
    /// Its name in the directory.
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// Its attributes as the listing reported them (a reparse point is
    /// listed as one; open it to judge it).
    #[must_use]
    pub const fn attributes(&self) -> Attributes {
        self.attributes
    }
}

/// The entries of `dir` (but `.` and `..`), with their listed attributes.
///
/// # Errors
/// It can't be listed, or holds more than [`MAX_ENTRIES`] entries.
pub fn list(dir: &Path) -> Result<Vec<Entry>, Error> {
    let pattern = wide(&dir.join("*"));
    // SAFETY: WIN32_FIND_DATAW is plain data; all zeroes is a valid value,
    // overwritten by the calls below.
    #[allow(unsafe_code, reason = "a zeroed find buffer")]
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated pattern, the basic info level, a buffer of
    // the level's type, no filter; the handle is closed below.
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
        return Err(Error::new(format!(
            "can't list {} ({})",
            dir.display(),
            last_error()
        )));
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
            out.push(Entry {
                name,
                attributes: Attributes(data.dwFileAttributes),
            });
        }
        if out.len() > MAX_ENTRIES {
            result = Err(Error::new(format!(
                "{} holds more than {MAX_ENTRIES} entries",
                dir.display()
            )));
            break;
        }
        // SAFETY: the open find handle and the same buffer.
        #[allow(unsafe_code, reason = "continues the listing")]
        let more = unsafe { FindNextFileW(find, &mut data) };
        if more == 0 {
            let error = last_error();
            if error.raw_os_error() != Some(NO_MORE_FILES) {
                result = Err(Error::new(format!(
                    "can't list {} ({error})",
                    dir.display()
                )));
            }
            break;
        }
    }
    // SAFETY: the find handle FindFirstFileExW returned, closed once.
    #[allow(unsafe_code, reason = "ends the listing")]
    let _ = unsafe { FindClose(find) };
    result.map(|()| out)
}
