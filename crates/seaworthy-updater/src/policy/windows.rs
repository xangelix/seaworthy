//! The policy on Windows: the Group Policy key, then the MSI's default,
//! each refused when someone other than SYSTEM, Administrators or
//! TrustedInstaller could have written it ([`super::acl`]). The same
//! reads serve the machine's update server (`Server` in both keys) and the
//! update helper: the MSI's installed `Release`, and the owner and DACL of
//! its staging directories.

// FFI: registry and security-descriptor reads through windows-sys. Each
// `unsafe` block is allowed on its own, with the invariant it relies on.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    PSID,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, REG_SZ, RegCloseKey, RegGetKeySecurity,
    RegOpenKeyExW, RegQueryValueExW,
};

use super::acl::{Ace, untrusted_writer};
use super::{AdminServer, PolicyDecision, PolicySource, UpdatePolicy};
use crate::Product;

/// The registry value holding the policy, in both keys.
const VALUE: &str = "UpdatePolicy";

/// The longest policy value read (`notify` and a terminator, with room to
/// spare).
const MAX_VALUE_BYTES: u32 = 64;

/// The longest other value read ([`read_install_value`]: a release's
/// spelling is at most a hundred-odd characters).
const MAX_INSTALL_VALUE_BYTES: u32 = 512;

/// ACE types that grant access: plain, object, callback, callback object.
const ALLOW_ACE_TYPES: [u8; 4] = [0, 5, 9, 11];
/// ACE types whose trustee SID directly follows the mask.
const PLAIN_SID_ACE_TYPES: [u8; 2] = [0, 9];

pub(super) fn read(product: &Product) -> PolicyDecision {
    for (key, source) in [
        (product.policy_key(), PolicySource::GroupPolicy),
        (product.install_key(), PolicySource::InstallDefault),
    ] {
        match read_value(&key, VALUE, MAX_VALUE_BYTES) {
            Ok(None) => {}
            Ok(Some(value)) => {
                return match UpdatePolicy::parse(&value) {
                    Some(policy) => PolicyDecision { policy, source },
                    None => PolicyDecision::untrusted(format!(
                        "HKLM\\{key}\\{VALUE} is {:?}, not auto, notify or off",
                        crate::log::line_safe(&value)
                    )),
                };
            }
            Err(why) => return PolicyDecision::untrusted(why),
        }
    }
    PolicyDecision::product_default(product)
}

/// The registry value naming the machine's update server, in both keys.
const SERVER_VALUE: &str = "Server";

/// The longest server value read: [`crate::MAX_SERVER_BYTES`] characters
/// of UTF-16 and a terminator; a longer value is refused.
const MAX_SERVER_VALUE_BYTES: u32 = (crate::MAX_SERVER_BYTES as u32 + 1) * 2;

/// The server Group Policy names, else the MSI's (`SERVER=`), each under
/// the policy's writer check; `Ok(None)` when neither key holds one.
pub(super) fn read_server(product: &Product) -> Result<Option<AdminServer>, String> {
    for (key, source) in [
        (product.policy_key(), PolicySource::GroupPolicy),
        (product.install_key(), PolicySource::InstallDefault),
    ] {
        if let Some(value) = read_value(&key, SERVER_VALUE, MAX_SERVER_VALUE_BYTES)? {
            let url = super::server::validate(&format!("HKLM\\{key}\\{SERVER_VALUE}"), &value)?;
            return Ok(Some(AdminServer { url, source }));
        }
    }
    Ok(None)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The UTF-16 units of a NUL-terminated wide string, without its
/// terminator.
///
/// # Safety
/// `text` must point to a readable, NUL-terminated UTF-16 string that
/// stays alive and unchanged for `'a`.
#[allow(unsafe_code, reason = "reads a C wide string")]
pub(crate) unsafe fn wide_units<'a>(text: *const u16) -> &'a [u16] {
    let mut len = 0usize;
    loop {
        #[allow(unsafe_code, reason = "reads one unit of a C wide string")]
        // SAFETY: the caller's string is terminated, so every unit up to
        // and including the terminator is readable; the loop stops at it.
        let unit = unsafe { text.wrapping_add(len).read() };
        if unit == 0 {
            break;
        }
        len = len.saturating_add(1);
    }
    #[allow(unsafe_code, reason = "views a C wide string as a slice")]
    // SAFETY: `len` readable units precede the terminator, alive for `'a`
    // (the caller's contract); u16 has no invalid bit patterns.
    unsafe {
        std::slice::from_raw_parts(text, len)
    }
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        #[allow(unsafe_code, reason = "closes a registry key")]
        // SAFETY: the handle came from RegOpenKeyExW and is closed once,
        // here.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

/// Opens `HKLM\<key>` for reading in the 64-bit view; `None` when it
/// doesn't exist.
fn open(key: &str) -> Result<Option<Key>, String> {
    let name = wide(key);
    let mut handle: HKEY = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "opens a registry key")]
    // SAFETY: `name` is NUL-terminated and outlives the call; `handle` is a
    // valid out pointer.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(Key(handle))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        error => Err(format!(
            "HKLM\\{key}: {}",
            std::io::Error::from_raw_os_error(error as i32)
        )),
    }
}

/// A SID as its string form (`S-1-5-18`).
pub(crate) fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "renders a SID")]
    // SAFETY: `sid` points into a security descriptor or token buffer the
    // caller holds; the string is allocated by the call and freed with
    // LocalFree below.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    if converted == 0 || text.is_null() {
        return None;
    }
    #[allow(unsafe_code, reason = "reads the rendered SID")]
    // SAFETY: `text` is the NUL-terminated wide string the call allocated,
    // alive until the LocalFree below (after the copy).
    let result = String::from_utf16(unsafe { wide_units(text) }).ok();
    #[allow(unsafe_code, reason = "frees the rendered SID")]
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    let _ = unsafe { LocalFree(text.cast()) };
    result
}

/// The key's owner and DACL, reduced for [`untrusted_writer`].
fn security(key: &Key, name: &str) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
    let wanted = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut size = 0u32;
    #[allow(unsafe_code, reason = "sizes a key's security descriptor")]
    // SAFETY: a size query with a NULL buffer and a valid size pointer.
    let status = unsafe { RegGetKeySecurity(key.0, wanted, std::ptr::null_mut(), &mut size) };
    if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return Err(format!(
            "HKLM\\{name}: can't read its security descriptor ({})",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    // u64-aligned storage: a security descriptor holds pointer-aligned
    // fields when absolute (RegGetKeySecurity returns it self-relative,
    // but alignment costs nothing).
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    let descriptor = buffer.as_mut_ptr().cast::<c_void>();
    #[allow(unsafe_code, reason = "reads a key's security descriptor")]
    // SAFETY: `buffer` holds at least `size` bytes; `size` is a valid
    // in/out pointer.
    let status = unsafe { RegGetKeySecurity(key.0, wanted, descriptor, &mut size) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "HKLM\\{name}: can't read its security descriptor ({})",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    #[allow(unsafe_code, reason = "reduces the descriptor just read")]
    // SAFETY: `descriptor` is the valid self-relative descriptor just read
    // into `buffer`, which outlives the call.
    unsafe {
        owner_and_aces(descriptor, &format!("HKLM\\{name}"))
    }
}

/// A security descriptor's owner and DACL, reduced for
/// [`super::acl::untrusted_writer_of`]; `what` names its object in errors.
///
/// # Safety
/// `descriptor` must point to a valid security descriptor that outlives
/// the call.
#[allow(unsafe_code, reason = "walks a security descriptor")]
unsafe fn owner_and_aces(
    descriptor: PSECURITY_DESCRIPTOR,
    what: &str,
) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut defaulted = 0;
    #[allow(unsafe_code, reason = "reads the descriptor's owner")]
    // SAFETY: the caller's valid descriptor; valid out pointers.
    let read = unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) };
    if read == 0 {
        return Err(format!("{what}: can't read its owner"));
    }
    let owner = sid_string(owner);
    let mut present = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "reads the descriptor's DACL")]
    // SAFETY: as above.
    let read =
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) };
    if read == 0 {
        return Err(format!("{what}: can't read its DACL"));
    }
    if present == 0 || dacl.is_null() {
        return Ok((owner, None));
    }
    #[allow(unsafe_code, reason = "reads the DACL's header")]
    // SAFETY: `dacl` is non-null and points to an ACL inside the caller's
    // descriptor.
    let count = unsafe { (*dacl).AceCount };
    let mut aces = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut entry: *mut c_void = std::ptr::null_mut();
        #[allow(unsafe_code, reason = "reads one ACE of the DACL")]
        // SAFETY: `dacl` is a valid ACL and `index` is below its count;
        // `entry` is a valid out pointer.
        let found = unsafe { GetAce(dacl, index, &mut entry) };
        if found == 0 || entry.is_null() {
            return Err(format!("{what}: can't read ACE {index}"));
        }
        #[allow(unsafe_code, reason = "reads an ACE's header")]
        // SAFETY: every ACE GetAce returns starts with an ACE_HEADER, inside
        // the caller's descriptor.
        let header = unsafe { entry.cast::<ACE_HEADER>().read_unaligned() };
        if !ALLOW_ACE_TYPES.contains(&header.AceType) {
            continue;
        }
        let mask_at = std::mem::size_of::<ACE_HEADER>();
        #[allow(unsafe_code, reason = "reads an allow ACE's mask")]
        // SAFETY: every allow ACE type read here continues its header with
        // a 32-bit access mask (ACCESS_ALLOWED_ACE.Mask and the object and
        // callback forms), inside the ACE.
        let mask = unsafe {
            entry
                .cast::<u8>()
                .wrapping_add(mask_at)
                .cast::<u32>()
                .read_unaligned()
        };
        let sid = if PLAIN_SID_ACE_TYPES.contains(&header.AceType) {
            // Plain and callback allow ACEs hold the SID right after the
            // mask (ACCESS_ALLOWED_ACE.SidStart).
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
}

/// Refuses `key` when it, or any existing key above it up to `SOFTWARE`,
/// could be written by someone other than SYSTEM, Administrators or
/// TrustedInstaller: such a principal could create or replace the value.
fn check_writers(key: &str) -> Result<(), String> {
    let mut path = key.to_owned();
    loop {
        if let Some(open) = open(&path)? {
            let (owner, dacl) = security(&open, &path)?;
            if let Some(why) = untrusted_writer(&path, owner.as_deref(), dacl.as_deref()) {
                return Err(why);
            }
        }
        match path.rsplit_once('\\') {
            Some((parent, _)) => path = parent.to_owned(),
            None => return Ok(()),
        }
    }
}

/// A directory's (or file's) owner and DACL, reduced for
/// [`super::acl::untrusted_writer_of`].
#[cfg_attr(
    not(feature = "helper"),
    allow(dead_code, reason = "only the helper audits directories")
)]
pub(crate) fn path_owner_and_dacl(
    path: &Path,
) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "reads a file's security descriptor")]
    // SAFETY: `name` is NUL-terminated and outlives the call; the out
    // pointers are valid. The descriptor is allocated by the call and
    // freed with LocalFree below; `owner` and `dacl` point into it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(format!(
            "{}: can't read its security descriptor ({})",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    #[allow(unsafe_code, reason = "reduces the descriptor just read")]
    // SAFETY: the descriptor GetNamedSecurityInfoW returned, freed only
    // after this read.
    let result = unsafe { owner_and_aces(descriptor, &path.display().to_string()) };
    #[allow(unsafe_code, reason = "frees the descriptor")]
    // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
    let _ = unsafe { LocalFree(descriptor) };
    result
}

/// An open file's owner and DACL, reduced for
/// [`super::acl::untrusted_writer_of`] (read through the handle, so what
/// was opened is what is judged).
#[cfg_attr(
    not(feature = "helper"),
    allow(dead_code, reason = "only the helper audits its log file")
)]
pub(crate) fn handle_owner_and_dacl(
    handle: windows_sys::Win32::Foundation::HANDLE,
    what: &str,
) -> Result<(Option<String>, Option<Vec<Ace>>), String> {
    use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "reads an open file's security descriptor")]
    // SAFETY: an open handle with READ_CONTROL and valid out pointers; the
    // descriptor is allocated by the call and freed with LocalFree below;
    // `owner` and `dacl` point into it.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(format!(
            "{what}: can't read its security descriptor ({})",
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    #[allow(unsafe_code, reason = "reduces the descriptor just read")]
    // SAFETY: the descriptor GetSecurityInfo returned, freed only after
    // this read.
    let result = unsafe { owner_and_aces(descriptor, what) };
    #[allow(unsafe_code, reason = "frees the descriptor")]
    // SAFETY: allocated by GetSecurityInfo, freed once.
    let _ = unsafe { LocalFree(descriptor) };
    result
}

/// `HKLM\<key>\<value>`, a string the MSI wrote under the product's
/// install key (the helper's `Release`), after the same writer check as
/// the policy; `None` when the key or the value doesn't exist.
#[cfg_attr(
    not(feature = "installers"),
    allow(dead_code, reason = "only the MSI installer reads its release")
)]
pub(crate) fn read_install_value(key: &str, value: &str) -> Result<Option<String>, String> {
    read_value(key, value, MAX_INSTALL_VALUE_BYTES)
}

/// `HKLM\<key>\<value>` (a `REG_SZ` of at most `max_bytes`), after the
/// writer check; `None` when the key or the value doesn't exist.
fn read_value(key: &str, value: &str, max_bytes: u32) -> Result<Option<String>, String> {
    check_writers(key)?;
    let Some(open) = open(key)? else {
        return Ok(None);
    };
    let name = wide(value);
    let mut kind = 0u32;
    let mut data = vec![0u16; (max_bytes / 2) as usize];
    let mut size = max_bytes;
    #[allow(unsafe_code, reason = "reads a registry value")]
    // SAFETY: `data` holds `size` bytes; `name` is NUL-terminated; `kind`
    // and `size` are valid out pointers.
    let status = unsafe {
        RegQueryValueExW(
            open.0,
            name.as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut size,
        )
    };
    match status {
        ERROR_SUCCESS => {}
        ERROR_FILE_NOT_FOUND => return Ok(None),
        error => {
            return Err(format!(
                "HKLM\\{key}\\{value}: {} (at most {max_bytes} bytes of REG_SZ)",
                std::io::Error::from_raw_os_error(error as i32)
            ));
        }
    }
    if kind != REG_SZ {
        return Err(format!(
            "HKLM\\{key}\\{value} is not a REG_SZ (type {kind})"
        ));
    }
    let units = data
        .get(..(size as usize / 2).min(data.len()))
        .unwrap_or_default();
    let text: Vec<u16> = units.iter().copied().take_while(|&u| u != 0).collect();
    String::from_utf16(&text)
        .map(Some)
        .map_err(|_| format!("HKLM\\{key}\\{value} is not valid UTF-16"))
}
