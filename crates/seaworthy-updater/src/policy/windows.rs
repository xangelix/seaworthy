//! The policy on Windows: the Group Policy key, then the MSI's default,
//! each refused when someone other than SYSTEM, Administrators or
//! TrustedInstaller could have written it ([`super::acl`]). The same
//! reads serve the machine's update server (`Server` in both keys) and the
//! update helper: the MSI's installed `Release`.

// FFI: registry reads through windows-sys (a key's descriptor is reduced by
// seaworthy-fsguard). Each `unsafe` block is allowed on its own, with the
// invariant it relies on.

use std::ffi::c_void;

use seaworthy_fsguard::windows::descriptor_security;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
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
    let found = unsafe { descriptor_security(descriptor, &format!("HKLM\\{name}")) }?;
    Ok((found.owner, found.dacl))
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
