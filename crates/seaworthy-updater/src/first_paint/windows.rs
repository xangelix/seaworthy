//! First-paint probation in the registry on Windows.
//!
//! - **The notice:** `HKLM\SOFTWARE\<Vendor>\<Directory>\ProbationPending`
//!   (`REG_SZ`), beside the MSI's `Release`: the helper (LocalSystem)
//!   writes and deletes it, everyone may read it (the key inherits
//!   `HKLM\SOFTWARE`'s descriptor), and the app reads it after the same
//!   writer check as the policy.
//! - **The markers:** one `REG_SZ` value per marker, named
//!   `<pid>.<16 hex>`, under `HKCU\Software\<Vendor>\<Directory>\FirstPaint`
//!   in the user's own hive. No folder anyone else can write is shared,
//!   and a user can only write their own hive. The helper reads the hives
//!   Windows has loaded (`HKEY_USERS\<SID>`, the logged-on users': the app
//!   asks the helper to run while its user is logged on), opening each key
//!   on the way with `REG_OPTION_OPEN_LINK`, so a symbolic link a user
//!   planted in their hive is opened as itself and leads nowhere; it reads
//!   at most [`super::MAX_MARKER_ENTRIES`] values, each a `REG_SZ` of at most
//!   [`super::MAX_RECORD_BYTES`], and deletes every value it reads.

// FFI: registry calls through windows-sys. Each `unsafe` block is allowed
// on its own, with the invariant it relies on.

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
#[cfg(feature = "helper")]
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegSetValueExW,
};
#[cfg(feature = "helper")]
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_WOW64_64KEY,
    REG_OPTION_OPEN_LINK, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
};

use super::{MARKERS_KEY, Marker};
use crate::Product;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn os_error(code: u32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code as i32)
}

/// An open registry key, closed on drop.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        #[allow(unsafe_code, reason = "closes a registry key")]
        // SAFETY: the handle came from RegOpenKeyExW or RegCreateKeyExW and
        // is closed once, here.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

/// Creates (or opens) `<root>\<path>` for setting values.
fn create(root: HKEY, path: &str, extra_access: u32) -> Result<Key, String> {
    let name = wide(path);
    let mut handle: HKEY = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "creates or opens a registry key")]
    // SAFETY: `name` is NUL-terminated and outlives the call; no class, no
    // security attributes, no disposition; `handle` is a valid out pointer.
    let status = unsafe {
        RegCreateKeyExW(
            root,
            name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | extra_access,
            std::ptr::null(),
            &mut handle,
            std::ptr::null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(Key(handle))
    } else {
        Err(format!("{path}: {}", os_error(status)))
    }
}

/// Sets `<key>\<value>` to `text` as a `REG_SZ`.
fn set_string(key: &Key, value: &str, text: &str) -> Result<(), String> {
    let name = wide(value);
    let data = wide(text);
    let bytes =
        u32::try_from(data.len().saturating_mul(2)).map_err(|_| format!("{value}: too long"))?;
    #[allow(unsafe_code, reason = "sets a registry value")]
    // SAFETY: `name` and `data` are NUL-terminated and outlive the call;
    // `bytes` is `data`'s size in bytes, terminator included.
    let status =
        unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), bytes) };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(format!("{value}: {}", os_error(status)))
    }
}

/// The markers' key under a user's hive: `<install key>\FirstPaint`.
fn markers_path(product: &Product) -> String {
    format!("{}\\{MARKERS_KEY}", product.install_key())
}

/// Leaves `marker` in the user's own hive (see the module docs).
pub(crate) fn write_marker(product: &Product, marker: &Marker) -> Result<(), String> {
    let key = create(HKEY_CURRENT_USER, &markers_path(product), 0)?;
    let name = format!("{}.{}", std::process::id(), super::nonce());
    set_string(&key, &name, &marker.encode())
}

/// Opens `<root>\<path>` one component at a time with
/// `REG_OPTION_OPEN_LINK` (a link key opens as itself, so a path through a
/// planted link finds nothing); `None` when a component doesn't exist.
#[cfg(feature = "helper")]
fn open_no_links(root: HKEY, path: &str, access: u32) -> Result<Option<Key>, String> {
    let mut current: Option<Key> = None;
    for component in path.split('\\') {
        let name = wide(component);
        let parent = current.as_ref().map_or(root, |key| key.0);
        let mut handle: HKEY = std::ptr::null_mut();
        #[allow(unsafe_code, reason = "opens a registry key without following a link")]
        // SAFETY: `parent` is a predefined or open key; `name` is
        // NUL-terminated and outlives the call; `handle` is a valid out
        // pointer.
        let status = unsafe {
            RegOpenKeyExW(
                parent,
                name.as_ptr(),
                REG_OPTION_OPEN_LINK,
                access | KEY_ENUMERATE_SUB_KEYS,
                &mut handle,
            )
        };
        match status {
            ERROR_SUCCESS => current = Some(Key(handle)),
            ERROR_FILE_NOT_FOUND => return Ok(None),
            error => return Err(format!("{path}: {}", os_error(error))),
        }
    }
    Ok(current)
}

/// Whether `name` is a loaded user hive's: a user SID (`S-1-5-21-…`, a
/// local or domain account; `S-1-12-1-…`, an Entra ID one), not its
/// `_Classes` companion, at most 184 characters.
#[cfg(feature = "helper")]
fn is_user_hive(name: &str) -> bool {
    let rest = name
        .strip_prefix("S-1-5-21-")
        .or_else(|| name.strip_prefix("S-1-12-1-"));
    rest.is_some_and(|rest| {
        !rest.is_empty()
            && name.len() <= 184
            && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
            && !rest.ends_with('-')
    })
}

/// The subkey names of `key`, at most `max` of them; `None` past it.
#[cfg(feature = "helper")]
fn subkeys(key: HKEY, max: usize) -> Result<Option<Vec<String>>, String> {
    let mut names = Vec::new();
    for index in 0u32.. {
        let mut buffer = [0u16; 256];
        let mut length = buffer.len() as u32;
        #[allow(unsafe_code, reason = "enumerates registry subkeys")]
        // SAFETY: `buffer` holds `length` UTF-16 units; the other out
        // pointers are NULL, which the call allows.
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                buffer.as_mut_ptr(),
                &mut length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        match status {
            ERROR_SUCCESS => {}
            ERROR_NO_MORE_ITEMS => break,
            // A name too long for a SID: skipped.
            ERROR_MORE_DATA => continue,
            error => return Err(format!("HKEY_USERS: {}", os_error(error))),
        }
        if names.len() >= max {
            return Ok(None);
        }
        let units = buffer.get(..length as usize).unwrap_or_default();
        names.push(String::from_utf16_lossy(units));
    }
    Ok(Some(names))
}

/// A markers key's value: its name (UTF-16), and its text when it is a
/// small `REG_SZ`.
#[cfg(feature = "helper")]
type Value = (Vec<u16>, Option<String>);

/// The values of a markers key, counted against `budget`; `None` past it.
#[cfg(feature = "helper")]
fn values(key: &Key, budget: &mut usize) -> Result<Option<Vec<Value>>, String> {
    let mut found = Vec::new();
    for index in 0u32.. {
        let mut name = [0u16; 128];
        let mut name_length = name.len() as u32;
        let mut kind = 0u32;
        let mut data = [0u16; super::MAX_RECORD_BYTES / 2 + 1];
        let mut size = (data.len() * 2) as u32;
        #[allow(unsafe_code, reason = "enumerates registry values")]
        // SAFETY: `name` holds `name_length` UTF-16 units and `data` holds
        // `size` bytes; `kind` is a valid out pointer.
        let status = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if *budget == 0 {
            return Ok(None);
        }
        *budget = budget.saturating_sub(1);
        // ERROR_MORE_DATA (234): a name or data too large: its name is
        // unknown, so it can't be deleted; it counts against the budget.
        if status != ERROR_SUCCESS {
            if status == ERROR_MORE_DATA {
                continue;
            }
            return Err(format!("a marker value: {}", os_error(status)));
        }
        let name: Vec<u16> = name
            .get(..name_length as usize)
            .unwrap_or_default()
            .to_vec();
        let text = (kind == REG_SZ).then(|| {
            let units: Vec<u16> = data
                .get(..(size as usize / 2).min(data.len()))
                .unwrap_or_default()
                .iter()
                .copied()
                .take_while(|&unit| unit != 0)
                .collect();
            String::from_utf16_lossy(&units)
        });
        found.push((name, text));
    }
    Ok(Some(found))
}

/// Reads, counts and deletes the markers for `pending` in every loaded
/// user hive (see the module docs).
///
/// # Errors
/// `HKEY_USERS` can't be listed, or a markers key can't be read.
#[cfg(feature = "helper")]
pub(crate) fn ingest(
    product: &Product,
    pending: &crate::release::Release,
) -> Result<super::Ingested, String> {
    let mut found = super::Ingested::default();
    let Some(hives) = subkeys(HKEY_USERS, 4096)? else {
        found.overflow = true;
        return Ok(found);
    };
    let path = markers_path(product);
    let mut budget = super::MAX_MARKER_ENTRIES;
    let mut read: Vec<(Key, Vec<Value>)> = Vec::new();
    for hive in hives.iter().filter(|name| is_user_hive(name)) {
        let Some(key) = open_no_links(
            HKEY_USERS,
            &format!("{hive}\\{path}"),
            KEY_QUERY_VALUE | KEY_SET_VALUE,
        )?
        else {
            continue;
        };
        match values(&key, &mut budget)? {
            Some(values) => read.push((key, values)),
            None => {
                found.overflow = true;
                return Ok(found);
            }
        }
    }
    for (key, values) in read {
        for (name, text) in values {
            if let Some(marker) = text.as_deref().and_then(|t| Marker::parse(t).ok())
                && &marker.release == pending
            {
                match marker.state {
                    super::MarkerState::Launched => {
                        found.launches = found.launches.saturating_add(1);
                    }
                    super::MarkerState::Painted => found.painted = true,
                }
            }
            let mut name = name;
            name.push(0);
            #[allow(unsafe_code, reason = "deletes a registry value")]
            // SAFETY: `key` is open with KEY_SET_VALUE; `name` is
            // NUL-terminated and outlives the call.
            let _ = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
        }
    }
    Ok(found)
}

/// The helper writes the notice under the product's install key.
///
/// # Errors
/// The key can't be opened or the value written.
#[cfg(feature = "helper")]
pub(crate) fn publish(product: &Product, notice: &super::Notice) -> Result<(), String> {
    let key = create(HKEY_LOCAL_MACHINE, &product.install_key(), KEY_WOW64_64KEY)?;
    set_string(&key, super::NOTICE_VALUE, &notice.encode())
}

/// The helper deletes the notice.
#[cfg(feature = "helper")]
pub(crate) fn withdraw(product: &Product) {
    let Ok(Some(key)) = open_no_links(
        HKEY_LOCAL_MACHINE,
        &product.install_key(),
        KEY_SET_VALUE | KEY_WOW64_64KEY,
    ) else {
        return;
    };
    let name = wide(super::NOTICE_VALUE);
    #[allow(unsafe_code, reason = "deletes a registry value")]
    // SAFETY: `key` is open with KEY_SET_VALUE; `name` is NUL-terminated and
    // outlives the call.
    let _ = unsafe { RegDeleteValueW(key.0, name.as_ptr()) };
}

#[cfg(all(test, feature = "helper"))]
mod tests {
    use super::*;

    #[test]
    fn only_user_hives_are_read() {
        for hive in [
            "S-1-5-21-1004336348-1177238915-682003330-1001",
            "S-1-12-1-1234-5678-9012-3456",
        ] {
            assert!(is_user_hive(hive), "{hive}");
        }
        for other in [
            ".DEFAULT",
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-20",
            "S-1-5-21-1004336348-1177238915-682003330-1001_Classes",
            "S-1-5-21-x",
        ] {
            assert!(!is_user_hive(other), "{other}");
        }
    }
}
