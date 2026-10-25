//! The update policy against real registry keys: `read_policy` and
//! `UpdateRequester` read HKLM as a product's MSI and Group Policy write
//! it, and refuse a key someone else could write.
//!
//! 1. no key: the product's default;
//! 2. the MSI's `HKLM\SOFTWARE\<Vendor>\<Directory>\UpdatePolicy` = `auto`:
//!    `auto` from the install default, and the requester asks the helper
//!    (no helper service exists here: the request fails, after the policy
//!    said to make it);
//! 3. Group Policy's `HKLM\SOFTWARE\Policies\<Vendor>\<Directory>` = `off`:
//!    it wins, the requester logs and asks nothing;
//! 4. Users granted a write on that Policies key: untrusted, `off`;
//! 5. Users granted a write on the MSI's key (no Group Policy): untrusted.
//!
//! It writes HKLM, so it runs only where `SEAWORTHY_WINDOWS_LIVE_REGISTRY=1`
//! (an administrator on a throwaway Windows host or container, such as a
//! CI runner); elsewhere (Wine, a developer's machine) it says it skipped.
//! The keys are its own vendor's, removed before and after. Its registry
//! writes go through windows-sys, each `unsafe` block allowed on its own.
#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test: a failed expectation is a test failure"
)]

use seaworthy_updater::{
    PolicySource, Product, RequestOutcome, UpdatePolicy, UpdateRequester, read_policy,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HANDLE, LUID, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetKeySecurity, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const VENDOR: &str = "SeaworthyLiveProbe";

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Removes `HKLM\<path>` and everything under it, if it exists.
fn delete_tree(path: &str) {
    let name = wide(path);
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: a NUL-terminated key name under HKLM.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, name.as_ptr()) };
    assert!(
        status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND,
        "removing HKLM\\{path}: {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
}

/// Enables `privilege` (`SeRestorePrivilege`: setting an owner other than
/// oneself) in this process's token.
fn enable(privilege: &str) {
    let mut token: HANDLE = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: GetCurrentProcess takes nothing and can't fail.
    let process = unsafe { GetCurrentProcess() };
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: the current process's pseudo handle and a valid out pointer;
    // the token is closed below.
    let opened =
        unsafe { OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) };
    assert_ne!(opened, 0, "opening the process token");
    let name = wide(privilege);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: a NUL-terminated privilege name and a valid out pointer.
    let found = unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) };
    assert_ne!(found, 0, "looking {privilege} up");
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: an open token and one privilege to enable; no previous state.
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: opened above, closed once.
    let _ = unsafe { CloseHandle(token) };
    assert_ne!(adjusted, 0, "enabling {privilege}");
}

/// Sets `key`'s owner or DACL (`what`) from `sddl`.
fn set_security(key: HKEY, what: u32, sddl: &str, path: &str) {
    let text = wide(sddl);
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: a NUL-terminated SDDL string and a valid out pointer; the
    // descriptor is freed with LocalFree below.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(converted, 0, "converting {sddl}");
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: an open key and the converted descriptor.
    let status = unsafe { RegSetKeySecurity(key, what, descriptor) };
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: allocated by the conversion above.
    let _ = unsafe { LocalFree(descriptor) };
    assert_eq!(
        status,
        ERROR_SUCCESS,
        "setting HKLM\\{path}'s security to {sddl}: {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
}

/// Opens `HKLM\<path>` (64-bit view), created if missing.
fn create(path: &str) -> HKEY {
    let name = wide(path);
    let mut key: HKEY = std::ptr::null_mut();
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: a NUL-terminated name and a valid out pointer; the caller
    // closes the key.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        status,
        ERROR_SUCCESS,
        "creating HKLM\\{path} (an administrator's run?): {}",
        std::io::Error::from_raw_os_error(status as i32)
    );
    key
}

/// What an MSI's or Group Policy's key holds: SYSTEM and Administrators
/// may write, Users read. Written by SYSTEM, `HKLM\SOFTWARE`'s CREATOR
/// OWNER entry adds nothing; written by a container's administrator
/// account it grants that account (S-1-5-93-2-1) full control, which the
/// policy rightly refuses.
const TRUSTED_DACL: &str = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)";

/// `HKLM\<path>`, created if missing (64-bit view), with `value` = `data`
/// (REG_SZ), and, when given, `sddl` as its DACL. The keys it creates are
/// made as an MSI's and Group Policy's are: Administrators' (a container's
/// account owns what it creates itself), with [`TRUSTED_DACL`].
fn write_value(path: &str, value: &str, data: &str, sddl: Option<&str>) {
    enable("SeRestorePrivilege");
    let vendor = &path[..path.find(VENDOR).expect("a probe key") + VENDOR.len()];
    for owned in [vendor, path] {
        let key = create(owned);
        set_security(key, OWNER_SECURITY_INFORMATION, "O:BA", owned);
        set_security(key, DACL_SECURITY_INFORMATION, TRUSTED_DACL, owned);
        #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
        // SAFETY: opened above, closed once.
        let _ = unsafe { RegCloseKey(key) };
    }
    let key = create(path);
    let value_name = wide(value);
    let bytes: Vec<u8> = wide(data).iter().flat_map(|u| u.to_le_bytes()).collect();
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: an open key, a NUL-terminated name, `bytes.len()` bytes.
    let status = unsafe {
        RegSetValueExW(
            key,
            value_name.as_ptr(),
            0,
            REG_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    assert_eq!(status, ERROR_SUCCESS, "writing HKLM\\{path}\\{value}");
    if let Some(sddl) = sddl {
        set_security(key, DACL_SECURITY_INFORMATION, sddl, path);
    }
    #[allow(unsafe_code, reason = "registry and token calls through windows-sys")]
    // SAFETY: opened above, closed once.
    let _ = unsafe { RegCloseKey(key) };
}

#[test]
fn the_update_policy_reads_real_keys_and_refuses_one_others_can_write() {
    if std::env::var_os("SEAWORTHY_WINDOWS_LIVE_REGISTRY").is_none_or(|v| v != "1") {
        eprintln!(
            "SKIPPED: writes HKLM; an administrator's run sets SEAWORTHY_WINDOWS_LIVE_REGISTRY=1"
        );
        return;
    }
    let product = Product::new(VENDOR, "probe", "Probe", "stable")
        .unwrap()
        .with_default_policy(UpdatePolicy::Off);
    let (install, policies) = (product.install_key(), product.policy_key());
    let clean = || {
        delete_tree(&format!("SOFTWARE\\Policies\\{VENDOR}"));
        delete_tree(&format!("SOFTWARE\\{VENDOR}"));
    };
    clean();
    // A requester per case: each asks at most once per interval.
    let ask = || UpdateRequester::new(product.clone()).on_version_mismatch("1.0.0", "1.1.0");

    // 1. No key: the product's default.
    let decision = read_policy(&product);
    assert_eq!(decision.policy, UpdatePolicy::Off, "{decision}");
    assert!(
        matches!(decision.source, PolicySource::ProductDefault),
        "{decision}"
    );

    // 2. The MSI's default, auto: the helper is asked (it isn't installed
    // here, so asking fails, after the policy said to ask).
    write_value(&install, "UpdatePolicy", "auto", None);
    let decision = read_policy(&product);
    assert_eq!(decision.policy, UpdatePolicy::Auto, "{decision}");
    assert!(
        matches!(decision.source, PolicySource::InstallDefault),
        "{decision}"
    );
    match ask() {
        RequestOutcome::Requested(d) | RequestOutcome::Failed(d, _) => {
            assert_eq!(d.policy, UpdatePolicy::Auto, "{d}");
        }
        other => panic!("auto asks the helper: {other:?}"),
    }

    // 3. Group Policy's off wins over the MSI's auto: nothing is asked.
    write_value(&policies, "UpdatePolicy", "off", None);
    let decision = read_policy(&product);
    assert_eq!(decision.policy, UpdatePolicy::Off, "{decision}");
    assert!(
        matches!(decision.source, PolicySource::GroupPolicy),
        "{decision}"
    );
    assert!(
        matches!(ask(), RequestOutcome::NotAuto(d) if matches!(d.source, PolicySource::GroupPolicy)),
        "Group Policy's off asks nothing"
    );

    // 4. Users may write the Policies key: untrusted, off.
    write_value(
        &policies,
        "UpdatePolicy",
        "auto",
        Some("D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)"),
    );
    let decision = read_policy(&product);
    assert_eq!(decision.policy, UpdatePolicy::Off, "{decision}");
    assert!(
        matches!(decision.source, PolicySource::Untrusted(_)),
        "{decision}"
    );
    assert!(
        matches!(ask(), RequestOutcome::NotAuto(d) if matches!(d.source, PolicySource::Untrusted(_))),
        "an untrusted key asks nothing"
    );

    // 5. No Group Policy, and Users may write the MSI's key: untrusted.
    delete_tree(&format!("SOFTWARE\\Policies\\{VENDOR}"));
    write_value(
        &install,
        "UpdatePolicy",
        "auto",
        Some("D:(A;;KA;;;SY)(A;;KA;;;BA)(A;;KA;;;BU)"),
    );
    let decision = read_policy(&product);
    assert_eq!(decision.policy, UpdatePolicy::Off, "{decision}");
    assert!(
        matches!(decision.source, PolicySource::Untrusted(_)),
        "{decision}"
    );

    clean();
}
