//! Pure renderers and validators: the text and the records a service
//! manager or an installer package needs, computed from a [`ServiceSpec`]
//! without touching the system.
//!
//! Every function here is platform-independent, so the seaworthy CLI
//! renders a Windows service's MSI tables, a Linux package's systemd units
//! and a macOS package's LaunchDaemon on one Linux build host. With the
//! `runtime` feature, the systemd backend writes exactly the unit
//! [`systemd::unit`] renders, the launchd backend the plist
//! [`launchd::plist`] renders. The Windows backend shares this module's
//! validation and account rules (`windows_policy`), but passes arguments to
//! the SCM through `windows-service`, which quotes them the same way
//! [`windows::quote_argument`] does.
//!
//! - [`systemd`]: the service unit, the update helper's `.path` and
//!   `.service` units, and the `sysusers.d` line for a sandbox user.
//! - [`launchd`]: the LaunchDaemon property list a macOS package installs
//!   and the backend loads, and the service's state from `launchctl
//!   print`.
//! - [`windows`]: the service record behind an MSI's `ServiceInstall`
//!   and `MsiServiceConfigFailureActions` rows, the account name and its
//!   SID (a virtual account's computed from the service name), and the
//!   program directory's and the update helper's SDDL.
//!
//! [`ServiceSpec`]: crate::ServiceSpec

pub mod launchd;
pub mod systemd;
pub mod windows;
// The Windows service record's pure rules, compiled everywhere so Linux CI
// runs their tests: the renderer here and the runtime's Windows backend
// both apply them.
pub(crate) mod windows_policy;

/// `true` for an absolute path over the conservative alphabet
/// `[A-Za-z0-9._/@+-]`: the rule for directive values systemd word-splits,
/// C-unescapes and specifier-expands. Non-UTF-8 paths fail, since the
/// alphabet is ASCII.
pub(crate) fn is_conservative_path(path: &std::path::Path) -> bool {
    path.to_str().is_some_and(|text| {
        text.starts_with('/')
            && text.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'@' | b'+' | b'-')
            })
    })
}

/// The shared rejection rule for service names and name-class values (unit
/// names, SCM names, launchd labels, sandbox user/group): the FIRST
/// character must be an ASCII letter or digit (a leading dot writes a
/// HIDDEN unit file — `/etc/systemd/system/.hidden.service` — and a
/// non-ASCII lead is never a portable name), and the rest must carry no
/// whitespace, control, path, or specifier characters. `%` is rejected
/// because systemd runs unit values through specifier expansion (`"%u"` in
/// a `User=` expands to root for a system unit) and it is invalid in unit
/// names outright. This is a rejection, not a sanitization — the caller
/// owns picking a clean name.
pub(crate) fn is_safe_service_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|c| !c.is_control() && !c.is_whitespace() && c != '/' && c != '\\' && c != '%')
}
