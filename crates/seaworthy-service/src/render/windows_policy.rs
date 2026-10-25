//! The Windows service record's pure rules: spec validation, account
//! resolution, and the DACLs a product's MSI applies (the program
//! directory and the `%ProgramData%` directories, through
//! [`crate::render::windows`]). The runtime's SCM backend shares them.
//!
//! Compiled on EVERY platform, without the `runtime` feature: validators
//! that live inside a `cfg(windows)` module only get tested on Windows, and
//! an account-name rule that once rejected every account it recommended
//! (`NT SERVICE\…` carries a space) shipped for exactly that reason.
//! Anything here is plain string logic.
//!
//! The crate installs no services: a product's MSI lays out its tree and
//! registers its service. The DACLs below are the ones the MSI sets:
//! protected, SYSTEM and Administrators full control, the service account
//! read + execute on its program directory (a service never writes its own
//! program) and Modify on its state directory.

use std::time::Duration;

use crate::{FailurePolicy, ServiceError, WindowsServiceAccount};

// ---------------------------------------------------------------------------
// Spec validation

/// Launch arguments: UTF-8, no control characters, no `%` (the same
/// `REG_EXPAND_SZ` expansion — `%USERPROFILE%` would be rewritten with the
/// service account's environment; there is no escape syntax).
pub(crate) fn validate_arguments<'a>(
    arguments: impl IntoIterator<Item = Option<&'a str>>,
) -> Result<(), ServiceError> {
    for argument in arguments {
        let valid = argument.is_some_and(|a| !a.chars().any(|c| c.is_control() || c == '%'));
        if !valid {
            return Err(ServiceError::InvalidSpec(format!(
                "argument {argument:?} must be UTF-8 without control characters or '%' (the SCM expands %VAR% in the stored command line; there is no escape syntax)"
            )));
        }
    }
    Ok(())
}

/// A free-text field (display name, description): no control characters.
pub(crate) fn validate_text(field: &str, value: &str) -> Result<(), ServiceError> {
    if value.chars().any(char::is_control) {
        return Err(ServiceError::InvalidSpec(format!(
            "{field} {value:?} must not contain control characters"
        )));
    }
    Ok(())
}

/// The SCM's failure actions are a Windows service's only recovery: with no
/// Restart action, a failed service stays stopped until someone starts it,
/// so every service carries at least one.
pub(crate) fn validate_failure_policy(policy: &FailurePolicy) -> Result<(), ServiceError> {
    if policy.restart_delays.is_empty() {
        return Err(ServiceError::InvalidSpec(
            "failure_policy.restart_delays is empty: the SCM restarts a failed service only through its failure actions, so an empty policy would leave it stopped; give at least one restart delay".to_owned(),
        ));
    }
    // The SCM takes 0 ms literally: an immediate restart, a hot loop.
    if policy
        .restart_delays
        .iter()
        .any(|delay| *delay < Duration::from_secs(1))
    {
        return Err(ServiceError::InvalidSpec(format!(
            "failure_policy.restart_delays {:?}: every delay must be at least 1s (a shorter one restarts a failing service in a hot loop)",
            policy.restart_delays
        )));
    }
    if policy.reset_period < Duration::from_secs(1) {
        return Err(ServiceError::InvalidSpec(format!(
            "failure_policy.reset_period {:?} must be at least 1s",
            policy.reset_period
        )));
    }
    Ok(())
}

/// Spellings of `LocalSystem` that must go through the explicit
/// [`WindowsServiceAccount::LocalSystem`] opt-in instead of `Named`.
fn is_local_system_spelling(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "localsystem"
            | ".\\localsystem"
            | "nt authority\\system"
            | "nt authority\\localsystem"
            | "system"
    )
}

/// The account's structural rule, rejected with `InvalidSpec` before any
/// side effect. A `Named` account name: non-empty, no control
/// characters, no leading/trailing whitespace, at most one `\` (interior
/// spaces are fine — `NT SERVICE\x`, `NT AUTHORITY\LocalService`); not a
/// LocalSystem spelling; a password only for non-`NT` accounts, without
/// control characters.
pub(crate) fn validate_account(account: &WindowsServiceAccount) -> Result<(), ServiceError> {
    let WindowsServiceAccount::Named {
        account_name,
        account_password,
    } = account
    else {
        return Ok(());
    };
    let name_ok = !account_name.is_empty()
        && !account_name.chars().any(char::is_control)
        && account_name.trim() == account_name
        && account_name.matches('\\').count() <= 1
        && !account_name.ends_with('\\')
        && !account_name.starts_with('\\');
    if !name_ok {
        return Err(ServiceError::InvalidSpec(format!(
            "windows account name {account_name:?} is not valid (non-empty, no control characters, no leading/trailing whitespace, at most one '\\')"
        )));
    }
    if is_local_system_spelling(account_name) {
        return Err(ServiceError::InvalidSpec(format!(
            "windows account name {account_name:?} names LocalSystem; use the explicit WindowsServiceAccount::LocalSystem opt-in (root-equivalent — prefer the Virtual default)"
        )));
    }
    if let Some(password) = account_password {
        let upper = account_name.to_ascii_uppercase();
        if upper.starts_with("NT SERVICE\\") || upper.starts_with("NT AUTHORITY\\") {
            return Err(ServiceError::InvalidSpec(format!(
                "windows account {account_name:?} is passwordless; leave account_password None"
            )));
        }
        if password.chars().any(char::is_control) {
            return Err(ServiceError::InvalidSpec(
                "windows account password must not contain control characters".to_owned(),
            ));
        }
    }
    Ok(())
}

/// The SCM account name for `account` (`None` = LocalSystem, the SCM API's
/// spelling of it).
pub(crate) fn scm_account_name(
    account: &WindowsServiceAccount,
    service_name: &str,
) -> Option<String> {
    match account {
        WindowsServiceAccount::Virtual => Some(format!("NT SERVICE\\{service_name}")),
        WindowsServiceAccount::LocalService => Some("NT AUTHORITY\\LocalService".to_owned()),
        WindowsServiceAccount::NetworkService => Some("NT AUTHORITY\\NetworkService".to_owned()),
        WindowsServiceAccount::LocalSystem => None,
        WindowsServiceAccount::Named { account_name, .. } => Some(account_name.clone()),
    }
}

/// The SDDL alias for the well-known accounts (no lookup needed).
pub(crate) fn well_known_account_sid(account: &WindowsServiceAccount) -> Option<&'static str> {
    match account {
        WindowsServiceAccount::LocalService => Some("LS"),
        WindowsServiceAccount::NetworkService => Some("NS"),
        WindowsServiceAccount::LocalSystem => Some("SY"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DACL builder

/// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`.
const READ_EXECUTE: &str = "0x1200a9";
/// Modify: read/execute/write/delete, no `WRITE_DAC`/`WRITE_OWNER`.
const MODIFY: &str = "0x1301bf";

/// The protected, admin-only DACL every DACL below starts from: SYSTEM and
/// Administrators full control, inherited by what the directory holds.
pub(crate) fn created_dir_sddl() -> String {
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned()
}

/// The protected DACL of the program directory: SYSTEM + Administrators
/// full, the service account read + execute. `account_sid` is an SDDL SID
/// string or alias (`None` for LocalSystem, already covered by SYSTEM).
pub(crate) fn install_dir_sddl(account_sid: Option<&str>) -> String {
    let mut sddl = created_dir_sddl();
    if let Some(sid) = account_sid.filter(|sid| *sid != "SY") {
        sddl.push_str(&format!("(A;OICI;{READ_EXECUTE};;;{sid})"));
    }
    sddl
}

/// The security descriptor of a packaged directory under `%ProgramData%`:
/// owner SYSTEM (`O:SY`), and a protected DACL of SYSTEM + Administrators
/// full and OWNER RIGHTS read-control only (`OW`, inherited). ProgramData
/// lets any user create a directory, so one can exist, owned by that user,
/// before the installer applies this. The installer takes the owner back
/// (an untrusted owner would make the update helper refuse its
/// staging directory, and the service its state, a denial of service), and
/// the OWNER RIGHTS entry strips an owner's implicit `WRITE_DAC` in any
/// case, so a squatter can't re-grant themselves anything, on the directory
/// or on anything planted inside it.
pub(crate) fn programdata_dir_sddl() -> String {
    format!("O:SY{}(A;OICI;RC;;;OW)", created_dir_sddl())
}

/// The protected DACL of a packaged service's state directory: the
/// [`programdata_dir_sddl`] rules, plus the service account Modify (never
/// `WRITE_DAC` or `WRITE_OWNER`). `account_sid` as [`install_dir_sddl`].
pub(crate) fn state_dir_sddl(account_sid: Option<&str>) -> String {
    let mut sddl = programdata_dir_sddl();
    if let Some(sid) = account_sid.filter(|sid| *sid != "SY") {
        sddl.push_str(&format!("(A;OICI;{MODIFY};;;{sid})"));
    }
    sddl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_accounts_are_accepted() {
        for good in [
            "NT SERVICE\\acme-demo",
            "NT AUTHORITY\\NetworkService",
            "NT AUTHORITY\\LocalService",
            "EXAMPLE\\svc-acme",
            ".\\svc-acme",
            "svc@example.com",
        ] {
            let account = WindowsServiceAccount::Named {
                account_name: good.to_owned(),
                account_password: None,
            };
            assert!(validate_account(&account).is_ok(), "{good:?} must pass");
        }
        for variant in [
            WindowsServiceAccount::Virtual,
            WindowsServiceAccount::LocalService,
            WindowsServiceAccount::NetworkService,
            WindowsServiceAccount::LocalSystem,
        ] {
            assert!(validate_account(&variant).is_ok());
        }
    }

    #[test]
    fn malformed_accounts_are_refused() {
        for bad in [
            "",
            " NT SERVICE\\x",
            "NT SERVICE\\x ",
            "svc\nacme",
            "svc\tacme",
            "svc\u{0}",
            "A\\B\\C",
            "\\x",
            "x\\",
            // LocalSystem goes through the explicit opt-in only.
            "LocalSystem",
            "NT AUTHORITY\\SYSTEM",
            ".\\LocalSystem",
        ] {
            let account = WindowsServiceAccount::Named {
                account_name: bad.to_owned(),
                account_password: None,
            };
            assert!(
                matches!(
                    validate_account(&account),
                    Err(ServiceError::InvalidSpec(_))
                ),
                "{bad:?} must be refused"
            );
        }
        let passworded_virtual = WindowsServiceAccount::Named {
            account_name: "NT SERVICE\\x".to_owned(),
            account_password: Some("pw".to_owned().into()),
        };
        assert!(validate_account(&passworded_virtual).is_err());
        let control_password = WindowsServiceAccount::Named {
            account_name: "EXAMPLE\\svc".to_owned(),
            account_password: Some("p@ss\nword".to_owned().into()),
        };
        assert!(validate_account(&control_password).is_err());
    }

    #[test]
    fn the_default_account_is_the_virtual_account() {
        let account = WindowsServiceAccount::default();
        assert!(matches!(account, WindowsServiceAccount::Virtual));
        assert_eq!(
            scm_account_name(&account, "acme-demo").as_deref(),
            Some("NT SERVICE\\acme-demo")
        );
        assert_eq!(
            scm_account_name(&WindowsServiceAccount::LocalSystem, "x"),
            None
        );
    }

    #[test]
    fn the_password_is_redacted_from_debug() {
        let account = WindowsServiceAccount::Named {
            account_name: "EXAMPLE\\svc-acme".to_owned(),
            account_password: Some("super-secret".to_owned().into()),
        };
        let debug = format!("{account:?}");
        assert!(
            debug.contains("svc-acme") && !debug.contains("super-secret"),
            "{debug}"
        );
    }

    #[test]
    fn percent_and_control_characters_are_refused() {
        assert!(validate_arguments([Some("run"), Some("--flag=%PATH%")]).is_err());
        assert!(validate_arguments([Some("a\u{0}b")]).is_err());
        assert!(validate_arguments([None]).is_err());
        assert!(validate_arguments([Some("run"), Some("--x=100 percent")]).is_ok());
        assert!(validate_text("description", "Demo\r\nInjected").is_err());
        assert!(validate_text("description", "Demo daemon").is_ok());
    }

    #[test]
    fn an_empty_windows_restart_policy_is_refused() {
        let policy = FailurePolicy {
            reset_period: Duration::from_secs(3600),
            restart_delays: vec![],
        };
        assert!(validate_failure_policy(&policy).is_err());
        assert!(validate_failure_policy(&FailurePolicy::default()).is_ok());
    }

    // ---- the DACLs the MSI applies ----

    #[test]
    fn the_program_dacl_is_protected_and_admin_only_writable() {
        for sid in [Some("S-1-5-80-1-2-3-4-5"), Some("NS"), None] {
            let sddl = install_dir_sddl(sid);
            assert!(sddl.starts_with("D:P("), "protected: {sddl}");
            // No ACE at all for Authenticated Users / Users / Everyone /
            // interactive users.
            for untrusted in ["AU", "BU", "WD", "IU"] {
                assert!(!sddl.contains(&format!(";;;{untrusted})")), "{sddl}");
            }
        }
        assert!(install_dir_sddl(Some("NS")).contains("(A;OICI;0x1200a9;;;NS)"));
        assert!(
            !install_dir_sddl(Some("NS")).contains("0x1301bf"),
            "never Modify"
        );
        assert_eq!(install_dir_sddl(Some("SY")), created_dir_sddl());
    }

    #[test]
    fn the_programdata_dacls_strip_a_squatting_owner_and_grant_state_only() {
        // The owner taken back from a user who created it first.
        assert_eq!(
            programdata_dir_sddl(),
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)"
        );
        let state = state_dir_sddl(Some("S-1-5-80-1-2-3-4-5"));
        assert!(state.starts_with(&programdata_dir_sddl()), "{state}");
        assert!(
            state.ends_with("(A;OICI;0x1301bf;;;S-1-5-80-1-2-3-4-5)"),
            "{state}"
        );
        assert_eq!(state_dir_sddl(Some("SY")), programdata_dir_sddl());
    }
}
