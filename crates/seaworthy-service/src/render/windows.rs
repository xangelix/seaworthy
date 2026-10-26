//! The Windows side of [`ServiceSpec`], as data an installer applies: the
//! service record behind an MSI's `ServiceInstall`, `ServiceControl` and
//! `MsiServiceConfigFailureActions` rows, the account it runs as and that
//! account's SID, and the SDDL for the program directory and the update
//! helper service. The seaworthy CLI turns these into a `.wxs`; nothing
//! here touches Windows, so it all renders and tests on Linux.
//!
//! The rules are the Windows backend's own (`windows_policy`, shared with
//! the runtime's SCM backend):
//! validation, account naming, and the directory DACL. A service never
//! writes its own program directory, so it grants its account read and
//! execute only.

use std::time::Duration;

use crate::{
    FailurePolicy, ServiceError, ServiceSpec, WindowsServiceAccount,
    render::windows_policy::{
        install_dir_sddl, programdata_dir_sddl, scm_account_name, state_dir_sddl as state_sddl,
        validate_account, validate_arguments, validate_failure_policy, validate_text,
        well_known_account_sid,
    },
};

/// The service record an MSI installs: one `ServiceInstall` row plus its
/// failure actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    /// The service name (`ServiceInstall.Name`).
    pub name: String,
    /// The display name (`ServiceInstall.DisplayName`).
    pub display_name: String,
    /// The description (`ServiceInstall.Description`).
    pub description: String,
    /// The account (`ServiceInstall.StartName`): `LocalSystem`,
    /// `NT SERVICE\<name>`, `NT AUTHORITY\LocalService`,
    /// `NT AUTHORITY\NetworkService`, or a passwordless named account.
    pub account: String,
    /// The account's SID: an SDDL alias (`SY`, `LS`, `NS`) or a computed
    /// `S-1-5-80-…` for a virtual account; `None` for a named account,
    /// whose SID only the target machine can resolve.
    pub account_sid: Option<String>,
    /// The arguments, quoted into one command-line string by the rules
    /// every MSVC-built program parses with (`ServiceInstall.Arguments`;
    /// the program path stays in its own column, so the Code 5 trap stays
    /// impossible).
    pub arguments: String,
    /// The failure actions.
    pub failure_actions: FailureActions,
}

/// `MsiServiceConfigFailureActions`, plus the flag that makes them apply to
/// non-crash failures too (`MsiServiceConfig`,
/// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureActions {
    /// Seconds of stable uptime after which the failure count resets.
    pub reset_period_secs: u32,
    /// One restart delay per failure, in milliseconds; the SCM repeats the
    /// last one for every further failure.
    pub restart_delays_ms: Vec<u32>,
    /// Apply the actions when the service stops with a non-zero exit code,
    /// not only when it crashes. Always `true`: a fatal exit
    /// (the run loop's `EXIT_CODE_FATAL`, a service-specific 1) must
    /// restart.
    pub on_non_crash_failures: bool,
}

/// The well-known SID string of a virtual account, `NT SERVICE\<name>`:
/// `S-1-5-80-` followed by the SHA-1 of the upper-cased name, encoded as
/// UTF-16LE, read as five little-endian 32-bit values. Windows derives it
/// from the name alone, so an MSI can grant the account access to a
/// directory before the service exists.
///
/// Only ASCII names are accepted. Windows upper-cases with its own
/// per-code-unit table, which no portable function reproduces exactly for
/// every non-ASCII character.
///
/// # Errors
/// [`ServiceError::InvalidName`] for an empty or non-ASCII name.
pub fn virtual_account_sid(service_name: &str) -> Result<String, ServiceError> {
    if service_name.is_empty() || !service_name.is_ascii() {
        return Err(ServiceError::InvalidName(format!(
            "{service_name:?}: a virtual account's SID is computed only for non-empty ASCII service names"
        )));
    }
    let utf16: Vec<u8> = service_name
        .to_ascii_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    #[allow(
        clippy::disallowed_methods,
        reason = "Windows defines the virtual-account SID as SHA-1 of the name; an identifier, not an integrity check: the sanctioned call site"
    )]
    let hash = seaworthy_crypto::digest::sha1_for_identifiers(&utf16);
    let mut sid = String::from("S-1-5-80");
    for word in hash.as_chunks::<4>().0 {
        sid.push_str(&format!("-{}", u32::from_le_bytes(*word)));
    }
    Ok(sid)
}

/// The account `spec` runs as, as `ServiceInstall.StartName` spells it
/// (`LocalSystem` for LocalSystem).
///
/// # Errors
/// As [`service_record`].
pub fn account_name(spec: &ServiceSpec) -> Result<String, ServiceError> {
    validate_account(&spec.windows_account)?;
    Ok(scm_account_name(&spec.windows_account, &spec.name)
        .unwrap_or_else(|| "LocalSystem".to_owned()))
}

/// The SID of the account `spec` runs as: an SDDL alias for the built-in
/// accounts, the computed SID for a virtual account, `None` for a named
/// account.
///
/// # Errors
/// As [`virtual_account_sid`] for a virtual account.
pub fn account_sid(spec: &ServiceSpec) -> Result<Option<String>, ServiceError> {
    if let Some(alias) = well_known_account_sid(&spec.windows_account) {
        return Ok(Some(alias.to_owned()));
    }
    match &spec.windows_account {
        WindowsServiceAccount::Virtual => virtual_account_sid(&spec.name).map(Some),
        _ => Ok(None),
    }
}

/// Validates `spec` for an MSI and returns its service record.
///
/// # Errors
/// [`ServiceError::InvalidName`] / [`ServiceError::InvalidSpec`]: the
/// Windows backend's rules (no control characters, no `%` in the command
/// line, a valid account, a failure policy of delays of 1 s or more), plus
/// two packaging rules:
///
/// - no `[` or `]` anywhere in the record: `ServiceInstall`'s columns are
///   MSI *Formatted* strings, where `[PROPERTY]` expands and `[~]` inserts
///   a NUL;
/// - no named account with a password (an MSI would carry it in a
///   property).
pub fn service_record(spec: &ServiceSpec) -> Result<ServiceRecord, ServiceError> {
    validate_name(&spec.name)?;
    validate_text("display_name", &spec.display_name)?;
    validate_text("description", &spec.description)?;
    validate_arguments(spec.arguments.iter().map(|argument| argument.to_str()))?;
    validate_account(&spec.windows_account)?;
    validate_failure_policy(&spec.failure_policy)?;
    if let WindowsServiceAccount::Named {
        account_password: Some(_),
        ..
    } = &spec.windows_account
    {
        return Err(ServiceError::InvalidSpec(
            "a named account with a password can't be packaged: an MSI would carry the password in a property; use a virtual account, or LocalService/NetworkService/LocalSystem".to_owned(),
        ));
    }
    let mut arguments = Vec::with_capacity(spec.arguments.len());
    for argument in &spec.arguments {
        let text = argument.to_str().ok_or_else(|| {
            ServiceError::InvalidSpec(format!("argument {argument:?} is not valid UTF-8"))
        })?;
        arguments.push(quote_argument(text));
    }
    let record = ServiceRecord {
        name: spec.name.clone(),
        display_name: spec.display_name.clone(),
        description: spec.description.clone(),
        account: account_name(spec)?,
        account_sid: account_sid(spec)?,
        arguments: arguments.join(" "),
        failure_actions: failure_actions(&spec.failure_policy)?,
    };
    for (field, value) in [
        ("name", &record.name),
        ("display_name", &record.display_name),
        ("description", &record.description),
        ("account", &record.account),
        ("arguments", &record.arguments),
    ] {
        if value.contains(['[', ']']) {
            return Err(ServiceError::InvalidSpec(format!(
                "{field} {value:?} contains '[' or ']': MSI expands [PROPERTY] in ServiceInstall's columns"
            )));
        }
    }
    Ok(record)
}

/// The failure actions for `policy`, in the units the SCM takes.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for an empty policy (the SCM can't tell
/// an update exit from a failure, so "never restart" would strand every
/// update), or a delay or reset period beyond the SCM's 32-bit fields.
pub fn failure_actions(policy: &FailurePolicy) -> Result<FailureActions, ServiceError> {
    validate_failure_policy(policy)?;
    let millis = |delay: &Duration| {
        u32::try_from(delay.as_millis()).map_err(|_| {
            ServiceError::InvalidSpec(format!(
                "restart delay {delay:?} exceeds the SCM's 32-bit millisecond field"
            ))
        })
    };
    let restart_delays_ms = policy
        .restart_delays
        .iter()
        .map(millis)
        .collect::<Result<Vec<_>, _>>()?;
    let reset_period_secs = u32::try_from(policy.reset_period.as_secs()).map_err(|_| {
        ServiceError::InvalidSpec(format!(
            "reset period {:?} exceeds the SCM's 32-bit seconds field",
            policy.reset_period
        ))
    })?;
    Ok(FailureActions {
        reset_period_secs,
        restart_delays_ms,
        on_non_crash_failures: true,
    })
}

/// The protected DACL of a packaged program directory: SYSTEM and
/// Administrators full control, the service's account read and execute
/// (nothing for LocalSystem, already covered by SYSTEM).
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for a named account: its SID can only be
/// resolved on the target machine, and an MSI's `MsiLockPermissionsEx`
/// takes SDDL. As [`virtual_account_sid`] otherwise.
pub fn program_dir_sddl(spec: &ServiceSpec) -> Result<String, ServiceError> {
    let sid = account_sid(spec)?;
    if sid.is_none() && !matches!(spec.windows_account, WindowsServiceAccount::LocalSystem) {
        return Err(ServiceError::InvalidSpec(
            "a named account's SID can't be computed at packaging time; grant its directory access with a virtual or built-in account".to_owned(),
        ));
    }
    Ok(install_dir_sddl(sid.as_deref()))
}

/// The security descriptor of a packaged service's state directory
/// (`%ProgramData%\<Vendor>\<Product>\state`):
/// owner SYSTEM, SYSTEM and Administrators full control, the service's account Modify
/// (read, write, create, delete; never the DACL or owner), and OWNER
/// RIGHTS read-control only (see [`data_dir_sddl`]). For LocalSystem the
/// SYSTEM entry already covers the account.
///
/// # Errors
/// As [`program_dir_sddl`]: a named account's SID can't be computed at
/// packaging time.
pub fn state_dir_sddl(spec: &ServiceSpec) -> Result<String, ServiceError> {
    let sid = account_sid(spec)?;
    if sid.is_none() && !matches!(spec.windows_account, WindowsServiceAccount::LocalSystem) {
        return Err(ServiceError::InvalidSpec(
            "a named account's SID can't be computed at packaging time; grant its state directory with a virtual or built-in account".to_owned(),
        ));
    }
    Ok(state_sddl(sid.as_deref()))
}

/// The security descriptor of the update helper's staging directory
/// (`%ProgramData%\<Vendor>\<Product>\updates`): owner SYSTEM,
/// SYSTEM and Administrators only, plus OWNER RIGHTS read-control (see
/// [`data_dir_sddl`]). The helper runs as LocalSystem; nothing else, the
/// product's own service included, may plant or swap a staged release.
#[must_use]
pub fn updates_dir_sddl() -> String {
    programdata_dir_sddl()
}

/// The security descriptor of the update helper's log directory
/// (`%ProgramData%\<Vendor>\<Product>\update-logs`), as
/// [`updates_dir_sddl`]: SYSTEM and Administrators only. The helper writes
/// its log as LocalSystem, so no other account, the service's included,
/// may create, replace or link anything there (the service's own logs are
/// in `logs`, which its account may modify).
#[must_use]
pub fn helper_log_dir_sddl() -> String {
    programdata_dir_sddl()
}

/// The security descriptor of the packaged directories above `state` and
/// `updates` (`%ProgramData%\<Vendor>` and `…\<Product>`): owner SYSTEM
/// (`O:SY`), and a protected DACL of SYSTEM and Administrators full
/// control and OWNER RIGHTS read-control only (`(A;OICI;RC;;;OW)`).
///
/// `%ProgramData%` lets any user create a directory there, so a user can
/// create one of these, and fill it, before the product is installed. A
/// lock on a folder doesn't reach a child with its own protected DACL
/// (its owner and grants survive), and an installer working by path
/// follows a junction put in a folder's place, so the seaworthy CLI's MSI
/// applies these descriptors through the launcher's guard, by handle: it
/// takes each folder back (owner SYSTEM, this DACL), refuses the install
/// when anything below the product's folder is a reparse point or owned
/// or writable by anyone else, and only then propagates. The OWNER RIGHTS
/// entry strips an owner's implicit `WRITE_DAC`, so whoever owns a folder
/// can't re-grant themselves anything. At run time the update helper
/// audits its staging and log directories, and a service its state
/// directory (seaworthy-service's runtime), refusing what isn't trusted.
#[must_use]
pub fn data_dir_sddl() -> String {
    programdata_dir_sddl()
}

/// Who may start the update helper service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperGrantee {
    /// A service product: the main service's account, its own SID — a
    /// virtual account's `S-1-5-80-…`, or `SY` for LocalSystem (where the
    /// grant adds nothing, since SYSTEM may already start any service, but
    /// keeps one code path). Never a shared account (`LS`, `NS`): every
    /// service running as LocalService or NetworkService would get the
    /// right too.
    Service(String),
    /// A desktop product: interactive users (`IU`), since the app runs as
    /// whoever is logged in.
    InteractiveUsers,
}

/// The update helper service's DACL (`MsiLockPermissionsEx` on its
/// `ServiceInstall` row). SYSTEM and Administrators get Windows' default
/// service rights. The grantee gets query config and status, enumerate
/// dependents, **start**, interrogate and read control. It never gets stop,
/// pause, reconfigure, delete or custom controls. The helper takes no input,
/// so starting it can only make the machine install the release the server
/// names.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for a service grantee that is neither
/// LocalSystem (`SY`) nor a virtual account's
/// `S-1-5-80-<five 32-bit numbers>`. The shared service accounts (`LS`,
/// `NS`) are refused: their SID is every LocalService or NetworkService
/// service's, so the grant would let any of them start the helper. Broad
/// principals (`WD`, `BU`, `AU`, `AN`, …) are never granted the start
/// right through this path.
pub fn helper_service_sddl(grantee: &HelperGrantee) -> Result<String, ServiceError> {
    let who = match grantee {
        HelperGrantee::InteractiveUsers => "IU",
        HelperGrantee::Service(sid) if matches!(sid.as_str(), "LS" | "NS") => {
            return Err(ServiceError::InvalidSpec(format!(
                "{sid:?} is a shared service account (every LocalService or NetworkService service runs as it): granting it the helper's start right would grant every such service; run the service as its virtual account"
            )));
        }
        HelperGrantee::Service(sid) => {
            let builtin = sid == "SY";
            let virtual_account = sid.strip_prefix("S-1-5-80-").is_some_and(|rest| {
                let parts: Vec<&str> = rest.split('-').collect();
                parts.len() == 5
                    && parts.iter().all(|p| {
                        !p.is_empty()
                            && p.bytes().all(|b| b.is_ascii_digit())
                            && p.parse::<u32>().is_ok()
                    })
            });
            if !(builtin || virtual_account) {
                return Err(ServiceError::InvalidSpec(format!(
                    "{sid:?} is not a service's own account (SY, or a virtual account's S-1-5-80-… SID)"
                )));
            }
            sid.as_str()
        }
    };
    Ok(format!(
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLORC;;;{who})"
    ))
}

/// The service-name rule shared with every backend (ASCII letter or digit
/// first; no whitespace, control characters, path separators or `%`).
fn validate_name(name: &str) -> Result<(), ServiceError> {
    if crate::render::is_safe_service_name(name) {
        Ok(())
    } else {
        Err(ServiceError::InvalidName(format!(
            "{name:?} is not a valid service name (ASCII letter or digit first; no whitespace, control characters, path separators or '%')"
        )))
    }
}

/// One argument quoted for a Windows command line, by the rules the MSVC
/// runtime (and Rust's `std::env::args`) parse with: wrapped in quotes when
/// it is empty or holds whitespace or a quote; a quote escaped with a
/// backslash; backslashes doubled only where they precede a quote.
#[must_use]
pub fn quote_argument(argument: &str) -> String {
    if !argument.is_empty() && !argument.chars().any(|c| c.is_whitespace() || c == '"') {
        return argument.to_owned();
    }
    let mut quoted = String::with_capacity(argument.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for c in argument.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', 2 * backslashes + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.extend(std::iter::repeat_n('\\', backslashes));
                quoted.push(c);
                backslashes = 0;
            }
        }
    }
    quoted.extend(std::iter::repeat_n('\\', 2 * backslashes));
    quoted.push('"');
    quoted
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::ffi::OsString;

    use super::*;
    use crate::SystemdHardening;

    fn spec(account: WindowsServiceAccount) -> ServiceSpec {
        ServiceSpec {
            name: "AcmeLiveResponseService".to_owned(),
            display_name: "Acme Live Response".to_owned(),
            description: "Collects forensic data".to_owned(),
            program: "C:\\Program Files\\Acme\\Collector\\AcmeForensicCollector.exe".into(),
            arguments: vec![OsString::from("service"), OsString::from("--state dir")],
            environment_files: vec![],
            open_files_limit: None,
            failure_policy: FailurePolicy::default(),
            unix_identity: crate::UnixIdentity::Unspecified,
            systemd_hardening: SystemdHardening::none(),
            windows_account: account,
            state_directory: None,
        }
    }

    #[test]
    fn virtual_account_sids_match_windows() {
        // Windows' own: `sc showsid TrustedInstaller`.
        assert_eq!(
            virtual_account_sid("TrustedInstaller").unwrap(),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        // Case-insensitive, as service names are.
        assert_eq!(
            virtual_account_sid("trustedinstaller").unwrap(),
            virtual_account_sid("TrustedInstaller").unwrap()
        );
        assert!(virtual_account_sid("").is_err());
        assert!(virtual_account_sid("Dienst-ä").is_err());
    }

    #[test]
    fn the_service_record_carries_account_arguments_and_failure_actions() {
        let record = service_record(&spec(WindowsServiceAccount::LocalSystem)).unwrap();
        assert_eq!(record.account, "LocalSystem");
        assert_eq!(record.account_sid.as_deref(), Some("SY"));
        assert_eq!(record.arguments, "service \"--state dir\"");
        let defaults = FailurePolicy::default();
        assert_eq!(
            record.failure_actions.restart_delays_ms.len(),
            defaults.restart_delays.len()
        );
        assert!(record.failure_actions.on_non_crash_failures);

        let record = service_record(&spec(WindowsServiceAccount::Virtual)).unwrap();
        assert_eq!(record.account, "NT SERVICE\\AcmeLiveResponseService");
        assert_eq!(
            record.account_sid,
            Some(virtual_account_sid("AcmeLiveResponseService").unwrap())
        );
        assert_eq!(
            service_record(&spec(WindowsServiceAccount::NetworkService))
                .unwrap()
                .account,
            "NT AUTHORITY\\NetworkService"
        );
    }

    #[test]
    fn packaging_refuses_passwords_percent_and_empty_policies() {
        let s = spec(WindowsServiceAccount::Named {
            account_name: ".\\svcuser".to_owned(),
            account_password: Some(zeroize::Zeroizing::new("hunter2".to_owned())),
        });
        let err = service_record(&s).unwrap_err().to_string();
        assert!(!err.contains("hunter2"), "{err}");

        let mut s = spec(WindowsServiceAccount::Virtual);
        s.arguments = vec![OsString::from("%TEMP%")];
        assert!(service_record(&s).is_err());

        let mut s = spec(WindowsServiceAccount::Virtual);
        s.failure_policy.restart_delays.clear();
        assert!(service_record(&s).is_err());

        let mut s = spec(WindowsServiceAccount::Virtual);
        s.name = "bad name".to_owned();
        assert!(service_record(&s).is_err());

        // MSI Formatted strings: [PROPERTY] would expand, [~] is a NUL.
        for field in 0..3 {
            let mut s = spec(WindowsServiceAccount::Virtual);
            match field {
                0 => s.display_name = "Collector [ProductVersion]".to_owned(),
                1 => s.description = "a [~] b".to_owned(),
                _ => s.arguments = vec![OsString::from("[INSTALLDIR]")],
            }
            let err = service_record(&s).unwrap_err().to_string();
            assert!(err.contains("'[' or ']'"), "{err}");
        }

        // A sub-second restart delay is a hot loop under the SCM.
        let mut s = spec(WindowsServiceAccount::Virtual);
        s.failure_policy.restart_delays = vec![std::time::Duration::ZERO];
        assert!(service_record(&s).is_err());
        s.failure_policy.restart_delays = vec![std::time::Duration::from_millis(999)];
        assert!(service_record(&s).is_err());
    }

    #[test]
    fn the_program_directory_grants_the_account_read_and_execute_only() {
        let sddl = program_dir_sddl(&spec(WindowsServiceAccount::Virtual)).unwrap();
        let sid = virtual_account_sid("AcmeLiveResponseService").unwrap();
        assert_eq!(
            sddl,
            format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{sid})")
        );
        assert_eq!(
            program_dir_sddl(&spec(WindowsServiceAccount::LocalSystem)).unwrap(),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        );
        let named = spec(WindowsServiceAccount::Named {
            account_name: ".\\svc".to_owned(),
            account_password: None,
        });
        assert!(program_dir_sddl(&named).is_err());
    }

    #[test]
    fn the_state_directory_grants_the_account_modify_and_staging_admits_no_one_else() {
        let sid = virtual_account_sid("AcmeLiveResponseService").unwrap();
        assert_eq!(
            state_dir_sddl(&spec(WindowsServiceAccount::Virtual)).unwrap(),
            format!(
                "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)(A;OICI;0x1301bf;;;{sid})"
            )
        );
        assert_eq!(
            state_dir_sddl(&spec(WindowsServiceAccount::LocalService)).unwrap(),
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)(A;OICI;0x1301bf;;;LS)"
        );
        assert_eq!(
            state_dir_sddl(&spec(WindowsServiceAccount::LocalSystem)).unwrap(),
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)"
        );
        let named = spec(WindowsServiceAccount::Named {
            account_name: ".\\svc".to_owned(),
            account_password: None,
        });
        assert!(state_dir_sddl(&named).is_err());
        // ProgramData directories: owned by SYSTEM (taken back from a user
        // who created one first), protected, admins only, and OWNER
        // RIGHTS read-control, which strips an owner's implicit WRITE_DAC.
        assert_eq!(
            updates_dir_sddl(),
            "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)"
        );
        assert_eq!(data_dir_sddl(), updates_dir_sddl());
        for sddl in [
            updates_dir_sddl(),
            state_dir_sddl(&spec(WindowsServiceAccount::Virtual)).unwrap(),
        ] {
            assert!(
                !sddl.contains(";BU)") && !sddl.contains(";WD)") && !sddl.contains(";AU)"),
                "{sddl}"
            );
        }
    }

    #[test]
    fn the_helper_grants_start_never_stop_or_reconfigure() {
        let iu = helper_service_sddl(&HelperGrantee::InteractiveUsers).unwrap();
        assert!(iu.ends_with("(A;;CCLCSWRPLORC;;;IU)"), "{iu}");
        let ace = iu.rsplit('(').next().unwrap();
        for forbidden in ["WP", "DT", "DC", "SD", "WD", "WO", "CR"] {
            assert!(!ace.contains(forbidden), "{forbidden} in {ace}");
        }
        let svc =
            helper_service_sddl(&HelperGrantee::Service("S-1-5-80-1-2-3-4-5".to_owned())).unwrap();
        assert!(svc.ends_with("(A;;CCLCSWRPLORC;;;S-1-5-80-1-2-3-4-5)"));
        assert!(helper_service_sddl(&HelperGrantee::Service("SY".to_owned())).is_ok());
        // The shared service accounts: every LocalService or NetworkService
        // service would get the start right.
        for shared in ["LS", "NS"] {
            let err = helper_service_sddl(&HelperGrantee::Service(shared.to_owned()))
                .unwrap_err()
                .to_string();
            assert!(err.contains("shared service account"), "{shared}: {err}");
        }
        let computed = virtual_account_sid("AcmeLiveResponseService").unwrap();
        assert!(helper_service_sddl(&HelperGrantee::Service(computed)).is_ok());
        for bad in [
            "",
            "S-1-",
            "WD)(A;;GA;;;WD",
            "sy",
            "S-1-5-x",
            "WD",
            "BU",
            "AU",
            "AN",
            "BA",
            "S-1-5--",
            "S-1-5-80-1-2-3-4",
            "S-1-5-80-1-2-3-4-5-6",
            "S-1-5-21-1-2-3-4-5",
            "S-1-5-80-99999999999-1-2-3-4",
        ] {
            assert!(
                helper_service_sddl(&HelperGrantee::Service(bad.to_owned())).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn arguments_quote_like_the_msvc_runtime_parses() {
        for (raw, quoted) in [
            ("plain", "plain"),
            ("with space", "\"with space\""),
            ("q\"uote", "\"q\\\"uote\""),
            ("trail\\ x\\", "\"trail\\ x\\\\\""),
            ("a\\\"b", "\"a\\\\\\\"b\""),
            ("", "\"\""),
            ("C:\\Program Files\\x", "\"C:\\Program Files\\x\""),
            ("C:\\dir\\", "C:\\dir\\"),
        ] {
            assert_eq!(quote_argument(raw), quoted, "{raw}");
        }
    }
}
