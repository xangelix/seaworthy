//! The systemd side of [`ServiceSpec`]: the service unit, the update
//! helper's `.path` and `.service` units, and a sandbox user's
//! `sysusers.d` entry; and for a desktop product (no service), its update
//! helper's `.service` unit and the polkit rule that lets the logged-in
//! session start it. Pure text: a packaging tool (the seaworthy CLI) puts
//! the result in packages (under `/usr/lib/systemd/system`,
//! `/usr/lib/sysusers.d` and `/usr/share/polkit-1/rules.d`), and the
//! runtime's systemd backend drives the unit the package installed.
//!
//! Every value is validated before anything renders, and refused rather
//! than flattened: systemd parses these files as root.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};

use super::is_conservative_path;
use crate::{
    ServiceError, ServiceSpec, SystemdHardening, SystemdSandbox, render::is_safe_service_name,
};

// ---------------------------------------------------------------------------
// The public surface

/// Which systemd manager a unit is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The system manager (`/usr/lib/systemd/system`, `/etc/systemd/system`).
    System,
    /// A per-user manager (`systemctl --user`): no `User=`/`Group=`,
    /// `WantedBy=default.target`, `ProtectHome=read-only`.
    User,
}

/// The file name of `spec`'s service unit: `<name>.service`.
///
/// # Errors
/// [`ServiceError::InvalidName`] for a name that can't be a unit name.
pub fn unit_file_name(spec: &ServiceSpec) -> Result<String, ServiceError> {
    validate_unit_name(&spec.name)?;
    Ok(format!("{}.service", spec.name))
}

/// Validates everything the service unit renders from `spec`: the name,
/// the sandbox, and every text, path and policy value.
///
/// # Errors
/// [`ServiceError::InvalidName`] / [`ServiceError::InvalidSpec`] naming the
/// first refused value.
pub fn validate(spec: &ServiceSpec) -> Result<(), ServiceError> {
    validate_unit_name(&spec.name)?;
    if let Some(sandbox) = &spec.sandbox {
        validate_sandbox(sandbox)?;
    }
    validate_spec(spec)
}

/// `spec`'s service unit, for `scope`.
///
/// # Errors
/// As [`validate`].
pub fn unit(spec: &ServiceSpec, scope: Scope) -> Result<String, ServiceError> {
    validate_unit_name(&spec.name)?;
    render_unit(spec, scope == Scope::User)
}

/// The name of the update request file inside the service's state
/// directory. Writing it is the only thing the service can do to ask for an
/// update: `<name>-update.path` watches it and starts
/// `<name>-update.service`.
pub const UPDATE_REQUEST_FILE: &str = "update-request";

/// The update helper's path unit, `<name>-update.path`: it starts
/// `<name>-update.service` when the service writes
/// `/var/lib/<state_directory>/`[`UPDATE_REQUEST_FILE`]. System scope only:
/// the helper is a system unit, and a user manager's `StateDirectory=`
/// lives under `~/.local/state` instead.
///
/// No `TriggerLimit*=` beyond systemd's defaults (2 s / 200 triggers): when
/// a path unit hits its trigger limit, systemd FAILS it and it stops
/// watching. Package scripts never restart it (an upgrade must not kill
/// the helper that started it), so a strict limit
/// would switch updates off until a reboot. Repeated requests cost one
/// oneshot run each. The helper's failure memo is the backoff, and the
/// app debounces its requests.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] when `spec` has no `state_directory` (the
/// request file lives there), or any value [`validate`] refuses.
pub fn update_path_unit(spec: &ServiceSpec) -> Result<String, ServiceError> {
    validate(spec)?;
    let state = spec.state_directory.as_deref().ok_or_else(|| {
        ServiceError::InvalidSpec(format!(
            "service {:?} has no state_directory: the update request file lives there (set ServiceSpec::state_directory)",
            spec.name
        ))
    })?;
    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str(&format!(
        "Description={} update request\n",
        update_label(spec)?
    ));
    unit.push_str("\n[Path]\n");
    unit.push_str(&format!(
        "PathChanged=/var/lib/{state}/{UPDATE_REQUEST_FILE}\n"
    ));
    unit.push_str(&format!("Unit={}-update.service\n", spec.name));
    unit.push_str("\n[Install]\n");
    unit.push_str("WantedBy=multi-user.target\n");
    Ok(unit)
}

/// The update helper's sandbox (see [`update_service_unit`]).
const HELPER_SANDBOX: &[&str] = &[
    "NoNewPrivileges=true",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "PrivateTmp=true",
    "PrivateDevices=true",
    "ProtectKernelTunables=true",
    "ProtectKernelModules=true",
    "ProtectKernelLogs=true",
    "ProtectControlGroups=true",
    "ProtectClock=true",
    "ProtectHostname=true",
    "RestrictNamespaces=true",
    "RestrictRealtime=true",
    "RestrictSUIDSGID=true",
    "LockPersonality=true",
    "MemoryDenyWriteExecute=true",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
];

/// The update helper's service unit, `<name>-update.service`: a root
/// oneshot running `helper` with no arguments (the helper takes no input
/// from the service). It has no `[Install]` section: only the path unit
/// starts it. It has no start limit (`StartLimitIntervalSec=0`): a path
/// unit whose service hits one fails and stops watching, switching updates
/// off until a reboot, so the helper paces itself instead.
///
/// Package scripts never restart this unit or the path unit on upgrade.
/// The helper hands the package manager to a transient unit
/// (`systemd-run --wait --collect`), so the upgrade it starts can't kill it
/// mid-transaction. That transient unit is
/// started by PID 1 and inherits none of this unit's sandbox, so the
/// helper itself (a root process parsing network data) is sandboxed:
///
/// - the file system is read-only (`ProtectSystem=strict`) except its
///   root-only staging directory, `CacheDirectory=<cache_directory>`
///   (mode 0700: `/var/cache/<vendor>/<product>`);
/// - no home directories, devices, kernel tunables, modules, logs or
///   control groups; no new privileges; native system calls of the
///   `@system-service` set; IPv4, IPv6 and Unix sockets only.
///
/// Connecting to systemd's socket needs neither write access nor
/// capabilities, so `systemd-run` works under all of this.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for a `helper` path systemd would misread
/// (the `ExecStart` rule of [`ServiceSpec::program`]), a `cache_directory`
/// outside the [`ServiceSpec::state_directory`] grammar, or any value
/// [`validate`] refuses.
pub fn update_service_unit(
    spec: &ServiceSpec,
    helper: &Path,
    cache_directory: &str,
) -> Result<String, ServiceError> {
    validate(spec)?;
    helper_unit(&update_label(spec)?, helper, cache_directory)
}

/// A desktop product's update helper unit, `<package>-update.service`
/// ([`desktop_update_unit_name`]): the same root oneshot and sandbox as a
/// service's ([`update_service_unit`]), for a product with no service. No
/// path unit and no request file: the logged-in user's session starts it
/// through the polkit rule [`desktop_update_polkit_rule`] renders (the
/// Windows interactive-users grant's twin). It has no `[Install]`
/// section either, so nothing enables it and package scripts never start
/// it. `display_name` names it (`<display name> updater`), checked like a
/// description.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for an empty or unrenderable display name,
/// a `helper` path systemd would misread, or a `cache_directory` outside
/// the [`ServiceSpec::state_directory`] grammar.
pub fn desktop_update_service_unit(
    display_name: &str,
    helper: &Path,
    cache_directory: &str,
) -> Result<String, ServiceError> {
    if display_name.is_empty() {
        return Err(ServiceError::InvalidSpec(
            "a desktop product's update unit needs its display name".to_owned(),
        ));
    }
    validate_description(display_name)?;
    helper_unit(&display_name.replace('%', "%%"), helper, cache_directory)
}

/// A desktop product's update helper unit name, `<name>.service`, where
/// `name` is the helper's (seaworthy-updater's product names it
/// `<package>-update`). The name goes into a polkit rule's string literal
/// as well as a unit file name, so it is held to
/// `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 200 bytes.
///
/// # Errors
/// [`ServiceError::InvalidName`] for anything else.
pub fn desktop_update_unit_name(name: &str) -> Result<String, ServiceError> {
    let valid = name.len() <= 200
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(ServiceError::InvalidName(format!(
            "desktop update helper {name:?} must be [A-Za-z0-9][A-Za-z0-9._-]*, at most 200 bytes"
        )));
    }
    Ok(format!("{name}.service"))
}

/// The polkit rule letting the active local session start a desktop
/// product's update helper `unit` ([`desktop_update_unit_name`]'s), for
/// `/usr/share/polkit-1/rules.d/`: systemd asks polkit about
/// `org.freedesktop.systemd1.manage-units` with the unit and the verb as
/// details, and the rule answers yes for exactly that unit and `start`,
/// for a subject in an active, local session. Anything else — another
/// unit, `stop`, `restart`, an inactive or remote session, a process in no
/// session at all — returns nothing, which falls through to the rules after
/// it and to systemd's own policy (an administrator's authentication).
/// The helper takes no input, so the most a session can do with this is
/// have the machine install the release the product's server names.
///
/// An administrator's rule in `/etc/polkit-1/rules.d` that sorts earlier
/// overrides it (polkit runs rules in file-name order across both
/// directories, and the first answer wins). JavaScript rules need polkit
/// 0.106 or later: every distribution the seaworthy CLI targets has one (Debian
/// 12's polkitd 122 onwards, RHEL 9's 0.117); an older polkit (Ubuntu
/// 22.04's 0.105) ignores the file, and the request is refused.
///
/// # Errors
/// [`ServiceError::InvalidName`] for a unit outside
/// [`desktop_update_unit_name`]'s grammar, or a `package` outside the same
/// alphabet (`[A-Za-z0-9][A-Za-z0-9._-]*`, at most 200 bytes): the rule is
/// JavaScript, and a name in its comment must not be able to end the
/// comment (a line terminator: CR, LF, U+2028, U+2029) or carry anything
/// else a reader could mistake.
pub fn desktop_update_polkit_rule(package: &str, unit: &str) -> Result<String, ServiceError> {
    let stem = unit.strip_suffix(".service").unwrap_or_default();
    if desktop_update_unit_name(stem).ok().as_deref() != Some(unit) {
        return Err(ServiceError::InvalidName(format!(
            "desktop update unit {unit:?} must be <[A-Za-z0-9][A-Za-z0-9._-]*>.service"
        )));
    }
    if desktop_update_unit_name(package).is_err() {
        return Err(ServiceError::InvalidName(format!(
            "package {package:?} must be [A-Za-z0-9][A-Za-z0-9._-]*, at most 200 bytes (it is written into the polkit rule)"
        )));
    }
    Ok(format!(
        "// Generated by seaworthy: {package}'s update helper.\n\
         //\n\
         // The active local session may start {unit}, and nothing more: not\n\
         // stop or restart it, not any other unit. The helper takes no input,\n\
         // so the most a session can do is have the machine install the release\n\
         // the product's server names. Anything else falls through to the\n\
         // rules after this one.\n\
         polkit.addRule(function (action, subject) {{\n\
         \x20   if (action.id === \"org.freedesktop.systemd1.manage-units\" &&\n\
         \x20       action.lookup(\"unit\") === \"{unit}\" &&\n\
         \x20       action.lookup(\"verb\") === \"start\" &&\n\
         \x20       subject.local && subject.active) {{\n\
         \x20       return polkit.Result.YES;\n\
         \x20   }}\n\
         }});\n"
    ))
}

/// The helper oneshot both [`update_service_unit`] and
/// [`desktop_update_service_unit`] render, named by `label` (already
/// checked and `%`-escaped).
fn helper_unit(label: &str, helper: &Path, cache_directory: &str) -> Result<String, ServiceError> {
    validate_program_path(helper)?;
    validate_state_directory(Some(cache_directory)).map_err(|_| {
        ServiceError::InvalidSpec(format!(
            "cache directory {cache_directory:?} must be relative segments over [A-Za-z0-9._@+-] (resolved under /var/cache)"
        ))
    })?;
    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str(&format!("Description={label} updater\n"));
    unit.push_str("After=network-online.target\n");
    unit.push_str("Wants=network-online.target\n");
    // No start limit: when the path unit starts a service past its start
    // limit, the path unit fails and stops watching, which would switch
    // updates off until a reboot. The helper paces itself instead (a
    // minimum interval between runs, before any network I/O).
    unit.push_str("StartLimitIntervalSec=0\n");
    unit.push_str("\n[Service]\n");
    unit.push_str("Type=oneshot\n");
    unit.push_str(&format!(
        "ExecStart={}\n",
        escape_exec_token(helper.as_os_str())?
    ));
    // A package install can take minutes on a slow host; the helper's own
    // deadlines are shorter.
    unit.push_str("TimeoutStartSec=1800\n");
    unit.push_str(&format!("CacheDirectory={cache_directory}\n"));
    unit.push_str("CacheDirectoryMode=0700\n");
    unit.push_str("UMask=0077\n");
    for directive in HELPER_SANDBOX {
        unit.push_str(directive);
        unit.push('\n');
    }
    Ok(unit)
}

/// The `sysusers.d` entry creating `spec`'s sandbox user (and its group,
/// when it differs), for `/usr/lib/sysusers.d/<name>.conf`. `None` when the
/// unit has no sandbox, or runs as root with root's group: there is
/// nothing to create. A root user with another group gets only the group.
///
/// A user whose group differs is `u <user> -:<group> …` (sysusers.d(5):
/// the group goes in the ID field), after a `g <group> -` line.
///
/// # Errors
/// As [`validate`]; the display name (the GECOS field) is refused with a
/// `"`, `:`, `\` or a control character, since sysusers refuses or
/// rewrites those; `%` is escaped as `%%` (sysusers expands specifiers).
pub fn sysusers(spec: &ServiceSpec) -> Result<Option<String>, ServiceError> {
    validate(spec)?;
    let Some(sandbox) = &spec.sandbox else {
        return Ok(None);
    };
    if spec
        .display_name
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | ':' | '\\'))
    {
        return Err(ServiceError::InvalidSpec(format!(
            "display name {:?} cannot be a sysusers.d GECOS field (no '\"', ':', '\\' or control characters)",
            spec.display_name
        )));
    }
    let gecos = spec.display_name.replace('%', "%%");
    let mut text = format!(
        "# {} — the service's sandbox identity (generated by seaworthy)\n",
        spec.name
    );
    match (sandbox.user == "root", sandbox.group == sandbox.user) {
        (true, true) => return Ok(None),
        (true, false) => text.push_str(&format!("g {} -\n", sandbox.group)),
        (false, true) => text.push_str(&format!("u {} - \"{gecos}\" - -\n", sandbox.user)),
        (false, false) => {
            text.push_str(&format!("g {} -\n", sandbox.group));
            text.push_str(&format!(
                "u {} -:{} \"{gecos}\" - -\n",
                sandbox.user, sandbox.group
            ));
        }
    }
    Ok(Some(text))
}

// ---------------------------------------------------------------------------
// Names and values

/// A service name becomes a unit file name (a path under the unit
/// directory) and a `systemctl` argument: reject anything that could
/// escape the unit directory (`/`, `\`), inject a `systemctl` option
/// (leading `-`), break the line-based unit format (whitespace, control
/// characters), or ride specifier expansion (`%`). This is a rejection,
/// not a sanitization — the caller owns picking a clean name.
pub(crate) fn validate_unit_name(name: &str) -> Result<(), ServiceError> {
    // The shared rule, then systemd's own unit-name alphabet (`:`, `-`,
    // `_`, `.`; `@` is refused — it makes a template instance), so
    // `Unit=<name>-update.service` and the file names systemd loads are
    // names it accepts.
    if is_safe_service_name(name)
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.'))
    {
        return Ok(());
    }
    Err(ServiceError::InvalidName(format!(
        "{name:?} is not a valid systemd unit name (an ASCII letter or digit first, then [A-Za-z0-9:_.-], at most 200 bytes)"
    )))
}

/// Validate a sandbox's values with the same strictness as the unit name
/// (`user`/`group`) plus the capability alphabet (`[A-Za-z0-9_]+`), with
/// three extra user/group rules: `%` (specifier expansion — `"%u"` is root
/// for a system unit), bare numeric IDs (`"0"` is root), and a literal
/// `root` without `allow_root` are all refused.
pub(crate) fn validate_sandbox(sandbox: &SystemdSandbox) -> Result<(), ServiceError> {
    for (kind, value) in [("user", &sandbox.user), ("group", &sandbox.group)] {
        if !is_safe_service_name(value) {
            return Err(ServiceError::InvalidName(format!(
                "{value:?} is not a valid systemd {kind} name (must start with an ASCII letter or digit; no path separators, whitespace, control characters, '%' specifiers, or leading '-')"
            )));
        }
        // The portable name rule sysusers and every libc accept (bare
        // numbers fall through to the root check below).
        let portable = value.len() <= 31
            && value
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !portable && !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServiceError::InvalidName(format!(
                "{value:?} is not a portable {kind} name ([A-Za-z_][A-Za-z0-9_-]*, at most 31 bytes)"
            )));
        }
        if value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServiceError::InvalidName(format!(
                "{value:?} is not a valid systemd {kind} name: bare numeric IDs are not accepted ('0' is root); name the {kind}"
            )));
        }
        if value == "root" && !sandbox.allow_root {
            return Err(ServiceError::InvalidName(format!(
                "sandbox {kind} \"root\" is refused: a root sandbox is not least privilege (set allow_root to opt in explicitly)"
            )));
        }
    }
    for capability in &sandbox.capabilities {
        let valid = !capability.is_empty()
            && capability
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid {
            return Err(ServiceError::InvalidName(format!(
                "{capability:?} is not a valid capability name (expected [A-Za-z0-9_]+)"
            )));
        }
    }
    Ok(())
}

/// The hardening set's free-form values: `ReadWritePaths=` over the
/// conservative path alphabet, extra address families over `AF_[A-Z0-9_]+`.
pub(crate) fn validate_hardening(hardening: &SystemdHardening) -> Result<(), ServiceError> {
    for path in &hardening.read_write_paths {
        if !is_conservative_path(path) {
            return Err(ServiceError::InvalidName(format!(
                "{} is not a valid ReadWritePaths entry (an absolute path over [A-Za-z0-9._/@+-]: the value is word-split, C-unescaped and specifier-expanded, and one stray quote drops the whole line)",
                path.display()
            )));
        }
    }
    for family in &hardening.extra_address_families {
        let valid = family.strip_prefix("AF_").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        });
        if !valid {
            return Err(ServiceError::InvalidName(format!(
                "{family:?} is not a valid address family (expected AF_[A-Z0-9_]+)"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Spec validation (before any filesystem / systemctl side effect)

/// Validate the spec values systemd is picky about, beyond the name-class
/// rules: the description and every `ExecStart` token carry
/// no control character (NUL included) and the description no trailing
/// `\`; the program path is absolute, modifier-free, and below a directory;
/// path lists stay in the conservative alphabet; the `FailurePolicy`
/// renders honest non-zero values.
pub(crate) fn validate_spec(spec: &ServiceSpec) -> Result<(), ServiceError> {
    validate_description(&spec.description)?;
    validate_program_path(&spec.program)?;
    for argument in &spec.arguments {
        let valid = argument
            .to_str()
            .is_some_and(|text| !text.chars().any(char::is_control));
        if !valid {
            return Err(ServiceError::InvalidSpec(format!(
                "argument {argument:?} must be valid UTF-8 without control characters (NUL, CR and LF included): systemd's unit parser ends a line at any of them, and a unit file parsed as root is no place for lossy mangling"
            )));
        }
    }
    validate_environment_files(&spec.environment_files)?;
    validate_state_directory(spec.state_directory.as_deref())?;
    validate_open_files_limit(spec.open_files_limit)?;
    validate_hardening(&spec.systemd_hardening)?;
    validate_failure_policy(&spec.failure_policy)
}

/// `StateDirectory=`: relative segments over `[A-Za-z0-9._@+-]` joined by
/// `/`, none empty, `.` or `..`. systemd resolves it under `/var/lib` and
/// chowns it to the service user, so an escape (`..`) or an absolute value
/// would hand the service a directory outside it.
pub(crate) fn validate_state_directory(directory: Option<&str>) -> Result<(), ServiceError> {
    let Some(directory) = directory else {
        return Ok(());
    };
    // systemd reserves `private/` for DynamicUser= and ignores (with only a
    // warning) any other unit's StateDirectory= under it.
    let reserved = directory.split('/').next() == Some("private");
    let valid = !directory.is_empty()
        && !reserved
        && directory.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-')
                })
        });
    if !valid {
        return Err(ServiceError::InvalidSpec(format!(
            "state_directory {directory:?} must be a relative path of segments over [A-Za-z0-9._@+-] (no leading or trailing '/', no empty, '.' or '..' segment, not under systemd's reserved 'private/'); systemd resolves it under /var/lib (~/.local/state for a user unit)"
        )));
    }
    Ok(())
}

/// `LimitNOFILE=` must leave the process room to run at all (see
/// [`crate::MIN_OPEN_FILES_LIMIT`]).
pub(crate) fn validate_open_files_limit(limit: Option<u64>) -> Result<(), ServiceError> {
    match limit {
        Some(limit) if limit < crate::MIN_OPEN_FILES_LIMIT => {
            Err(ServiceError::InvalidSpec(format!(
                "open_files_limit {limit} is below the minimum {} (a process needs descriptors for \
             its standard streams, runtime, listener, and pools; a connection server wants \
             thousands — the default is {})",
                crate::MIN_OPEN_FILES_LIMIT,
                crate::DEFAULT_OPEN_FILES_LIMIT
            )))
        }
        _ => Ok(()),
    }
}

/// What the update units call the product: its display name, as the MSI's
/// helper service does (`<display name> updater`) — the description is a
/// sentence, which reads wrongly with a suffix — or the description when
/// there is no display name. Checked like a description; `%` escaped.
fn update_label(spec: &ServiceSpec) -> Result<String, ServiceError> {
    let label = if spec.display_name.is_empty() {
        &spec.description
    } else {
        &spec.display_name
    };
    validate_description(label)?;
    Ok(label.replace('%', "%%"))
}

/// `Description=`: no control characters (systemd ends a line at NUL, CR
/// and LF alike — refusal, never flattening), and no trailing `\` (a line
/// continuation that would swallow the next directive). `%` is escaped at
/// render.
pub(crate) fn validate_description(description: &str) -> Result<(), ServiceError> {
    if description.chars().any(char::is_control) {
        return Err(ServiceError::InvalidSpec(format!(
            "description {description:?} must not contain control characters (NUL, CR and LF end a unit-file line)"
        )));
    }
    if description.ends_with('\\') {
        return Err(ServiceError::InvalidSpec(format!(
            "description {description:?} must not end in '\\' (a unit-file line continuation)"
        )));
    }
    Ok(())
}

/// `EnvironmentFile=` values render verbatim and the directive is
/// word-split, C-unescaped and specifier-expanded: each must be an
/// absolute path over the conservative alphabet.
pub(crate) fn validate_environment_files(files: &[PathBuf]) -> Result<(), ServiceError> {
    for file in files {
        if !is_conservative_path(file) {
            return Err(ServiceError::InvalidSpec(format!(
                "{} is not a valid EnvironmentFile path (an absolute path over [A-Za-z0-9._/@+-])",
                file.display()
            )));
        }
    }
    Ok(())
}

/// The `ExecStart` first word takes modifier prefixes in systemd: `+` runs
/// the command with FULL PRIVILEGES ignoring `User=`/`Group=` (the sandbox
/// silently defeated), and `@`/`-`/`!`/`!!` are modifiers too. Requiring an
/// absolute, `/`-leading, UTF-8 path makes every modifier form
/// unrepresentable. Control characters are refused, and the program must
/// sit below a directory (install walks and may chown that directory; `/`
/// is never it).
pub(crate) fn validate_program_path(program: &Path) -> Result<(), ServiceError> {
    let valid = program.as_os_str().to_str().is_some_and(|text| {
        // No `\`: a Windows build host would read it as a separator and
        // judge `parent()` differently from the Linux machine that runs it.
        text.starts_with('/')
            && !text.chars().any(|c| c.is_control() || c == '\\')
            && !text.ends_with('/')
    }) && program
        .parent()
        .is_some_and(|parent| parent != Path::new("/") && !parent.as_os_str().is_empty())
        && program.file_name().is_some();
    if !valid {
        return Err(ServiceError::InvalidSpec(format!(
            "program {} is not an absolute, UTF-8, control-character-free, '/'-leading file path below a directory; systemd's ExecStart first word must not carry a modifier prefix ('+', '@', '-', '!', '!!')",
            program.display()
        )));
    }
    Ok(())
}

/// The renderer truncates durations with `.as_secs()`: a sub-second first
/// delay renders `RestartSec=0` (immediate restarts — a hot loop). The
/// escalation interpolates first → last, so the last must not undercut the
/// first. Empty delays render `Restart=no`.
pub(crate) fn validate_failure_policy(policy: &crate::FailurePolicy) -> Result<(), ServiceError> {
    let (Some(first), Some(last)) = (policy.restart_delays.first(), policy.restart_delays.last())
    else {
        return Ok(());
    };
    if *first < Duration::from_secs(1) {
        return Err(ServiceError::InvalidSpec(format!(
            "failure_policy.restart_delays[0] {first:?} renders RestartSec=0 (immediate restarts, a hot restart loop); the first restart delay must be at least 1s"
        )));
    }
    if last < first {
        return Err(ServiceError::InvalidSpec(format!(
            "failure_policy.restart_delays must not end below where they start ({first:?} → {last:?}): systemd interpolates RestartSec= up to RestartMaxDelaySec="
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit rendering

/// Render the unit file for `spec`.
///
/// `user` affects the `WantedBy` target (user units cannot hook
/// `multi-user.target`, they attach to `default.target`), skips the
/// sandbox's `User=`/`Group=` lines (system-unit-only directives a
/// `systemctl --user` manager rejects), and renders `ProtectHome=read-only`
/// (the program usually lives under `$HOME`).
///
/// # Errors
/// [`ServiceError::InvalidSpec`] for any value `validate_spec` refuses —
/// the renderer re-validates as the defense-in-depth layer for direct
/// callers.
pub(crate) fn render_unit(spec: &ServiceSpec, user: bool) -> Result<String, ServiceError> {
    validate_spec(spec)?;
    if let Some(sandbox) = &spec.sandbox {
        validate_sandbox(sandbox)?;
    }
    let mut unit = String::new();

    unit.push_str("[Unit]\n");
    unit.push_str(&format!(
        "Description={}\n",
        spec.description.replace('%', "%%")
    ));
    unit.push_str("After=network-online.target\n");
    unit.push_str("Wants=network-online.target\n");
    // No start limit — the capped escalation below is the only
    // brake, and it never gives up.
    unit.push_str("StartLimitIntervalSec=0\n");

    unit.push_str("\n[Service]\n");
    unit.push_str("Type=simple\n");
    let mut exec_start = escape_exec_token(spec.program.as_os_str())?;
    for argument in &spec.arguments {
        exec_start.push(' ');
        exec_start.push_str(&escape_exec_token(argument)?);
    }
    unit.push_str(&format!("ExecStart={exec_start}\n"));

    let delays = &spec.failure_policy.restart_delays;
    match (delays.first(), delays.last()) {
        (Some(first), Some(last)) => {
            unit.push_str("Restart=on-failure\n");
            unit.push_str(&format!("RestartSec={}\n", first.as_secs()));
            if delays.len() > 1 {
                unit.push_str(&format!("RestartSteps={}\n", delays.len() - 1));
                unit.push_str(&format!("RestartMaxDelaySec={}\n", last.as_secs()));
            }
        }
        _ => {
            // Never restart after a failure.
            unit.push_str("Restart=no\n");
        }
    }
    // One descriptor per live connection: never systemd's soft 1024.
    unit.push_str(&format!(
        "LimitNOFILE={}\n",
        spec.open_files_limit
            .unwrap_or(crate::DEFAULT_OPEN_FILES_LIMIT)
    ));

    for file in &spec.environment_files {
        unit.push_str(&format!("EnvironmentFile={}\n", file.display()));
    }
    if let Some(directory) = &spec.state_directory {
        unit.push_str(&format!("StateDirectory={directory}\n"));
        unit.push_str("StateDirectoryMode=0700\n");
    }

    if let Some(sandbox) = &spec.sandbox {
        if !user {
            unit.push_str(&format!("User={}\n", sandbox.user));
            unit.push_str(&format!("Group={}\n", sandbox.group));
        }
        // The bounding set is the CEILING, the ambient set the GRANT. EMPTY
        // means NO capabilities: an empty `CapabilityBoundingSet=`
        // — "no line" would be the full bounding set.
        let capabilities = sandbox.capabilities.join(" ");
        unit.push_str(&format!("CapabilityBoundingSet={capabilities}\n"));
        if !capabilities.is_empty() {
            unit.push_str(&format!("AmbientCapabilities={capabilities}\n"));
        }
    }

    render_hardening(&mut unit, spec, user);

    unit.push_str("\n[Install]\n");
    if user {
        unit.push_str("WantedBy=default.target\n");
    } else {
        unit.push_str("WantedBy=multi-user.target\n");
    }
    Ok(unit)
}

/// One directive per enabled [`SystemdHardening`] knob, plus
/// `ReadWritePaths=` (the declared paths).
pub(crate) fn render_hardening(unit: &mut String, spec: &ServiceSpec, user: bool) {
    let h = &spec.systemd_hardening;
    let line = |unit: &mut String, enabled: bool, directive: &str| {
        if enabled {
            unit.push_str(directive);
            unit.push('\n');
        }
    };
    line(unit, h.no_new_privileges, "NoNewPrivileges=true");
    line(unit, h.protect_system_strict, "ProtectSystem=strict");
    line(
        unit,
        h.protect_home,
        if user {
            "ProtectHome=read-only"
        } else {
            "ProtectHome=true"
        },
    );
    line(unit, h.private_tmp, "PrivateTmp=true");
    line(unit, h.private_devices, "PrivateDevices=true");
    line(unit, h.device_policy_closed, "DevicePolicy=closed");
    line(
        unit,
        h.protect_kernel_tunables,
        "ProtectKernelTunables=true",
    );
    line(unit, h.protect_kernel_modules, "ProtectKernelModules=true");
    line(unit, h.protect_kernel_logs, "ProtectKernelLogs=true");
    line(unit, h.protect_control_groups, "ProtectControlGroups=true");
    line(unit, h.protect_clock, "ProtectClock=true");
    line(unit, h.protect_hostname, "ProtectHostname=true");
    line(unit, h.protect_proc, "ProtectProc=invisible");
    line(unit, h.protect_proc, "ProcSubset=pid");
    line(unit, h.restrict_namespaces, "RestrictNamespaces=true");
    line(unit, h.restrict_realtime, "RestrictRealtime=true");
    line(unit, h.restrict_suid_sgid, "RestrictSUIDSGID=true");
    line(unit, h.lock_personality, "LockPersonality=true");
    line(
        unit,
        h.memory_deny_write_execute,
        "MemoryDenyWriteExecute=true",
    );
    line(unit, h.remove_ipc, "RemoveIPC=true");
    line(
        unit,
        h.system_call_architectures_native,
        "SystemCallArchitectures=native",
    );
    line(
        unit,
        h.system_call_filter,
        "SystemCallFilter=@system-service",
    );
    line(
        unit,
        h.system_call_filter,
        "SystemCallFilter=~@privileged @resources",
    );
    line(unit, h.system_call_filter, "SystemCallErrorNumber=EPERM");
    if h.restrict_address_families {
        let mut families = String::from("AF_INET AF_INET6 AF_UNIX");
        for family in &h.extra_address_families {
            families.push(' ');
            families.push_str(family);
        }
        unit.push_str(&format!("RestrictAddressFamilies={families}\n"));
    }
    line(unit, h.umask_0077, "UMask=0077");

    let paths: Vec<String> = h
        .read_write_paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    if !paths.is_empty() {
        unit.push_str(&format!("ReadWritePaths={}\n", paths.join(" ")));
    }
}

/// Quote one `ExecStart` token per systemd.syntax, against every special
/// form the Exec-line grammar has:
///
/// * tokens containing whitespace, quotes or backslashes get double quotes
///   (with `\` and `"` backslash-escaped inside);
/// * `%` is always doubled, quoted or not (specifier expansion);
/// * `$` is always doubled, quoted or not — `$FOO`/`${FOO}` undergo
///   environment substitution; `$$` is systemd's literal dollar;
/// * a lone `;` WORD renders as `\;` — bare, it is systemd's command
///   separator.
///
/// # Errors
/// [`ServiceError::InvalidSpec`] when the token is not valid UTF-8 or
/// carries a control character (NUL, CR, LF included — a unit-file line
/// ends at any of them, quoted or not; refused rather than flattened).
pub(crate) fn escape_exec_token(token: &OsStr) -> Result<String, ServiceError> {
    let raw = token
        .to_str()
        .filter(|text| !text.chars().any(char::is_control))
        .ok_or_else(|| {
            ServiceError::InvalidSpec(format!(
                "{token:?} is not valid control-character-free UTF-8; systemd unit values cannot carry it"
            ))
        })?;
    if raw == ";" {
        return Ok("\\;".to_owned());
    }
    let needs_quoting = raw.is_empty()
        || raw
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if !needs_quoting {
        return Ok(raw.replace('%', "%%").replace('$', "$$"));
    }
    let mut escaped = String::with_capacity(raw.len() + 2);
    escaped.push('"');
    for c in raw.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '%' => escaped.push_str("%%"),
            '$' => escaped.push_str("$$"),
            _ => escaped.push(c),
        }
    }
    escaped.push('"');
    Ok(escaped)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
pub(crate) mod tests {
    use std::ffi::OsString;

    use crate::{FailurePolicy, WindowsServiceAccount};

    use super::*;

    pub(crate) fn demo_spec() -> ServiceSpec {
        ServiceSpec {
            name: "acme-demo".to_owned(),
            display_name: "Acme demo".to_owned(),
            description: "Demo daemon".to_owned(),
            program: PathBuf::from("/opt/acme/bin/acme-demo"),
            arguments: vec![
                OsString::from("service"),
                OsString::from("-t"),
                OsString::from("token with space"),
            ],
            environment_files: vec![],
            open_files_limit: None,
            failure_policy: FailurePolicy::default(),
            sandbox: None,
            systemd_hardening: SystemdHardening::none(),
            windows_account: WindowsServiceAccount::default(),
            state_directory: None,
        }
    }

    pub(crate) fn sandboxed_spec() -> ServiceSpec {
        ServiceSpec {
            sandbox: Some(SystemdSandbox {
                user: "acme".to_owned(),
                group: "acme".to_owned(),
                capabilities: vec!["CAP_NET_BIND_SERVICE".to_owned(), "CAP_NET_RAW".to_owned()],
                allow_root: false,
            }),
            systemd_hardening: SystemdHardening::default(),
            ..demo_spec()
        }
    }

    pub(crate) fn exec_line(unit: &str) -> &str {
        unit.lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("unit must have an ExecStart line")
    }

    // ---- golden units ----

    #[test]
    fn open_files_limit_defaults_high_and_is_configurable() {
        // Thousands of sockets per node need thousands of descriptors: the
        // default renders 65536 (soft = hard), never systemd's soft 1024.
        let unit = render_unit(&demo_spec(), false).expect("renders");
        assert!(unit.contains("\nLimitNOFILE=65536\n"), "{unit}");
        let unit = render_unit(
            &ServiceSpec {
                open_files_limit: Some(200_000),
                ..demo_spec()
            },
            false,
        )
        .expect("renders");
        assert!(unit.contains("\nLimitNOFILE=200000\n"), "{unit}");
        // User units carry it too (bounded by the user manager's hard limit).
        let unit = render_unit(&demo_spec(), true).expect("renders");
        assert!(unit.contains("\nLimitNOFILE=65536\n"), "{unit}");
        // A limit too small to run anything is a loud spec error.
        for bad in [0, 1, 63] {
            let err = render_unit(
                &ServiceSpec {
                    open_files_limit: Some(bad),
                    ..demo_spec()
                },
                false,
            )
            .expect_err("a tiny fd limit must be refused");
            assert!(matches!(err, ServiceError::InvalidSpec(_)), "{err:?}");
        }
    }

    #[test]
    fn renders_the_golden_system_unit() {
        let expected = "\
[Unit]
Description=Demo daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/opt/acme/bin/acme-demo service -t \"token with space\"
Restart=on-failure
RestartSec=15
RestartSteps=3
RestartMaxDelaySec=900
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
";
        assert_eq!(render_unit(&demo_spec(), false).expect("renders"), expected);
    }

    #[test]
    fn renders_the_golden_sandboxed_hardened_unit() {
        let expected = "\
[Unit]
Description=Demo daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/opt/acme/bin/acme-demo service -t \"token with space\"
Restart=on-failure
RestartSec=15
RestartSteps=3
RestartMaxDelaySec=900
LimitNOFILE=65536
User=acme
Group=acme
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
DevicePolicy=closed
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077

[Install]
WantedBy=multi-user.target
";
        assert_eq!(
            render_unit(&sandboxed_spec(), false).expect("renders"),
            expected
        );
    }

    #[test]
    fn user_unit_targets_default_target_and_skips_identity() {
        let unit = render_unit(&sandboxed_spec(), true).expect("renders");
        assert!(unit.contains("WantedBy=default.target\n"));
        assert!(!unit.contains("multi-user.target"));
        assert!(!unit.lines().any(|line| line.starts_with("User=")));
        assert!(!unit.lines().any(|line| line.starts_with("Group=")));
        assert!(unit.contains("ProtectHome=read-only\n"), "{unit}");
        assert!(unit.contains("ProtectSystem=strict\n"));
    }

    // ---- restart policy: retry forever, never fail-stop ----

    #[test]
    fn restarts_have_no_start_limit_and_no_update_exit() {
        let unit = render_unit(&demo_spec(), false).expect("renders");
        assert!(unit.contains("StartLimitIntervalSec=0\n"), "{unit}");
        assert!(!unit.contains("StartLimitBurst"), "{unit}");
        // Services never exit to update: no exit status is special.
        assert!(!unit.contains("SuccessExitStatus"), "{unit}");
        assert!(!unit.contains("RestartForceExitStatus"), "{unit}");
        // `restart_delays: []` means never restart after a failure.
        let mut spec = demo_spec();
        spec.failure_policy.restart_delays = vec![];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(unit.contains("Restart=no\n"), "{unit}");
        assert!(!unit.contains("RestartSec"), "{unit}");
    }

    #[test]
    fn the_escalation_renders_natively_and_caps() {
        let mut spec = demo_spec();
        spec.failure_policy = FailurePolicy {
            reset_period: Duration::from_secs(3600),
            restart_delays: vec![Duration::from_secs(7), Duration::from_secs(70)],
        };
        let unit = render_unit(&spec, false).expect("renders");
        assert!(unit.contains("RestartSec=7\n"));
        assert!(unit.contains("RestartSteps=1\n"));
        assert!(unit.contains("RestartMaxDelaySec=70\n"));
        // One delay: a constant delay, forever.
        spec.failure_policy.restart_delays = vec![Duration::from_secs(30)];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(unit.contains("RestartSec=30\n"));
        assert!(!unit.contains("RestartSteps") && !unit.contains("RestartMaxDelaySec"));
    }

    #[test]
    fn failure_policy_values_are_validated() {
        let mut spec = demo_spec();
        spec.failure_policy.restart_delays = vec![Duration::from_millis(500)];
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
        spec.failure_policy.restart_delays = vec![Duration::from_secs(60), Duration::from_secs(10)];
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
        spec.failure_policy.restart_delays = vec![Duration::from_secs(1)];
        assert!(validate_spec(&spec).is_ok());
    }

    // ---- text fields are refused, never flattened ----

    #[test]
    fn nul_in_description_or_argument_is_refused() {
        let mut spec = demo_spec();
        spec.description = "Demo\0[Service]\0ExecStartPre=+/nonexistent/INJECTED".to_owned();
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
        assert!(matches!(
            render_unit(&spec, false),
            Err(ServiceError::InvalidSpec(_))
        ));
        let mut spec = demo_spec();
        spec.arguments = vec![OsString::from("run\0ExecStartPre=+/nonexistent/INJECTED")];
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
        assert!(matches!(
            render_unit(&spec, false),
            Err(ServiceError::InvalidSpec(_))
        ));
    }

    #[test]
    fn crlf_and_every_control_character_are_refused_too() {
        for bad in [
            "demo\ndaemon",
            "demo\rdaemon",
            "demo\tdaemon",
            "demo\u{1b}[31m",
        ] {
            let mut spec = demo_spec();
            spec.description = bad.to_owned();
            assert!(validate_spec(&spec).is_err(), "description {bad:?}");
            let mut spec = demo_spec();
            spec.arguments = vec![OsString::from(bad)];
            assert!(validate_spec(&spec).is_err(), "argument {bad:?}");
        }
        let mut spec = demo_spec();
        spec.program = PathBuf::from("/opt/acme/bin/acme\ndemo");
        assert!(render_unit(&spec, false).is_err());
    }

    #[test]
    fn trailing_backslash_in_description_is_refused() {
        let mut spec = demo_spec();
        spec.description = "Demo daemon \\".to_owned();
        assert!(matches!(
            validate_spec(&spec),
            Err(ServiceError::InvalidSpec(_))
        ));
        // Interior backslashes and percent render faithfully.
        spec.description = "Demo \\ daemon 100%".to_owned();
        let unit = render_unit(&spec, false).expect("renders");
        assert!(
            unit.contains("Description=Demo \\ daemon 100%%\n"),
            "{unit}"
        );
    }

    #[test]
    fn exec_start_quoting_escapes_quotes_backslashes_and_percents() {
        let mut spec = demo_spec();
        spec.program = PathBuf::from("/opt/my acme/acme-demo");
        spec.arguments = vec![
            OsString::from("say \"hi\""),
            OsString::from("C:\\temp"),
            OsString::from("100%"),
        ];
        let unit = render_unit(&spec, false).expect("renders");
        assert_eq!(
            exec_line(&unit),
            "ExecStart=\"/opt/my acme/acme-demo\" \"say \\\"hi\\\"\" \"C:\\\\temp\" 100%%"
        );
    }

    #[test]
    fn lone_semicolon_argument_cannot_split_exec_start_into_a_second_command() {
        let mut spec = demo_spec();
        spec.arguments = vec![OsString::from(";"), OsString::from("/bin/evil")];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(
            !exec_line(&unit).split_whitespace().any(|word| word == ";"),
            "a bare ';' word would split ExecStart into two commands:\n{unit}"
        );
    }

    #[test]
    fn dollar_tokens_render_doubled_so_environment_substitution_cannot_fire() {
        let mut spec = demo_spec();
        spec.arguments = vec![OsString::from("$HOME"), OsString::from("${PATH}")];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(exec_line(&unit).contains("$$HOME"));
        assert!(exec_line(&unit).contains("$${PATH}"));
    }

    // ---- sandbox + hardening ----

    #[test]
    fn root_sandbox_refused_and_empty_caps_mean_none() {
        for (user, group) in [("root", "acme"), ("acme", "root")] {
            let mut spec = sandboxed_spec();
            let sandbox = spec.sandbox.as_mut().unwrap();
            sandbox.user = user.to_owned();
            sandbox.group = group.to_owned();
            assert!(validate_sandbox(spec.sandbox.as_ref().unwrap()).is_err());
            spec.sandbox.as_mut().unwrap().allow_root = true;
            assert!(validate_sandbox(spec.sandbox.as_ref().unwrap()).is_ok());
        }
        let mut spec = sandboxed_spec();
        spec.sandbox.as_mut().unwrap().capabilities = vec![];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(unit.contains("CapabilityBoundingSet=\n"), "{unit}");
        assert!(!unit.contains("AmbientCapabilities"), "{unit}");
        assert!(unit.contains("PrivateDevices=true\n"), "{unit}");
    }

    #[test]
    fn every_hardening_knob_opts_out_individually() {
        let defaults = render_unit(&sandboxed_spec(), false).expect("renders");
        let mut spec = sandboxed_spec();
        spec.systemd_hardening.memory_deny_write_execute = false;
        spec.systemd_hardening.extra_address_families = vec!["AF_NETLINK".to_owned()];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(!unit.contains("MemoryDenyWriteExecute"));
        assert!(unit.contains("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n"));
        assert_eq!(
            unit.lines().count() + 1,
            defaults.lines().count(),
            "exactly one directive dropped"
        );
        // `none()` renders no hardening at all.
        let mut spec = sandboxed_spec();
        spec.systemd_hardening = SystemdHardening::none();
        let unit = render_unit(&spec, false).expect("renders");
        assert!(
            !unit.contains("Protect") && !unit.contains("NoNewPrivileges"),
            "{unit}"
        );
        // Bad address families are refused.
        for bad in ["AF_", "af_netlink", "NETLINK", "AF_NET LINK"] {
            let mut spec = sandboxed_spec();
            spec.systemd_hardening.extra_address_families = vec![bad.to_owned()];
            assert!(validate_spec(&spec).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sandbox_validation_rejects_injection_shaped_values() {
        for bad in [
            "a b", "a\nb", "a\rb", "a\tb", "../root", "a/b", "a\\b", "-r", "", "%u", "%i", "0",
            "12345",
        ] {
            for field in ["user", "group"] {
                let mut spec = sandboxed_spec();
                let sandbox = spec.sandbox.as_mut().unwrap();
                if field == "user" {
                    sandbox.user = bad.to_owned();
                } else {
                    sandbox.group = bad.to_owned();
                }
                let result = validate_sandbox(spec.sandbox.as_ref().unwrap());
                assert!(
                    matches!(result, Err(ServiceError::InvalidName(_))),
                    "{field} {bad:?} must be rejected, got {result:?}"
                );
            }
        }
        for bad in [
            "CAP NET RAW",
            "CAP_NET_RAW\nNice=-20",
            "cap;rm -rf /",
            "",
            "CAP-CHOWN",
            "CAP_%i",
        ] {
            let mut spec = sandboxed_spec();
            spec.sandbox.as_mut().unwrap().capabilities = vec![bad.to_owned()];
            assert!(matches!(
                validate_sandbox(spec.sandbox.as_ref().unwrap()),
                Err(ServiceError::InvalidName(_))
            ));
        }
        assert!(validate_sandbox(sandboxed_spec().sandbox.as_ref().unwrap()).is_ok());
    }

    // ---- path lists ----

    #[test]
    fn quote_backslash_percent_in_path_lists_are_refused() {
        for bad in [
            "/opt/a\"b",
            "/opt/a\\b",
            "/opt/%h",
            "/opt/a'b",
            "relative",
            "/var/log /etc",
            "/opt/x\ny",
            "/opt/x\u{0}",
        ] {
            let mut spec = sandboxed_spec();
            spec.systemd_hardening.read_write_paths = vec![PathBuf::from(bad)];
            assert!(validate_spec(&spec).is_err(), "ReadWritePaths {bad:?}");
            let mut spec = demo_spec();
            spec.environment_files = vec![PathBuf::from(bad)];
            assert!(validate_spec(&spec).is_err(), "EnvironmentFile {bad:?}");
        }
        let mut spec = sandboxed_spec();
        spec.systemd_hardening.read_write_paths = vec![
            PathBuf::from("/var/lib/acme"),
            PathBuf::from("/srv/app@1/data+x"),
        ];
        spec.environment_files = vec![PathBuf::from("/etc/acme-demo/secrets.env")];
        let unit = render_unit(&spec, false).expect("renders");
        assert!(
            unit.contains("ReadWritePaths=/var/lib/acme /srv/app@1/data+x\n"),
            "{unit}"
        );
        assert!(unit.contains("EnvironmentFile=/etc/acme-demo/secrets.env\n"));
    }

    // ---- names / state mapping ----

    #[test]
    fn unit_name_validation_rejects_traversal_options_and_control_chars() {
        for bad in [
            "../evil", "a/b", "a\\b", "-H", "--user", "a b", "a\nb", "", ".hidden", ".-x",
            "éclair", ".",
        ] {
            assert!(validate_unit_name(bad).is_err(), "{bad:?} must be rejected");
        }
        for good in [
            "acme-demo",
            "acme-demo.service",
            "app_v2",
            "my.app",
            "1st-app",
        ] {
            assert!(
                validate_unit_name(good).is_ok(),
                "{good:?} must be accepted"
            );
        }
    }

    // ---- the packaging renderers ----

    #[test]
    fn the_state_directory_renders_private_and_is_validated() {
        let mut spec = demo_spec();
        spec.state_directory = Some("acme/collector".to_owned());
        let rendered = unit(&spec, Scope::System).expect("renders");
        assert!(
            rendered.contains("\nStateDirectory=acme/collector\nStateDirectoryMode=0700\n"),
            "{rendered}"
        );
        for bad in [
            "",
            "/var/lib/x",
            "x/",
            "a//b",
            "../etc",
            "a/../b",
            "a/./b",
            "x y",
            "x%n",
            "x\\y",
            "x\ny",
            "private",
            "private/x",
        ] {
            spec.state_directory = Some(bad.to_owned());
            assert!(validate(&spec).is_err(), "{bad:?} accepted");
            assert!(unit(&spec, Scope::System).is_err(), "{bad:?} rendered");
        }
        // Only the FIRST segment is reserved.
        spec.state_directory = Some("vendor/private".to_owned());
        assert!(validate(&spec).is_ok());
        spec.state_directory = None;
        assert!(
            !unit(&spec, Scope::System)
                .expect("renders")
                .contains("StateDirectory")
        );
    }

    #[test]
    fn unit_names_stay_in_systemds_alphabet() {
        assert_eq!(
            unit_file_name(&demo_spec()).expect("valid"),
            "acme-demo.service"
        );
        let mut spec = demo_spec();
        for good in ["AcmeLiveResponseService", "a.b_c-d", "x:y"] {
            spec.name = good.to_owned();
            assert!(unit_file_name(&spec).is_ok(), "{good:?}");
        }
        for bad in [
            "../evil",
            "tmpl@inst",
            "quote\"d",
            "do$llar",
            "brack[et]",
            "ünit",
            "a'b",
        ] {
            spec.name = bad.to_owned();
            assert!(unit_file_name(&spec).is_err(), "{bad:?}");
            assert!(unit(&spec, Scope::System).is_err(), "{bad:?}");
        }
        spec.name = "x".repeat(201);
        assert!(unit_file_name(&spec).is_err());
    }

    #[test]
    fn program_paths_refuse_backslashes() {
        let mut spec = demo_spec();
        spec.program = PathBuf::from("/opt/a\\b/demo");
        assert!(validate(&spec).is_err());
    }

    #[test]
    fn renders_the_golden_update_units() {
        let mut spec = demo_spec();
        spec.state_directory = Some("acme/demo".to_owned());
        assert_eq!(
            update_path_unit(&spec).expect("renders"),
            "[Unit]\n\
             Description=Acme demo update request\n\
             \n\
             [Path]\n\
             PathChanged=/var/lib/acme/demo/update-request\n\
             Unit=acme-demo-update.service\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
        let helper = update_service_unit(
            &spec,
            Path::new("/opt/acme/demo/libexec/acme-demo-update"),
            "acme/demo",
        )
        .expect("renders");
        let mut expected = String::from(
            "[Unit]\n\
             Description=Acme demo updater\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             StartLimitIntervalSec=0\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             ExecStart=/opt/acme/demo/libexec/acme-demo-update\n\
             TimeoutStartSec=1800\n\
             CacheDirectory=acme/demo\n\
             CacheDirectoryMode=0700\n\
             UMask=0077\n",
        );
        for directive in HELPER_SANDBOX {
            expected.push_str(directive);
            expected.push('\n');
        }
        assert_eq!(helper, expected);
        // The sandbox that matters: read-only system, no new privileges,
        // the network families only.
        for must in [
            "ProtectSystem=strict",
            "NoNewPrivileges=true",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallFilter=@system-service",
        ] {
            assert!(helper.contains(must), "{must}");
        }
        assert!(
            !helper.contains("[Install]"),
            "only the path unit starts the helper"
        );
        assert!(
            !update_path_unit(&spec)
                .expect("renders")
                .contains("TriggerLimit")
        );
    }

    #[test]
    fn the_update_units_refuse_what_the_service_unit_refuses() {
        // No state directory: nowhere for the request file.
        assert!(update_path_unit(&demo_spec()).is_err());
        let mut spec = demo_spec();
        spec.state_directory = Some("acme/demo".to_owned());
        // The helper path follows the ExecStart rule: no modifier prefix.
        for bad in [
            "+/opt/x/helper",
            "relative/helper",
            "/helper",
            "/opt/x/he\nlper",
            "/opt/x\\y/helper",
        ] {
            assert!(
                update_service_unit(&spec, Path::new(bad), "acme/demo").is_err(),
                "{bad:?}"
            );
        }
        for bad in ["", "/var/cache/x", "../x", "private/x", "x y"] {
            assert!(
                update_service_unit(&spec, Path::new("/opt/x/helper"), bad).is_err(),
                "{bad:?}"
            );
        }
        spec.description = "evil\nExecStartPre=+/bin/sh".to_owned();
        assert!(update_path_unit(&spec).is_err());
        assert!(update_service_unit(&spec, Path::new("/opt/x/helper"), "acme/demo").is_err());
        // The update units name the product by its display name, checked as
        // strictly as the description (a unit-file line each).
        let mut spec = demo_spec();
        spec.state_directory = Some("acme/demo".to_owned());
        for bad in ["evil\nExecStartPre=+/bin/sh", "trailing\\"] {
            spec.display_name = bad.to_owned();
            assert!(update_path_unit(&spec).is_err(), "{bad:?}");
            assert!(
                update_service_unit(&spec, Path::new("/opt/x/helper"), "acme/demo").is_err(),
                "{bad:?}"
            );
        }
        spec.display_name = "100% up".to_owned();
        assert!(
            update_path_unit(&spec)
                .expect("renders")
                .contains("Description=100%% up update request\n")
        );
        assert!(
            update_service_unit(&spec, Path::new("/opt/x/helper"), "acme/demo")
                .expect("renders")
                .contains("Description=100%% up updater\n")
        );
        // No display name: the description.
        spec.display_name = String::new();
        spec.description = "A demo".to_owned();
        assert!(
            update_path_unit(&spec)
                .expect("renders")
                .contains("Description=A demo update request\n")
        );
    }

    #[test]
    fn renders_the_golden_desktop_update_unit_and_polkit_rule() {
        let helper = Path::new("/opt/acme/console/libexec/acme-console-update");
        let unit =
            desktop_update_service_unit("Acme Console", helper, "acme/console").expect("renders");
        // The service product's helper unit, named by the display name.
        let mut spec = demo_spec();
        spec.state_directory = Some("acme/demo".to_owned());
        spec.display_name = "Acme Console".to_owned();
        assert_eq!(
            unit,
            update_service_unit(&spec, helper, "acme/console").expect("renders")
        );
        assert!(
            unit.contains("Description=Acme Console updater\n"),
            "{unit}"
        );
        assert!(
            !unit.contains("[Install]"),
            "only the session starts it: {unit}"
        );
        assert_eq!(
            desktop_update_unit_name("acme-console-update").expect("valid"),
            "acme-console-update.service"
        );
        assert_eq!(
            desktop_update_polkit_rule("acme-console", "acme-console-update.service")
                .expect("renders"),
            "// Generated by seaworthy: acme-console's update helper.\n\
             //\n\
             // The active local session may start acme-console-update.service, and nothing more: not\n\
             // stop or restart it, not any other unit. The helper takes no input,\n\
             // so the most a session can do is have the machine install the release\n\
             // the product's server names. Anything else falls through to the\n\
             // rules after this one.\n\
             polkit.addRule(function (action, subject) {\n\
             \x20   if (action.id === \"org.freedesktop.systemd1.manage-units\" &&\n\
             \x20       action.lookup(\"unit\") === \"acme-console-update.service\" &&\n\
             \x20       action.lookup(\"verb\") === \"start\" &&\n\
             \x20       subject.local && subject.active) {\n\
             \x20       return polkit.Result.YES;\n\
             \x20   }\n\
             });\n"
        );
    }

    /// The rule's decisions, evaluated by JavaScript (node) against a stub
    /// of polkit's rule API: only `start` of exactly its unit, from a local
    /// and active subject, is granted; everything else falls through to the
    /// next rules. A Linux conformance lane in containers cannot show the grant:
    /// polkit counts a session as local only when it has a seat, and no
    /// container session has one (seatless — ssh, su, a service's PAM
    /// session — is refused there). Skipped without node, unless
    /// SEAWORTHY_REQUIRE_NODE=1.
    #[test]
    fn the_desktop_update_rule_grants_only_start_from_a_local_active_subject() {
        let rule = desktop_update_polkit_rule("acme-console", "acme-console-update.service")
            .expect("renders");
        let harness = r#"
const rules = [];
globalThis.polkit = {
    Result: { YES: "yes", NO: "no", AUTH_ADMIN: "auth_admin" },
    addRule: (rule) => rules.push(rule),
    log: () => {},
};
eval(require("fs").readFileSync(0, "utf8"));
const decide = (id, unit, verb, local, active) => {
    const action = { id, lookup: (key) => ({ unit, verb })[key] };
    for (const rule of rules) {
        const verdict = rule(action, { local, active });
        if (verdict !== undefined) return verdict;
    }
    return "next";
};
const manage = "org.freedesktop.systemd1.manage-units";
const unit = "acme-console-update.service";
console.log(JSON.stringify([
    decide(manage, unit, "start", true, true),
    decide(manage, unit, "start", false, true),
    decide(manage, unit, "start", true, false),
    decide(manage, unit, "stop", true, true),
    decide(manage, unit, "restart", true, true),
    decide(manage, "sshd.service", "start", true, true),
    decide(manage, "acme-console-update.service.d", "start", true, true),
    decide("org.freedesktop.systemd1.manage-unit-files", unit, "start", true, true),
]));
"#;
        let node = std::process::Command::new("node")
            .arg("-e")
            .arg(harness)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let mut node = match node {
            Ok(node) => node,
            Err(error) => {
                assert!(
                    std::env::var_os("SEAWORTHY_REQUIRE_NODE").is_none_or(|v| v != "1"),
                    "node is required (SEAWORTHY_REQUIRE_NODE=1): {error}"
                );
                eprintln!("SKIPPED: no node ({error})");
                return;
            }
        };
        {
            use std::io::Write as _;
            node.stdin
                .take()
                .expect("stdin")
                .write_all(rule.as_bytes())
                .expect("writes the rule");
        }
        let output = node.wait_with_output().expect("node runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            r#"["yes","next","next","next","next","next","next","next"]"#
        );
    }

    #[test]
    fn the_desktop_update_unit_and_rule_refuse_what_would_misread() {
        let helper = Path::new("/opt/x/helper");
        for bad in ["", "evil\nExecStartPre=+/bin/sh", "trailing\\"] {
            assert!(
                desktop_update_service_unit(bad, helper, "acme/console").is_err(),
                "{bad:?}"
            );
        }
        assert!(desktop_update_service_unit("A", Path::new("relative/helper"), "a/b").is_err());
        assert!(desktop_update_service_unit("A", helper, "../x").is_err());
        assert!(
            desktop_update_service_unit("100% up", helper, "a/b")
                .expect("renders")
                .contains("Description=100%% up updater\n")
        );
        // The unit name lands in a JavaScript string literal: no quotes,
        // backslashes, spaces or path separators; a unit name's length.
        for bad in [
            "",
            "-dash",
            "a\"b",
            "a\\b",
            "a b",
            "a/b",
            "a\nb",
            "a'b",
            &"a".repeat(201),
        ] {
            assert!(desktop_update_unit_name(bad).is_err(), "{bad:?}");
            assert!(
                desktop_update_polkit_rule("acme", &format!("{bad}.service")).is_err(),
                "{bad:?}"
            );
        }
        for bad in [
            "acme-console-update",
            "acme-console-update.path",
            ".service",
        ] {
            assert!(desktop_update_polkit_rule("acme", bad).is_err(), "{bad:?}");
        }
        assert!(desktop_update_polkit_rule("ac\nme", "a.service").is_err());
        // U+2028 and U+2029 end a JavaScript line comment just as LF does:
        // a package name carrying one would put code in the rule.
        for bad in [
            "acme\u{2028}polkit.addRule(function(){return polkit.Result.YES;});//",
            "acme\u{2029}x",
            "acme\rx",
            "acme */ x",
            "acme console",
            "",
            "-acme",
        ] {
            assert!(
                desktop_update_polkit_rule(bad, "acme-update.service").is_err(),
                "{bad:?}"
            );
        }
        assert!(desktop_update_polkit_rule("acme-console.v2_x", "acme-update.service").is_ok());
    }

    #[test]
    fn sysusers_creates_the_sandbox_identity() {
        assert_eq!(sysusers(&demo_spec()).expect("valid"), None);
        assert_eq!(
            sysusers(&sandboxed_spec()).expect("valid").as_deref(),
            Some(
                "# acme-demo — the service's sandbox identity (generated by seaworthy)\nu acme - \"Acme demo\" - -\n"
            )
        );
    }

    #[test]
    fn sysusers_puts_a_separate_group_in_the_id_field() {
        // sysusers.d(5): `u user -:group …` — `user:group` in the NAME field
        // is not a valid name, and sysusers then creates nothing.
        let mut split = sandboxed_spec();
        if let Some(sandbox) = split.sandbox.as_mut() {
            sandbox.group = "acme-data".to_owned();
        }
        let text = sysusers(&split).expect("valid").expect("a sandbox");
        assert!(
            text.ends_with("\ng acme-data -\nu acme -:acme-data \"Acme demo\" - -\n"),
            "{text}"
        );
        assert!(!text.contains("acme:acme-data"), "{text}");
    }

    #[test]
    fn sysusers_for_root_creates_at_most_the_group() {
        let mut root = sandboxed_spec();
        if let Some(sandbox) = root.sandbox.as_mut() {
            sandbox.user = "root".to_owned();
            sandbox.group = "root".to_owned();
            sandbox.allow_root = true;
        }
        assert_eq!(sysusers(&root).expect("valid"), None);
        if let Some(sandbox) = root.sandbox.as_mut() {
            sandbox.group = "acme-data".to_owned();
        }
        let text = sysusers(&root).expect("valid").expect("the group");
        assert!(text.ends_with("\ng acme-data -\n"), "{text}");
        assert!(!text.contains("\nu "), "{text}");
    }

    #[test]
    fn sysusers_refuses_gecos_values_sysusers_would_refuse_or_rewrite() {
        for bad in [
            "evil\" - - x",
            "Acme: Collector",
            "back\\slash",
            "trailing\\",
            "tab\tthere",
            "nl\nu root - - -",
        ] {
            let mut spec = sandboxed_spec();
            spec.display_name = bad.to_owned();
            assert!(sysusers(&spec).is_err(), "{bad:?} accepted");
        }
        let mut spec = sandboxed_spec();
        spec.display_name = "100% demo".to_owned();
        let text = sysusers(&spec).expect("valid").expect("a sandbox");
        assert!(text.contains("\"100%% demo\""), "{text}");
    }

    #[test]
    fn sandbox_names_are_portable() {
        for bad in [
            "9lives",
            "has.dot",
            "x".repeat(32).as_str(),
            "ünicode",
            "a$b",
        ] {
            let mut spec = sandboxed_spec();
            if let Some(sandbox) = spec.sandbox.as_mut() {
                sandbox.user = bad.to_owned();
            }
            assert!(validate(&spec).is_err(), "{bad:?}");
        }
        // (A leading `_` is already refused by the shared name rule.)
        for good in ["acme-svc", "svc_user", "a1"] {
            let mut spec = sandboxed_spec();
            if let Some(sandbox) = spec.sandbox.as_mut() {
                sandbox.user = good.to_owned();
            }
            assert!(validate(&spec).is_ok(), "{good:?}");
        }
    }
}
