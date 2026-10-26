//! launchd: the LaunchDaemon property list a macOS service runs from, and
//! the service's state as `launchctl print` reports it. Platform-independent,
//! like the systemd and Windows renderers: the seaworthy CLI writes a
//! package's plist on its Linux build host, and Linux CI pins the state
//! mapping the macOS backend uses.
//!
//! The daemon, `/Library/LaunchDaemons/<name>.plist`:
//!
//! - `Label` is the service name, which is also the file's name, so it
//!   takes launchd's file-name-safe alphabet (`[A-Za-z0-9._-]`).
//! - `ProgramArguments`: the program, then the arguments, each its own
//!   string (launchd runs no shell, so nothing is re-split or expanded).
//! - `RunAtLoad`: started whenever launchd loads it, at boot and at
//!   install.
//! - `KeepAlive` = { `SuccessfulExit` = false }: restarted after a non-zero
//!   exit or a crash, never after exit 0, the run loop's clean stop (and a
//!   supervisor's retirement, also exit 0, no restart). The systemd unit
//!   (`Restart=on-failure`) and the SCM's failure actions on non-crash
//!   failures do the same. A [`FailurePolicy`](crate::FailurePolicy)
//!   without restart delays leaves `KeepAlive` out: never restarted.
//! - `ThrottleInterval`: the first restart delay, the least time between two
//!   spawns. launchd has one fixed interval, so the escalation the systemd
//!   and SCM backends render (first delay up to the last) isn't available.
//! - `ProcessType` `Standard`: without it launchd throttles the daemon's
//!   CPU and I/O as a background job.
//! - `UserName`/`GroupName`: the account of a [`UnixIdentity::User`];
//!   nothing for [`UnixIdentity::Root`], which runs as root by explicit
//!   choice (macOS has no per-service accounts like Windows' virtual
//!   accounts). [`UnixIdentity::Unspecified`] is refused: no daemon runs as
//!   root because a field was left out.
//! - `SoftResourceLimits`/`HardResourceLimits` `NumberOfFiles`: the
//!   open-files limit.
//! - `Umask` 63 (0o077) with the hardening's `umask_0077`.
//! - `ExitTimeOut`: how long launchd waits after SIGTERM before SIGKILL.
//!
//! The systemd sandbox switches have no launchd counterpart and aren't
//! rendered. Environment files are refused: launchd has no
//! `EnvironmentFile=`, and copying their contents into a world-readable
//! plist would publish the credentials they hold.
//!
//! A package (the seaworthy CLI's macOS `pkg`) installs [`daemon_plist`]: the
//! same daemon with `StandardOutPath`/`StandardErrorPath` naming its log
//! file (`/Library/Logs/<Vendor>/<Directory>/<name>.log`; without them
//! launchd sends a daemon's output nowhere). With the update helper it
//! also installs [`update_helper_plist`],
//! `/Library/LaunchDaemons/<name>-update.plist`: the helper as root, on
//! demand — no `RunAtLoad`, no `KeepAlive` — whenever the request file
//! changes (`WatchPaths`), the launchd counterpart of the systemd path
//! unit (`update_path_unit`). The service asks for an update by writing
//! that file, so it never needs the right to start a system daemon
//! (`launchctl kickstart system/…` takes root).
//!
//! Every string goes through [`xml_text`] (XML-escaped) after validation:
//! no control characters (XML 1.0 can't carry most of them, and a plist
//! read as root is no place for lossy mangling).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ServiceError;
use crate::render::is_safe_service_name;
use crate::render::systemd::{
    validate_description, validate_failure_policy, validate_open_files_limit,
    validate_program_path, validate_state_directory,
};
use crate::spec::{ServiceSpec, SystemdSandbox, UnixIdentity};
use crate::state::ServiceState;

/// Where system daemons' property lists live.
pub const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";

/// launchd's grace between SIGTERM and SIGKILL: the run loop stops within
/// its stop wait hint (10 s) plus the runtime's shutdown grace (5 s).
pub const EXIT_TIMEOUT: Duration = Duration::from_secs(20);

/// `/Library/LaunchDaemons/<name>.plist`.
///
/// # Errors
/// [`ServiceError::InvalidName`] for a name [`validate_label`] refuses.
pub fn plist_path(spec: &ServiceSpec) -> Result<PathBuf, ServiceError> {
    validate_label(&spec.name)?;
    Ok(PathBuf::from(LAUNCH_DAEMONS).join(format!("{}.plist", spec.name)))
}

/// A label is the plist's file name and a `launchctl` service target
/// (`system/<label>`): the shared name rule, then `[A-Za-z0-9._-]`, at most
/// 200 bytes. This is a rejection, not a sanitization.
///
/// # Errors
/// [`ServiceError::InvalidName`] for anything else.
pub fn validate_label(name: &str) -> Result<(), ServiceError> {
    if is_safe_service_name(name)
        && name.len() <= 200
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Ok(());
    }
    Err(ServiceError::InvalidName(format!(
        "{name:?} is not a valid launchd label (an ASCII letter or digit first, then [A-Za-z0-9._-], at most 200 bytes)"
    )))
}

/// Validate the values the plist carries (see the module docs).
///
/// # Errors
/// [`ServiceError::InvalidName`] or [`ServiceError::InvalidSpec`].
pub fn validate(spec: &ServiceSpec) -> Result<(), ServiceError> {
    validate_label(&spec.name)?;
    validate_description(&spec.description)?;
    validate_program_path(&spec.program)?;
    for argument in &spec.arguments {
        let valid = argument
            .to_str()
            .is_some_and(|text| !text.chars().any(char::is_control));
        if !valid {
            return Err(ServiceError::InvalidSpec(format!(
                "argument {argument:?} must be valid UTF-8 without control characters: XML 1.0 can't carry most of them"
            )));
        }
    }
    if !spec.environment_files.is_empty() {
        return Err(ServiceError::InvalidSpec(
            "environment_files has no launchd counterpart (launchd has no EnvironmentFile=, and a plist is world-readable): read credentials from a root-only file in the service instead".into(),
        ));
    }
    match &spec.unix_identity {
        UnixIdentity::Unspecified => {
            return Err(ServiceError::InvalidSpec(
                "unix_identity is unspecified: name the account the daemon runs as, UnixIdentity::User (UserName/GroupName) or UnixIdentity::Root (by explicit choice)".into(),
            ));
        }
        UnixIdentity::User(sandbox) => validate_account(sandbox)?,
        UnixIdentity::Root => {}
    }
    validate_state_directory(spec.state_directory.as_deref())?;
    validate_open_files_limit(spec.open_files_limit)?;
    validate_failure_policy(&spec.failure_policy)
}

/// The sandbox's account as launchd's `UserName`/`GroupName`: the portable
/// name rule (`[A-Za-z_][A-Za-z0-9_-]*`, at most 31 bytes; macOS daemon
/// accounts start with `_`), never a bare number, and neither `root` nor
/// `wheel` (gid 0) unless `allow_root` says so. Capabilities are
/// Linux's: refused rather than silently dropped.
///
/// # Errors
/// [`ServiceError::InvalidName`].
pub fn validate_account(sandbox: &SystemdSandbox) -> Result<(), ServiceError> {
    for (kind, value) in [("user", &sandbox.user), ("group", &sandbox.group)] {
        let portable = value.len() <= 31
            && value
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !portable {
            return Err(ServiceError::InvalidName(format!(
                "{value:?} is not a valid launchd {kind} name ([A-Za-z_][A-Za-z0-9_-]*, at most 31 bytes; bare numeric IDs are not accepted)"
            )));
        }
        if matches!(value.as_str(), "root" | "wheel") && !sandbox.allow_root {
            return Err(ServiceError::InvalidName(format!(
                "sandbox {kind} {value:?} is refused: uid/gid 0 is not least privilege (set allow_root to opt in explicitly)"
            )));
        }
    }
    if !sandbox.capabilities.is_empty() {
        return Err(ServiceError::InvalidSpec(
            "sandbox capabilities are Linux's and have no launchd counterpart".into(),
        ));
    }
    Ok(())
}

/// The LaunchDaemon property list for `spec` (see the module docs), as the
/// backend installs it.
///
/// # Errors
/// As [`validate`]: the renderer validates before it writes anything.
pub fn plist(spec: &ServiceSpec) -> Result<String, ServiceError> {
    render(spec, None)
}

/// The LaunchDaemon property list a package installs: [`plist`], with the
/// daemon's standard output and error appended to `log_file`.
///
/// # Errors
/// As [`validate`]; [`ServiceError::InvalidSpec`] for a log file that
/// isn't an absolute, UTF-8, control-character-free file path.
pub fn daemon_plist(spec: &ServiceSpec, log_file: &Path) -> Result<String, ServiceError> {
    validate_file_path(log_file, "log file")?;
    render(spec, Some(log_file))
}

/// The update helper's label: `<name>-update`, as the helper's systemd
/// units and Windows service are named.
///
/// # Errors
/// [`ServiceError::InvalidName`] when that isn't a valid label.
pub fn update_helper_label(spec: &ServiceSpec) -> Result<String, ServiceError> {
    let label = format!("{}-update", spec.name);
    validate_label(&label)?;
    Ok(label)
}

/// The update helper's LaunchDaemon (see the module docs):
/// `helper` as root whenever `request_file` changes, its output appended to
/// `log_file`. Never at load, never kept alive: one run per request, which
/// paces itself.
///
/// # Errors
/// As [`validate`]; [`ServiceError::InvalidName`] for a label too long once
/// `-update` is appended; [`ServiceError::InvalidSpec`] for a path that
/// isn't an absolute, UTF-8, control-character-free file path.
pub fn update_helper_plist(
    spec: &ServiceSpec,
    helper: &Path,
    request_file: &Path,
    log_file: &Path,
) -> Result<String, ServiceError> {
    validate(spec)?;
    let label = update_helper_label(spec)?;
    validate_file_path(helper, "update helper")?;
    validate_file_path(request_file, "update request file")?;
    validate_file_path(log_file, "log file")?;
    let mut out = String::from(PLIST_HEAD);
    let string = |out: &mut String, key: &str, value: &str| {
        out.push_str(&format!(
            "\t<key>{key}</key>\n\t<string>{}</string>\n",
            xml_text(value)
        ));
    };
    let array = |out: &mut String, key: &str, value: &Path| {
        out.push_str(&format!(
            "\t<key>{key}</key>\n\t<array>\n\t\t<string>{}</string>\n\t</array>\n",
            xml_text(value.to_str().unwrap_or_default())
        ));
    };
    string(&mut out, "Label", &label);
    array(&mut out, "ProgramArguments", helper);
    array(&mut out, "WatchPaths", request_file);
    string(&mut out, "ProcessType", "Standard");
    out.push_str(&format!(
        "\t<key>ExitTimeOut</key>\n\t<integer>{}</integer>\n",
        EXIT_TIMEOUT.as_secs()
    ));
    out.push_str("\t<key>Umask</key>\n\t<integer>63</integer>\n");
    let log = log_file.to_str().unwrap_or_default();
    string(&mut out, "StandardOutPath", log);
    string(&mut out, "StandardErrorPath", log);
    out.push_str(PLIST_TAIL);
    Ok(out)
}

/// A path a plist names: absolute, UTF-8, no control characters, a file
/// below a directory.
fn validate_file_path(path: &Path, what: &str) -> Result<(), ServiceError> {
    let valid = path.to_str().is_some_and(|text| {
        text.starts_with('/') && !text.ends_with('/') && !text.chars().any(char::is_control)
    }) && path.parent().is_some_and(|parent| parent != Path::new("/"));
    if valid {
        Ok(())
    } else {
        Err(ServiceError::InvalidSpec(format!(
            "{what} {} is not an absolute, UTF-8, control-character-free file path below a directory",
            path.display()
        )))
    }
}

const PLIST_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n\
     <dict>\n";

const PLIST_TAIL: &str = "</dict>\n</plist>\n";

fn render(spec: &ServiceSpec, log_file: Option<&Path>) -> Result<String, ServiceError> {
    validate(spec)?;
    let mut out = String::from(PLIST_HEAD);
    let key = |out: &mut String, name: &str| {
        out.push_str(&format!("\t<key>{name}</key>\n"));
    };
    key(&mut out, "Label");
    out.push_str(&format!("\t<string>{}</string>\n", xml_text(&spec.name)));
    key(&mut out, "ProgramArguments");
    out.push_str("\t<array>\n");
    // `validate` proved the program and every argument UTF-8.
    let program = spec.program.to_str().unwrap_or_default();
    out.push_str(&format!("\t\t<string>{}</string>\n", xml_text(program)));
    for argument in &spec.arguments {
        let text = argument.to_str().unwrap_or_default();
        out.push_str(&format!("\t\t<string>{}</string>\n", xml_text(text)));
    }
    out.push_str("\t</array>\n");
    key(&mut out, "RunAtLoad");
    out.push_str("\t<true/>\n");
    if let Some(first) = spec.failure_policy.restart_delays.first() {
        key(&mut out, "KeepAlive");
        out.push_str("\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
        key(&mut out, "ThrottleInterval");
        out.push_str(&format!("\t<integer>{}</integer>\n", first.as_secs()));
    }
    key(&mut out, "ProcessType");
    out.push_str("\t<string>Standard</string>\n");
    key(&mut out, "ExitTimeOut");
    out.push_str(&format!(
        "\t<integer>{}</integer>\n",
        EXIT_TIMEOUT.as_secs()
    ));
    if let UnixIdentity::User(sandbox) = &spec.unix_identity {
        key(&mut out, "UserName");
        out.push_str(&format!("\t<string>{}</string>\n", xml_text(&sandbox.user)));
        key(&mut out, "GroupName");
        out.push_str(&format!(
            "\t<string>{}</string>\n",
            xml_text(&sandbox.group)
        ));
    }
    if let Some(limit) = spec.open_files_limit {
        for limits in ["SoftResourceLimits", "HardResourceLimits"] {
            key(&mut out, limits);
            out.push_str(&format!(
                "\t<dict>\n\t\t<key>NumberOfFiles</key>\n\t\t<integer>{limit}</integer>\n\t</dict>\n"
            ));
        }
    }
    if spec.systemd_hardening.umask_0077 {
        key(&mut out, "Umask");
        out.push_str("\t<integer>63</integer>\n");
    }
    if let Some(log) = log_file.and_then(Path::to_str) {
        for stream in ["StandardOutPath", "StandardErrorPath"] {
            key(&mut out, stream);
            out.push_str(&format!("\t<string>{}</string>\n", xml_text(log)));
        }
    }
    out.push_str(PLIST_TAIL);
    Ok(out)
}

/// `text` escaped for an XML text node or attribute.
#[must_use]
pub fn xml_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The service's state from `launchctl print system/<label>`'s output: its
/// top-level `state = …` line (one tab deep; nested blocks carry their own
/// `state` lines). `running` is [`ServiceState::Running`]; `not running`
/// and `exited` are [`ServiceState::Stopped`]; `spawn scheduled` and
/// `waiting` (a restart throttled by `ThrottleInterval`) are
/// [`ServiceState::StartPending`]; anything else is
/// [`ServiceState::Unknown`], which neither a start nor a stop wait reads
/// as success. launchctl's text isn't an interface Apple promises, so the
/// mapping reads only that one line and fails closed.
#[must_use]
pub fn state(print_output: &str) -> ServiceState {
    let value = print_output.lines().find_map(|line| {
        let rest = line.strip_prefix('\t')?;
        if rest.starts_with('\t') {
            return None;
        }
        rest.strip_prefix("state = ")
    });
    match value.map(str::trim) {
        Some("running") => ServiceState::Running,
        Some("not running" | "exited") => ServiceState::Stopped,
        Some("spawn scheduled" | "waiting") => ServiceState::StartPending,
        _ => ServiceState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::spec::{FailurePolicy, SystemdSandbox};

    fn spec() -> ServiceSpec {
        let mut spec = ServiceSpec {
            name: "com.acme.agent".into(),
            display_name: "Acme Agent".into(),
            description: "The Acme agent".into(),
            program: "/Applications/Acme Agent.app/Contents/MacOS/AcmeAgent".into(),
            arguments: vec!["service".into(), "--name=a&b".into()],
            failure_policy: FailurePolicy {
                reset_period: Duration::from_secs(86_400),
                restart_delays: vec![Duration::from_secs(15), Duration::from_secs(900)],
            },
            open_files_limit: Some(4096),
            unix_identity: UnixIdentity::Root,
            ..ServiceSpec::default()
        };
        spec.systemd_hardening.umask_0077 = true;
        spec
    }

    #[test]
    fn the_daemon_plist_runs_the_program_and_restarts_only_after_a_failure() {
        let text = plist(&spec()).unwrap();
        assert_eq!(
            text,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>com.acme.agent</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>/Applications/Acme Agent.app/Contents/MacOS/AcmeAgent</string>\n\
             \t\t<string>service</string>\n\
             \t\t<string>--name=a&amp;b</string>\n\
             \t</array>\n\
             \t<key>RunAtLoad</key>\n\
             \t<true/>\n\
             \t<key>KeepAlive</key>\n\
             \t<dict>\n\
             \t\t<key>SuccessfulExit</key>\n\
             \t\t<false/>\n\
             \t</dict>\n\
             \t<key>ThrottleInterval</key>\n\
             \t<integer>15</integer>\n\
             \t<key>ProcessType</key>\n\
             \t<string>Standard</string>\n\
             \t<key>ExitTimeOut</key>\n\
             \t<integer>20</integer>\n\
             \t<key>SoftResourceLimits</key>\n\
             \t<dict>\n\
             \t\t<key>NumberOfFiles</key>\n\
             \t\t<integer>4096</integer>\n\
             \t</dict>\n\
             \t<key>HardResourceLimits</key>\n\
             \t<dict>\n\
             \t\t<key>NumberOfFiles</key>\n\
             \t\t<integer>4096</integer>\n\
             \t</dict>\n\
             \t<key>Umask</key>\n\
             \t<integer>63</integer>\n\
             </dict>\n\
             </plist>\n"
        );
        assert_eq!(
            plist_path(&spec()).unwrap(),
            PathBuf::from("/Library/LaunchDaemons/com.acme.agent.plist")
        );
    }

    #[test]
    fn a_sandbox_runs_as_its_account_and_no_delays_means_no_restarts() {
        let mut spec = spec();
        spec.unix_identity = UnixIdentity::User(SystemdSandbox {
            user: "_acme".into(),
            group: "_acme".into(),
            capabilities: Vec::new(),
            allow_root: false,
        });
        spec.failure_policy.restart_delays.clear();
        let text = plist(&spec).unwrap();
        assert!(
            text.contains("\t<key>UserName</key>\n\t<string>_acme</string>\n\t<key>GroupName</key>\n\t<string>_acme</string>\n"),
            "{text}"
        );
        assert!(!text.contains("KeepAlive"), "{text}");
        assert!(!text.contains("ThrottleInterval"), "{text}");
    }

    #[test]
    fn values_a_plist_cannot_carry_safely_are_refused() {
        for name in ["", ".hidden", "a/b", "a b", "-x", "a%b", "a:b", "a@b"] {
            let mut bad = spec();
            bad.name = name.into();
            assert!(
                matches!(plist(&bad), Err(ServiceError::InvalidName(_))),
                "{name:?}"
            );
        }
        let mut long = spec();
        long.name = "a".repeat(201);
        assert!(matches!(plist(&long), Err(ServiceError::InvalidName(_))));
        let mut control = spec();
        control.arguments = vec!["a\u{1}b".into()];
        assert!(matches!(plist(&control), Err(ServiceError::InvalidSpec(_))));
        let mut relative = spec();
        relative.program = "AcmeAgent".into();
        assert!(matches!(
            plist(&relative),
            Err(ServiceError::InvalidSpec(_))
        ));
        let mut credentials = spec();
        credentials.environment_files = vec!["/etc/acme/env".into()];
        let err = plist(&credentials).unwrap_err().to_string();
        assert!(err.contains("environment_files"), "{err}");
        let mut root = spec();
        root.unix_identity = UnixIdentity::User(SystemdSandbox {
            user: "root".into(),
            group: "wheel".into(),
            capabilities: Vec::new(),
            allow_root: false,
        });
        assert!(plist(&root).is_err(), "a sandbox never names root silently");
        for (user, group) in [
            ("acme", "wheel"),
            ("0", "acme"),
            ("acme", "1"),
            ("a b", "acme"),
        ] {
            let mut bad = spec();
            bad.unix_identity = UnixIdentity::User(SystemdSandbox {
                user: user.into(),
                group: group.into(),
                capabilities: Vec::new(),
                allow_root: false,
            });
            assert!(
                matches!(plist(&bad), Err(ServiceError::InvalidName(_))),
                "{user}:{group}"
            );
        }
        let mut capabilities = spec();
        capabilities.unix_identity = UnixIdentity::User(SystemdSandbox {
            user: "_acme".into(),
            group: "_acme".into(),
            capabilities: vec!["CAP_NET_BIND_SERVICE".into()],
            allow_root: false,
        });
        assert!(matches!(
            plist(&capabilities),
            Err(ServiceError::InvalidSpec(_))
        ));
        let mut opted_in = spec();
        opted_in.unix_identity = UnixIdentity::User(SystemdSandbox {
            user: "root".into(),
            group: "wheel".into(),
            capabilities: Vec::new(),
            allow_root: true,
        });
        assert!(plist(&opted_in).is_ok(), "allow_root opts in");
        let mut hot = spec();
        hot.failure_policy.restart_delays = vec![Duration::from_millis(500)];
        assert!(matches!(plist(&hot), Err(ServiceError::InvalidSpec(_))));
        // No identity named: never root by omission.
        let mut unspecified = spec();
        unspecified.unix_identity = UnixIdentity::Unspecified;
        let err = plist(&unspecified).unwrap_err().to_string();
        assert!(err.contains("unix_identity is unspecified"), "{err}");
    }

    #[test]
    fn xml_specials_are_escaped() {
        assert_eq!(
            xml_text("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;"
        );
    }

    #[test]
    fn launchctl_print_s_state_line_maps_and_unknown_fails_closed() {
        let print = |state: &str| {
            format!(
                "system/com.acme.agent = {{\n\
                 \tactive count = 1\n\
                 \tpath = /Library/LaunchDaemons/com.acme.agent.plist\n\
                 \ttype = LaunchDaemon\n\
                 \tstate = {state}\n\
                 \n\
                 \tprogram = /Applications/Acme Agent.app/Contents/MacOS/AcmeAgent\n\
                 \tendpoints = {{\n\
                 \t\tstate = running\n\
                 \t}}\n\
                 }}\n"
            )
        };
        assert_eq!(state(&print("running")), ServiceState::Running);
        assert_eq!(state(&print("not running")), ServiceState::Stopped);
        assert_eq!(state(&print("exited")), ServiceState::Stopped);
        assert_eq!(state(&print("spawn scheduled")), ServiceState::StartPending);
        assert_eq!(state(&print("waiting")), ServiceState::StartPending);
        assert_eq!(state(&print("penalty box")), ServiceState::Unknown);
        // Only the top-level line counts: a nested block's `state` never does.
        assert_eq!(
            state("system/x = {\n\t\tstate = running\n}\n"),
            ServiceState::Unknown
        );
        assert_eq!(state(""), ServiceState::Unknown);
    }

    #[test]
    fn a_package_s_daemon_logs_to_its_file() {
        let log = Path::new("/Library/Logs/Acme/Agent/com.acme.agent.log");
        let text = daemon_plist(&spec(), log).unwrap();
        let plain = plist(&spec()).unwrap();
        // The backend's plist, with both streams appended to the log file.
        assert_eq!(
            text,
            plain.replace(
                "</dict>\n</plist>\n",
                "\t<key>StandardOutPath</key>\n\
                 \t<string>/Library/Logs/Acme/Agent/com.acme.agent.log</string>\n\
                 \t<key>StandardErrorPath</key>\n\
                 \t<string>/Library/Logs/Acme/Agent/com.acme.agent.log</string>\n\
                 </dict>\n</plist>\n"
            )
        );
        for bad in [
            "logs/agent.log",
            "/Library/Logs/",
            "/agent.log",
            "/Library/Logs/a\nb.log",
        ] {
            assert!(
                matches!(
                    daemon_plist(&spec(), Path::new(bad)),
                    Err(ServiceError::InvalidSpec(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_update_helper_runs_as_root_whenever_the_request_file_changes() {
        let text = update_helper_plist(
            &spec(),
            Path::new("/Applications/Acme Agent.app/Contents/MacOS/AcmeAgentUpdate"),
            Path::new("/Library/Application Support/Acme/Agent/state/update-request"),
            Path::new("/Library/Logs/Acme/Agent/com.acme.agent-update.log"),
        )
        .unwrap();
        assert_eq!(
            text,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \t<key>Label</key>\n\
             \t<string>com.acme.agent-update</string>\n\
             \t<key>ProgramArguments</key>\n\
             \t<array>\n\
             \t\t<string>/Applications/Acme Agent.app/Contents/MacOS/AcmeAgentUpdate</string>\n\
             \t</array>\n\
             \t<key>WatchPaths</key>\n\
             \t<array>\n\
             \t\t<string>/Library/Application Support/Acme/Agent/state/update-request</string>\n\
             \t</array>\n\
             \t<key>ProcessType</key>\n\
             \t<string>Standard</string>\n\
             \t<key>ExitTimeOut</key>\n\
             \t<integer>20</integer>\n\
             \t<key>Umask</key>\n\
             \t<integer>63</integer>\n\
             \t<key>StandardOutPath</key>\n\
             \t<string>/Library/Logs/Acme/Agent/com.acme.agent-update.log</string>\n\
             \t<key>StandardErrorPath</key>\n\
             \t<string>/Library/Logs/Acme/Agent/com.acme.agent-update.log</string>\n\
             </dict>\n\
             </plist>\n"
        );
        // Never at load, never kept alive, never as the service's account.
        for absent in ["RunAtLoad", "KeepAlive", "UserName"] {
            assert!(!text.contains(absent), "{absent}");
        }
        // A label with no room for `-update`, and paths a plist can't name.
        let mut long = spec();
        long.name = "a".repeat(195);
        assert!(matches!(
            update_helper_plist(
                &long,
                Path::new("/x/helper"),
                Path::new("/x/request"),
                Path::new("/x/log")
            ),
            Err(ServiceError::InvalidName(_))
        ));
        assert!(matches!(
            update_helper_plist(
                &spec(),
                Path::new("helper"),
                Path::new("/x/request"),
                Path::new("/x/log")
            ),
            Err(ServiceError::InvalidSpec(_))
        ));
        assert_eq!(
            update_helper_label(&spec()).unwrap(),
            "com.acme.agent-update"
        );
    }
}
