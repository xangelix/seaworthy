//! `service_unit` — `seaworthy-service`'s systemd unit renderer (via the
//! `__fuzz` seam): spec fields → the unit file systemd parses AS ROOT.
//!
//! Input: an `arbitrary`-built `ServiceSpec` (+ `--user` flag).
//!
//! Invariants on every rendered unit (the directive-injection class):
//! - structure: exactly `[Unit]`, `[Service]`, `[Install]` in order; every
//!   other line is `Key=value` with the key on a per-section allowlist; no
//!   line terminator systemd honors other than `\n` (no CR/NUL), no line
//!   continuation (`\` at a line end), no comment line; spec-fed keys
//!   appear exactly as often as the spec says (one `ExecStart`, one
//!   `Description`, one `EnvironmentFile` per file, at most one
//!   `User`/`Group`/`ReadWritePaths`) — a field can never add a line;
//! - `ExecStart`: an independent systemd.syntax unquoter (quotes, the two
//!   escapes the renderer emits, the `\;` literal, `%%` specifier and `$$`
//!   environment un-doubling — a lone `%`/`$` or an unescaped `;` word is a
//!   violation) recovers EXACTLY `[program, args...]`, and the first word
//!   carries no modifier prefix (`+`, `-`, `@`, `!`, `:`);
//! - `Description`, `User`, `Group`, `EnvironmentFile`, `ReadWritePaths`,
//!   `StateDirectory` recover exactly their spec values.
//!
//! And on the packaging renderers (`seaworthy_service::render::systemd`), for
//! the same spec:
//! - the update path unit is exactly `[Unit]`, `[Path]`, `[Install]`, with
//!   `PathChanged=/var/lib/<state_directory>/update-request`,
//!   `Unit=<name>-update.service` and `Description=<label> update request`
//!   recovered exactly — the label is the display name, or the description
//!   when there is none (the update units name the product as the MSI's
//!   helper service does);
//! - the helper unit is exactly `[Unit]`, `[Service]` (no `[Install]`), its
//!   `ExecStart` recovers the helper path alone, `CacheDirectory=` the cache
//!   directory and `Description=` `<label> updater` exactly;
//! - the `sysusers.d` text is a comment plus `g`/`u` lines only, and the
//!   `u` line's quoted GECOS field recovers the display name (`%%` the only
//!   `%` form) — no field can add a line or a column.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;
use std::time::Duration;

use arbitrary::{Arbitrary, Unstructured};
use seaworthy_service::{
    FailurePolicy, ServiceSpec, SystemdHardening, SystemdSandbox, UnixIdentity,
    WindowsServiceAccount,
};

#[derive(Arbitrary, Debug)]
enum Arg {
    Text(String),
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    name: String,
    description: String,
    program: String,
    args: Vec<Arg>,
    env_files: Vec<String>,
    delays: Vec<u16>,
    sandbox: Option<(String, String, Vec<String>, bool)>,
    flags: u32,
    families: Vec<String>,
    rw_paths: Vec<String>,
    user_unit: bool,
    state_directory: Option<String>,
    cache_directory: String,
    display_name: String,
    helper: String,
}

pub fn run(data: &[u8]) {
    let Ok(input) = Input::arbitrary_take_rest(Unstructured::new(data)) else {
        return;
    };
    let spec = build(&input);
    let Ok(unit) = seaworthy_service::__fuzz::render_systemd_unit(&spec, input.user_unit) else {
        return;
    };
    if let Err(why) = check_unit(&unit, &spec, input.user_unit) {
        panic!("rendered unit violates the structure oracle: {why}\n---\n{unit}---");
    }
    let render = seaworthy_service::render::systemd::update_path_unit;
    if let Ok(path_unit) = render(&spec)
        && let Err(why) = check_path_unit(&path_unit, &spec)
    {
        panic!("update path unit violates the oracle: {why}\n---\n{path_unit}---");
    }
    let helper = PathBuf::from(format!("/opt/{}", input.helper));
    if let Ok(helper_unit) = seaworthy_service::render::systemd::update_service_unit(
        &spec,
        &helper,
        &input.cache_directory,
    ) && let Err(why) = check_helper_unit(&helper_unit, &spec, &helper, &input.cache_directory)
    {
        panic!("helper unit violates the oracle: {why}\n---\n{helper_unit}---");
    }
    if let Ok(Some(text)) = seaworthy_service::render::systemd::sysusers(&spec)
        && let Err(why) = check_sysusers(&text, &spec)
    {
        panic!("sysusers text violates the oracle: {why}\n---\n{text}---");
    }
}

fn build(input: &Input) -> ServiceSpec {
    let mut hardening = SystemdHardening::none();
    let bit = |n: u32| input.flags & (1 << n) != 0;
    hardening.no_new_privileges = bit(0);
    hardening.protect_system_strict = bit(1);
    hardening.protect_home = bit(2);
    hardening.private_tmp = bit(3);
    hardening.private_devices = bit(4);
    hardening.protect_kernel_tunables = bit(5);
    hardening.protect_kernel_modules = bit(6);
    hardening.protect_kernel_logs = bit(7);
    hardening.protect_control_groups = bit(8);
    hardening.protect_clock = bit(9);
    hardening.protect_hostname = bit(10);
    hardening.protect_proc = bit(11);
    hardening.restrict_namespaces = bit(12);
    hardening.restrict_realtime = bit(13);
    hardening.restrict_suid_sgid = bit(14);
    hardening.lock_personality = bit(15);
    hardening.memory_deny_write_execute = bit(16);
    hardening.remove_ipc = bit(17);
    hardening.system_call_architectures_native = bit(18);
    hardening.system_call_filter = bit(19);
    hardening.restrict_address_families = bit(20);
    hardening.umask_0077 = bit(21);
    hardening.device_policy_closed = bit(22);
    hardening.extra_address_families = input.families.clone();
    hardening.read_write_paths = input
        .rw_paths
        .iter()
        .map(|p| PathBuf::from(format!("/{p}")))
        .collect();

    ServiceSpec {
        name: input.name.clone(),
        display_name: input.display_name.clone(),
        description: input.description.clone(),
        // Mostly-valid programs: '/'-rooted under a directory.
        program: PathBuf::from(format!("/opt/{}", input.program)),
        arguments: input
            .args
            .iter()
            .map(|arg| match arg {
                Arg::Text(text) => OsString::from(text),
                Arg::Raw(bytes) => OsString::from_vec(bytes.clone()),
            })
            .collect(),
        environment_files: input
            .env_files
            .iter()
            .map(|p| PathBuf::from(format!("/{p}")))
            .collect(),
        open_files_limit: None,
        failure_policy: FailurePolicy {
            reset_period: Duration::from_secs(3600),
            restart_delays: input
                .delays
                .iter()
                .map(|s| Duration::from_secs(u64::from(*s)))
                .collect(),
        },
        // A sandbox is a dedicated user; without one, bit 23 chooses root
        // and its absence leaves the identity unspecified (which a system
        // unit refuses).
        unix_identity: match &input.sandbox {
            Some((user, group, capabilities, allow_root)) => UnixIdentity::User(SystemdSandbox {
                user: user.clone(),
                group: group.clone(),
                capabilities: capabilities.clone(),
                allow_root: *allow_root,
            }),
            None if bit(23) => UnixIdentity::Root,
            None => UnixIdentity::Unspecified,
        },
        systemd_hardening: hardening,
        windows_account: WindowsServiceAccount::default(),
        state_directory: input.state_directory.clone(),
    }
}

const UNIT_KEYS: &[&str] = &["Description", "After", "Wants", "StartLimitIntervalSec"];
const SERVICE_KEYS: &[&str] = &[
    "Type",
    "ExecStart",
    "Restart",
    "RestartSec",
    "RestartSteps",
    "RestartMaxDelaySec",
    "EnvironmentFile",
    "User",
    "Group",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "DevicePolicy",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "ProtectProc",
    "ProcSubset",
    "RestrictNamespaces",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RemoveIPC",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "RestrictAddressFamilies",
    "UMask",
    "ReadWritePaths",
    "LimitNOFILE",
    "StateDirectory",
    "StateDirectoryMode",
];
const INSTALL_KEYS: &[&str] = &["WantedBy"];

fn check_unit(unit: &str, spec: &ServiceSpec, user_unit: bool) -> Result<(), String> {
    if unit.contains(['\r', '\0']) {
        return Err("a CR/NUL line terminator".into());
    }
    if unit.chars().any(|c| c.is_control() && c != '\n') {
        return Err("a control character".into());
    }
    let mut sections = Vec::new();
    let mut values: HashMap<&str, Vec<&str>> = HashMap::new();
    for line in unit.lines() {
        if line.is_empty() {
            continue;
        }
        if line.ends_with('\\') {
            return Err(format!("line continuation: {line:?}"));
        }
        if line.starts_with(['#', ';']) || line.starts_with(char::is_whitespace) {
            return Err(format!("comment/indented line: {line:?}"));
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push(section);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("not Key=value: {line:?}"))?;
        let allowed = match sections.last().copied() {
            Some("Unit") => UNIT_KEYS,
            Some("Service") => SERVICE_KEYS,
            Some("Install") => INSTALL_KEYS,
            other => return Err(format!("{key} outside a known section ({other:?})")),
        };
        if !allowed.contains(&key) {
            return Err(format!("key {key:?} not allowed in its section"));
        }
        values.entry(key).or_default().push(value);
    }
    if sections != ["Unit", "Service", "Install"] {
        return Err(format!("sections {sections:?}"));
    }
    let count = |key: &str| values.get(key).map_or(0, Vec::len);
    for (key, max) in [
        ("User", 1),
        ("Group", 1),
        ("ReadWritePaths", 1),
        ("CapabilityBoundingSet", 1),
        ("AmbientCapabilities", 1),
        ("RestrictAddressFamilies", 1),
    ] {
        if count(key) > max {
            return Err(format!("{key} appears {} times", count(key)));
        }
    }
    for key in SERVICE_KEYS.iter().chain(UNIT_KEYS).chain(INSTALL_KEYS) {
        let max = if *key == "SystemCallFilter" { 2 } else { 1 };
        if *key != "EnvironmentFile" && count(key) > max {
            return Err(format!("{key} appears {} times", count(key)));
        }
    }
    if count("ExecStart") != 1 || count("Description") != 1 {
        return Err("ExecStart/Description must appear exactly once".into());
    }
    // LimitNOFILE: rendered on every unit, exactly the spec's value (or the
    // documented default) — never a value a spec field could inject.
    let expected_nofile = spec
        .open_files_limit
        .unwrap_or(seaworthy_service::DEFAULT_OPEN_FILES_LIMIT)
        .to_string();
    if values.get("LimitNOFILE").map(Vec::as_slice) != Some(&[expected_nofile.as_str()][..]) {
        return Err(format!(
            "LimitNOFILE must appear once as {expected_nofile}: {:?}",
            values.get("LimitNOFILE")
        ));
    }
    if count("EnvironmentFile") != spec.environment_files.len() {
        return Err("EnvironmentFile count differs from the spec".into());
    }
    match &spec.state_directory {
        Some(dir) => {
            if values.get("StateDirectory").map(Vec::as_slice) != Some(&[dir.as_str()][..])
                || values.get("StateDirectoryMode").map(Vec::as_slice) != Some(&["0700"][..])
            {
                return Err("StateDirectory/StateDirectoryMode differ from the spec".into());
            }
        }
        None => {
            if count("StateDirectory") + count("StateDirectoryMode") != 0 {
                return Err("StateDirectory without a spec value".into());
            }
        }
    }

    // Description: `%%` is the only `%` form.
    let description =
        undouble(values["Description"][0], '%').ok_or("a lone % (specifier) in Description")?;
    if description != spec.description {
        return Err(format!("Description recovers {description:?}"));
    }

    // ExecStart: the independent unquoter.
    let exec = values["ExecStart"][0];
    if exec.starts_with(['+', '-', '@', '!', ':']) {
        return Err("ExecStart carries a modifier prefix".into());
    }
    let argv = systemd_argv(exec)?;
    let mut expected = vec![spec.program.to_str().unwrap().to_owned()];
    expected.extend(
        spec.arguments
            .iter()
            .map(|a| a.to_str().unwrap().to_owned()),
    );
    if argv != expected {
        return Err(format!("ExecStart recovers {argv:?}, spec is {expected:?}"));
    }

    // Plain-value directives recover their spec values exactly.
    for (index, file) in spec.environment_files.iter().enumerate() {
        if values["EnvironmentFile"][index] != file.to_str().unwrap() {
            return Err("EnvironmentFile value differs".into());
        }
    }
    if !user_unit && spec.unix_identity == UnixIdentity::Unspecified {
        return Err("a system unit rendered without an identity".into());
    }
    if let (UnixIdentity::User(sandbox), false) = (&spec.unix_identity, user_unit) {
        if values.get("User").map(|v| v[0]) != Some(sandbox.user.as_str())
            || values.get("Group").map(|v| v[0]) != Some(sandbox.group.as_str())
        {
            return Err("User/Group differ from the sandbox".into());
        }
    } else if count("User") + count("Group") != 0 {
        return Err("User/Group without a system-unit sandbox".into());
    }
    if let Some(paths) = values.get("ReadWritePaths") {
        let rendered: Vec<&str> = paths[0].split(' ').collect();
        for path in &spec.systemd_hardening.read_write_paths {
            if !rendered.contains(&path.to_str().unwrap()) {
                return Err("a ReadWritePaths entry is missing or split".into());
            }
        }
        if rendered
            .iter()
            .any(|p| !p.starts_with('/') || p.contains(['"', '\'', '\\', '%']))
        {
            return Err("a ReadWritePaths word is not a plain absolute path".into());
        }
    }
    Ok(())
}

/// A parsed unit: its section names in order, and each `(section, key)`'s
/// values in order.
type ParsedUnit = (Vec<String>, HashMap<(String, String), Vec<String>>);

/// Splits a rendered unit into `(sections, key → values)`, refusing
/// anything that isn't a section header or a plain `Key=value` line.
fn parse_unit(unit: &str) -> Result<ParsedUnit, String> {
    if unit.chars().any(|c| c.is_control() && c != '\n') {
        return Err("a control character".into());
    }
    let mut sections: Vec<String> = Vec::new();
    let mut values: HashMap<(String, String), Vec<String>> = HashMap::new();
    for line in unit.lines().filter(|l| !l.is_empty()) {
        if line.ends_with('\\')
            || line.starts_with(['#', ';'])
            || line.starts_with(char::is_whitespace)
        {
            return Err(format!("continuation/comment/indented line: {line:?}"));
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push(section.to_owned());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("not Key=value: {line:?}"))?;
        let section = sections.last().cloned().ok_or("a key before any section")?;
        values
            .entry((section, key.to_owned()))
            .or_default()
            .push(value.to_owned());
    }
    Ok((sections, values))
}

fn one<'a>(
    values: &'a HashMap<(String, String), Vec<String>>,
    section: &str,
    key: &str,
) -> Result<&'a str, String> {
    match values
        .get(&(section.to_owned(), key.to_owned()))
        .map(Vec::as_slice)
    {
        Some([value]) => Ok(value),
        other => Err(format!("{section}.{key} must appear once: {other:?}")),
    }
}

fn check_path_unit(unit: &str, spec: &ServiceSpec) -> Result<(), String> {
    let (sections, values) = parse_unit(unit)?;
    if sections != ["Unit", "Path", "Install"] {
        return Err(format!("sections {sections:?}"));
    }
    let allowed = [
        ("Unit", "Description"),
        ("Path", "PathChanged"),
        ("Path", "Unit"),
        ("Install", "WantedBy"),
    ];
    if let Some(((section, key), _)) = values
        .iter()
        .find(|((s, k), _)| !allowed.contains(&(s.as_str(), k.as_str())))
    {
        return Err(format!("{section}.{key} not allowed"));
    }
    let state = spec
        .state_directory
        .as_deref()
        .ok_or("rendered without a state directory")?;
    if one(&values, "Path", "PathChanged")? != format!("/var/lib/{state}/update-request") {
        return Err("PathChanged differs from the state directory".into());
    }
    if one(&values, "Path", "Unit")? != format!("{}-update.service", spec.name) {
        return Err("Unit differs from <name>-update.service".into());
    }
    let description = one(&values, "Unit", "Description")?;
    if undouble(description, '%') != Some(format!("{} update request", update_label(spec))) {
        return Err("Description does not recover".into());
    }
    Ok(())
}

/// What the update units call the product: the display name, or the
/// description when there is none.
fn update_label(spec: &ServiceSpec) -> &str {
    if spec.display_name.is_empty() {
        &spec.description
    } else {
        &spec.display_name
    }
}

fn check_helper_unit(
    unit: &str,
    spec: &ServiceSpec,
    helper: &std::path::Path,
    cache: &str,
) -> Result<(), String> {
    let (sections, values) = parse_unit(unit)?;
    if sections != ["Unit", "Service"] {
        return Err(format!(
            "sections {sections:?} (the helper has no [Install])"
        ));
    }
    let exec = one(&values, "Service", "ExecStart")?;
    if exec.starts_with(['+', '-', '@', '!', ':']) {
        return Err("ExecStart carries a modifier prefix".into());
    }
    if systemd_argv(exec)? != [helper.to_str().unwrap().to_owned()] {
        return Err("ExecStart does not recover the helper path alone".into());
    }
    if one(&values, "Service", "CacheDirectory")? != cache {
        return Err("CacheDirectory differs".into());
    }
    if one(&values, "Service", "ProtectSystem")? != "strict" {
        return Err("the helper is not ProtectSystem=strict".into());
    }
    let description = one(&values, "Unit", "Description")?;
    if undouble(description, '%') != Some(format!("{} updater", update_label(spec))) {
        return Err("Description does not recover".into());
    }
    Ok(())
}

fn check_sysusers(text: &str, spec: &ServiceSpec) -> Result<(), String> {
    let UnixIdentity::User(sandbox) = &spec.unix_identity else {
        return Err("sysusers text without a sandbox user".into());
    };
    let lines: Vec<&str> = text.lines().collect();
    if lines.first().is_none_or(|l| !l.starts_with("# ")) || lines.len() < 2 || lines.len() > 3 {
        return Err(format!("{} lines", lines.len()));
    }
    for line in &lines[1..] {
        if line.starts_with("g ") {
            if *line != format!("g {} -", sandbox.group) {
                return Err(format!("unexpected g line {line:?}"));
            }
        } else if let Some(rest) = line.strip_prefix("u ") {
            let id = if sandbox.group == sandbox.user {
                "-".to_owned()
            } else {
                format!("-:{}", sandbox.group)
            };
            let head = format!("{} {id} \"", sandbox.user);
            let gecos = rest
                .strip_prefix(&head)
                .and_then(|r| r.strip_suffix("\" - -"))
                .ok_or_else(|| format!("u line shape {line:?}"))?;
            if gecos.contains('"')
                || undouble(gecos, '%').as_deref() != Some(spec.display_name.as_str())
            {
                return Err("the GECOS field does not recover the display name".into());
            }
        } else {
            return Err(format!("unexpected line {line:?}"));
        }
    }
    Ok(())
}

/// Un-double `mark` (`%%` → `%`); `None` on a lone `mark`.
fn undouble(text: &str, mark: char) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == mark && chars.next() != Some(mark) {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

/// systemd's ExecStart word splitting (systemd.syntax / systemd.service
/// "Command lines"), restricted to what a SAFE rendering may contain.
fn systemd_argv(value: &str) -> Result<Vec<String>, String> {
    let mut argv = Vec::new();
    let mut chars = value.chars().peekable();
    loop {
        while chars
            .next_if(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
            .is_some()
        {}
        if chars.peek().is_none() {
            break;
        }
        let mut raw_word = String::new();
        let mut word = String::new();
        let mut quoted = false;
        let mut escaped_semicolon = false;
        while let Some(&c) = chars.peek() {
            if !quoted && matches!(c, ' ' | '\t' | '\n' | '\r') {
                break;
            }
            chars.next();
            raw_word.push(c);
            match c {
                '"' => quoted = !quoted,
                '\\' => {
                    let escaped = chars.next().ok_or("a trailing backslash")?;
                    raw_word.push(escaped);
                    match escaped {
                        '\\' | '"' if quoted => word.push(escaped),
                        ';' if !quoted => {
                            escaped_semicolon = true;
                            word.push(';');
                        }
                        other => return Err(format!("an unexpected escape \\{other}")),
                    }
                }
                '\'' if !quoted => return Err("an unquoted single quote".into()),
                other => word.push(other),
            }
        }
        if quoted {
            return Err("an unterminated quote".into());
        }
        if raw_word == ";" {
            return Err("an unescaped ';' command separator".into());
        }
        if escaped_semicolon && raw_word != "\\;" {
            return Err("an escaped ';' inside a longer word".into());
        }
        let word = undouble(&word, '%').ok_or("a lone % (specifier) in ExecStart")?;
        let word = undouble(&word, '$').ok_or("a lone $ (env substitution) in ExecStart")?;
        argv.push(word);
    }
    Ok(argv)
}
