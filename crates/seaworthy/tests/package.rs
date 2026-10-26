//! Step 4 for Linux, over the synthetic fixture product (the Windows side
//! is `tests/wix.rs`):
//!
//! - what a Linux package carries (tree, units, `sysusers.d`, preset,
//!   owned directories, retired units);
//! - golden files for the package scripts and the nFPM configurations
//!   (`tests/golden/`; `SEAWORTHY_BLESS=1` rewrites them, for review in
//!   the diff);
//! - every package script parsed by `sh`, `dash` and `shellcheck`, and the
//!   lifecycle played out for deb, rpm and pacman against a stateful
//!   stand-in `systemctl` on an isolated `PATH` (the host's own `systemctl`
//!   is never reachable): fresh installs, masked units, site presets,
//!   upgrades (adding and dropping units), a deb reinstall after `apt
//!   remove`, dpkg's abort calls, a unit that fails to start,
//!   `policy-rc.d`, `DPKG_ROOT`, a tampered marker, removal, and hosts
//!   without a running systemd or without systemd at all;
//! - real deb, rpm and pacman packages built with nFPM and read back with
//!   `dpkg-deb`, `rpm`, `bsdtar` and `pacman`, built twice, byte-identical.
//!
//! The installed behaviour on real distributions (systemd as PID 1) is the
//! Linux conformance lane's. A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure. An
//! explicitly configured `NFPM` that doesn't run always fails.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output as ProcessOutput};

use common::{artifact, build, golden, have, layout_for, layouts, nfpm, release, run};
use seaworthy::config::{Config, Output};
use seaworthy::inputs::LINUX;
use seaworthy::linux::{Source, linux_package};
use seaworthy::package::{Kind, Options, package};
use seaworthy::scripts::{Units, scripts};

const AGENT: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"
homepage = "https://acme.test"

[product.agent]
display-name = "Acme Agent"
description = "Collects things for Acme."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
sidecars.windows = ["extra_*.dll"]
outputs = ["msi", "zip", "deb", "rpm", "pacman", "tar"]
linux.depends.deb = ["libc6 (>= 2.36)"]
linux.depends.rpm = ["glibc >= 2.34"]
linux.depends.pacman = ["glibc"]

[product.agent.service]
name = "AcmeAgent"
account = "virtual"
arguments = ["service", "--mode", "full scan"]
restart-delays = ["15s", "60s"]
state-directory = "acme/agent"

[product.agent.service.sandbox]
user = "acme-agent"
"#;

const DESKTOP: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
sidecars.windows = ["extra_*.dll"]
outputs = ["deb", "tar"]
updates.default = "notify"
"#;

// ---------------------------------------------------------------------------
// What a Linux package carries

#[test]
fn a_linux_package_carries_the_tree_units_sysusers_and_preset() {
    let config = Config::parse(AGENT).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "agent", tmp.path());
    let pkg = linux_package(&config, "agent", layout_for(&layouts, LINUX)).unwrap();
    assert_eq!(pkg.name, "acme-agent");
    assert_eq!(
        pkg.directories,
        [
            "/opt/acme",
            "/opt/acme/agent",
            "/opt/acme/agent/lib",
            "/opt/acme/agent/libexec"
        ]
    );
    let files: BTreeMap<&str, (u32, &Source)> = pkg
        .files
        .iter()
        .map(|f| (f.dst.as_str(), (f.mode, &f.source)))
        .collect();
    let generated = |dst: &str| match files.get(dst) {
        Some((0o644, Source::Generated(text))) => text.clone(),
        other => panic!("{dst}: {other:?}"),
    };
    for staged in [
        "/opt/acme/agent/AcmeTool",
        "/opt/acme/agent/lib/libacme_core_x86-64-v3.so",
        "/opt/acme/agent/lib/libacme_core_x86-64-v2.so",
        "/opt/acme/agent/libexec/acme-agent-update",
    ] {
        assert!(
            matches!(files.get(staged), Some((0o755, Source::Staged(_)))),
            "{staged}"
        );
    }
    let unit = generated("/usr/lib/systemd/system/AcmeAgent.service");
    assert!(
        unit.contains("ExecStart=/opt/acme/agent/AcmeTool service --mode \"full scan\"\n"),
        "{unit}"
    );
    assert!(unit.contains("StateDirectory=acme/agent\n"), "{unit}");
    let path = generated("/usr/lib/systemd/system/AcmeAgent-update.path");
    assert!(
        path.contains("PathChanged=/var/lib/acme/agent/update-request\n"),
        "{path}"
    );
    let helper = generated("/usr/lib/systemd/system/AcmeAgent-update.service");
    assert!(
        helper.contains("ExecStart=/opt/acme/agent/libexec/acme-agent-update\n"),
        "{helper}"
    );
    assert!(helper.contains("CacheDirectory=acme/agent\n"), "{helper}");
    let sysusers = generated("/usr/lib/sysusers.d/AcmeAgent.conf");
    assert!(
        sysusers.contains("u acme-agent - \"Acme Agent\" - -\n"),
        "{sysusers}"
    );
    assert_eq!(
        generated("/usr/lib/systemd/system-preset/80-acme-agent.preset"),
        "# Generated by seaworthy: enable this package's units by default.\n\
         # A site preset in /etc/systemd/system-preset that sorts earlier wins.\n\
         enable AcmeAgent-update.path\nenable AcmeAgent.service\n"
    );
    assert_eq!(pkg.units.service.as_deref(), Some("AcmeAgent.service"));
    assert_eq!(
        pkg.units.update_path.as_deref(),
        Some("AcmeAgent-update.path")
    );
    assert_eq!(
        pkg.units.update_service.as_deref(),
        Some("AcmeAgent-update.service")
    );
    assert!(pkg.units.retired.is_empty());
    assert_eq!(
        pkg.units.sysusers.as_deref(),
        Some("/usr/lib/sysusers.d/AcmeAgent.conf")
    );
}

#[test]
fn a_service_without_the_helper_retires_the_update_path_unit() {
    let config = Config::parse(
        &AGENT
            .replace("helper = \"AcmeToolUpdate\"\n", "")
            .replace("outputs = [", "updates.default = \"off\"\noutputs = ["),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "agent", tmp.path());
    let pkg = linux_package(&config, "agent", layout_for(&layouts, LINUX)).unwrap();
    assert_eq!(pkg.units.update_path, None);
    assert_eq!(pkg.units.retired, ["AcmeAgent-update.path"]);
    assert!(
        !pkg.files.iter().any(|f| f.dst.contains("-update.")),
        "{:?}",
        pkg.files
    );
}

#[test]
fn a_desktop_package_without_the_helper_carries_no_units_and_no_scripts() {
    let config = Config::parse(
        &DESKTOP.replace("updates.default = \"notify\"", "updates.default = \"off\""),
    )
    .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "console", tmp.path());
    let pkg = linux_package(&config, "console", layout_for(&layouts, LINUX)).unwrap();
    assert!(
        pkg.files
            .iter()
            .all(|f| f.dst.starts_with("/opt/acme/console/")),
        "{:?}",
        pkg.files
    );
    assert!(pkg.units.enabled().is_empty());
    assert_eq!(pkg.units.update_service, None);
    for format in [Output::Deb, Output::Rpm, Output::Pacman] {
        assert!(scripts(format, &pkg.name, &pkg.units).is_none());
    }
}

/// A desktop app's helper is started by the logged-in session, so
/// its package carries the helper's unit (nothing enables it) and the
/// polkit rule letting an active local session start exactly that unit.
#[test]
fn a_desktop_package_with_the_helper_carries_its_unit_and_polkit_rule() {
    let config = Config::parse(DESKTOP).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let desktop = layouts(&config, "console", tmp.path());
    let pkg = linux_package(&config, "console", layout_for(&desktop, LINUX)).unwrap();
    let generated = |dst: &str| match pkg.files.iter().find(|f| f.dst == dst) {
        Some(file) => match (&file.source, file.mode) {
            (Source::Generated(text), 0o644) => text.clone(),
            other => panic!("{dst}: {other:?}"),
        },
        None => panic!("{dst} isn't packaged: {:?}", pkg.files),
    };
    let names = config
        .update_product("console", &config.products["console"])
        .unwrap();
    assert_eq!(names.helper_name(), "acme-console-update");
    let unit = generated("/usr/lib/systemd/system/acme-console-update.service");
    assert_eq!(
        unit,
        seaworthy_service::render::systemd::desktop_update_service_unit(
            "Acme Console",
            Path::new("/opt/acme/console/libexec/acme-console-update"),
            "acme/console",
        )
        .unwrap()
    );
    assert!(!unit.contains("[Install]"), "{unit}");
    let rule = generated(&seaworthy::linux::polkit_rule_path("acme-console-update"));
    assert_eq!(
        seaworthy::linux::polkit_rule_path("acme-console-update"),
        "/usr/share/polkit-1/rules.d/60-acme-console-update.rules"
    );
    assert!(
        rule.contains("action.lookup(\"unit\") === \"acme-console-update.service\"")
            && rule.contains("action.lookup(\"verb\") === \"start\"")
            && rule.contains("subject.local && subject.active"),
        "{rule}"
    );
    // Nothing enabled, no preset, no path unit: only the helper's oneshot.
    assert!(pkg.units.enabled().is_empty());
    assert_eq!(
        pkg.units.update_service.as_deref(),
        Some("acme-console-update.service")
    );
    assert!(
        !pkg.files
            .iter()
            .any(|f| f.dst.ends_with(".path") || f.dst.contains("system-preset")),
        "{:?}",
        pkg.files
    );
    for format in [Output::Deb, Output::Rpm, Output::Pacman] {
        let s = scripts(format, &pkg.name, &pkg.units).unwrap();
        for text in [
            &s.pre_install,
            &s.post_install,
            &s.pre_remove,
            &s.post_remove,
        ] {
            assert!(
                !text.contains(" start ") && !text.contains("preset") && !text.contains("enable"),
                "{format:?}: never started, preset or enabled:\n{text}"
            );
        }
    }
    // The unit needs systemd (rpm: before its scripts run), the helper the
    // CA store, and the rule polkit.
    let versions = release().package_versions().unwrap();
    for (format, polkit) in [
        (Output::Deb, "polkitd | policykit-1"),
        (Output::Rpm, "polkit"),
        (Output::Pacman, "polkit"),
    ] {
        let path = seaworthy::nfpm::write_config(
            &config,
            "console",
            &pkg,
            format,
            &versions,
            1_700_000_000,
            &tmp.path().join("work"),
        )
        .unwrap();
        let nfpm: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let depends: Vec<&str> = nfpm["depends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        for want in ["systemd", "ca-certificates", polkit] {
            assert!(depends.contains(&want), "{format:?}: {depends:?}");
        }
        assert_eq!(
            nfpm["rpm"]["requires"]["post"],
            serde_json::json!(["systemd"]),
            "{format:?}"
        );
    }
    // A tool's helper ships as a file only: no unit, no start right.
    let tool = Config::parse(&DESKTOP.replace("kind = \"desktop\"", "kind = \"tool\"")).unwrap();
    let tool_layouts = layouts(&tool, "console", &tmp.path().join("tool"));
    let pkg = linux_package(&tool, "console", layout_for(&tool_layouts, LINUX)).unwrap();
    assert_eq!(pkg.units.update_service, None);
    assert!(
        pkg.files
            .iter()
            .all(|f| f.dst.starts_with("/opt/acme/console/")),
        "{:?}",
        pkg.files
    );
}

// ---------------------------------------------------------------------------
// Package scripts: text

fn agent_units() -> Units {
    Units {
        service: Some("AcmeAgent.service".into()),
        update_path: Some("AcmeAgent-update.path".into()),
        update_service: Some("AcmeAgent-update.service".into()),
        retired: vec![],
        sysusers: Some("/usr/lib/sysusers.d/AcmeAgent.conf".into()),
    }
}

/// The units of the same product built without the helper.
fn helperless_units() -> Units {
    Units {
        update_path: None,
        update_service: None,
        retired: vec!["AcmeAgent-update.path".into()],
        ..agent_units()
    }
}

/// A desktop app's: its helper's oneshot, alone.
fn desktop_units() -> Units {
    Units {
        update_service: Some("acme-console-update.service".into()),
        ..Units::default()
    }
}

/// Every script of every format, by `<prefix><format>-<phase>.sh`.
fn all_scripts(units: &Units, prefix: &str) -> Vec<(String, String)> {
    let package = if prefix == "desktop-" {
        "acme-console"
    } else {
        "acme-agent"
    };
    let mut all = Vec::new();
    for (format, name) in [
        (Output::Deb, "deb"),
        (Output::Rpm, "rpm"),
        (Output::Pacman, "pacman"),
    ] {
        let s = scripts(format, package, units).unwrap();
        all.push((format!("{prefix}{name}-preinstall.sh"), s.pre_install));
        all.push((format!("{prefix}{name}-postinstall.sh"), s.post_install));
        all.push((format!("{prefix}{name}-preremove.sh"), s.pre_remove));
        all.push((format!("{prefix}{name}-postremove.sh"), s.post_remove));
        if let Some(text) = s.pre_upgrade {
            all.push((format!("{prefix}{name}-preupgrade.sh"), text));
        }
        if let Some(text) = s.post_upgrade {
            all.push((format!("{prefix}{name}-postupgrade.sh"), text));
        }
    }
    all
}

#[test]
fn package_scripts_match_their_golden_files() {
    for (name, text) in all_scripts(&agent_units(), "")
        .into_iter()
        .chain(all_scripts(&helperless_units(), "helperless-"))
        .chain(all_scripts(&desktop_units(), "desktop-"))
    {
        golden(&format!("scripts/{name}"), &text);
    }
}

#[test]
fn package_scripts_parse_in_every_shell_and_pass_shellcheck() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, text) in all_scripts(&agent_units(), "")
        .into_iter()
        .chain(all_scripts(&helperless_units(), "helperless-"))
        .chain(all_scripts(&desktop_units(), "desktop-"))
    {
        let path = tmp.path().join(&name);
        std::fs::write(&path, &text).unwrap();
        for shell in ["sh", "dash", "bash"] {
            if have(shell, &["-c", "true"]) {
                run(Command::new(shell).arg("-n").arg(&path));
            }
        }
        if have("shellcheck", &["--version"]) {
            run(Command::new("shellcheck")
                .args(["--shell=sh", "--severity=style"])
                .arg(&path));
        }
    }
}

// ---------------------------------------------------------------------------
// Package scripts: the lifecycle on a simulated host

/// A stand-in systemctl: logs every call, keeps unit state in
/// `$SIM/state/<unit>`, applies the site preset in `$SIM/site-preset`, and
/// fails a start or restart of a unit listed in `$SIM/fail`.
const STUB_SYSTEMCTL: &str = r#"#!/bin/sh
echo "systemctl $*" >> "$SIM/log"
[ "$1" = --no-block ] && shift
quiet=
if [ "$1" = is-enabled ] && [ "$2" = --quiet ]; then quiet=1; set -- is-enabled "$3"; fi
case "$1" in
  start|try-restart|restart)
    for arg in "$@"; do
      if [ -f "$SIM/fail" ] && grep -qx "$arg" "$SIM/fail"; then echo "Job for $arg failed." >&2; exit 1; fi
    done ;;
esac
state_of() { cat "$SIM/state/$1" 2>/dev/null || echo disabled; }
case "$1" in
  is-enabled)
    s=$(state_of "$2")
    [ -n "$quiet" ] || echo "$s"
    case "$s" in enabled|enabled-runtime|static|indirect|alias|generated) exit 0 ;; *) exit 1 ;; esac ;;
  preset)
    if [ "$(state_of "$2")" = masked ]; then echo "Failed to preset unit: Unit $2 is masked." >&2; exit 1; fi
    if [ -f "$SIM/site-preset" ] && grep -qx "disable $2" "$SIM/site-preset"; then echo disabled > "$SIM/state/$2"; else echo enabled > "$SIM/state/$2"; fi ;;
  disable)
    shift
    for unit in "$@"; do [ "$(state_of "$unit")" = masked ] || echo disabled > "$SIM/state/$unit"; done ;;
  *) : ;;
esac
"#;

/// The few tools the scripts and the stand-ins use, by absolute path, so a
/// test's `PATH` holds nothing else (the host's `systemctl` stays out).
#[cfg(unix)]
const TOOLS: &[&str] = &["cat", "rm", "mkdir", "grep"];

fn which(tool: &str) -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{tool} not on PATH"))
}

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// A simulated host: unit files, unit state, a site preset policy, and
/// stand-ins for `systemctl` and `systemd-sysusers` that log every call.
struct Host {
    root: tempfile::TempDir,
    shell: PathBuf,
}

impl Host {
    fn new(shell: &str, running: bool) -> Self {
        Self::with(shell, running, true)
    }

    fn with(shell: &str, running: bool, systemd_installed: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["bin", "state", "units", "run"] {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        if running {
            std::fs::create_dir_all(root.path().join("run/systemd/system")).unwrap();
        }
        let bin = root.path().join("bin");
        #[cfg(unix)]
        for tool in TOOLS {
            std::os::unix::fs::symlink(which(tool), bin.join(tool)).unwrap();
        }
        if systemd_installed {
            executable(&bin.join("systemctl"), STUB_SYSTEMCTL);
            executable(
                &bin.join("systemd-sysusers"),
                "#!/bin/sh\necho \"systemd-sysusers $*\" >> \"$SIM/log\"\n",
            );
        }
        Self {
            root,
            shell: which(shell),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.path().join(relative)
    }

    /// The package's unit files as a version ships them.
    fn unpack(&self, units: &[&str]) {
        for unit in units {
            std::fs::write(self.path("units").join(unit), "[Unit]\n").unwrap();
        }
    }

    /// A version's removal deleting its unit files.
    fn delete_units(&self, units: &[&str]) {
        for unit in units {
            std::fs::remove_file(self.path("units").join(unit)).unwrap();
        }
    }

    fn set_state(&self, unit: &str, state: &str) {
        std::fs::write(self.path("state").join(unit), state).unwrap();
    }

    fn state(&self, unit: &str) -> String {
        std::fs::read_to_string(self.path("state").join(unit))
            .map_or_else(|_| "disabled".into(), |s| s.trim().to_owned())
    }

    fn site_preset(&self, line: &str) {
        std::fs::write(self.path("site-preset"), format!("{line}\n")).unwrap();
    }

    fn fail(&self, unit: &str) {
        std::fs::write(self.path("fail"), format!("{unit}\n")).unwrap();
    }

    fn policy_rc_d(&self, exit: u8) {
        executable(
            &self.path("policy-rc.d"),
            &format!("#!/bin/sh\necho \"policy-rc.d $*\" >> \"$SIM/log\"\nexit {exit}\n"),
        );
    }

    /// The script with the host's paths in place of the real ones.
    fn localize(&self, text: &str) -> String {
        let root = self.root.path().display().to_string();
        text.replace("/run/systemd/system", &format!("{root}/run/systemd/system"))
            .replace("/run/seaworthy", &format!("{root}/run/seaworthy"))
            .replace("[ -d /run ]", &format!("[ -d {root}/run ]"))
            .replace("/usr/lib/systemd/system/", &format!("{root}/units/"))
            .replace("/usr/sbin/policy-rc.d", &format!("{root}/policy-rc.d"))
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.shell);
        cmd.env_clear()
            .env("PATH", self.path("bin"))
            .env("SIM", self.root.path());
        cmd
    }

    fn finish(output: ProcessOutput) -> String {
        assert!(
            output.status.success(),
            "the script failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    /// Runs a deb or rpm script with `args` and `env`; its stderr.
    fn script_env(&self, text: &str, args: &[&str], env: &[(&str, &str)]) -> String {
        let path = self.path("script.sh");
        std::fs::write(&path, self.localize(text)).unwrap();
        let mut cmd = self.command();
        cmd.arg(&path).args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        Self::finish(cmd.output().unwrap())
    }

    fn script(&self, text: &str, args: &[&str]) -> String {
        self.script_env(text, args, &[])
    }

    /// Runs a pacman script as nFPM's `.INSTALL` holds it: the script as
    /// the body of `function`, called with `args` by bash.
    fn pacman(&self, function: &str, text: &str, args: &[&str]) {
        let path = self.path("install");
        std::fs::write(
            &path,
            format!("function {function}() {{\n{}\n}}\n", self.localize(text)),
        )
        .unwrap();
        let mut cmd = self.command();
        cmd.arg("-c")
            .arg(format!(". \"$0\"; {function} \"$@\""))
            .arg(&path)
            .args(args);
        Self::finish(cmd.output().unwrap());
    }

    /// The calls since the last `take`, without `is-enabled` queries.
    fn take(&self) -> Vec<String> {
        let log = self.path("log");
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_file(&log);
        text.lines()
            .filter(|l| !l.starts_with("systemctl is-enabled"))
            .map(str::to_owned)
            .collect()
    }

    fn marker(&self) -> PathBuf {
        self.path("run/seaworthy/acme-agent.new-units")
    }

    fn no_marker_left(&self) {
        assert!(
            !self.marker().exists(),
            "the marker outlived the transaction"
        );
    }
}

const SVC: &str = "AcmeAgent.service";
const PATH: &str = "AcmeAgent-update.path";
const HELPER: &str = "AcmeAgent-update.service";
const SYSUSERS: &str = "systemd-sysusers /usr/lib/sysusers.d/AcmeAgent.conf";

fn calls(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|l| (*l).to_owned()).collect()
}

fn install_calls() -> Vec<String> {
    calls(&[
        SYSUSERS,
        "systemctl daemon-reload",
        "systemctl preset AcmeAgent-update.path",
        "systemctl preset AcmeAgent.service",
        "systemctl --no-block start AcmeAgent-update.path",
        "systemctl --no-block start AcmeAgent.service",
    ])
}

fn upgrade_calls() -> Vec<String> {
    calls(&[
        SYSUSERS,
        "systemctl daemon-reload",
        "systemctl --no-block start AcmeAgent-update.path",
        "systemctl --no-block try-restart AcmeAgent.service",
    ])
}

fn remove_calls() -> Vec<String> {
    calls(&[
        "systemctl stop AcmeAgent-update.path AcmeAgent-update.service AcmeAgent.service",
        "systemctl disable AcmeAgent-update.path AcmeAgent.service",
    ])
}

fn shells() -> Vec<&'static str> {
    ["sh", "dash"]
        .into_iter()
        .filter(|s| have(s, &["-c", "true"]))
        .collect()
}

#[test]
fn deb_scripts_install_upgrade_and_remove() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        // Fresh install.
        host.script(&s.pre_install, &["install"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", ""]);
        assert_eq!(host.take(), install_calls(), "{shell}: install");
        assert_eq!(
            (host.state(SVC).as_str(), host.state(PATH).as_str()),
            ("enabled", "enabled")
        );
        host.no_marker_left();
        // Upgrade: old prerm, new preinst, unpack, old postrm, new postinst.
        host.script(&s.pre_remove, &["upgrade", "1.5.0-900"]);
        host.script(&s.pre_install, &["upgrade", "1.4.0~rc.2-812"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_remove, &["upgrade", "1.5.0-900"]);
        host.script(&s.post_install, &["configure", "1.4.0~rc.2-812"]);
        assert_eq!(host.take(), upgrade_calls(), "{shell}: upgrade");
        host.no_marker_left();
        // Removal, then purge.
        host.script(&s.pre_remove, &["remove"]);
        host.script(&s.post_remove, &["remove"]);
        host.script(&s.post_remove, &["purge"]);
        let mut expected = remove_calls();
        expected.extend(calls(&[
            "systemctl daemon-reload",
            "systemctl daemon-reload",
        ]));
        assert_eq!(host.take(), expected, "{shell}: remove");
        assert_eq!(
            (host.state(SVC).as_str(), host.state(PATH).as_str()),
            ("disabled", "disabled")
        );
    }
}

#[test]
fn a_deb_reinstall_after_remove_enables_and_starts_again() {
    // `apt remove` leaves the package in `rc`; reinstalling calls
    // `preinst install <old>` and `postinst configure <old>`, like an upgrade.
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.script(&s.pre_install, &["install"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", ""]);
        host.script(&s.pre_remove, &["remove"]);
        host.delete_units(&[SVC, PATH, HELPER]);
        host.script(&s.post_remove, &["remove"]);
        let _ = host.take();
        assert_eq!(host.state(SVC), "disabled");
        host.script(&s.pre_install, &["install", "1.4.0~rc.2-812"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", "1.4.0~rc.2-812"]);
        assert_eq!(host.take(), install_calls(), "{shell}: reinstall");
        assert_eq!(
            (host.state(SVC).as_str(), host.state(PATH).as_str()),
            ("enabled", "enabled")
        );
        host.no_marker_left();
    }
}

#[test]
fn deb_abort_and_failed_calls_restore_without_presets() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.unpack(&[SVC, PATH, HELPER]);
        host.set_state(SVC, "enabled");
        host.set_state(PATH, "enabled");
        // A failed upgrade: the old version is configured again.
        host.script(&s.pre_remove, &["failed-upgrade", "1.5.0-900"]);
        host.script(&s.post_remove, &["failed-upgrade", "1.5.0-900"]);
        assert!(
            host.take().is_empty(),
            "{shell}: failed-upgrade does nothing"
        );
        host.script(&s.post_install, &["abort-upgrade", "1.5.0-900"]);
        assert_eq!(host.take(), upgrade_calls(), "{shell}: abort-upgrade");
        // An aborted removal undoes `prerm remove`.
        host.script(&s.pre_remove, &["remove"]);
        let _ = host.take();
        host.script(&s.post_install, &["abort-remove"]);
        assert_eq!(host.take(), install_calls(), "{shell}: abort-remove");
        // An aborted install only drops the marker.
        host.script(&s.pre_install, &["install"]);
        host.script(&s.post_remove, &["abort-install"]);
        assert!(host.take().is_empty(), "{shell}");
        host.no_marker_left();
    }
}

#[test]
fn an_upgrade_that_adds_the_update_units_presets_and_starts_them() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        // The installed version shipped the service only.
        host.unpack(&[SVC]);
        host.set_state(SVC, "enabled");
        host.script(&s.pre_remove, &["upgrade", "1.5.0-900"]);
        host.script(&s.pre_install, &["upgrade", "1.4.0-700"]);
        host.unpack(&[PATH, HELPER]);
        // The old postrm runs between the new preinst and postinst, and
        // must leave the marker.
        host.script(&s.post_remove, &["upgrade", "1.5.0-900"]);
        host.script(&s.post_install, &["configure", "1.4.0-700"]);
        assert_eq!(
            host.take(),
            calls(&[
                SYSUSERS,
                "systemctl daemon-reload",
                "systemctl preset AcmeAgent-update.path",
                "systemctl --no-block start AcmeAgent-update.path",
                "systemctl --no-block try-restart AcmeAgent.service",
            ]),
            "{shell}"
        );
        assert_eq!(host.state(PATH), "enabled");
        host.no_marker_left();
    }
}

#[test]
fn an_upgrade_to_a_version_without_the_helper_stops_its_trigger() {
    // The dropped unit's file is still there before unpack.
    let s = scripts(Output::Deb, "acme-agent", &helperless_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.unpack(&[SVC, PATH, HELPER]);
        host.set_state(SVC, "enabled");
        host.set_state(PATH, "enabled");
        host.script(&s.pre_install, &["upgrade", "1.5.0-900"]);
        assert_eq!(
            host.take(),
            calls(&[
                "systemctl --no-block stop AcmeAgent-update.path",
                "systemctl disable AcmeAgent-update.path"
            ]),
            "{shell}"
        );
        assert_eq!(host.state(PATH), "disabled");
        host.delete_units(&[PATH, HELPER]);
        host.script(&s.post_install, &["configure", "1.5.0-900"]);
        assert_eq!(
            host.take(),
            calls(&[
                SYSUSERS,
                "systemctl daemon-reload",
                "systemctl --no-block try-restart AcmeAgent.service"
            ]),
            "{shell}"
        );
        host.no_marker_left();
    }
}

#[test]
fn masked_units_and_site_presets_are_respected() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        // A masked service: neither preset nor started; the path unit is.
        let host = Host::new(shell, true);
        host.set_state(SVC, "masked");
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", ""]);
        assert_eq!(
            host.take(),
            calls(&[
                SYSUSERS,
                "systemctl daemon-reload",
                "systemctl preset AcmeAgent-update.path",
                "systemctl --no-block start AcmeAgent-update.path",
            ]),
            "{shell}: masked"
        );
        assert_eq!(host.state(SVC), "masked");
        // An upgrade doesn't touch it either.
        host.script(&s.post_install, &["configure", "1.0.0-1"]);
        let upgrade = host.take();
        assert!(
            !upgrade.iter().any(|c| c.contains(SVC)),
            "{shell}: {upgrade:?}"
        );
        // A site preset disabling the service: preset, not started.
        let host = Host::new(shell, true);
        host.site_preset(&format!("disable {SVC}"));
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", ""]);
        let site = host.take();
        assert!(
            site.contains(&format!("systemctl preset {SVC}")),
            "{shell}: {site:?}"
        );
        assert!(
            !site.iter().any(|c| c.contains("start AcmeAgent.service")),
            "{shell}: {site:?}"
        );
        assert_eq!(host.state(SVC), "disabled");
    }
}

#[test]
fn a_unit_that_fails_to_start_warns_and_the_transaction_goes_on() {
    // One failing unit must not leave the package half-configured.
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.fail(PATH);
        host.script(&s.pre_install, &["install"]);
        host.unpack(&[SVC, PATH, HELPER]);
        let stderr = host.script(&s.post_install, &["configure", ""]);
        assert!(
            stderr.contains(
                "acme-agent: warning: 'systemctl --no-block start AcmeAgent-update.path' failed"
            ),
            "{shell}: {stderr}"
        );
        assert_eq!(
            host.take(),
            install_calls(),
            "{shell}: every later step still ran"
        );
        host.no_marker_left();
    }
}

#[test]
fn deb_honours_policy_rc_d_and_dpkg_root() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.policy_rc_d(101);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["configure", ""]);
        assert_eq!(
            host.take(),
            calls(&[
                SYSUSERS,
                "systemctl daemon-reload",
                "systemctl preset AcmeAgent-update.path",
                "systemctl preset AcmeAgent.service",
                "policy-rc.d AcmeAgent-update start",
                "policy-rc.d AcmeAgent start",
            ]),
            "{shell}: enabled for the next boot, never started"
        );
        let host = Host::new(shell, true);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script_env(
            &s.post_install,
            &["configure", ""],
            &[("DPKG_ROOT", "/target")],
        );
        assert_eq!(
            host.take(),
            calls(&["systemd-sysusers --root=/target /usr/lib/sysusers.d/AcmeAgent.conf"]),
            "{shell}: chrootless dpkg never touches the running system"
        );
        host.script_env(&s.pre_remove, &["remove"], &[("DPKG_ROOT", "/target")]);
        assert!(host.take().is_empty(), "{shell}");
    }
}

#[test]
fn the_marker_is_trusted_only_in_a_root_owned_directory_and_only_for_known_units() {
    let s = scripts(Output::Deb, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.unpack(&[SVC, PATH, HELPER]);
        std::fs::create_dir_all(host.path("run/seaworthy")).unwrap();
        std::fs::write(host.marker(), "evil.service\nAcmeAgent-update.path\n").unwrap();
        host.script(&s.post_install, &["configure", "1.0.0-1"]);
        let taken = host.take();
        assert!(
            !taken.iter().any(|c| c.contains("evil")),
            "{shell}: {taken:?}"
        );
        assert!(
            taken.contains(&"systemctl preset AcmeAgent-update.path".to_owned()),
            "{shell}: {taken:?}"
        );
        // A symlinked marker directory is ignored.
        let host = Host::new(shell, true);
        host.unpack(&[SVC]);
        let elsewhere = host.path("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&elsewhere, host.path("run/seaworthy")).unwrap();
        host.script(&s.pre_install, &["upgrade", "1.0.0-1"]);
        assert!(
            std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "{shell}: wrote through the symlink"
        );
    }
}

#[test]
fn without_a_running_systemd_units_are_enabled_but_never_started() {
    let s = scripts(Output::Rpm, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, false);
        host.script(&s.pre_install, &["1"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["1"]);
        assert_eq!(
            host.take(),
            calls(&[
                SYSUSERS,
                "systemctl preset AcmeAgent-update.path",
                "systemctl preset AcmeAgent.service"
            ]),
            "{shell}"
        );
        assert_eq!(host.state(SVC), "enabled");
        host.script(&s.pre_remove, &["0"]);
        host.script(&s.post_remove, &["0"]);
        assert_eq!(
            host.take(),
            calls(&["systemctl disable AcmeAgent-update.path AcmeAgent.service"]),
            "{shell}"
        );
    }
}

#[test]
fn without_systemd_installed_every_script_succeeds_and_does_nothing() {
    for format in [Output::Deb, Output::Rpm] {
        let s = scripts(format, "acme-agent", &agent_units()).unwrap();
        let (unpack, install, upgrade, remove): (&[&str], &[&str], &[&str], &[&str]) =
            if format == Output::Deb {
                (
                    &["install"],
                    &["configure", ""],
                    &["configure", "1.0.0-1"],
                    &["remove"],
                )
            } else {
                (&["1"], &["1"], &["2"], &["0"])
            };
        for shell in shells() {
            let host = Host::with(shell, false, false);
            host.script(&s.pre_install, unpack);
            host.script(&s.post_install, install);
            host.script(&s.post_install, upgrade);
            host.script(&s.pre_remove, remove);
            host.script(&s.post_remove, remove);
            assert!(host.take().is_empty(), "{shell} {format:?}");
        }
    }
}

#[test]
fn rpm_scripts_install_upgrade_and_erase() {
    let s = scripts(Output::Rpm, "acme-agent", &agent_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.script(&s.pre_install, &["1"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["1"]);
        assert_eq!(host.take(), install_calls(), "{shell}: install");
        // Upgrade: new %pre 2, unpack, new %post 2, old %preun 1, old %postun 1.
        host.script(&s.pre_install, &["2"]);
        host.unpack(&[SVC, PATH, HELPER]);
        host.script(&s.post_install, &["2"]);
        host.script(&s.pre_remove, &["1"]);
        host.script(&s.post_remove, &["1"]);
        assert_eq!(host.take(), upgrade_calls(), "{shell}: upgrade");
        host.no_marker_left();
        host.script(&s.pre_remove, &["0"]);
        host.script(&s.post_remove, &["0"]);
        let mut expected = remove_calls();
        expected.push("systemctl daemon-reload".into());
        assert_eq!(host.take(), expected, "{shell}: erase");
    }
}

#[test]
fn pacman_install_functions_install_upgrade_and_remove() {
    if !have("bash", &["-c", "true"]) {
        return;
    }
    let s = scripts(Output::Pacman, "acme-agent", &agent_units()).unwrap();
    let (pre_upgrade, post_upgrade) = (
        s.pre_upgrade.clone().unwrap(),
        s.post_upgrade.clone().unwrap(),
    );
    let host = Host::new("bash", true);
    host.pacman("pre_install", &s.pre_install, &["1.4.0rc.2-812"]);
    host.unpack(&[SVC, PATH, HELPER]);
    host.pacman("post_install", &s.post_install, &["1.4.0rc.2-812"]);
    assert_eq!(host.take(), install_calls(), "install");
    host.pacman("pre_upgrade", &pre_upgrade, &["1.5.0-900", "1.4.0rc.2-812"]);
    host.unpack(&[SVC, PATH, HELPER]);
    host.pacman(
        "post_upgrade",
        &post_upgrade,
        &["1.5.0-900", "1.4.0rc.2-812"],
    );
    assert_eq!(host.take(), upgrade_calls(), "upgrade");
    host.no_marker_left();
    host.pacman("pre_remove", &s.pre_remove, &["1.5.0-900"]);
    host.pacman("post_remove", &s.post_remove, &["1.5.0-900"]);
    let mut expected = remove_calls();
    expected.push("systemctl daemon-reload".into());
    assert_eq!(host.take(), expected, "remove");
}

/// A desktop app's scripts only reload systemd after an install or
/// upgrade and stop its helper before removal, in every format; without a
/// running systemd, or without systemd, they do nothing.
#[test]
fn a_desktop_apps_helper_unit_is_never_started_by_its_scripts() {
    const UNIT: &str = "acme-console-update.service";
    let reload = || calls(&["systemctl daemon-reload"]);
    let remove = || {
        calls(&[
            "systemctl stop acme-console-update.service",
            "systemctl daemon-reload",
        ])
    };
    let deb = scripts(Output::Deb, "acme-console", &desktop_units()).unwrap();
    let rpm = scripts(Output::Rpm, "acme-console", &desktop_units()).unwrap();
    for shell in shells() {
        let host = Host::new(shell, true);
        host.script(&deb.pre_install, &["install"]);
        host.unpack(&[UNIT]);
        host.script(&deb.post_install, &["configure", ""]);
        assert_eq!(host.take(), reload(), "{shell}: deb install");
        host.script(&deb.pre_remove, &["upgrade", "1.5.0-900"]);
        host.script(&deb.pre_install, &["upgrade", "1.4.0~rc.2-812"]);
        host.script(&deb.post_remove, &["upgrade", "1.5.0-900"]);
        host.script(&deb.post_install, &["configure", "1.4.0~rc.2-812"]);
        assert_eq!(host.take(), reload(), "{shell}: deb upgrade");
        host.script(&deb.pre_remove, &["remove"]);
        host.script(&deb.post_remove, &["remove"]);
        assert_eq!(host.take(), remove(), "{shell}: deb remove");
        assert_eq!(host.state(UNIT), "disabled", "never enabled");

        host.script(&rpm.pre_install, &["1"]);
        host.script(&rpm.post_install, &["1"]);
        assert_eq!(host.take(), reload(), "{shell}: rpm install");
        host.script(&rpm.pre_install, &["2"]);
        host.script(&rpm.post_install, &["2"]);
        host.script(&rpm.pre_remove, &["1"]);
        host.script(&rpm.post_remove, &["1"]);
        assert_eq!(host.take(), reload(), "{shell}: rpm upgrade");
        host.script(&rpm.pre_remove, &["0"]);
        host.script(&rpm.post_remove, &["0"]);
        assert_eq!(host.take(), remove(), "{shell}: rpm erase");

        // No running systemd (an image build), or none at all: nothing.
        for host in [Host::new(shell, false), Host::with(shell, true, false)] {
            host.script(&deb.pre_install, &["install"]);
            host.script(&deb.post_install, &["configure", ""]);
            host.script(&deb.pre_remove, &["remove"]);
            host.script(&deb.post_remove, &["remove"]);
            assert_eq!(host.take(), Vec::<String>::new(), "{shell}");
        }
    }
    if have("bash", &["-c", "true"]) {
        let pacman = scripts(Output::Pacman, "acme-console", &desktop_units()).unwrap();
        let host = Host::new("bash", true);
        host.pacman("pre_install", &pacman.pre_install, &["1.4.0rc.2-812"]);
        host.pacman("post_install", &pacman.post_install, &["1.4.0rc.2-812"]);
        assert_eq!(host.take(), reload(), "pacman install");
        let args = ["1.5.0-900", "1.4.0rc.2-812"];
        host.pacman("pre_upgrade", pacman.pre_upgrade.as_ref().unwrap(), &args);
        host.pacman("post_upgrade", pacman.post_upgrade.as_ref().unwrap(), &args);
        assert_eq!(host.take(), reload(), "pacman upgrade");
        host.pacman("pre_remove", &pacman.pre_remove, &["1.5.0-900"]);
        host.pacman("post_remove", &pacman.post_remove, &["1.5.0-900"]);
        assert_eq!(host.take(), remove(), "pacman remove");
    }
}

// ---------------------------------------------------------------------------
// nFPM configurations

/// A generated file with the temporary directory replaced by `<tmp>`.
fn portable(text: &str, tmp: &Path) -> String {
    text.replace(&tmp.display().to_string(), "<tmp>")
}

#[test]
fn nfpm_configurations_match_their_golden_files() {
    let config = Config::parse(AGENT).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "agent", tmp.path());
    let pkg = linux_package(&config, "agent", layout_for(&layouts, LINUX)).unwrap();
    let versions = release().package_versions().unwrap();
    let work = tmp.path().join("work");
    for (format, name) in [
        (Output::Deb, "deb"),
        (Output::Rpm, "rpm"),
        (Output::Pacman, "archlinux"),
    ] {
        let path = seaworthy::nfpm::write_config(
            &config,
            "agent",
            &pkg,
            format,
            &versions,
            1_700_000_000,
            &work,
        )
        .unwrap();
        assert_eq!(path, work.join(name).join("nfpm.json"));
        golden(
            &format!("nfpm/{name}.json"),
            &portable(&std::fs::read_to_string(&path).unwrap(), tmp.path()),
        );
    }
}

// ---------------------------------------------------------------------------
// Real packages

#[test]
fn every_output_builds_reads_back_and_reproduces() {
    let Some(nfpm) = nfpm() else { return };
    let version = seaworthy::nfpm::tool_version(&nfpm).unwrap();
    if version != seaworthy::nfpm::PINNED_VERSION {
        eprintln!(
            "WARNING: nFPM {version}, not the pinned {}",
            seaworthy::nfpm::PINNED_VERSION
        );
    }
    let config = Config::parse(AGENT).unwrap();
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let first = build(&config, "agent", a.path(), &nfpm, None);
    let second = build(&config, "agent", b.path(), &nfpm, None);
    let names = |artifacts: &[seaworthy::package::Artifact]| -> Vec<(Kind, String, String)> {
        artifacts
            .iter()
            .map(|x| {
                (
                    x.kind,
                    x.path.file_name().unwrap().to_string_lossy().into_owned(),
                    x.sha256.clone(),
                )
            })
            .collect()
    };
    let listed = names(&first);
    assert_eq!(
        listed
            .iter()
            .map(|(k, n, _)| (*k, n.as_str()))
            .collect::<Vec<_>>(),
        [
            (Kind::Wxs, "acme-agent-1.4.0-rc.2-812-windows-x86_64.wxs"),
            (
                Kind::PolicyTemplates,
                "acme-agent-1.4.0-rc.2-812-policy-templates.zip"
            ),
            (Kind::Zip, "acme-agent-1.4.0-rc.2-812-windows-x86_64.zip"),
            (Kind::Deb, "acme-agent_1.4.0~rc.2-812_amd64.deb"),
            (Kind::Rpm, "acme-agent-1.4.0~rc.2-812.x86_64.rpm"),
            (Kind::Pacman, "acme-agent-1.4.0rc.2-812-x86_64.pkg.tar.zst"),
            (Kind::Tar, "acme-agent-1.4.0-rc.2-812-linux-x86_64.tar.zst"),
            (
                Kind::Sbom,
                "acme-agent-1.4.0-rc.2-812-windows-x86_64.zip.cdx.json"
            ),
            (Kind::Sbom, "acme-agent_1.4.0~rc.2-812_amd64.deb.cdx.json"),
            (Kind::Sbom, "acme-agent-1.4.0~rc.2-812.x86_64.rpm.cdx.json"),
            (
                Kind::Sbom,
                "acme-agent-1.4.0rc.2-812-x86_64.pkg.tar.zst.cdx.json"
            ),
            (
                Kind::Sbom,
                "acme-agent-1.4.0-rc.2-812-linux-x86_64.tar.zst.cdx.json"
            ),
        ]
    );
    // Each SBOM describes its artifact's final bytes and its files.
    let deb_sbom: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            a.path()
                .join("dist/agent/packages/acme-agent_1.4.0~rc.2-812_amd64.deb.cdx.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        deb_sbom["metadata"]["component"]["hashes"][0]["content"],
        seaworthy_crypto::digest::sha512_hex(&std::fs::read(artifact(&first, Kind::Deb)).unwrap())
    );
    let sbom_files: Vec<&str> = deb_sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(
        sbom_files.contains(&"/usr/lib/systemd/system/AcmeAgent.service"),
        "{sbom_files:?}"
    );
    assert!(
        sbom_files.contains(&"/opt/acme/agent/AcmeTool"),
        "{sbom_files:?}"
    );
    // Byte for byte, twice.
    assert_eq!(listed, names(&second), "two builds differ");
    let listing: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(a.path().join("dist/agent/packages.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(listing["version"], "1.4.0-rc.2");
    assert_eq!(listing["sequence"], 812);
    assert_eq!(
        listing["artifacts"][3]["file"],
        "packages/acme-agent_1.4.0~rc.2-812_amd64.deb"
    );
    assert_eq!(listing["artifacts"][3]["sha256"], listed[3].2);
    let in_packages: Vec<String> = std::fs::read_dir(a.path().join("dist/agent/packages"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    assert_eq!(
        in_packages.len(),
        listed.len(),
        "only the listed artifacts: {in_packages:?}"
    );

    let deb = artifact(&first, Kind::Deb);
    if have("dpkg-deb", &["--version"]) {
        let field = |name: &str| {
            run(Command::new("dpkg-deb").arg("-f").arg(&deb).arg(name))
                .trim()
                .to_owned()
        };
        assert_eq!(field("Package"), "acme-agent");
        assert_eq!(field("Version"), "1.4.0~rc.2-812");
        assert_eq!(field("Architecture"), "amd64");
        assert_eq!(field("Maintainer"), "Acme Packaging <pkg@acme.test>");
        // The helper ships: its TLS client needs the CA store.
        assert_eq!(
            field("Depends"),
            "libc6 (>= 2.36), systemd, ca-certificates"
        );
        assert_eq!(field("Homepage"), "https://acme.test");
        let contents = run(Command::new("dpkg-deb").arg("-c").arg(&deb));
        for (mode, path) in [
            ("-rwxr-xr-x root/root", "./opt/acme/agent/AcmeTool"),
            (
                "-rwxr-xr-x root/root",
                "./opt/acme/agent/libexec/acme-agent-update",
            ),
            (
                "-rw-r--r-- root/root",
                "./usr/lib/systemd/system/AcmeAgent.service",
            ),
            (
                "-rw-r--r-- root/root",
                "./usr/lib/systemd/system/AcmeAgent-update.path",
            ),
            (
                "-rw-r--r-- root/root",
                "./usr/lib/sysusers.d/AcmeAgent.conf",
            ),
            (
                "-rw-r--r-- root/root",
                "./usr/lib/systemd/system-preset/80-acme-agent.preset",
            ),
        ] {
            assert!(
                contents
                    .lines()
                    .any(|l| l.starts_with(mode) && l.ends_with(path)),
                "{mode} {path} in:\n{contents}"
            );
        }
        let control = tempfile::tempdir().unwrap();
        run(Command::new("dpkg-deb")
            .arg("-e")
            .arg(&deb)
            .arg(control.path()));
        for script in ["preinst", "postinst", "prerm", "postrm"] {
            let text = std::fs::read_to_string(control.path().join(script)).unwrap();
            assert!(
                text.contains("Generated by seaworthy: acme-agent, deb"),
                "{script}: {text}"
            );
        }
    }
    let rpm = artifact(&first, Kind::Rpm);
    if have("rpm", &["--version"]) {
        let db = tempfile::tempdir().unwrap();
        let rpm_q = |args: &[&str]| {
            run(Command::new("rpm")
                .arg("--dbpath")
                .arg(db.path())
                .arg("-qp")
                .args(args)
                .arg(&rpm))
        };
        assert_eq!(
            rpm_q(&[
                "--qf",
                "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{BUILDHOST}|%{BUILDTIME}|%{LICENSE}"
            ]),
            "acme-agent|1.4.0~rc.2|812|x86_64|seaworthy|1700000000|MIT"
        );
        let requires = rpm_q(&["--requires"]);
        assert!(
            requires.lines().any(|l| l.trim() == "glibc >= 2.34"),
            "{requires}"
        );
        assert!(
            requires.lines().any(|l| l.trim() == "systemd"),
            "{requires}"
        );
        let scripts = rpm_q(&["--scripts"]);
        for phase in ["preinstall", "postinstall", "preuninstall", "postuninstall"] {
            assert!(
                scripts.contains(&format!("{phase} scriptlet (using /bin/sh)")),
                "{scripts}"
            );
        }
        assert!(
            scripts.contains("Generated by seaworthy: acme-agent, rpm"),
            "{scripts}"
        );
        let files = rpm_q(&["-lv"]);
        for dir in [
            "/opt/acme",
            "/opt/acme/agent",
            "/opt/acme/agent/lib",
            "/opt/acme/agent/libexec",
        ] {
            assert!(
                files
                    .lines()
                    .any(|l| l.starts_with("drwxr-xr-x") && l.ends_with(&format!(" {dir}"))),
                "rpm owns {dir}:\n{files}"
            );
        }
        for system in [
            "/opt",
            "/usr/lib/systemd/system",
            "/usr/lib/systemd/system-preset",
            "/usr/lib/sysusers.d",
        ] {
            assert!(
                !files.lines().any(|l| l.ends_with(&format!(" {system}"))),
                "never {system}:\n{files}"
            );
        }
    }
    let pacman = artifact(&first, Kind::Pacman);
    if have("bsdtar", &["--version"]) {
        let read = |member: &str| run(Command::new("bsdtar").arg("-xOf").arg(&pacman).arg(member));
        let info = read(".PKGINFO");
        for line in [
            "pkgname = acme-agent",
            "pkgver = 1.4.0rc.2-812",
            "arch = x86_64",
            "depend = glibc",
            "depend = systemd",
            "builddate = 1700000000",
        ] {
            assert!(info.lines().any(|l| l == line), "{line} in:\n{info}");
        }
        let install = read(".INSTALL");
        for function in [
            "pre_install",
            "post_install",
            "pre_upgrade",
            "post_upgrade",
            "pre_remove",
            "post_remove",
        ] {
            assert!(
                install.contains(&format!("function {function}() {{")),
                "{function} in:\n{install}"
            );
        }
        assert!(
            install.contains("Generated by seaworthy: acme-agent, pacman"),
            "{install}"
        );
        if have("pacman", &["--version"]) {
            let q = run(Command::new("pacman").arg("-Qip").arg(&pacman));
            assert!(
                q.lines()
                    .any(|l| l.starts_with("Version") && l.ends_with("1.4.0rc.2-812")),
                "{q}"
            );
        }
    }
    if have("tar", &["--version"]) && have("zstd", &["--version"]) {
        let listing = run(Command::new("tar")
            .arg("--zstd")
            .arg("-tf")
            .arg(artifact(&first, Kind::Tar)));
        let top = "acme-agent-1.4.0-rc.2-812";
        for entry in [
            format!("{top}/"),
            format!("{top}/AcmeTool"),
            format!("{top}/lib/"),
            format!("{top}/lib/libacme_core_x86-64-v3.so"),
            format!("{top}/libexec/acme-agent-update"),
        ] {
            assert!(
                listing.lines().any(|l| l == entry),
                "{entry} in:\n{listing}"
            );
        }
        assert!(
            !listing.contains("systemd"),
            "the tarball is the tree only:\n{listing}"
        );
    }
    if have("zipinfo", &["-v"]) {
        let listing = run(Command::new("zipinfo")
            .arg("-1")
            .arg(artifact(&first, Kind::Zip)));
        let top = "acme-agent-1.4.0-rc.2-812";
        assert_eq!(
            listing.lines().collect::<Vec<_>>(),
            [
                format!("{top}/"),
                format!("{top}/AcmeTool.exe"),
                format!("{top}/AcmeToolUpdate.exe"),
                format!("{top}/acme_core_x86-64-v2.dll"),
                format!("{top}/acme_core_x86-64-v3.dll"),
                format!("{top}/extra_1.dll"),
            ]
        );
        let policy = run(Command::new("zipinfo")
            .arg("-1")
            .arg(artifact(&first, Kind::PolicyTemplates)));
        assert_eq!(
            policy.lines().collect::<Vec<_>>(),
            [
                "PolicyDefinitions/Acme.Agent.admx",
                "PolicyDefinitions/en-US/Acme.Agent.adml"
            ]
        );
    }
}

#[test]
fn a_packages_directory_seaworthy_did_not_create_is_never_replaced() {
    let config =
        Config::parse(&DESKTOP.replace("outputs = [\"deb\", \"tar\"]", "outputs = [\"tar\"]"))
            .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "console", tmp.path());
    let packages = tmp.path().join("dist/console/packages");
    std::fs::create_dir_all(&packages).unwrap();
    std::fs::write(packages.join("precious"), "keep").unwrap();
    let err = package(
        &config,
        "console",
        &layouts,
        &tmp.path().join("dist"),
        &Options {
            release: release(),
            mtime: 1_700_000_000,
            nfpm: PathBuf::from("nfpm"),
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("was not created by seaworthy"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(packages.join("precious")).unwrap(),
        "keep"
    );
}

// ---------------------------------------------------------------------------
// The repository package

/// A stand-in for a pinned key: the package carries the armored text as
/// it is, and nothing here reads it as a key.
const PLACEHOLDER_KEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZacmeFgkrBgEEAdpHDwEBB0Bplaceholder\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n";

/// [`AGENT`] with `[defaults.repository]` and the pinned key in `dir`.
fn repository_config(dir: &Path, text: &str) -> Config {
    std::fs::write(dir.join("repo.asc"), PLACEHOLDER_KEY).unwrap();
    let text = text.replacen(
        "license = \"MIT\"\n",
        "license = \"MIT\"\nopenpgp-keys = [\"repo.asc\"]\n",
        1,
    ) + "\n[defaults.repository]\nurl = \"https://packages.acme.test/repo\"\n";
    let mut config = Config::parse(&text).unwrap();
    config.dir = dir.to_path_buf();
    config
}

#[test]
fn repository_nfpm_configurations_match_their_golden_files() {
    let tmp = tempfile::tempdir().unwrap();
    let config = repository_config(tmp.path(), AGENT);
    let versions = release().package_versions().unwrap();
    let work = tmp.path().join("work");
    for (format, name) in [(Output::Deb, "deb"), (Output::Rpm, "rpm")] {
        let contents = seaworthy::repository_package::contents(&config, format).unwrap();
        let path = seaworthy::nfpm::write_repository_config(
            &config,
            &contents,
            format,
            &versions,
            1_700_000_000,
            &work,
        )
        .unwrap();
        assert_eq!(path, work.join(name).join("nfpm.json"));
        golden(
            &format!("nfpm/repository-{name}.json"),
            &portable(&std::fs::read_to_string(&path).unwrap(), tmp.path()),
        );
    }
    // No pacman package (README: Arch's section and pacman-key), and no
    // product depends on it (the products' configurations are golden too).
    let err = seaworthy::repository_package::contents(&config, Output::Pacman)
        .unwrap_err()
        .to_string();
    assert!(err.contains("deb and rpm only"), "{err}");
}

#[test]
fn the_repository_package_is_built_in_the_formats_its_repositories_need() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        seaworthy::repository_package::formats(&repository_config(tmp.path(), AGENT)),
        [Output::Deb, Output::Rpm]
    );
    // The console builds a deb only (and a tarball): no DNF repository.
    assert_eq!(
        seaworthy::repository_package::formats(&repository_config(tmp.path(), DESKTOP)),
        [Output::Deb]
    );
    // Its keys must be armored: apt's `.asc` keyrings and dnf's gpgkey=.
    let config = repository_config(tmp.path(), AGENT);
    std::fs::write(tmp.path().join("repo.asc"), [0x99_u8, 0x01, 0x0d]).unwrap();
    let err = seaworthy::repository_package::contents(&config, Output::Deb)
        .unwrap_err()
        .to_string();
    assert!(err.contains("isn't an armored public key"), "{err}");
    std::fs::write(tmp.path().join("repo.asc"), "mQENBGacme\n").unwrap();
    let err = seaworthy::repository_package::contents(&config, Output::Rpm)
        .unwrap_err()
        .to_string();
    assert!(err.contains("isn't an armored public key"), "{err}");
    // Two keys (a rotation): one after the other, each on its own lines
    // even when a file lacks its final newline.
    let mut two = repository_config(tmp.path(), AGENT);
    std::fs::write(
        tmp.path().join("a.asc"),
        PLACEHOLDER_KEY.trim_end_matches('\n'),
    )
    .unwrap();
    std::fs::write(tmp.path().join("b.asc"), PLACEHOLDER_KEY).unwrap();
    two.defaults.openpgp_keys = vec!["a.asc".into(), "b.asc".into()];
    assert_eq!(
        seaworthy::repository_package::pinned_keys(&two).unwrap(),
        format!("{PLACEHOLDER_KEY}{PLACEHOLDER_KEY}")
    );
    // A key file past 1 MiB is refused unread.
    let mut big = PLACEHOLDER_KEY.as_bytes().to_vec();
    big.resize(1024 * 1024 + 1, b'A');
    std::fs::write(tmp.path().join("a.asc"), big).unwrap();
    let err = seaworthy::repository_package::pinned_keys(&two)
        .unwrap_err()
        .to_string();
    assert!(err.contains("is over 1048576 bytes"), "{err}");
    // Without [defaults.repository], nothing to build.
    let plain = Config::parse(AGENT).unwrap();
    let err = seaworthy::package::repository(
        &plain,
        &tmp.path().join("out"),
        &Options {
            release: release(),
            mtime: 1_700_000_000,
            nfpm: PathBuf::from("nfpm"),
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("no [defaults.repository]"), "{err}");
}

#[test]
fn the_repository_package_builds_reads_back_and_reproduces() {
    let Some(nfpm) = nfpm() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let config = repository_config(tmp.path(), AGENT);
    let options = Options {
        release: release(),
        mtime: 1_700_000_000,
        nfpm,
        wix: None,
        build: seaworthy::sign::BuildId::default(),
    };
    let signing = seaworthy::package::Signing::default();
    let first =
        seaworthy::package::repository(&config, &tmp.path().join("a"), &options, &signing).unwrap();
    let second =
        seaworthy::package::repository(&config, &tmp.path().join("b"), &options, &signing).unwrap();
    let names = |artifacts: &[seaworthy::package::Artifact]| -> Vec<(Kind, String, String)> {
        artifacts
            .iter()
            .map(|x| {
                (
                    x.kind,
                    x.path.file_name().unwrap().to_string_lossy().into_owned(),
                    x.sha256.clone(),
                )
            })
            .collect()
    };
    assert_eq!(
        names(&first)
            .iter()
            .map(|(k, n, _)| (*k, n.as_str()))
            .collect::<Vec<_>>(),
        [
            (Kind::Deb, "acme-repository_1.4.0~rc.2-812_all.deb"),
            (Kind::Rpm, "acme-repository-1.4.0~rc.2-812.noarch.rpm"),
            (
                Kind::Sbom,
                "acme-repository_1.4.0~rc.2-812_all.deb.cdx.json"
            ),
            (
                Kind::Sbom,
                "acme-repository-1.4.0~rc.2-812.noarch.rpm.cdx.json"
            ),
        ]
    );
    assert_eq!(names(&first), names(&second), "two builds differ");
    // A failed run never leaves the previous run's listing beside its
    // partial output: here nFPM doesn't run.
    let broken = Options {
        nfpm: tmp.path().join("no-nfpm"),
        ..options.clone()
    };
    assert!(
        seaworthy::package::repository(&config, &tmp.path().join("b"), &broken, &signing).is_err()
    );
    assert!(
        !tmp.path().join("b/repository/packages.json").exists(),
        "the stale packages.json is gone"
    );
    let listing: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join("a/repository/packages.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(listing["product"], "repository");
    assert_eq!(listing["package"], "acme-repository");
    assert_eq!(listing["version"], "1.4.0-rc.2");
    assert_eq!(listing["sequence"], 812);
    assert_eq!(
        listing["artifacts"][0]["file"],
        "packages/acme-repository_1.4.0~rc.2-812_all.deb"
    );
    assert_eq!(listing["artifacts"][0]["target"], LINUX);
    // The SBOM names both files by their bytes.
    let sbom: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            tmp.path()
                .join("a/repository/packages/acme-repository_1.4.0~rc.2-812_all.deb.cdx.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let files: Vec<(&str, &str)> = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap(),
                c["hashes"][0]["content"].as_str().unwrap(),
            )
        })
        .collect();
    let sources = seaworthy::repository_package::sources(&config).unwrap();
    assert_eq!(
        files,
        [
            (
                "/etc/apt/sources.list.d/acme.sources",
                seaworthy_crypto::digest::sha256_hex(sources.as_bytes()).as_str()
            ),
            (
                "/usr/share/keyrings/acme-archive-keyring.asc",
                seaworthy_crypto::digest::sha256_hex(PLACEHOLDER_KEY.as_bytes()).as_str()
            ),
        ]
    );

    let deb = artifact(&first, Kind::Deb);
    if have("dpkg-deb", &["--version"]) {
        let field = |name: &str| {
            run(Command::new("dpkg-deb").arg("-f").arg(&deb).arg(name))
                .trim()
                .to_owned()
        };
        assert_eq!(field("Package"), "acme-repository");
        assert_eq!(field("Version"), "1.4.0~rc.2-812");
        assert_eq!(field("Architecture"), "all");
        assert_eq!(field("Depends"), "");
        assert_eq!(
            field("Description"),
            "Sets apt up for Acme's packages: their repository and signing keys"
        );
        let contents = run(Command::new("dpkg-deb").arg("-c").arg(&deb));
        for path in [
            "./etc/apt/sources.list.d/acme.sources",
            "./usr/share/keyrings/acme-archive-keyring.asc",
        ] {
            assert!(
                contents
                    .lines()
                    .any(|l| l.starts_with("-rw-r--r-- root/root") && l.ends_with(path)),
                "{path} in:\n{contents}"
            );
        }
        let control = tempfile::tempdir().unwrap();
        run(Command::new("dpkg-deb")
            .arg("-e")
            .arg(&deb)
            .arg(control.path()));
        assert_eq!(
            std::fs::read_to_string(control.path().join("conffiles")).unwrap(),
            "/etc/apt/sources.list.d/acme.sources\n"
        );
        for script in ["preinst", "postinst", "prerm", "postrm"] {
            assert!(!control.path().join(script).exists(), "no {script}");
        }
        let unpacked = tempfile::tempdir().unwrap();
        run(Command::new("dpkg-deb")
            .arg("-x")
            .arg(&deb)
            .arg(unpacked.path()));
        assert_eq!(
            std::fs::read_to_string(unpacked.path().join("etc/apt/sources.list.d/acme.sources"))
                .unwrap(),
            sources
        );
    }
    let rpm = artifact(&first, Kind::Rpm);
    if have("rpm", &["--version"]) {
        let db = tempfile::tempdir().unwrap();
        let rpm_q = |args: &[&str]| {
            run(Command::new("rpm")
                .arg("--dbpath")
                .arg(db.path())
                .arg("-qp")
                .args(args)
                .arg(&rpm))
        };
        assert_eq!(
            rpm_q(&[
                "--qf",
                "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{BUILDHOST}|%{BUILDTIME}|%{LICENSE}"
            ]),
            "acme-repository|1.4.0~rc.2|812|noarch|seaworthy|1700000000|MIT"
        );
        let requires = rpm_q(&["--requires"]);
        assert!(
            requires.lines().all(|l| l.starts_with("rpmlib(")),
            "only rpm's own features: {requires}"
        );
        assert_eq!(rpm_q(&["--scripts"]), "", "no scriptlets");
        assert_eq!(
            rpm_q(&[
                "--qf",
                "[%{FILEFLAGS:fflags} %{FILEMODES:perms} %{FILENAMES}\\n]"
            ])
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>(),
            [
                "-rw-r--r-- /etc/pki/rpm-gpg/RPM-GPG-KEY-acme",
                "cn -rw-r--r-- /etc/yum.repos.d/acme.repo",
            ]
        );
    }
}
