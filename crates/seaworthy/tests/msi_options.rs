//! `[product.<id>.msi]`: who the MSI installs for (`install-scope`), the
//! licence page, `PATH` and Windows Error Reporting. Every refusal, the
//! `.wxs` each option writes, adopt-msi's model of it (accepted exactly,
//! refused on any other row), and, with `SEAWORTHY_WIX` (WiX 5, on the
//! Windows runner or under Wine), the MSI WiX builds from it, read back
//! with msitools and checked by adopt-msi's own table check.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{have, program_layouts, release, run, wxs_lines};
use seaworthy::config::{Config, InstallScope};
use seaworthy::inputs::WINDOWS;
use seaworthy::msi_check::{Table, expected_from_wxs, findings, parse_sql_export};

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"
"#;

/// The several-programs fixture: a command-line program and an app.
const TROVE: &str = r#"
[product.trove]
display-name = "Acme Trove"
description = "Packs and unpacks Trove archives."
kind = "desktop"
windows-directory = "Trove"
outputs = ["deb", "zip", "msi"]
updates.default = "off"
upgrade-code = "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}"

[[product.trove.programs]]
executable = "trove"
core = "trove_cli_core"
role = "cli"

[[product.trove.programs]]
executable = "TroveGui"
core = "trove_gui_core"
role = "gui"

[product.trove.desktop]
categories = ["Utility"]
desktop-shortcut = true
"#;

/// A service product with the update helper: machine-wide by nature.
const AGENT: &str = r#"
[product.agent]
display-name = "Acme Agent"
description = "Collects things for Acme."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
outputs = ["msi"]

[product.agent.service]
name = "AcmeAgent"
state-directory = "acme/agent"

[product.agent.service.sandbox]
user = "acme-agent"
"#;

fn with_msi(product: &str, id: &str, msi: &str) -> String {
    format!("{product}\n[product.{id}.msi]\n{msi}\n")
}

fn parse(products: &str) -> Config {
    Config::parse(&format!("{DEFAULTS}{products}")).unwrap()
}

fn refused(products: &str, mentions: &str) {
    let err = Config::parse(&format!("{DEFAULTS}{products}"))
        .expect_err("must be refused")
        .to_string();
    assert!(err.contains(mentions), "expected {mentions:?} in: {err}");
}

/// The `.wxs` of `products`' `trove` (or `id`), laid out under `dir`.
fn wxs_of(config: &Config, id: &str, dir: &Path) -> String {
    let layouts = program_layouts(config, id, dir, false);
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    seaworthy::wix::wxs(config, id, windows, &release()).unwrap()
}

#[test]
fn the_msi_table_is_validated() {
    let release_keys = "release-signatures = [\"ml-dsa-87\"]\n";
    // Only with an msi output.
    refused(
        &with_msi(
            &TROVE.replace("\"zip\", \"msi\"", "\"zip\""),
            "trove",
            "path = true",
        )
        .replace(
            "upgrade-code = \"{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}\"\n",
            "",
        ),
        "product.trove.msi: set, but no output is msi",
    );
    // Per user, or either: nothing machine-wide. A service...
    for scope in ["user", "either"] {
        let err = Config::parse(&format!(
            "{DEFAULTS}{release_keys}{}",
            with_msi(AGENT, "agent", &format!("install-scope = \"{scope}\""))
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(&format!("product.agent.msi.install-scope: \"{scope}\""))
                && err.contains("the product's service (\"AcmeAgent\""),
            "{err}"
        );
    }
    // ... and the update helper, a desktop app's too.
    let desktop_helper = TROVE.replace(
        "updates.default = \"off\"",
        "updates.default = \"notify\"\nhelper = \"TroveUpdate\"",
    );
    let err = Config::parse(&format!(
        "{DEFAULTS}{release_keys}{}",
        with_msi(&desktop_helper, "trove", "install-scope = \"either\"")
    ))
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("ships the update helper (helper = \"TroveUpdate\")")
            && err.contains("updates.default = \"off\""),
        "{err}"
    );
    // PATH needs a cli program.
    let gui_only = TROVE.replace(
        "[[product.trove.programs]]\nexecutable = \"trove\"\ncore = \"trove_cli_core\"\nrole = \"cli\"\n",
        "",
    );
    assert_ne!(gui_only, TROVE);
    refused(
        &with_msi(&gui_only, "trove", "path = true"),
        "product.trove.msi.path: puts the install directory on PATH",
    );
    // wer-exclude names the product's programs, each once.
    refused(
        &with_msi(TROVE, "trove", "wer-exclude = [\"trove.exe\"]"),
        "\"trove.exe\" isn't one of the product's programs (their executables: trove, TroveGui)",
    );
    refused(
        &with_msi(TROVE, "trove", "wer-exclude = [\"trove\", \"trove\"]"),
        "\"trove\" is listed twice",
    );
    // Unknown keys and scopes.
    refused(
        &with_msi(TROVE, "trove", "scope = \"user\""),
        "unknown field `scope`",
    );
    refused(
        &with_msi(TROVE, "trove", "install-scope = \"everyone\""),
        "unknown variant `everyone`",
    );
    // And what loads.
    let config = parse(&with_msi(
        TROVE,
        "trove",
        "install-scope = \"either\"\npath = true\nwer-exclude = [\"TroveGui\", \"trove\"]",
    ));
    let options = config.products["trove"].msi_options();
    assert_eq!(options.install_scope, InstallScope::Either);
    assert!(options.path);
    assert_eq!(options.wer_exclude, ["TroveGui", "trove"]);
    // Without the table: machine-wide, nothing else.
    let plain = parse(TROVE).products["trove"].msi_options();
    assert_eq!(plain.install_scope, InstallScope::Machine);
    assert!(!plain.path && plain.wer_exclude.is_empty());
}

/// `machine` is WiX's perMachine (ALLUSERS=1); `user` and `either` are a
/// Windows Installer 5 dual-purpose package (ALLUSERS=2,
/// MSIINSTALLPERUSER=1), `user` refusing a machine-wide install.
#[test]
fn the_scope_is_the_packages() {
    let dir = tempfile::tempdir().unwrap();
    for (scope, package, refuses_machine) in [
        (None, "Scope=\"perMachine\"", false),
        (Some("machine"), "Scope=\"perMachine\"", false),
        (Some("user"), "Scope=\"perUserOrMachine\"", true),
        (Some("either"), "Scope=\"perUserOrMachine\"", false),
    ] {
        let products = match scope {
            Some(scope) => with_msi(TROVE, "trove", &format!("install-scope = \"{scope}\"")),
            None => TROVE.to_owned(),
        };
        let config = parse(&products);
        let wxs = wxs_of(
            &config,
            "trove",
            &dir.path().join(scope.unwrap_or("default")),
        );
        let lines = wxs_lines(&wxs, &["<Package ", "MSIINSTALLPERUSER"]);
        assert!(lines[0].contains(package), "{scope:?}: {lines:#?}");
        assert_eq!(
            wxs.contains("<Launch Condition=\"Installed OR NOT ALLUSERS\""),
            refuses_machine,
            "{scope:?}: {lines:#?}"
        );
        expected_from_wxs(&wxs).unwrap();
    }
}

/// `path` appends the install directory to the system's PATH (machine),
/// the user's (user), or whichever the install's scope is (either: two
/// components, one condition each); `wer-exclude` writes each program's
/// value under HKLM, or HKMU when the install may be per user.
#[test]
fn path_and_wer_follow_the_scope() {
    let dir = tempfile::tempdir().unwrap();
    for (scope, components, root) in [
        ("machine", &[("PathMachine", "yes", "")][..], "HKLM"),
        ("user", &[("PathUser", "no", "")][..], "HKMU"),
        (
            "either",
            &[
                ("PathMachine", "yes", " Condition=\"ALLUSERS = 1\""),
                ("PathUser", "no", " Condition=\"NOT ALLUSERS\""),
            ][..],
            "HKMU",
        ),
    ] {
        let config = parse(&with_msi(
            TROVE,
            "trove",
            &format!(
                "install-scope = \"{scope}\"\npath = true\nwer-exclude = [\"trove\", \"TroveGui\"]"
            ),
        ));
        let wxs = wxs_of(&config, "trove", &dir.path().join(scope));
        let lines = wxs_lines(
            &wxs,
            &[
                "<Environment ",
                "Component Id=\"Path",
                "ExcludedApplications",
            ],
        );
        assert_eq!(lines.len(), 2 * components.len() + 2, "{scope}: {lines:#?}");
        for (component, system, condition) in components {
            assert!(
                wxs.contains(&format!(
                    "<Component Id=\"{component}\" Directory=\"InstallDir\" Guid=\"{{"
                )),
                "{scope}: {lines:#?}"
            );
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains(&format!("Id=\"{component}\""))
                        && l.ends_with(&format!("Bitness=\"always64\"{condition}>"))),
                "{scope} {component}: {lines:#?}"
            );
            assert!(
                wxs.contains(&format!("<Environment Id=\"{component}\" Name=\"PATH\" Value=\"[InstallDir]\" Action=\"set\" Part=\"last\" System=\"{system}\" />")),
                "{scope}: {lines:#?}"
            );
        }
        for executable in ["trove.exe", "TroveGui.exe"] {
            assert!(
                wxs.contains(&format!("<RegistryValue Root=\"{root}\" Key=\"Software\\Microsoft\\Windows\\Windows Error Reporting\\ExcludedApplications\" Name=\"{executable}\" Type=\"integer\" Value=\"1\" KeyPath=\"yes\" />")),
                "{scope} {executable}: {lines:#?}"
            );
        }
        expected_from_wxs(&wxs).unwrap();
    }
    // Neither, without the options.
    let wxs = wxs_of(&parse(TROVE), "trove", &dir.path().join("plain"));
    assert!(wxs_lines(&wxs, &["<Environment ", "ExcludedApplications"]).is_empty());
}

fn wix() -> Option<PathBuf> {
    let wix = std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from);
    if wix.is_none() {
        eprintln!(
            "SKIPPED: SEAWORTHY_WIX is unset (a wix binary, or a wrapper running it under Wine)"
        );
    }
    wix
}

/// WiX 5 builds `wxs` over the layout's tree at `tree`, into `dir`.
fn build_msi(wix: &Path, wxs: &str, tree: &Path, dir: &Path) -> PathBuf {
    let source = dir.join("product.wxs");
    std::fs::write(&source, wxs).unwrap();
    let msi = dir.join("product.msi");
    let mut bindpath = std::ffi::OsString::from("tree=");
    bindpath.push(tree);
    // The environment `seaworthy package` gives WiX (an allowlist), not
    // the test runner's.
    let mut command = Command::new(wix);
    command.env_clear();
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "COMSPEC",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let output = command
        .current_dir(tree)
        .args(["build", "-arch", "x64", "-nologo", "-bindpath"])
        .arg(bindpath)
        .arg("-o")
        .arg(&msi)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success() && msi.is_file(),
        "wix build failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    msi
}

/// Every table of `msi` adopt-msi reads, as it reads them.
fn tables(msi: &Path) -> BTreeMap<String, Table> {
    let listed = run(Command::new("msiinfo").arg("tables").arg(msi));
    let mut tables = BTreeMap::new();
    for name in listed.lines().map(str::trim).filter(|n| !n.is_empty()) {
        if !seaworthy::msi_check::is_read(name) {
            continue;
        }
        let output = Command::new("msiinfo")
            .args(["export", "-s"])
            .arg(msi)
            .arg(name)
            .output()
            .unwrap();
        let table = parse_sql_export(&String::from_utf8(output.stdout).unwrap()).unwrap();
        tables.insert(name.to_owned(), table);
    }
    tables
}

/// The values of `msi`'s `Property` table.
fn properties(msi: &Path) -> BTreeMap<String, String> {
    run(Command::new("msiinfo")
        .arg("export")
        .arg(msi)
        .arg("Property"))
    .lines()
    .skip(3)
    .filter_map(|line| line.split_once('\t'))
    .map(|(k, v)| (k.to_owned(), v.trim_end_matches('\r').to_owned()))
    .collect()
}

/// The product's MSI, built by WiX 5 for `scope`: its properties make it
/// a dual-purpose package, and adopt-msi's model of the `.wxs` accepts
/// exactly its tables.
#[test]
fn wix_builds_each_scope_and_adopt_msi_accepts_it() {
    let Some(wix) = wix() else {
        return;
    };
    if !have("msiinfo", &["--version"]) {
        return;
    }
    for (scope, allusers, per_user, path_names, wer_root) in [
        ("machine", "1", None, &["=-*PATH"][..], "2"),
        ("user", "2", Some("1"), &["=-PATH"][..], "-1"),
        ("either", "2", Some("1"), &["=-*PATH", "=-PATH"][..], "-1"),
    ] {
        let config = parse(&with_msi(
            TROVE,
            "trove",
            &format!("install-scope = \"{scope}\"\npath = true\nwer-exclude = [\"TroveGui\"]"),
        ));
        let dir = tempfile::tempdir().unwrap();
        let layouts = program_layouts(&config, "trove", dir.path(), false);
        let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
        let wxs = seaworthy::wix::wxs(&config, "trove", windows, &release()).unwrap();
        let msi = build_msi(&wix, &wxs, &windows.tree, dir.path());
        let properties = properties(&msi);
        assert_eq!(
            properties.get("ALLUSERS").map(String::as_str),
            Some(allusers),
            "{scope}"
        );
        assert_eq!(
            properties.get("MSIINSTALLPERUSER").map(String::as_str),
            per_user,
            "{scope}"
        );
        let tables = tables(&msi);
        // PATH: the system's and/or the user's, the install directory
        // appended, removed on uninstall (WiX's own encoding).
        let mut names: Vec<&str> = tables["Environment"]
            .rows
            .iter()
            .map(|row| {
                assert_eq!(row["Value"], "[~];[InstallDir]", "{scope}");
                row["Name"].as_str()
            })
            .collect();
        names.sort_unstable();
        assert_eq!(names, path_names, "{scope}");
        // WER: the executable's name, a DWORD 1, under HKLM or HKMU.
        let wer: Vec<_> = tables["Registry"]
            .rows
            .iter()
            .filter(|row| row["Key"] == seaworthy::wix::WER_EXCLUDED_KEY)
            .collect();
        assert_eq!(wer.len(), 1, "{scope}");
        assert_eq!(
            (
                wer[0]["Root"].as_str(),
                wer[0]["Name"].as_str(),
                wer[0]["Value"].as_str()
            ),
            (wer_root, "TroveGui.exe", "#1"),
            "{scope}"
        );
        let code = seaworthy::wix::upgrade_code(&config, "trove").unwrap();
        let found = findings(&expected_from_wxs(&wxs).unwrap(), &tables, &code);
        assert!(found.is_empty(), "{scope}: {found:#?}");
    }
}

/// A minimal RTF licence.
const LICENSE_RTF: &str = "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Segoe UI;}}\n\\f0\\fs18 Acme Trove licence: use it [freely] {at} 100% of the time.\\par\n}\n";

/// `products` loaded from a directory holding `packaging/license.rtf`.
fn with_license_file(products: &str, dir: &Path) -> Config {
    std::fs::create_dir_all(dir.join("packaging")).unwrap();
    std::fs::write(dir.join("packaging/license.rtf"), LICENSE_RTF).unwrap();
    std::fs::write(dir.join("seaworthy.toml"), format!("{DEFAULTS}{products}")).unwrap();
    Config::load(&dir.join("seaworthy.toml")).unwrap()
}

/// The licence page and the scope choice: WiX 5 builds each combination
/// (a licence alone, the choice alone, both), its dialogs are seaworthy's
/// own (no `Binary` row, no custom action but the scope's property
/// setter), and adopt-msi's model accepts exactly its tables.
#[test]
fn wix_builds_the_setup_dialogs_and_adopt_msi_accepts_them() {
    let Some(wix) = wix() else {
        return;
    };
    if !have("msiinfo", &["--version"]) {
        return;
    }
    for (scope, license) in [
        ("user", true),
        ("either", false),
        ("either", true),
        ("machine", true),
    ] {
        let mut msi = format!("install-scope = \"{scope}\"");
        if license {
            msi.push_str("\nlicense = \"packaging/license.rtf\"");
        }
        let dir = tempfile::tempdir().unwrap();
        let config = with_license_file(&with_msi(TROVE, "trove", &msi), dir.path());
        let layouts = program_layouts(&config, "trove", &dir.path().join("out"), false);
        let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
        let wxs = seaworthy::wix::wxs(&config, "trove", windows, &release()).unwrap();
        let msi = build_msi(&wix, &wxs, &windows.tree, dir.path());
        let tables = tables(&msi);
        let label = format!("{scope}, licence {license}");
        assert!(
            !tables.contains_key("Binary") || tables["Binary"].rows.is_empty(),
            "{label}"
        );
        let dialogs: Vec<&str> = tables["Dialog"]
            .rows
            .iter()
            .map(|r| r["Dialog"].as_str())
            .collect();
        for dialog in [
            "SetupDlg",
            "ProgressDlg",
            "CancelDlg",
            "ExitDlg",
            "UserExitDlg",
            "FatalErrorDlg",
            "ErrorDlg",
            "FilesInUse",
        ] {
            assert!(dialogs.contains(&dialog), "{label}: {dialogs:?}");
        }
        let licence_text = tables["Control"]
            .rows
            .iter()
            .any(|r| r["Control"] == "LicenseText");
        assert_eq!(licence_text, license, "{label}");
        let scope_choice = tables.get("RadioButton").map_or(0, |t| t.rows.len());
        assert_eq!(
            scope_choice,
            if scope == "either" { 2 } else { 0 },
            "{label}"
        );
        // The only events: dialogs ending, opening, and the scope's two
        // properties.
        for row in &tables["ControlEvent"].rows {
            assert!(
                matches!(
                    row["Event"].as_str(),
                    "EndDialog" | "SpawnDialog" | "[ALLUSERS]" | "[MSIINSTALLPERUSER]"
                ),
                "{label}: {row:?}"
            );
        }
        let code = seaworthy::wix::upgrade_code(&config, "trove").unwrap();
        let found = findings(&expected_from_wxs(&wxs).unwrap(), &tables, &code);
        assert!(found.is_empty(), "{label}: {found:#?}");
    }
}

/// A product without a licence or a scope choice has no dialogs at all:
/// Windows Installer's basic UI, as before.
#[test]
fn no_dialogs_without_a_licence_or_a_choice() {
    let dir = tempfile::tempdir().unwrap();
    for scope in ["machine", "user"] {
        let config = parse(&with_msi(
            TROVE,
            "trove",
            &format!("install-scope = \"{scope}\""),
        ));
        let wxs = wxs_of(&config, "trove", &dir.path().join(scope));
        assert!(
            !wxs.contains("<UI>") && !wxs.contains("<Dialog "),
            "{scope}"
        );
    }
}

/// The licence must be an RTF document of a sane size, inside the project.
#[test]
fn the_licence_is_checked_when_laid_out() {
    for license in [
        "\"license.txt\"",
        "\"../license.rtf\"",
        "\"/etc/license.rtf\"",
        "\"a$b.rtf\"",
    ] {
        refused(
            &with_msi(TROVE, "trove", &format!("license = {license}")),
            "product.trove.msi.license",
        );
    }
    let products = with_msi(TROVE, "trove", "license = \"packaging/license.rtf\"");
    for (bytes, wanted) in [
        (b"Not RTF at all".to_vec(), "not an RTF document"),
        (
            [b"{\\rtf1 ".as_slice(), &vec![b'x'; 1024 * 1024 + 1]].concat(),
            "past the 1048576 a licence may have",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = with_license_file(&products, dir.path());
        std::fs::write(dir.path().join("packaging/license.rtf"), &bytes).unwrap();
        let input = dir.path().join("artifacts");
        common::program_artifacts(&config, "trove", &input, false);
        let verified = seaworthy::verify::verify(&config, "trove", &input).unwrap();
        let err = seaworthy::layout::layout(
            &config,
            "trove",
            &verified,
            &dir.path().join("dist"),
            seaworthy::layout::Options {
                strip: false,
                ..seaworthy::layout::Options::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(wanted), "{wanted}: {err}");
    }
    // A licence that's a link out of the project is refused too.
    #[cfg(unix)]
    {
        let dir = tempfile::tempdir().unwrap();
        let config = with_license_file(&products, dir.path());
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("l.rtf"), LICENSE_RTF).unwrap();
        std::fs::remove_file(dir.path().join("packaging/license.rtf")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("l.rtf"),
            dir.path().join("packaging/license.rtf"),
        )
        .unwrap();
        let input = dir.path().join("artifacts");
        common::program_artifacts(&config, "trove", &input, false);
        let verified = seaworthy::verify::verify(&config, "trove", &input).unwrap();
        let err = seaworthy::layout::layout(
            &config,
            "trove",
            &verified,
            &dir.path().join("dist"),
            seaworthy::layout::Options::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("resolves outside seaworthy.toml's directory"),
            "{err}"
        );
    }
}

/// adopt-msi's model of the `Property` table, against WiX's real build of
/// a service product with the update helper (its secure `UPDATES` and
/// `SERVER`) and a product that conflicts with another (its detect-only
/// search's property): exactly accepted.
#[test]
fn wix_builds_a_service_and_a_conflict_and_adopt_msi_accepts_their_properties() {
    let Some(wix) = wix() else {
        return;
    };
    if !have("msiinfo", &["--version"]) {
        return;
    }
    let agent = Config::parse(&format!(
        "{DEFAULTS}release-signatures = [\"ml-dsa-87\"]\n{}\n[product.other]\ndisplay-name = \"Acme Other\"\ndescription = \"x\"\nexecutable = \"AcmeTool\"\ncore = \"acme_core\"\nkind = \"tool\"\nwindows-directory = \"Other\"\noutputs = [\"msi\"]\nupdates.default = \"off\"\n",
        AGENT.replace("outputs = [\"msi\"]", "outputs = [\"msi\"]\nconflicts = [\"other\"]")
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let layouts = common::layouts(&agent, "agent", dir.path());
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    let wxs = seaworthy::wix::wxs(&agent, "agent", windows, &release()).unwrap();
    let msi = build_msi(&wix, &wxs, &windows.tree, dir.path());
    let properties = properties(&msi);
    let secure = &properties["SecureCustomProperties"];
    for name in [
        "UPDATES",
        "SERVER",
        "CONFLICT_OTHER",
        "WIX_UPGRADE_DETECTED",
    ] {
        assert!(secure.split(';').any(|s| s == name), "{name}: {secure}");
    }
    let code = seaworthy::wix::upgrade_code(&agent, "agent").unwrap();
    let found = findings(&expected_from_wxs(&wxs).unwrap(), &tables(&msi), &code);
    assert!(found.is_empty(), "{found:#?}");
}
