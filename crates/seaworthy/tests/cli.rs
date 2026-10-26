//! The `seaworthy` binary: commands, output, and exit codes (0 success, 1
//! refusal, 2 usage).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::path::Path;
use std::process::{Command, Output};

fn seaworthy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .args(args)
        .output()
        .expect("runs")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn version_spells_every_format() {
    let out = seaworthy(&["version", "--release", "1.4.0-rc.2", "--sequence", "812"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("deb     1.4.0~rc.2-812"), "{stdout}");
    assert!(stdout.contains("rpm     1.4.0~rc.2-812"), "{stdout}");
    assert!(stdout.contains("pacman  1.4.0rc.2-812"), "{stdout}");
    assert!(stdout.contains("msi     1.4.0"), "{stdout}");

    let out = seaworthy(&["version", "--release", "2.0.0", "--sequence", "3", "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
    assert_eq!(json["deb"], "2.0.0-3");
    assert_eq!(json["pacman_pkgrel"], "3");
}

#[test]
fn version_and_help_answer_on_stdout() {
    for flag in ["--version", "-V"] {
        let out = seaworthy(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("seaworthy {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
    for flag in ["--help", "-h"] {
        let out = seaworthy(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("usage:"));
    }
    let out = seaworthy(&["--version", "extra"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

#[test]
fn refusals_exit_1_and_name_the_problem() {
    let out = seaworthy(&["version", "--release", "1.0.0-rc1", "--sequence", "1"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("pre-release"), "{}", text(&out));

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("seaworthy.toml");
    std::fs::write(&config, "[defaults]\nvendor = \"x\"\n").unwrap();
    let out = seaworthy(&["check", "--config", config.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("seaworthy.toml"), "{}", text(&out));
}

#[test]
fn options_must_apply_once_and_have_values() {
    for (args, mentions) in [
        (
            &["check", "--artifacts", "x"][..],
            "check does not take \"--artifacts\"",
        ),
        (&["check", "--json"][..], "check does not take \"--json\""),
        (
            &[
                "version",
                "--release",
                "1.0.0",
                "--release",
                "2.0.0",
                "--sequence",
                "1",
            ][..],
            "--release given twice",
        ),
        (
            &["verify", "--artifacts", "--product"][..],
            "--artifacts needs a value",
        ),
        (
            &["version", "--release", "1.0.0", "--sequence", "+5"][..],
            "--sequence must be a decimal number",
        ),
        (
            &[
                "version",
                "--release",
                "1.0.0",
                "--sequence",
                "99999999999999999999999",
            ][..],
            "out of range",
        ),
        (
            &["version", "--release", "1.0.0"][..],
            "version needs --sequence",
        ),
        (&["layout", "--artifacts", "x"][..], "layout needs --out"),
        (
            &[
                "package",
                "--artifacts",
                "x",
                "--out",
                "y",
                "--sequence",
                "1",
            ][..],
            "package needs --release",
        ),
        (
            &["package", "--artifacts", "x", "--out", "y", "--json"][..],
            "package does not take \"--json\"",
        ),
    ] {
        let out = seaworthy(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(text(&out).contains(mentions), "{args:?}: {}", text(&out));
    }
}

#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_a_usage_error() {
    use std::os::unix::ffi::OsStrExt as _;
    let out = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .arg("check")
        .arg("--config")
        .arg(std::ffi::OsStr::from_bytes(b"dist\xff.toml"))
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &[][..],
        &["frobnicate"][..],
        &["verify", "--bogus"][..],
        &["layout", "--out"][..],
    ] {
        let out = seaworthy(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(text(&out).contains("usage:"), "{args:?}");
    }
}

#[test]
fn check_notes_a_derived_upgrade_code_without_failing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("seaworthy.toml");
    let product = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v2"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "A viewer."
executable = "AcmeViewer"
core = "acme_core"
kind = "tool"
windows-directory = "Viewer"
outputs = ["msi", "zip"]
updates.default = "off"
"#;
    std::fs::write(&config, product).unwrap();
    let out = seaworthy(&["check", "--config", config.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("seaworthy: note: [viewer] the MSI's UpgradeCode is derived, {"),
        "{stderr}"
    );
    // Pinned, it's quiet.
    std::fs::write(
        &config,
        product.replace(
            "windows-directory = \"Viewer\"",
            "windows-directory = \"Viewer\"\nupgrade-code = \"{6F1C4A2E-3B5D-4C7E-9A1B-2D3E4F5A6B7C}\"",
        ),
    )
    .unwrap();
    let out = seaworthy(&["check", "--config", config.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(out.stderr.is_empty(), "{}", text(&out));
}

#[test]
fn verify_and_layout_require_their_directories() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("seaworthy.toml");
    std::fs::write(
        &config,
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.tool]
display-name = "Acme Tool"
description = "A tool."
executable = "AcmeTool"
core = "acme_core"
kind = "tool"
outputs = ["tar"]
updates.default = "off"
"#,
    )
    .unwrap();
    let config = config.to_str().unwrap();
    let out = seaworthy(&["check", "--config", config]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let out = seaworthy(&["verify", "--config", config]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a missing option is a usage error"
    );
    assert!(
        text(&out).contains("verify needs --artifacts"),
        "{}",
        text(&out)
    );
    let out = seaworthy(&[
        "verify",
        "--config",
        config,
        "--artifacts",
        dir.path().to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out).contains("verify found"), "{}", text(&out));
    let out = seaworthy(&[
        "verify",
        "--config",
        config,
        "--artifacts",
        "x",
        "--product",
        "nope",
    ]);
    assert!(text(&out).contains("no product \"nope\""), "{}", text(&out));
}

const DESKTOP: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
sidecars.windows = ["extra_*.dll"]
outputs = ["tar", "zip"]
"#;

fn package(
    dir: &Path,
    out: &str,
    release: &str,
    epoch: Option<&str>,
    nfpm: Option<&str>,
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_seaworthy"));
    cmd.args(["package", "--no-strip", "--config"])
        .arg(dir.join("seaworthy.toml"))
        .arg("--artifacts")
        .arg(dir.join("artifacts"))
        .arg("--out")
        .arg(dir.join(out))
        .args(["--release", release, "--sequence", "7"])
        .env_remove("SOURCE_DATE_EPOCH")
        .env_remove("NFPM")
        .env_remove("SEAWORTHY_WIX");
    if let Some(epoch) = epoch {
        cmd.env("SOURCE_DATE_EPOCH", epoch);
    }
    if let Some(nfpm) = nfpm {
        cmd.env("NFPM", nfpm);
    }
    cmd.output().expect("runs")
}

fn setup(config: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), config).unwrap();
    common::acme_artifacts(&dir.path().join("artifacts"));
    dir
}

#[test]
fn package_builds_every_output_reproducibly() {
    let dir = setup(DESKTOP);
    let first = package(dir.path(), "a", "2.1.0", Some("1700000000"), None);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(stdout.contains("console Tar: "), "{stdout}");
    assert!(
        stdout.contains("acme-console-2.1.0-7-linux-x86_64.tar.zst"),
        "{stdout}"
    );
    assert!(
        stdout.contains("acme-console-2.1.0-7-windows-x86_64.zip"),
        "{stdout}"
    );
    let second = package(dir.path(), "b", "2.1.0", Some("1700000000"), None);
    assert_eq!(second.status.code(), Some(0), "{}", text(&second));
    for name in [
        "acme-console-2.1.0-7-linux-x86_64.tar.zst",
        "acme-console-2.1.0-7-windows-x86_64.zip",
    ] {
        let read = |out: &str| {
            std::fs::read(dir.path().join(out).join("console/packages").join(name)).unwrap()
        };
        assert_eq!(read("a"), read("b"), "{name} differs between two runs");
    }
    // Without SOURCE_DATE_EPOCH: 1980-01-01, still reproducible.
    let third = package(dir.path(), "c", "2.1.0", None, None);
    assert_eq!(third.status.code(), Some(0), "{}", text(&third));
    let listing: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("c/console/packages.json")).unwrap())
            .unwrap();
    assert_eq!(listing["product"], "console");
    assert_eq!(listing["sequence"], 7);
    assert_eq!(listing["artifacts"][0]["kind"], "zip");
    assert_eq!(listing["artifacts"][1]["kind"], "tar");
}

#[test]
fn package_refuses_a_bad_epoch_a_bad_version_and_a_missing_nfpm() {
    let dir = setup(DESKTOP);
    // 4300000000 fits a zip (to 2107) but not an rpm's 32-bit timestamps.
    for epoch in ["soon", "-1", "100", "4300000000", "99999999999"] {
        let out = package(dir.path(), "a", "2.1.0", Some(epoch), None);
        assert_eq!(out.status.code(), Some(1), "{epoch}: {}", text(&out));
        assert!(
            text(&out).contains("SOURCE_DATE_EPOCH"),
            "{epoch}: {}",
            text(&out)
        );
    }
    // MSI can't spell it: refused before anything is written.
    let out = package(dir.path(), "v", "256.0.0", None, None);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        !dir.path().join("v").exists(),
        "nothing laid out for a refused version"
    );
    let deb = setup(&DESKTOP.replace("outputs = [\"tar\", \"zip\"]", "outputs = [\"deb\"]"));
    let out = package(deb.path(), "a", "2.1.0", None, Some("/nonexistent/nfpm"));
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("cannot run /nonexistent/nfpm"),
        "{}",
        text(&out)
    );
}

#[test]
fn package_builds_the_repository_package_with_every_product_but_not_with_one() {
    // With [defaults.repository], a run without --product builds the
    // repository package too (in the formats the products build: here a
    // deb); `--product console` builds the console alone.
    let Some(nfpm) = common::nfpm() else { return };
    if !common::have("gpg", &["--version"]) {
        return;
    }
    let config = DESKTOP
        .replacen(
            "outputs = [\"tar\", \"zip\"]",
            "outputs = [\"deb\", \"tar\", \"zip\"]",
            1,
        )
        .replacen(
            "license = \"MIT\"\n",
            "license = \"MIT\"\nopenpgp-keys = [\"repo.asc\"]\n",
            1,
        )
        + "\n[defaults.repository]\nurl = \"https://packages.acme.test/repo\"\n";
    let dir = setup(&config);
    let keyring = common::Keyring::new();
    keyring.export(&dir.path().join("repo.asc"));
    let nfpm = nfpm.to_str().unwrap();
    let all = package(dir.path(), "all", "2.1.0", Some("1700000000"), Some(nfpm));
    assert_eq!(all.status.code(), Some(0), "{}", text(&all));
    let stdout = String::from_utf8_lossy(&all.stdout);
    assert!(stdout.contains("console Deb: "), "{stdout}");
    assert!(
        stdout.contains("repository Deb: ") && stdout.contains("acme-repository_2.1.0-7_all.deb"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("repository Rpm"),
        "no product builds an rpm: {stdout}"
    );
    assert!(dir.path().join("all/repository/packages.json").is_file());

    let one = Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .args(["package", "--no-strip", "--config"])
        .arg(dir.path().join("seaworthy.toml"))
        .arg("--artifacts")
        .arg(dir.path().join("artifacts"))
        .arg("--out")
        .arg(dir.path().join("one"))
        .args([
            "--release",
            "2.1.0",
            "--sequence",
            "7",
            "--product",
            "console",
        ])
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .env("NFPM", nfpm)
        .output()
        .unwrap();
    assert_eq!(one.status.code(), Some(0), "{}", text(&one));
    assert!(
        !String::from_utf8_lossy(&one.stdout).contains("repository"),
        "{}",
        text(&one)
    );
    assert!(!dir.path().join("one/repository").exists());

    // The repository package is a Linux package: never without linux in
    // --platforms, and asked for alone there, a usage error.
    let windows = |out: &str, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .args(["package", "--no-strip", "--config"])
            .arg(dir.path().join("seaworthy.toml"))
            .arg("--out")
            .arg(dir.path().join(out))
            .args([
                "--release",
                "2.1.0",
                "--sequence",
                "7",
                "--platforms",
                "windows",
            ])
            .args(extra)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .env("NFPM", nfpm)
            .output()
            .unwrap()
    };
    let artifacts = dir.path().join("artifacts");
    let zip = windows("zip", &["--artifacts", artifacts.to_str().unwrap()]);
    assert_eq!(zip.status.code(), Some(0), "{}", text(&zip));
    let stdout = String::from_utf8_lossy(&zip.stdout);
    assert!(stdout.contains("console Zip: "), "{stdout}");
    assert!(
        !stdout.contains("repository") && !stdout.contains("console Deb"),
        "{stdout}"
    );
    assert!(!dir.path().join("zip/repository").exists());
    let refused = windows("none", &["--product", "repository"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused));
    assert!(
        text(&refused).contains("--platforms must name linux"),
        "{}",
        text(&refused)
    );
}
