//! `conflicts` and `linux.provides`: products that can't be installed
//! together (one per crypto build of a tool) and the virtual package they
//! all provide. The rules, the Linux packages' metadata in every format,
//! and the MSI's refusal to install beside a conflicting product's.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::process::Command;

use common::{artifact, have, layout_for, layouts, nfpm, required, run};
use seaworthy::config::Config;
use seaworthy::inputs::WINDOWS;
use seaworthy::package::Kind;

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"
"#;

/// One profile of the tool (the fixture's launcher and core): every
/// profile installs the same command, directory and shortcut name.
fn profile(id: &str, display: &str, conflicts: &str) -> String {
    format!(
        r#"
[product.{id}]
display-name = "{display}"
description = "Packs Trove archives."
executable = "AcmeTool"
core = "acme_core"
kind = "tool"
windows-directory = "Trove"
sidecars.windows = ["extra_*.dll"]
outputs = ["deb", "rpm", "pacman", "msi"]
updates.default = "off"
linux.command = "trove"
linux.provides = ["acme-trove"]
conflicts = [{conflicts}]
"#
    )
}

/// The FIPS profile names the other two; they name nothing (a conflict
/// holds both ways).
fn profiles() -> String {
    format!(
        "{DEFAULTS}{}{}{}",
        profile(
            "trove-fips",
            "Acme Trove [FIPS]",
            "\"trove-aws-lc\", \"trove-portable\", \"trove\""
        ),
        profile("trove-aws-lc", "Acme Trove (AWS-LC)", "\"trove-portable\""),
        profile("trove-portable", "Acme Trove", ""),
    )
}

fn refused(text: &str, mentions: &str) {
    let err = Config::parse(text)
        .expect_err("must be refused")
        .to_string();
    assert!(err.contains(mentions), "expected {mentions:?} in: {err}");
}

#[test]
fn a_conflict_holds_both_ways() {
    let config = Config::parse(&profiles()).unwrap();
    assert_eq!(
        config.conflicting_products("trove-fips"),
        ["trove-aws-lc", "trove-portable"]
    );
    assert_eq!(
        config.conflicting_products("trove-portable"),
        ["trove-aws-lc", "trove-fips"]
    );
    // A plain name is a Linux package of someone else's.
    assert_eq!(
        config.conflicting_packages("trove-fips"),
        ["acme-trove-aws-lc", "acme-trove-portable", "trove"]
    );
    assert_eq!(
        config.conflicting_packages("trove-portable"),
        ["acme-trove-aws-lc", "acme-trove-fips"]
    );
}

#[test]
fn conflicts_and_provides_are_validated() {
    let base = profiles();
    let fips = "conflicts = [\"trove-aws-lc\", \"trove-portable\", \"trove\"]";
    assert!(base.contains(fips));
    for (to, mentions) in [
        (
            "conflicts = [\"trove-fips\"]",
            "product.trove-fips.conflicts: a product can't conflict with itself",
        ),
        (
            "conflicts = [\"acme-trove-fips\"]",
            "a product can't conflict with itself",
        ),
        (
            "conflicts = [\"trove-aws-lc\", \"trove-aws-lc\"]",
            "\"trove-aws-lc\" is listed twice",
        ),
        (
            "conflicts = [\"Trove\"]",
            "\"Trove\" is neither a product of this seaworthy.toml nor a package name",
        ),
        (
            "conflicts = [\"acme-trove-portable\"]",
            "\"acme-trove-portable\" is a package this seaworthy.toml builds: name the product (\"trove-portable\")",
        ),
    ] {
        refused(&base.replacen(fips, to, 1), mentions);
    }
    // A plain name linux.replaces names conflicts already.
    refused(
        &base.replacen(
            "linux.provides = [\"acme-trove\"]\nconflicts = [\"trove-aws-lc\", \"trove-portable\", \"trove\"]",
            "linux.provides = [\"acme-trove\"]\nlinux.replaces = [\"trove\"]\nconflicts = [\"trove\"]",
            1,
        ),
        "\"trove\" is in linux.replaces",
    );
    // A plain name needs a Linux package; a product id needs none.
    let windows_only = base.replacen(
        "outputs = [\"deb\", \"rpm\", \"pacman\", \"msi\"]\nupdates.default = \"off\"\nlinux.command = \"trove\"\nlinux.provides = [\"acme-trove\"]\nconflicts = [\"trove-aws-lc\", \"trove-portable\", \"trove\"]",
        "outputs = [\"msi\"]\nupdates.default = \"off\"\nconflicts = [\"trove-aws-lc\", \"trove-portable\", \"trove\"]",
        1,
    );
    refused(
        &windows_only,
        "only a Linux package (deb, rpm, pacman) conflicts with one",
    );
    Config::parse(&windows_only.replace(", \"trove\"]", "]")).unwrap();
    for (to, mentions) in [
        ("linux.provides = [\"Trove\"]", "isn't a package name"),
        (
            "linux.provides = [\"xy\", \"xy\"]",
            "\"xy\" is listed twice",
        ),
        (
            "linux.provides = [\"acme-trove-fips\"]",
            "\"acme-trove-fips\" is a package this seaworthy.toml builds",
        ),
        (
            "linux.provides = [\"acme-trove-portable\"]",
            "\"acme-trove-portable\" is a package this seaworthy.toml builds",
        ),
    ] {
        refused(
            &base.replacen("linux.provides = [\"acme-trove\"]", to, 1),
            mentions,
        );
    }
    refused(
        &base.replacen(
            "outputs = [\"deb\", \"rpm\", \"pacman\", \"msi\"]\nupdates.default = \"off\"\nlinux.command = \"trove\"\n",
            "outputs = [\"msi\"]\nupdates.default = \"off\"\n",
            1,
        )
        .replacen(", \"trove\"]", "]", 1),
        "product.trove-fips.linux.provides: only a Linux package",
    );
}

/// Products that conflict are never installed together: they may share
/// the command, the install directory, the menu entry and the shortcut
/// name. Nothing else, and not with a product they don't conflict with.
#[test]
fn conflicting_products_may_share_what_one_installation_holds() {
    let config = Config::parse(&profiles()).unwrap();
    assert_eq!(config.products.len(), 3);
    // A fourth product, conflicting with none, on the same command.
    let fourth = format!(
        "{}{}",
        profiles(),
        profile("trove-extra", "Acme Trove Extra", "").replace(
            "windows-directory = \"Trove\"",
            "windows-directory = \"Extra\""
        )
    );
    refused(
        &fourth,
        "share linux.command \"trove\" (only products that conflict may)",
    );
    // …or two of them that don't conflict with each other, though both
    // conflict with a third.
    let pairwise = profiles().replacen("conflicts = [\"trove-portable\"]", "conflicts = []", 1);
    refused(&pairwise, "products trove-aws-lc and trove-portable share");
    // The UpgradeCode is never shared: it would make one the other's upgrade.
    let code = "upgrade-code = \"{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}\"\n";
    refused(
        &profiles().replace(
            "windows-directory = \"Trove\"\n",
            &format!("windows-directory = \"Trove\"\n{code}"),
        ),
        "share upgrade-code",
    );
}

/// Every format names the conflicts and what the package provides, and
/// replaces nothing.
#[test]
fn the_linux_packages_conflict_and_provide() {
    let Some(nfpm) = nfpm() else { return };
    let config = Config::parse(&profiles()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let artifacts = common::build(&config, "trove-fips", out.path(), &nfpm, None);
    if have("dpkg-deb", &["--version"]) {
        let deb = artifact(&artifacts, Kind::Deb);
        let field = |name: &str| {
            run(Command::new("dpkg-deb").arg("-f").arg(&deb).arg(name))
                .trim()
                .to_owned()
        };
        assert_eq!(
            field("Conflicts"),
            "acme-trove-aws-lc, acme-trove-portable, trove"
        );
        assert_eq!(field("Provides"), "acme-trove");
        assert_eq!(field("Replaces"), "");
    } else {
        assert!(!required(), "dpkg-deb is required");
    }
    if have("rpm", &["--version"]) {
        let rpm = artifact(&artifacts, Kind::Rpm);
        let query = |what: &str| {
            run(Command::new("rpm").arg("-qp").arg(what).arg(&rpm))
                .lines()
                .map(|l| l.trim().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            query("--conflicts"),
            ["acme-trove-aws-lc", "acme-trove-portable", "trove"]
        );
        assert!(
            query("--provides").contains(&"acme-trove".to_owned()),
            "{:?}",
            query("--provides")
        );
        assert!(query("--obsoletes").is_empty());
    } else {
        assert!(!required(), "rpm is required");
    }
    if have("bsdtar", &["--version"]) {
        let pacman = artifact(&artifacts, Kind::Pacman);
        let info = run(Command::new("bsdtar")
            .arg("-xOf")
            .arg(&pacman)
            .arg(".PKGINFO"));
        let values = |key: &str| {
            info.lines()
                .filter_map(|l| l.strip_prefix(&format!("{key} = ")))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            values("conflict"),
            ["acme-trove-aws-lc", "acme-trove-portable", "trove"],
            "{info}"
        );
        assert_eq!(values("provides"), ["acme-trove"], "{info}");
        assert!(values("replaces").is_empty(), "{info}");
    } else {
        assert!(!required(), "bsdtar is required");
    }
}

/// The MSI finds every conflicting product's MSI by its UpgradeCode,
/// detect-only, and refuses a first install while one is there, naming it;
/// adopt-msi's model reads the search as declared.
#[test]
fn the_msi_refuses_to_install_beside_a_conflicting_product() {
    // The portable profile ships no MSI: nothing to search for.
    let text = profiles().replacen(
        "outputs = [\"deb\", \"rpm\", \"pacman\", \"msi\"]",
        "outputs = [\"deb\", \"rpm\", \"pacman\"]",
        3,
    );
    let text = text.replacen(
        "outputs = [\"deb\", \"rpm\", \"pacman\"]",
        "outputs = [\"deb\", \"rpm\", \"pacman\", \"msi\"]",
        2,
    );
    let config = Config::parse(&text).unwrap();
    assert!(
        !config.products["trove-portable"]
            .outputs
            .contains(&seaworthy::config::Output::Msi)
    );
    let out = tempfile::tempdir().unwrap();
    let fips = layouts(&config, "trove-fips", out.path());
    let wxs = seaworthy::wix::wxs(
        &config,
        "trove-fips",
        layout_for(&fips, WINDOWS),
        &common::release(),
    )
    .unwrap();
    let other = seaworthy::wix::upgrade_code(&config, "trove-aws-lc").unwrap();
    let search = format!(
        "    <Upgrade Code=\"{other}\">\n      <UpgradeVersion Minimum=\"0.0.0\" IncludeMinimum=\"yes\" OnlyDetect=\"yes\" Property=\"CONFLICT_TROVE_AWS_LC\" />\n    </Upgrade>\n    <Launch Condition=\"Installed OR NOT CONFLICT_TROVE_AWS_LC\" Message=\"[ProductName] can't be installed while Acme Trove (AWS-LC) is installed: uninstall Acme Trove (AWS-LC) first.\" />\n"
    );
    assert!(wxs.contains(&search), "{wxs}");
    assert_eq!(wxs.matches("<Upgrade ").count(), 1, "{wxs}");
    assert!(!wxs.contains("TROVE_PORTABLE"), "{wxs}");
    assert_eq!(
        seaworthy::wix::conflict_property("trove-aws-lc"),
        "CONFLICT_TROVE_AWS_LC"
    );
    seaworthy::msi_check::expected_from_wxs(&wxs).unwrap();
    // The other way: a display name's brackets stay literal in the
    // message (a Formatted string expands [PROPERTY]).
    let aws = layouts(&config, "trove-aws-lc", out.path());
    let wxs = seaworthy::wix::wxs(
        &config,
        "trove-aws-lc",
        layout_for(&aws, WINDOWS),
        &common::release(),
    )
    .unwrap();
    assert!(
        wxs.contains(
            "Message=\"[ProductName] can't be installed while Acme Trove [\\[]FIPS[\\]] is installed: uninstall Acme Trove [\\[]FIPS[\\]] first.\""
        ),
        "{wxs}"
    );
    seaworthy::msi_check::expected_from_wxs(&wxs).unwrap();
}
