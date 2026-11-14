//! First-paint probation on the packaging side: a probation product's
//! Linux and Windows trees carry their installed release record, its MSI
//! lets the helper's revert replace a newer release, and its Group Policy
//! template has the `Probation` switch; a product without probation gets
//! none of it (its packages are what they were).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::{Path, PathBuf};

use common::{layouts, release};
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::package::{Options, Signing, package};

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"
"#;

const CONSOLE: &str = r#"
[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["extra_*.dll"]
outputs = ["tar", "zip", "msi"]
upgrade-code = "{0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b}"
"#;

const PROBATION: &str = "updates.probation = { launches = 3, window = \"24h\" }\n";

fn config(probation: bool) -> Config {
    let product = if probation {
        format!("{CONSOLE}{PROBATION}")
    } else {
        CONSOLE.to_owned()
    };
    Config::parse(&format!("{DEFAULTS}{product}")).unwrap()
}

/// Packages the console (no external tool: tar, zip and the `.wxs`) and
/// returns the output directory.
fn packaged(config: &Config, out: &Path, build: &str) -> PathBuf {
    let layouts = layouts(config, "console", out);
    let dist = out.join("dist");
    package(
        config,
        "console",
        &layouts,
        &dist,
        &Options {
            release: release(),
            mtime: 1_700_000_000,
            nfpm: PathBuf::from("nfpm"),
            wix: None,
            build: seaworthy::sign::BuildId {
                metadata: build.to_owned(),
            },
        },
        &Signing::default(),
    )
    .expect("packages");
    dist.join("console")
}

fn tree_file(base: &Path, triple: &str, relative: &str) -> PathBuf {
    base.join(triple).join("tree").join(relative)
}

#[test]
fn a_probation_products_trees_carry_their_installed_release_record() {
    let tmp = tempfile::tempdir().unwrap();
    let base = packaged(&config(true), tmp.path(), "0a1b2c3");
    let expected =
        "seaworthy-installed-release:1\nversion 1.4.0-rc.2\nsequence 812\nbuild 0a1b2c3\n";
    for (triple, relative) in [
        (LINUX, "opt/acme/console/seaworthy-release"),
        (WINDOWS, "Acme/Console/seaworthy-release"),
    ] {
        let path = tree_file(&base, triple, relative);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            expected,
            "{triple}"
        );
        let record = seaworthy_updater::InstalledRelease::parse(expected).unwrap();
        assert_eq!(record.token(), "1.4.0-rc.2+0a1b2c3");
        // layout.json lists it, as data, mode 0644.
        let listing = std::fs::read_to_string(base.join(triple).join("layout.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&listing).unwrap();
        let entry = json["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["role"]["kind"] == "release-record")
            .unwrap_or_else(|| panic!("{triple}: {listing}"));
        assert_eq!(entry["mode"], 0o644);
        assert!(
            entry["install_path"]
                .as_str()
                .unwrap()
                .ends_with("seaworthy-release")
        );
        assert!(entry.get("sign").is_none() && entry.get("stamp").is_none());
    }
    // The MSI carries it and allows the revert's downgrade.
    let wxs = std::fs::read_to_string(
        base.join("packages")
            .join("acme-console-1.4.0-rc.2-812-windows-x86_64.wxs"),
    )
    .unwrap();
    assert!(
        wxs.contains(seaworthy::wix::MAJOR_UPGRADE_DOWNGRADES),
        "{wxs}"
    );
    assert!(!wxs.contains("DowngradeErrorMessage"));
    assert!(wxs.contains("seaworthy-release"));
    // adopt-msi models the form it wrote.
    seaworthy::msi_check::expected_from_wxs(&wxs).unwrap();
    // Without build metadata the record says `-`.
    let tmp = tempfile::tempdir().unwrap();
    let base = packaged(&config(true), tmp.path(), "");
    assert!(
        std::fs::read_to_string(tree_file(
            &base,
            LINUX,
            "opt/acme/console/seaworthy-release"
        ))
        .unwrap()
        .ends_with("build -\n")
    );
}

#[test]
fn a_product_without_probation_is_packaged_as_before() {
    let tmp = tempfile::tempdir().unwrap();
    let base = packaged(&config(false), tmp.path(), "0a1b2c3");
    for (triple, relative) in [
        (LINUX, "opt/acme/console/seaworthy-release"),
        (WINDOWS, "Acme/Console/seaworthy-release"),
    ] {
        assert!(!tree_file(&base, triple, relative).exists(), "{triple}");
        let listing = std::fs::read_to_string(base.join(triple).join("layout.json")).unwrap();
        assert!(!listing.contains("release-record"), "{listing}");
    }
    let wxs = std::fs::read_to_string(
        base.join("packages")
            .join("acme-console-1.4.0-rc.2-812-windows-x86_64.wxs"),
    )
    .unwrap();
    assert!(wxs.contains(seaworthy::wix::MAJOR_UPGRADE));
    assert!(!wxs.contains("AllowDowngrades"));
    assert!(!wxs.contains("seaworthy-release"));
    // The two trees differ by the record alone.
    let probation_tmp = tempfile::tempdir().unwrap();
    let with = packaged(&config(true), probation_tmp.path(), "0a1b2c3");
    for triple in [LINUX, WINDOWS] {
        let files = |base: &Path| -> Vec<(String, String)> {
            let listing = std::fs::read_to_string(base.join(triple).join("layout.json")).unwrap();
            let json: serde_json::Value = serde_json::from_str(&listing).unwrap();
            json["files"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|f| f["role"]["kind"] != "release-record")
                .map(|f| {
                    (
                        f["install_path"].as_str().unwrap().to_owned(),
                        f["sha256"].as_str().unwrap().to_owned(),
                    )
                })
                .collect()
        };
        assert_eq!(files(&base), files(&with), "{triple}");
    }
}

#[test]
fn the_group_policy_template_has_the_probation_switch_only_for_probation_products() {
    let with = seaworthy::admx::template_with("Acme", "Console", "Acme Console", true);
    let without = seaworthy::admx::template("Acme", "Console", "Acme Console");
    assert_eq!(
        seaworthy::admx::template_with("Acme", "Console", "Acme Console", false),
        without
    );
    let product = seaworthy_updater::Product::new("Acme", "console", "Console", "stable").unwrap();
    assert!(
        with.admx.contains(&format!(
            "<policy name=\"Probation\" class=\"Machine\" displayName=\"$(string.Probation)\" explainText=\"$(string.Probation_Help)\" presentation=\"$(presentation.Probation)\" key=\"{}\">",
            product.policy_key()
        )),
        "{}",
        with.admx
    );
    for value in ["on", "off"] {
        assert!(
            with.admx
                .contains(&format!("<value><string>{value}</string></value>"))
        );
    }
    assert!(with.adml.contains("<dropdownList refId=\"Probation\""));
    assert!(with.adml.contains("<string id=\"Probation_Help\">"));
    assert!(!without.admx.contains("Probation") && !without.adml.contains("Probation"));
    // The probation policy only adds: every line of the plain template is
    // there, in order.
    for (plain, probation) in [(&without.admx, &with.admx), (&without.adml, &with.adml)] {
        let mut rest = probation.lines();
        for line in plain.lines() {
            assert!(rest.any(|l| l == line), "{line}");
        }
    }
}
