//! `layout` over a verified synthetic tree: install paths, roles, modes,
//! the manifest, the marker rule, and stripping that keeps every record.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;

use common::{CPUS, Pe, acme_artifacts as artifacts, write};
use seaworthy::DistError;
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::layout::{MARKER, Options, Role, layout};

fn config() -> Config {
    Config::parse(
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.tool]
display-name = "Acme Super Tool"
description = "A tool."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
sidecars.windows = ["extra_*.dll"]
outputs = ["zip", "tar"]

[product.tool.service]
name = "AcmeToolService"
account = "local-system"
state-directory = "acme/tool"

[product.other]
display-name = "Acme Other"
description = "Another tool."
executable = "AcmeOther"
core = "other_core"
kind = "tool"
outputs = ["tar"]
updates.default = "off"
"#,
    )
    .expect("valid config")
}

fn run(out: &Path, strip: bool) -> Result<Vec<seaworthy::layout::Layout>, DistError> {
    let input = tempfile::tempdir().unwrap();
    artifacts(input.path());
    let config = config();
    let verified = seaworthy::verify::verify(&config, "tool", input.path()).expect("verifies");
    layout(
        &config,
        "tool",
        &verified,
        out,
        Options {
            strip,
            ..Options::default()
        },
    )
}

#[test]
fn trees_install_where_the_design_says() {
    let out = tempfile::tempdir().unwrap();
    let trees = run(out.path(), false).expect("lays out");
    assert_eq!(trees.len(), 2);

    let linux = trees.iter().find(|t| t.triple == LINUX).unwrap();
    assert_eq!(linux.install_root, "/opt/acme/tool");
    let paths: Vec<&str> = linux
        .files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/opt/acme/tool/AcmeTool",
            "/opt/acme/tool/lib/libacme_core_x86-64-v3.so",
            "/opt/acme/tool/lib/libacme_core_x86-64-v2.so",
            "/opt/acme/tool/libexec/acme-tool-update",
        ]
    );
    assert_eq!(linux.launcher().unwrap().role, Role::Launcher);
    assert!(
        linux
            .tree
            .join("opt/acme/tool/lib/libacme_core_x86-64-v2.so")
            .is_file()
    );

    let windows = trees.iter().find(|t| t.triple == WINDOWS).unwrap();
    // The display name's last word is the default directory.
    assert_eq!(windows.install_root, "Acme\\Tool");
    let paths: Vec<&str> = windows
        .files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "Acme\\Tool\\AcmeTool.exe",
            "Acme\\Tool\\acme_core_x86-64-v3.dll",
            "Acme\\Tool\\acme_core_x86-64-v2.dll",
            "Acme\\Tool\\extra_1.dll",
            "Acme\\Tool\\AcmeToolUpdate.exe",
        ]
    );
    assert!(windows.tree.join("Acme/Tool/extra_1.dll").is_file());
    assert_eq!(windows.helper().unwrap().role, Role::Helper);
}

#[test]
fn every_file_is_0755_and_hashed_in_the_manifest() {
    let out = tempfile::tempdir().unwrap();
    let trees = run(out.path(), false).expect("lays out");
    for tree in &trees {
        for file in &tree.files {
            assert_eq!(file.mode, 0o755);
            let bytes = std::fs::read(&file.staged).unwrap();
            assert_eq!(file.sha256, seaworthy_crypto::digest::sha256_hex(&bytes));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&file.staged)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o755, "{}", file.staged.display());
            }
        }
        let manifest = out
            .path()
            .join("tool")
            .join(&tree.triple)
            .join("layout.json");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest).unwrap()).unwrap();
        assert_eq!(json["install_root"], tree.install_root.as_str());
        assert_eq!(json["files"].as_array().unwrap().len(), tree.files.len());
        assert_eq!(json["files"][0]["role"]["kind"], "launcher");
    }
}

#[test]
fn a_directory_layout_did_not_create_is_never_replaced() {
    let out = tempfile::tempdir().unwrap();
    let foreign = out.path().join("tool").join(LINUX);
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("precious.txt"), b"keep me").unwrap();
    let err = run(out.path(), false).expect_err("refused").to_string();
    assert!(err.contains("was not created by seaworthy layout"), "{err}");
    assert_eq!(
        std::fs::read(foreign.join("precious.txt")).unwrap(),
        b"keep me"
    );

    // Its own directory (with the marker) is replaced on a re-run.
    let out = tempfile::tempdir().unwrap();
    run(out.path(), false).expect("first run");
    let marker = out.path().join("tool").join(LINUX).join(MARKER);
    assert!(marker.is_file());
    std::fs::write(out.path().join("tool").join(LINUX).join("stale"), b"x").unwrap();
    run(out.path(), false).expect("second run");
    assert!(!out.path().join("tool").join(LINUX).join("stale").exists());
}

fn have(tool: &str) -> bool {
    std::process::Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn stripping_removes_symbols_and_keeps_every_record() {
    if !have("strip") {
        eprintln!("SKIP: strip (binutils) not installed");
        return;
    }
    let out = tempfile::tempdir().unwrap();
    let trees = run(out.path(), true).expect("lays out with stripping");
    let linux = trees.iter().find(|t| t.triple == LINUX).unwrap();
    for file in &linux.files {
        let bytes = std::fs::read(&file.staged).unwrap();
        match &file.role {
            Role::Launcher => {
                seaworthy_levels::read_cpu_list(&file.staged)
                    .expect("the stripped launcher keeps .cpulist");
            }
            Role::Core { cpu } => {
                let record = seaworthy_levels::read_requirement(&file.staged)
                    .expect("the stripped core keeps .cpureq");
                assert_eq!(&record.cpu, cpu);
                // The symbol table is gone: stripping really ran.
                let findings = seaworthy::verify::fips_symbol_findings(&bytes, "x_");
                assert!(findings[0].starts_with("no symbol table"), "{findings:?}");
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
#[test]
fn a_strip_that_loses_a_record_is_refused() {
    if !have("objcopy") {
        eprintln!("SKIP: objcopy (binutils) not installed");
        return;
    }
    let tools = tempfile::tempdir().unwrap();
    let bad_strip = tools.path().join("strip-records-too");
    std::fs::write(
        &bad_strip,
        "#!/bin/sh\n# $1 = --strip-all, $2 = the file\nexec objcopy --remove-section .cpureq --remove-section .cpulist \"$2\"\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&bad_strip, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let input = tempfile::tempdir().unwrap();
    artifacts(input.path());
    let config = config();
    let verified = seaworthy::verify::verify(&config, "tool", input.path()).expect("verifies");
    let out = tempfile::tempdir().unwrap();
    let options = Options {
        strip: true,
        strip_tool: bad_strip,
    };
    let err = layout(&config, "tool", &verified, out.path(), options)
        .expect_err("refused")
        .to_string();
    assert!(err.contains("lost its record when stripped"), "{err}");
}

#[test]
fn two_files_on_one_install_path_are_refused() {
    // A sidecar named like the launcher (case differs: NTFS doesn't care).
    let input = tempfile::tempdir().unwrap();
    artifacts(input.path());
    let mut config = config();
    config.products.get_mut("tool").unwrap().sidecars.windows = vec!["acmetool.exe".into()];
    let dll = Pe {
        sections: vec![(".text".into(), b"sidecar".to_vec())],
        ..Pe::default()
    }
    .build();
    for cpu in CPUS {
        write(
            input.path(),
            &format!("{WINDOWS}/cores/{cpu}/acmetool.exe"),
            &dll,
        );
    }
    let verified = seaworthy::verify::verify(&config, "tool", input.path()).expect("verifies");
    let out = tempfile::tempdir().unwrap();
    // Not stripped: the refusal is the point, and the Linux tree laid out
    // first would need a GNU-style strip (macOS's has no --strip-all).
    let options = Options {
        strip: false,
        ..Options::default()
    };
    let err = layout(&config, "tool", &verified, out.path(), options)
        .expect_err("refused")
        .to_string();
    assert!(err.contains("two files would install as"), "{err}");
}

#[test]
fn a_file_changed_after_verify_is_refused() {
    let input = tempfile::tempdir().unwrap();
    artifacts(input.path());
    let config = config();
    let verified = seaworthy::verify::verify(&config, "tool", input.path()).expect("verifies");
    // Swapped between verify and layout.
    let core = input
        .path()
        .join(format!("{LINUX}/cores/x86-64-v2/libacme_core.so"));
    let mut bytes = std::fs::read(&core).unwrap();
    bytes.push(0);
    std::fs::write(&core, bytes).unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = layout(
        &config,
        "tool",
        &verified,
        out.path(),
        Options {
            strip: false,
            ..Options::default()
        },
    )
    .expect_err("refused")
    .to_string();
    assert!(err.contains("changed since verify read it"), "{err}");
}

#[test]
fn artifacts_verified_for_another_product_are_refused() {
    let input = tempfile::tempdir().unwrap();
    artifacts(input.path());
    let config = config();
    let verified = seaworthy::verify::verify(&config, "tool", input.path()).expect("verifies");
    let out = tempfile::tempdir().unwrap();
    let err = layout(&config, "other", &verified, out.path(), Options::default())
        .expect_err("refused")
        .to_string();
    assert!(err.contains("verified for product \"tool\""), "{err}");
}

#[test]
fn the_manifest_is_relative_to_its_directory() {
    let out = tempfile::tempdir().unwrap();
    run(out.path(), false).expect("lays out");
    let manifest = out.path().join("tool").join(LINUX).join("layout.json");
    let json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    assert_eq!(json["tree"], "tree");
    let first = json["files"][0]["path"].as_str().unwrap();
    assert_eq!(first, "opt/acme/tool/AcmeTool");
    assert!(
        manifest
            .parent()
            .unwrap()
            .join("tree")
            .join(first)
            .is_file()
    );
}
