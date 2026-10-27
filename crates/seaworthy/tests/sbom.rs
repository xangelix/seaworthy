//! SBOMs (`seaworthy::sbom`): the artifact's own identity
//! and digest, every file it installs with its SHA-256, the Rust crates
//! `cargo auditable` recorded in its binaries (runtime ones only, with
//! purls for crates.io), the dependency graph, determinism, and the
//! refusals for broken audit data.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{Elf, release};
use seaworthy::config::Config;
use seaworthy::sbom::{ArtifactInfo, SbomFile, auditable_crates, sbom, sbom_path};
use serde_json::Value;

fn config() -> Config {
    Config::parse(
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
    .unwrap()
}

/// `cargo auditable`'s `.dep-v0` payload for `json`.
fn dep_v0(json: &str) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(json.as_bytes(), 6)
}

const AUDIT: &str = r#"{"packages":[
  {"name":"acme_tool","version":"0.1.0","source":"local","kind":"runtime","dependencies":[1,3,4,2],"root":true},
  {"name":"serde","version":"1.0.210","source":"crates.io","kind":"runtime","dependencies":[]},
  {"name":"zstd-sys","version":"2.1.1+zstd.1.5.7","source":"crates.io","kind":"runtime","dependencies":[]},
  {"name":"tokio","version":"1.40.0","source":"crates.io","dependencies":[1]},
  {"name":"cc","version":"1.1.0","source":"crates.io","kind":"build","dependencies":[]}
]}"#;

fn binary_with_audit(json: &str) -> Vec<u8> {
    Elf {
        sections: vec![(".dep-v0".into(), dep_v0(json))],
        needed: vec!["libc.so.6".into()],
        interp: Some(common::LOADER.into()),
        ..Elf::default()
    }
    .build()
}

fn document(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn an_sbom_names_the_artifact_its_files_and_its_crates() {
    let tmp = tempfile::tempdir().unwrap();
    let artifact = tmp
        .path()
        .join("acme-tool-1.4.0-rc.2-812-linux-x86_64.tar.zst");
    std::fs::write(&artifact, b"the artifact bytes").unwrap();
    let binary = tmp.path().join("AcmeTool");
    std::fs::write(&binary, binary_with_audit(AUDIT)).unwrap();
    let files = vec![
        SbomFile {
            path: "/opt/acme/tool/AcmeTool".into(),
            sha256: seaworthy_crypto::digest::sha256_hex(&std::fs::read(&binary).unwrap()),
            binary: Some(binary.clone()),
        },
        SbomFile {
            path: "/usr/lib/systemd/system/acme.service".into(),
            sha256: seaworthy_crypto::digest::sha256_hex(b"[Unit]\n"),
            binary: None,
        },
    ];
    let info = ArtifactInfo {
        path: &artifact,
        format: "tar",
        target: "x86_64-unknown-linux-gnu",
        files: &files,
    };
    let text = sbom(
        &config(),
        "tool",
        &release(),
        "a1b2c3d4",
        &info,
        1_700_000_000,
    )
    .unwrap();
    // Deterministic: the same inputs give the same bytes.
    assert_eq!(
        text,
        sbom(
            &config(),
            "tool",
            &release(),
            "a1b2c3d4",
            &info,
            1_700_000_000
        )
        .unwrap()
    );
    let doc = document(&text);
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.6");
    let serial = doc["serialNumber"].as_str().unwrap();
    assert!(
        serial.starts_with("urn:uuid:") && serial.len() == 45,
        "{serial}"
    );
    assert_eq!(doc["metadata"]["timestamp"], "2023-11-14T22:13:20Z");
    let component = &doc["metadata"]["component"];
    assert_eq!(component["name"], "acme-tool");
    assert_eq!(component["version"], "1.4.0-rc.2");
    assert_eq!(component["supplier"]["name"], "Acme");
    assert_eq!(component["hashes"][0]["alg"], "SHA-512");
    assert_eq!(
        component["hashes"][0]["content"],
        seaworthy_crypto::digest::sha512_hex(b"the artifact bytes")
    );
    let properties: Vec<(String, String)> = component["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_owned(),
                p["value"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert!(
        properties.contains(&("seaworthy:sequence".into(), "812".into())),
        "{properties:?}"
    );
    assert!(
        properties.contains(&("seaworthy:format".into(), "tar".into())),
        "{properties:?}"
    );
    assert!(
        properties.contains(&("seaworthy:build".into(), "a1b2c3d4".into())),
        "{properties:?}"
    );
    // No build metadata, no build property.
    let bare = document(&sbom(&config(), "tool", &release(), "", &info, 1_700_000_000).unwrap());
    assert!(
        bare["metadata"]["component"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["name"] != "seaworthy:build"),
        "{bare}"
    );
    let components: Vec<(&str, &str)> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["type"].as_str().unwrap(), c["bom-ref"].as_str().unwrap()))
        .collect();
    assert_eq!(
        components,
        [
            ("application", "crate:acme_tool@0.1.0:local"),
            ("file", "file:/opt/acme/tool/AcmeTool"),
            ("file", "file:/usr/lib/systemd/system/acme.service"),
            ("library", "pkg:cargo/serde@1.0.210"),
            ("library", "pkg:cargo/tokio@1.40.0"),
            ("library", "pkg:cargo/zstd-sys@2.1.1%2Bzstd.1.5.7"),
        ],
        "sorted by bom-ref; the build-only crate `cc` is left out"
    );
    let serde = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "serde")
        .unwrap();
    assert_eq!(serde["purl"], "pkg:cargo/serde@1.0.210");
    let local = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "acme_tool")
        .unwrap();
    assert!(local.get("purl").is_none(), "no purl for a local crate");
    let depends = |reference: &str| -> Vec<String> {
        doc["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["ref"] == reference)
            .unwrap()["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        depends("artifact"),
        [
            "file:/opt/acme/tool/AcmeTool",
            "file:/usr/lib/systemd/system/acme.service"
        ]
    );
    assert_eq!(
        depends("file:/opt/acme/tool/AcmeTool"),
        ["crate:acme_tool@0.1.0:local"]
    );
    assert_eq!(
        depends("crate:acme_tool@0.1.0:local"),
        [
            "pkg:cargo/serde@1.0.210",
            "pkg:cargo/tokio@1.40.0",
            "pkg:cargo/zstd-sys@2.1.1%2Bzstd.1.5.7"
        ]
    );
    let zstd = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "zstd-sys")
        .unwrap();
    assert_eq!(
        zstd["purl"], "pkg:cargo/zstd-sys@2.1.1%2Bzstd.1.5.7",
        "the canonical purl: `+` percent-encoded"
    );
    assert_eq!(
        zstd["version"], "2.1.1+zstd.1.5.7",
        "the version itself as written"
    );
    assert_eq!(
        depends("pkg:cargo/tokio@1.40.0"),
        ["pkg:cargo/serde@1.0.210"]
    );
    assert!(
        sbom_path(&artifact)
            .to_string_lossy()
            .ends_with(".tar.zst.cdx.json")
    );
}

#[test]
fn a_binary_without_audit_data_contributes_its_file_only() {
    let plain = Elf {
        interp: Some(common::LOADER.into()),
        ..Elf::default()
    }
    .build();
    assert!(auditable_crates(&plain).unwrap().is_none());
    assert!(auditable_crates(b"not an object file").unwrap().is_none());
}

#[test]
fn broken_audit_data_is_refused() {
    // Not zlib.
    let bad = Elf {
        sections: vec![(".dep-v0".into(), b"garbage".to_vec())],
        ..Elf::default()
    }
    .build();
    assert!(auditable_crates(&bad).is_err());
    // Not the schema.
    assert!(auditable_crates(&binary_with_audit(r#"{"crates":[]}"#)).is_err());
    // A dependency index out of range.
    assert!(auditable_crates(&binary_with_audit(
        r#"{"packages":[{"name":"a","version":"1","source":"local","dependencies":[5],"root":true}]}"#
    ))
    .is_err());
    // A decompression bomb stops at the bound.
    let bomb = vec![b' '; 9 << 20];
    let json = format!("{{\"packages\":[]}}{}", String::from_utf8(bomb).unwrap());
    assert!(auditable_crates(&binary_with_audit(&json)).is_err());
}
