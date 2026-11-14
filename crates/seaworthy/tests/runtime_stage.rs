//! `seaworthy runtime-stage`: a bundled runtime staged from an unpacked
//! distribution into the artifact directory, each pinned file from the
//! first root holding it, checked against its pin as it is copied, never
//! through a link, all or nothing; on Windows also beside each core.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use seaworthy::DistError;
use seaworthy::config::Config;

const LINUX: &str = "x86_64-unknown-linux-gnu";
const WINDOWS: &str = "x86_64-pc-windows-msvc";

const CONFIG: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "Views."
executable = "AcmeViewer"
core = "acme_viewer_core"
kind = "desktop"
updates.default = "off"
windows-directory = "Viewer"
outputs = ["deb", "zip"]

[[product.viewer.runtime]]
name = "engine"
distribution = "engine-1.0-linux64"
platform = "linux"
pins = "linux.sha256"
destination = "lib"

[[product.viewer.runtime.files]]
path = "engine-sandbox"
destination = "engine-sandbox"

[[product.viewer.runtime]]
name = "engine"
distribution = "engine-1.0-win64"
platform = "windows"
pins = "windows.sha256"
destination = "engine"
"#;

/// A project (its seaworthy.toml and pins), an unpacked distribution with
/// two roots (`Release`, `Resources`) and an artifact directory.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }
    fn write(&self, relative: &str, bytes: &[u8]) {
        let path = self.path(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    fn config(&self) -> Config {
        Config::load(&self.path("project/seaworthy.toml")).unwrap()
    }
    fn roots(&self) -> Vec<PathBuf> {
        vec![self.path("dist/Release"), self.path("dist/Resources")]
    }
    fn stage(&self, triple: &str, beside: bool) -> Result<seaworthy::runtime::Staged, DistError> {
        seaworthy::runtime::stage(
            &self.config(),
            "viewer",
            "engine",
            triple,
            &self.roots(),
            &self.path("artifacts"),
            beside,
        )
    }
    fn refusals(&self, triple: &str, beside: bool) -> Vec<String> {
        match self.stage(triple, beside) {
            Err(DistError::Verify(findings)) => findings,
            other => panic!("expected refusals, got {other:?}"),
        }
    }
    fn runtime(&self, triple: &str) -> PathBuf {
        self.path("artifacts").join(triple).join("runtime/engine")
    }
}

fn digest(bytes: &[u8]) -> String {
    seaworthy_crypto::digest::sha256_hex(bytes)
}

fn fixture() -> Fixture {
    let fx = Fixture {
        dir: tempfile::tempdir().unwrap(),
    };
    fx.write("project/seaworthy.toml", CONFIG.as_bytes());
    // The distribution: more than ships (an import library, headers), the
    // runtime's files split over two roots.
    fx.write("dist/Release/libengine.so", b"\x7fELF engine");
    fx.write("dist/Release/engine-sandbox", b"\x7fELF sandbox");
    fx.write("dist/Release/engine.dll", b"MZ engine");
    fx.write("dist/Release/engine.lib", b"import library");
    fx.write("dist/Resources/resources.pak", b"PAK resources");
    fx.write("dist/Resources/locales/en-US.pak", b"PAK en-US");
    fx.write("dist/include/engine.h", b"/* header */");
    let pins = |files: &[(&str, &[u8])]| {
        files
            .iter()
            .map(|(path, bytes)| format!("{}  {path}\n", digest(bytes)))
            .collect::<String>()
    };
    fx.write(
        "project/linux.sha256",
        pins(&[
            ("libengine.so", b"\x7fELF engine"),
            ("engine-sandbox", b"\x7fELF sandbox"),
            ("resources.pak", b"PAK resources"),
            ("locales/en-US.pak", b"PAK en-US"),
        ])
        .as_bytes(),
    );
    fx.write(
        "project/windows.sha256",
        pins(&[
            ("engine.dll", b"MZ engine"),
            ("resources.pak", b"PAK resources"),
            ("locales/en-US.pak", b"PAK en-US"),
        ])
        .as_bytes(),
    );
    fx
}

/// Every file below `dir`, relative and sorted.
fn listing(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                out.push(
                    entry
                        .path()
                        .strip_prefix(dir)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_pinned_files_are_staged_from_the_roots_and_nothing_else() {
    let fx = fixture();
    let staged = fx.stage(LINUX, false).unwrap();
    assert_eq!(staged.dir, fx.runtime(LINUX));
    assert_eq!(staged.files, 4);
    assert!(staged.beside_cores.is_empty());
    // Exactly the pinned files, from either root; never the import
    // library or the headers.
    assert_eq!(
        listing(&fx.runtime(LINUX)),
        [
            "engine-sandbox",
            "libengine.so",
            "locales/en-US.pak",
            "resources.pak"
        ]
    );
    assert_eq!(
        std::fs::read(fx.runtime(LINUX).join("locales/en-US.pak")).unwrap(),
        b"PAK en-US"
    );
    // What verify then reads: no leftover staging directory beside it.
    assert_eq!(
        std::fs::read_dir(fx.path("artifacts").join(LINUX).join("runtime"))
            .unwrap()
            .count(),
        1
    );
    // Staging again replaces it whole (a file that no longer belongs goes).
    fx.write(
        &format!("artifacts/{LINUX}/runtime/engine/stale.pak"),
        b"stale",
    );
    fx.stage(LINUX, false).unwrap();
    assert!(!fx.runtime(LINUX).join("stale.pak").exists());
}

#[test]
fn the_first_root_holding_a_path_wins() {
    let fx = fixture();
    // resources.pak in both roots: the Release one (first) is taken, and
    // it isn't the pinned one, so the stage is refused rather than falling
    // through to the second root's matching copy.
    fx.write("dist/Release/resources.pak", b"PAK other");
    let found = fx.refusals(LINUX, false);
    assert!(
        found
            .iter()
            .any(|f| f.contains("Release/resources.pak") && f.contains("pins")),
        "{found:#?}"
    );
    assert!(!fx.runtime(LINUX).exists(), "nothing staged");
    // The other way round: the first root's copy is the pinned one, so the
    // second root's different copy is never read.
    let fx = fixture();
    fx.write("dist/Release/resources.pak", b"PAK resources");
    fx.write("dist/Resources/resources.pak", b"PAK other");
    fx.stage(LINUX, false).unwrap();
    assert_eq!(
        std::fs::read(fx.runtime(LINUX).join("resources.pak")).unwrap(),
        b"PAK resources"
    );
}

#[test]
fn every_refusal_is_reported_together_and_nothing_is_half_staged() {
    let fx = fixture();
    std::fs::remove_file(fx.path("dist/Resources/locales/en-US.pak")).unwrap();
    fx.write("dist/Release/libengine.so", b"\x7fELF tampered");
    let found = fx.refusals(LINUX, false);
    assert!(
        found
            .iter()
            .any(|f| f.contains("locales/en-US.pak: pinned in runtime \"engine\", but in no root")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("libengine.so: SHA-256") && f.contains("engine-1.0-linux64")),
        "{found:#?}"
    );
    assert!(!fx.runtime(LINUX).exists());
    assert_eq!(
        std::fs::read_dir(fx.path("artifacts").join(LINUX).join("runtime"))
            .unwrap()
            .count(),
        0,
        "the staging directory is gone"
    );
    // An earlier staging stays as it was when a new one is refused.
    let fx = fixture();
    fx.stage(LINUX, false).unwrap();
    fx.write("dist/Release/libengine.so", b"\x7fELF tampered");
    fx.refusals(LINUX, false);
    assert_eq!(
        std::fs::read(fx.runtime(LINUX).join("libengine.so")).unwrap(),
        b"\x7fELF engine"
    );
}

#[cfg(unix)]
#[test]
fn a_link_is_refused_never_followed() {
    // The file itself a link (to a pinned file's bytes, even).
    let fx = fixture();
    std::fs::remove_file(fx.path("dist/Resources/resources.pak")).unwrap();
    std::fs::write(fx.path("outside.pak"), b"PAK resources").unwrap();
    std::os::unix::fs::symlink(
        fx.path("outside.pak"),
        fx.path("dist/Resources/resources.pak"),
    )
    .unwrap();
    let found = fx.refusals(LINUX, false);
    assert!(
        found.iter().any(|f| f.contains("resources.pak: a link")),
        "{found:#?}"
    );
    // A directory on the way a link (`locales` pointing out of the root).
    let fx = fixture();
    std::fs::rename(fx.path("dist/Resources/locales"), fx.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink(fx.path("elsewhere"), fx.path("dist/Resources/locales")).unwrap();
    let found = fx.refusals(LINUX, false);
    assert!(
        found.iter().any(|f| f.contains("locales: a link")),
        "{found:#?}"
    );
    // A root that is itself a link.
    let fx = fixture();
    std::os::unix::fs::symlink(fx.path("dist/Release"), fx.path("release-link")).unwrap();
    let err = seaworthy::runtime::stage(
        &fx.config(),
        "viewer",
        "engine",
        LINUX,
        &[fx.path("release-link"), fx.path("dist/Resources")],
        &fx.path("artifacts"),
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("release-link"), "{err}");
}

#[test]
fn a_root_that_doesnt_exist_and_a_path_out_of_the_runtime_are_refused() {
    let fx = fixture();
    let err = seaworthy::runtime::stage(
        &fx.config(),
        "viewer",
        "engine",
        LINUX,
        &[fx.path("dist/Release"), fx.path("dist/Nowhere")],
        &fx.path("artifacts"),
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("dist/Nowhere"), "{err}");
    // A pin naming `..` never reaches a root: its pin list is refused as
    // it is read (by `load`, and by the stage itself).
    let fx = fixture();
    let config = fx.config();
    fx.write(
        "project/linux.sha256",
        format!("{}  ../outside.pak\n", digest(b"x")).as_bytes(),
    );
    let err = Config::load(&fx.path("project/seaworthy.toml"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("isn't a path in the runtime"), "{err}");
    let err = seaworthy::runtime::stage(
        &config,
        "viewer",
        "engine",
        LINUX,
        &fx.roots(),
        &fx.path("artifacts"),
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("isn't a path in the runtime"), "{err}");
    assert!(!fx.runtime(LINUX).exists());
}

#[test]
fn beside_the_cores_on_windows_and_never_over_a_different_file() {
    let fx = fixture();
    // No core build directory yet: --beside-cores runs after the build.
    let found = fx.refusals(WINDOWS, true);
    assert!(
        found
            .iter()
            .any(|f| f.contains("cores/x86-64-v3: no core build directory")),
        "{found:#?}"
    );
    for cpu in ["x86-64-v3", "x86-64-v2"] {
        fx.write(
            &format!("artifacts/{WINDOWS}/cores/{cpu}/acme_viewer_core.dll"),
            b"MZ core",
        );
    }
    let staged = fx.stage(WINDOWS, true).unwrap();
    assert_eq!(staged.beside_cores.len(), 2);
    for cpu in ["x86-64-v3", "x86-64-v2"] {
        // At each file's install path relative to the install root (the
        // runtime's destination, `engine/`), where the core is.
        let dir = fx.path("artifacts").join(WINDOWS).join("cores").join(cpu);
        assert_eq!(
            listing(&dir),
            [
                "acme_viewer_core.dll",
                "engine/engine.dll",
                "engine/locales/en-US.pak",
                "engine/resources.pak"
            ]
        );
    }
    // Again: the same bytes are there, nothing to do.
    fx.stage(WINDOWS, true).unwrap();
    // A different file where one goes: refused, and nothing staged.
    std::fs::remove_dir_all(fx.runtime(WINDOWS)).unwrap();
    fx.write(
        &format!("artifacts/{WINDOWS}/cores/x86-64-v2/engine/engine.dll"),
        b"MZ other",
    );
    let found = fx.refusals(WINDOWS, true);
    assert!(
        found
            .iter()
            .any(|f| f.contains("engine.dll: a different file is there already")),
        "{found:#?}"
    );
    assert!(!fx.runtime(WINDOWS).exists());
    // Linux cores find their libraries through their search path.
    let err = fx.stage(LINUX, true).unwrap_err().to_string();
    assert!(err.contains("--beside-cores"), "{err}");
}

#[test]
fn an_unknown_product_runtime_or_triple_is_refused() {
    let fx = fixture();
    let config = fx.config();
    for (id, name, triple, mentions) in [
        ("nobody", "engine", LINUX, "no product \"nobody\""),
        ("viewer", "other", LINUX, "no runtime \"other\" for linux"),
        ("viewer", "engine", "aarch64-apple-darwin", "ships for"),
        (
            "viewer",
            "engine",
            "riscv64gc-unknown-linux-gnu",
            "ships for",
        ),
    ] {
        let err = seaworthy::runtime::stage(
            &config,
            id,
            name,
            triple,
            &fx.roots(),
            &fx.path("artifacts"),
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(mentions), "{id} {name} {triple}: {err}");
    }
}

/// The command line: staging, `--check`, and its usage refusals.
#[test]
fn the_command_stages_checks_and_refuses_bad_usage() {
    let fx = fixture();
    let config = fx.path("project/seaworthy.toml");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .arg("runtime-stage")
            .arg("--config")
            .arg(&config)
            .args(args)
            .output()
            .unwrap()
    };
    let text = |out: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let base = [
        "--product",
        "viewer",
        "--runtime",
        "engine",
        "--triple",
        LINUX,
    ];
    let check = run(&[&base[..], &["--check"]].concat());
    assert!(check.status.success(), "{}", text(&check));
    assert!(text(&check).contains("4 pinned file(s) (engine-1.0-linux64)"));
    let from = format!(
        "{},{}",
        fx.path("dist/Release").display(),
        fx.path("dist/Resources").display()
    );
    let artifacts = fx.path("artifacts").display().to_string();
    let staged = run(&[&base[..], &["--from", &from, "--artifacts", &artifacts]].concat());
    assert!(staged.status.success(), "{}", text(&staged));
    assert!(text(&staged).contains("4 file(s)"), "{}", text(&staged));
    assert!(fx.runtime(LINUX).join("libengine.so").is_file());
    for (args, code, mentions) in [
        (
            vec!["--product", "viewer", "--triple", LINUX, "--check"],
            2,
            "needs --runtime",
        ),
        (
            [&base[..], &["--check", "--artifacts", &artifacts]].concat(),
            2,
            "--check stages nothing",
        ),
        (
            [&base[..], &["--artifacts", &artifacts]].concat(),
            2,
            "needs --from",
        ),
        (
            [&base[..], &["--from", "a,,b", "--artifacts", &artifacts]].concat(),
            2,
            "empty root",
        ),
        (
            vec![
                "--product",
                "viewer",
                "--runtime",
                "engine",
                "--triple",
                "x",
                "--check",
            ],
            1,
            "ships for",
        ),
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", text(&out));
        assert!(text(&out).contains(mentions), "{args:?}: {}", text(&out));
    }
}
