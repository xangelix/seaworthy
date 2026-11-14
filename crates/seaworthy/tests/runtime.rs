//! Bundled runtimes (`[[product.<id>.runtime]]`) through `verify` and
//! `layout`: exactly the pinned files with the pinned bytes, native code of
//! the platform checked as the product's own, a `DT_NEEDED` entry reached
//! through an `$ORIGIN` `DT_RUNPATH` and nothing else, and the tree laid out
//! with each file's mode and destination.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::{Path, PathBuf};

use common::{Elf, LOADER, Pe, cpulist, record, write};
use seaworthy::DistError;
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::layout::Role;

const V2: &[&str] = &[
    "cmpxchg16b",
    "fxsr",
    "lahfsahf",
    "popcnt",
    "sse",
    "sse2",
    "sse3",
    "sse4.1",
    "sse4.2",
    "ssse3",
    "x87",
];

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
outputs = ["deb", "rpm", "tar", "zip"]
targets = ["x86-64-v2"]
linux.needed = ["libnss3.so"]
linux.depends.deb = ["libnss3"]
linux.depends.rpm = ["nss"]

[[product.viewer.runtime]]
name = "engine"
distribution = "engine-1.0-linux64"
platform = "linux"
pins = "engine-linux.sha256"
destination = "lib"
strip = true

[[product.viewer.runtime.files]]
path = "engine-sandbox"
destination = "engine-sandbox"
mode = "4755"

[[product.viewer.runtime]]
name = "engine"
distribution = "engine-1.0-win64"
platform = "windows"
pins = "engine-windows.sha256"
"#;

/// A project directory (its `seaworthy.toml` and pin lists) and an
/// artifact directory with everything the viewer needs.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn project(&self) -> PathBuf {
        self.dir.path().join("project")
    }
    fn artifacts(&self) -> PathBuf {
        self.dir.path().join("artifacts")
    }
    fn runtime(&self, triple: &str) -> PathBuf {
        self.artifacts().join(triple).join("runtime/engine")
    }
    /// Rewrites the pin lists from what the runtime directories hold now.
    fn pin(&self) {
        for (triple, pins) in [
            (LINUX, "engine-linux.sha256"),
            (WINDOWS, "engine-windows.sha256"),
        ] {
            let mut lines = Vec::new();
            pin_dir(&self.runtime(triple), "", &mut lines);
            lines.sort();
            std::fs::write(self.project().join(pins), lines.join("")).unwrap();
        }
    }
    fn config(&self) -> Config {
        Config::load(&self.project().join("seaworthy.toml")).expect("loads")
    }
    fn with_config(&self, text: &str) -> Config {
        std::fs::write(self.project().join("seaworthy.toml"), text).unwrap();
        self.config()
    }
    fn findings(&self, config: &Config) -> Vec<String> {
        match seaworthy::verify::verify(config, "viewer", &self.artifacts()) {
            Ok(_) => Vec::new(),
            Err(DistError::Verify(findings)) => findings,
            Err(other) => panic!("not a verify error: {other}"),
        }
    }
    fn expect(&self, mentions: &[&str]) {
        let found = self.findings(&self.config());
        assert!(
            found.iter().any(|f| mentions.iter().all(|m| f.contains(m))),
            "expected a finding mentioning {mentions:?}, got {found:#?}"
        );
    }
}

fn pin_dir(dir: &Path, prefix: &str, lines: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().unwrap().is_dir() {
            pin_dir(&entry.path(), &relative, lines);
        } else {
            let bytes = std::fs::read(entry.path()).unwrap();
            lines.push(format!(
                "{}  {relative}\n",
                seaworthy_crypto::digest::sha256_hex(&bytes)
            ));
        }
    }
}

fn core(needed: &[&str], runpath: Option<&str>) -> Elf {
    Elf {
        sections: vec![(".cpureq".into(), record(LINUX, "x86-64-v2", V2))],
        symbols: vec![("main".into(), true)],
        needed: needed.iter().map(|s| (*s).to_owned()).collect(),
        runpath: runpath.map(str::to_owned),
        ..Elf::default()
    }
}

fn engine_library() -> Elf {
    Elf {
        symbols: vec![("engine_init".into(), true)],
        needed: vec!["libc.so.6".into(), "libnss3.so".into()],
        soname: Some("libengine.so".into()),
        ..Elf::default()
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let fx = Fixture { dir };
    std::fs::create_dir_all(fx.project()).unwrap();
    std::fs::write(fx.project().join("seaworthy.toml"), CONFIG).unwrap();
    let root = fx.artifacts();
    let list = cpulist("acme_viewer_core", &["x86-64-v2"]);
    write(
        &root,
        &format!("{LINUX}/launcher/AcmeViewer"),
        &Elf {
            sections: vec![(".cpulist".into(), list.clone())],
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    write(
        &root,
        &format!("{LINUX}/cores/x86-64-v2/libacme_viewer_core.so"),
        &core(&["libc.so.6", "libengine.so"], Some("$ORIGIN")).build(),
    );
    let rt = format!("{LINUX}/runtime/engine");
    write(
        &root,
        &format!("{rt}/libengine.so"),
        &engine_library().build(),
    );
    write(
        &root,
        &format!("{rt}/engine-sandbox"),
        &Elf {
            symbols: vec![("main".into(), true)],
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    write(&root, &format!("{rt}/resources.pak"), b"PAK resources");
    write(&root, &format!("{rt}/locales/en-US.pak"), b"PAK en-US");
    write(
        &root,
        &format!("{WINDOWS}/launcher/AcmeViewer.exe"),
        &Pe {
            sections: vec![(".cpulist".into(), list)],
            imports: vec!["kernel32.dll".into()],
            executable: true,
        }
        .build(),
    );
    write(
        &root,
        &format!("{WINDOWS}/cores/x86-64-v2/acme_viewer_core.dll"),
        &Pe {
            sections: vec![(".cpureq".into(), record(WINDOWS, "x86-64-v2", V2))],
            imports: vec!["engine.dll".into(), "kernel32.dll".into()],
            executable: false,
        }
        .build(),
    );
    let rt = format!("{WINDOWS}/runtime/engine");
    write(
        &root,
        &format!("{rt}/engine.dll"),
        &Pe {
            sections: vec![(".text".into(), b"engine".to_vec())],
            imports: vec!["kernel32.dll".into()],
            executable: false,
        }
        .build(),
    );
    write(&root, &format!("{rt}/resources.pak"), b"PAK resources");
    fx.pin();
    fx
}

#[test]
fn a_pinned_runtime_verifies_with_its_destinations_and_modes() {
    let fx = fixture();
    let verified =
        seaworthy::verify::verify(&fx.config(), "viewer", &fx.artifacts()).expect("verifies");
    let linux = verified
        .platforms()
        .iter()
        .find(|p| p.inputs.triple == LINUX)
        .unwrap();
    let [runtime] = linux.runtimes.as_slice() else {
        panic!("one linux runtime: {:?}", linux.runtimes);
    };
    assert_eq!(runtime.distribution, "engine-1.0-linux64");
    let files: Vec<(&str, &str, u32)> = runtime
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.install.as_str(), f.mode))
        .collect();
    assert_eq!(
        files,
        [
            ("engine-sandbox", "engine-sandbox", 0o4755),
            ("libengine.so", "lib/libengine.so", 0o755),
            ("locales/en-US.pak", "lib/locales/en-US.pak", 0o644),
            ("resources.pak", "lib/resources.pak", 0o644),
        ]
    );
    let windows = verified
        .platforms()
        .iter()
        .find(|p| p.inputs.triple == WINDOWS)
        .unwrap();
    let installs: Vec<&str> = windows.runtimes[0]
        .files
        .iter()
        .map(|f| f.install.as_str())
        .collect();
    assert_eq!(installs, ["engine.dll", "resources.pak"]);
}

#[test]
fn a_runtime_holds_exactly_its_pinned_bytes() {
    // An extra file.
    let fx = fixture();
    write(&fx.runtime(LINUX), "extra.so", b"extra");
    fx.expect(&["extra.so", "isn't in runtime \"engine\"'s pins"]);
    // A missing one.
    let fx = fixture();
    std::fs::remove_file(fx.runtime(LINUX).join("locales/en-US.pak")).unwrap();
    fx.expect(&["en-US.pak", "is pinned in runtime \"engine\", but missing"]);
    // Other bytes.
    let fx = fixture();
    write(&fx.runtime(WINDOWS), "resources.pak", b"PAK other");
    fx.expect(&["resources.pak", "SHA-256", "engine-1.0-win64"]);
    // A link (never followed) and no directory at all.
    let fx = fixture();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", fx.runtime(LINUX).join("passwd")).unwrap();
        fx.expect(&["passwd", "a link or a special file"]);
    }
    let fx = fixture();
    std::fs::remove_dir_all(fx.runtime(WINDOWS)).unwrap();
    fx.expect(&["runtime/engine", "the runtime's directory"]);
}

#[test]
fn a_file_past_the_cap_is_refused_and_the_cap_is_explicit() {
    let fx = fixture();
    let big = vec![b'P'; 2 * 1024 * 1024];
    write(&fx.runtime(LINUX), "big.pak", &big);
    fx.pin();
    let config =
        fx.with_config(&CONFIG.replace("strip = true\n", "strip = true\nmax-file-mib = 1\n"));
    let found = fx.findings(&config);
    assert!(
        found
            .iter()
            .any(|f| f.contains("big.pak") && f.contains("max-file-mib (1 MiB)")),
        "{found:#?}"
    );
    // The default (256 MiB) holds it.
    assert_eq!(fx.findings(&fx.with_config(CONFIG)), Vec::<String>::new());
}

#[test]
fn native_code_must_be_the_platforms_and_pass_its_checks() {
    // A PE in a Linux runtime.
    let fx = fixture();
    write(
        &fx.runtime(LINUX),
        "helper.dll",
        &Pe {
            imports: vec!["kernel32.dll".into()],
            ..Pe::default()
        }
        .build(),
    );
    fx.pin();
    fx.expect(&["helper.dll", "native code for another platform"]);
    // A runtime library needing a library nobody declared.
    let fx = fixture();
    let mut lib = engine_library();
    lib.needed.push("libcups.so.2".into());
    write(&fx.runtime(LINUX), "libengine.so", &lib.build());
    fx.pin();
    fx.expect(&["libengine.so", "needs libcups.so.2 beyond the base system"]);
    // Initial-exec TLS in a runtime library the launcher's dlopen loads.
    let fx = fixture();
    let mut lib = engine_library();
    lib.static_tls = true;
    write(&fx.runtime(LINUX), "libengine.so", &lib.build());
    fx.pin();
    fx.expect(&["libengine.so", "initial-exec TLS"]);
    // A glibc past the floor.
    let fx = fixture();
    let mut lib = engine_library();
    lib.verneed = vec![("libc.so.6".into(), vec![("GLIBC_2.39".into(), 0)])];
    lib.imports = vec![("pidfd_spawnp".into(), "GLIBC_2.39".into())];
    write(&fx.runtime(LINUX), "libengine.so", &lib.build());
    fx.pin();
    fx.expect(&["libengine.so", "GLIBC_2.39", "glibc floor 2.34"]);
    // A Windows runtime DLL importing the dynamic C runtime.
    let fx = fixture();
    write(
        &fx.runtime(WINDOWS),
        "engine.dll",
        &Pe {
            imports: vec!["VCRUNTIME140.dll".into(), "kernel32.dll".into()],
            ..Pe::default()
        }
        .build(),
    );
    fx.pin();
    fx.expect(&["engine.dll", "dynamic C runtime"]);
    // Setuid for anything but an ELF executable.
    let fx = fixture();
    let config = CONFIG.replace("path = \"engine-sandbox\"", "path = \"libengine.so\"");
    let found = fx.findings(&fx.with_config(&config));
    assert!(
        found
            .iter()
            .any(|f| f.contains("libengine.so") && f.contains("mode 4755")),
        "{found:#?}"
    );
}

#[test]
fn a_bundled_library_is_reached_only_through_an_origin_runpath() {
    let core_path = format!("{LINUX}/cores/x86-64-v2/libacme_viewer_core.so");
    let with_core = |elf: Elf| {
        let fx = fixture();
        write(&fx.artifacts(), &core_path, &elf.build());
        fx
    };
    // No DT_RUNPATH.
    with_core(core(&["libc.so.6", "libengine.so"], None)).expect(&[
        "libacme_viewer_core.so",
        "needs libengine.so",
        "no DT_RUNPATH",
    ]);
    // An absolute entry, even beside $ORIGIN.
    with_core(core(
        &["libc.so.6", "libengine.so"],
        Some("$ORIGIN:/usr/lib"),
    ))
    .expect(&["needs libengine.so", "\"/usr/lib\" isn't $ORIGIN-relative"]);
    // Leaving the install root.
    with_core(core(&["libc.so.6", "libengine.so"], Some("$ORIGIN/../..")))
        .expect(&["needs libengine.so", "leaves the install root"]);
    // A directory the library isn't in.
    with_core(core(&["libc.so.6", "libengine.so"], Some("$ORIGIN/engine"))).expect(&[
        "needs libengine.so",
        "not in a directory this binary's DT_RUNPATH reaches",
    ]);
    // DT_RPATH instead of DT_RUNPATH.
    let mut rpath = core(&["libc.so.6", "libengine.so"], None);
    rpath.rpath = Some("$ORIGIN".into());
    with_core(rpath).expect(&["needs libengine.so", "DT_RPATH"]);
    // `$ORIGIN/../lib` from lib/ is lib/ again.
    assert_eq!(
        with_core(core(&["libc.so.6", "libengine.so"], Some("$ORIGIN/../lib")))
            .findings(&fixture().config()),
        Vec::<String>::new()
    );
    // A library whose DT_SONAME is another name.
    let fx = fixture();
    let mut lib = engine_library();
    lib.soname = Some("libengine.so.2".into());
    write(&fx.runtime(LINUX), "libengine.so", &lib.build());
    fx.pin();
    fx.expect(&["needs libengine.so", "DT_SONAME"]);
    // The launcher at the root reaches lib/ through $ORIGIN/lib.
    let fx = fixture();
    write(
        &fx.artifacts(),
        &format!("{LINUX}/launcher/AcmeViewer"),
        &Elf {
            sections: vec![(
                ".cpulist".into(),
                cpulist("acme_viewer_core", &["x86-64-v2"]),
            )],
            needed: vec!["libc.so.6".into(), "libengine.so".into()],
            interp: Some(LOADER.into()),
            runpath: Some("$ORIGIN/lib".into()),
            ..Elf::default()
        }
        .build(),
    );
    assert_eq!(fx.findings(&fx.config()), Vec::<String>::new());
    // Without the runtime, the core's need is what it always was.
    let fx = fixture();
    let config = CONFIG
        .split("[[product.viewer.runtime]]")
        .next()
        .unwrap()
        .to_owned();
    let found = fx.findings(&fx.with_config(&config));
    assert!(
        found
            .iter()
            .any(|f| f.contains("needs libengine.so beyond the base system")
                && !f.contains("DT_RUNPATH")),
        "{found:#?}"
    );
}

#[test]
fn the_tree_lays_out_with_each_files_destination_mode_and_strip() {
    let fx = fixture();
    let config = fx.config();
    let verified = seaworthy::verify::verify(&config, "viewer", &fx.artifacts()).unwrap();
    let out = fx.dir.path().join("dist");
    let strip = common::have("strip", &["--version"]);
    let layouts = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        &out,
        seaworthy::layout::Options {
            strip,
            ..seaworthy::layout::Options::default()
        },
    )
    .expect("lays out");
    let linux = common::layout_for(&layouts, LINUX);
    let runtime: Vec<(&str, u32)> = linux
        .files
        .iter()
        .filter(|f| matches!(&f.role, Role::Runtime { runtime } if runtime == "engine"))
        .map(|f| (f.install_path.as_str(), f.mode))
        .collect();
    assert_eq!(
        runtime,
        [
            ("/opt/acme/viewer/engine-sandbox", 0o4755),
            ("/opt/acme/viewer/lib/libengine.so", 0o755),
            ("/opt/acme/viewer/lib/locales/en-US.pak", 0o644),
            ("/opt/acme/viewer/lib/resources.pak", 0o644),
        ]
    );
    assert_eq!(
        linux.runtimes,
        [("engine".to_owned(), "engine-1.0-linux64".to_owned())]
    );
    // Staged without the setuid bit (only the package's copy gets it).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let sandbox = linux
            .files
            .iter()
            .find(|f| f.install_path.ends_with("/engine-sandbox"))
            .unwrap();
        let mode = std::fs::metadata(&sandbox.staged)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755);
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("viewer").join(LINUX).join("layout.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["runtimes"],
        serde_json::json!([{ "name": "engine", "distribution": "engine-1.0-linux64" }])
    );
    let entry = |suffix: &str| {
        manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["install_path"].as_str().unwrap().ends_with(suffix))
            .unwrap()
            .clone()
    };
    let lib = entry("/lib/libengine.so");
    assert_eq!(
        lib["role"],
        serde_json::json!({ "kind": "runtime", "runtime": "engine" })
    );
    if strip {
        assert_eq!(lib["strip"], "non-alloc");
        assert_eq!(entry("/engine-sandbox")["strip"], "non-alloc");
    }
    assert!(entry("/lib/resources.pak").get("strip").is_none());
    let windows = common::layout_for(&layouts, WINDOWS);
    let installs: Vec<&str> = windows
        .files
        .iter()
        .filter(|f| matches!(f.role, Role::Runtime { .. }))
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        installs,
        ["Acme\\Viewer\\engine.dll", "Acme\\Viewer\\resources.pak"]
    );
}

#[test]
fn a_runtime_file_may_not_land_on_the_products_own() {
    let fx = fixture();
    // Its destination is the launcher's.
    let config = fx.with_config(&CONFIG.replace(
        "destination = \"engine-sandbox\"",
        "destination = \"AcmeViewer\"",
    ));
    let verified = seaworthy::verify::verify(&config, "viewer", &fx.artifacts()).unwrap();
    let err = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        &fx.dir.path().join("dist"),
        seaworthy::layout::Options {
            strip: false,
            ..seaworthy::layout::Options::default()
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("two files would install as /opt/acme/viewer/AcmeViewer"),
        "{err}"
    );
}

/// The Linux packages and the tarball install the runtime with its modes,
/// root-owned: the setuid helper as `-rwsr-xr-x root root`, a library 0755,
/// data 0644, nested directories included; the zip carries the Windows
/// runtime beside the launcher.
#[test]
fn the_packages_carry_each_runtime_file_root_owned_with_its_mode() {
    let Some(nfpm) = common::nfpm() else { return };
    let tools = ["dpkg-deb", "rpm", "bsdtar"];
    if !tools.iter().all(|tool| common::have(tool, &["--version"])) {
        assert!(!common::required(), "{tools:?} are required");
        return;
    }
    let fx = fixture();
    let config = fx.config();
    let verified = seaworthy::verify::verify(&config, "viewer", &fx.artifacts()).unwrap();
    let out = fx.dir.path().join("dist");
    let layouts = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        &out,
        seaworthy::layout::Options {
            strip: false,
            ..seaworthy::layout::Options::default()
        },
    )
    .unwrap();
    let artifacts = seaworthy::package::package(
        &config,
        "viewer",
        &layouts,
        &out,
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm,
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .expect("packages");
    use seaworthy::package::Kind;
    let listing = |program: &str, args: &[&str], file: &Path| {
        common::run(std::process::Command::new(program).args(args).arg(file))
    };
    let deb = listing(
        "dpkg-deb",
        &["-c"],
        &common::artifact(&artifacts, Kind::Deb),
    );
    let line = |text: &str, path: &str| {
        text.lines()
            .find(|l| l.ends_with(path))
            .unwrap_or_else(|| panic!("{path} not in:\n{text}"))
            .to_owned()
    };
    assert!(line(&deb, "/opt/acme/viewer/engine-sandbox").starts_with("-rwsr-xr-x root/root"));
    assert!(line(&deb, "/opt/acme/viewer/lib/libengine.so").starts_with("-rwxr-xr-x root/root"));
    assert!(
        line(&deb, "/opt/acme/viewer/lib/locales/en-US.pak").starts_with("-rw-r--r-- root/root")
    );
    assert!(line(&deb, "/opt/acme/viewer/lib/locales/").starts_with("drwxr-xr-x root/root"));
    let rpm = listing(
        "rpm",
        &[
            "-qp",
            "--qf",
            "[%{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILENAMES}\n]",
        ],
        &common::artifact(&artifacts, Kind::Rpm),
    );
    assert_eq!(
        line(&rpm, "/opt/acme/viewer/engine-sandbox"),
        "-rwsr-xr-x root root /opt/acme/viewer/engine-sandbox"
    );
    assert_eq!(
        line(&rpm, "/opt/acme/viewer/lib/resources.pak"),
        "-rw-r--r-- root root /opt/acme/viewer/lib/resources.pak"
    );
    let tar = listing(
        "bsdtar",
        &["-tvf"],
        &common::artifact(&artifacts, Kind::Tar),
    );
    assert!(
        line(&tar, "/engine-sandbox").starts_with("-rwsr-xr-x"),
        "{tar}"
    );
    assert!(
        line(&tar, "/lib/locales/en-US.pak").starts_with("-rw-r--r--"),
        "{tar}"
    );
    let zip = listing("bsdtar", &["-tf"], &common::artifact(&artifacts, Kind::Zip));
    assert!(
        zip.lines().any(|l| l.ends_with("/engine.dll"))
            && zip.lines().any(|l| l.ends_with("/resources.pak")),
        "{zip}"
    );
}

/// A self-signed code-signing certificate for `subject` (OpenSSL's slash
/// form) and its key (0600).
fn certificate(dir: &Path, name: &str, subject: &str) -> (PathBuf, PathBuf) {
    let (cert, key) = (
        dir.join(format!("{name}.pem")),
        dir.join(format!("{name}.key")),
    );
    common::run(
        std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30", "-subj", subject,
            ])
            .args([
                "-addext",
                "extendedKeyUsage=codeSigning",
                "-addext",
                "keyUsage=digitalSignature",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (cert, key)
}

fn osslsigncode(cert: &Path, key: &Path) -> seaworthy::codesign::Osslsigncode {
    seaworthy::codesign::Osslsigncode {
        tool: PathBuf::from("osslsigncode"),
        certificate: cert.to_path_buf(),
        key: key.to_path_buf(),
        timestamp_url: None,
        url: None,
        timeout: std::time::Duration::from_secs(120),
    }
}

/// Windows: an unsigned runtime DLL is signed with the product's identity
/// (never version-stamped); one that arrives signed keeps its signature only
/// when it verifies to a publisher the runtime lists, and anyone else's is
/// refused; data is shipped as pinned.
#[test]
fn a_signed_runtime_dll_keeps_its_signature_only_from_a_listed_publisher() {
    use seaworthy::codesign::AuthenticodeSigner as _;
    if !common::have("osslsigncode", &["--version"]) || !common::have("openssl", &["version"]) {
        assert!(!common::required(), "osslsigncode and openssl are required");
        return;
    }
    let fx = fixture();
    let keys = fx.project();
    let (own_cert, own_key) = certificate(&keys, "own", "/CN=Acme Test Code Signing/O=Acme");
    let (vendor_cert, vendor_key) = certificate(
        &keys,
        "vendor",
        "/CN=Engine Vendor Code Signing/O=Engine Vendor",
    );
    let (stranger_cert, stranger_key) = certificate(&keys, "stranger", "/CN=Stranger/O=Nobody");
    let runtime = fx.runtime(WINDOWS);
    // The vendor's signed DLL, pinned as it arrives.
    std::fs::copy(runtime.join("engine.dll"), runtime.join("vendor.dll")).unwrap();
    osslsigncode(&vendor_cert, &vendor_key)
        .sign(&runtime.join("vendor.dll"), "Engine")
        .unwrap();
    fx.pin();
    let config_text = format!(
        "{}\n[[product.viewer.runtime.publishers]]\nsubject = \"O=Engine Vendor,CN=Engine Vendor Code Signing\"\ntrust = \"vendor.pem\"\n",
        CONFIG.replace(
            "license = \"MIT\"\n",
            "license = \"MIT\"\n\n[defaults.authenticode]\nsubject = \"O=Acme,CN=Acme Test Code Signing\"\ntrust = \"own.pem\"\n",
        )
    );
    let config = fx.with_config(&config_text);
    let package = |config: &Config, out: &str| {
        let mut config = config.clone();
        config.only_platforms(&[seaworthy::config::Platform::Windows]);
        let config = &config;
        let verified = seaworthy::verify::verify(config, "viewer", &fx.artifacts())?;
        let out = fx.dir.path().join(out);
        let layouts = seaworthy::layout::layout(
            config,
            "viewer",
            &verified,
            &out,
            seaworthy::layout::Options {
                strip: false,
                ..seaworthy::layout::Options::default()
            },
        )?;
        seaworthy::package::package(
            config,
            "viewer",
            &layouts,
            &out,
            &seaworthy::package::Options {
                release: common::release(),
                mtime: 1_700_000_000,
                nfpm: PathBuf::from("nfpm"),
                wix: None,
                build: seaworthy::sign::BuildId::default(),
            },
            &seaworthy::package::Signing {
                authenticode: Some(Box::new(osslsigncode(&own_cert, &own_key))),
                authenticode_only: true,
                ..seaworthy::package::Signing::default()
            },
        )
        .map(|_| out)
    };
    let out = package(&config, "dist").expect("packages");
    let tree = out.join("viewer").join(WINDOWS).join("tree/Acme/Viewer");
    let signer = |file: &str, ca: &Path| {
        let report = seaworthy::codesign::verify_authenticode(
            Path::new("osslsigncode"),
            &tree.join(file),
            Some(ca),
        )
        .unwrap();
        seaworthy::codesign::signer_subject(&report).map(str::to_owned)
    };
    assert_eq!(
        signer("engine.dll", &own_cert).as_deref(),
        Some("O=Acme,CN=Acme Test Code Signing")
    );
    assert_eq!(
        signer("vendor.dll", &vendor_cert).as_deref(),
        Some("O=Engine Vendor,CN=Engine Vendor Code Signing")
    );
    // The vendor's file is shipped as pinned; data too; ours was only signed
    // (no version resource stamped into the engine's DLL).
    let pinned = |file: &str| std::fs::read(runtime.join(file)).unwrap();
    assert_eq!(
        std::fs::read(tree.join("vendor.dll")).unwrap(),
        pinned("vendor.dll")
    );
    assert_eq!(
        std::fs::read(tree.join("resources.pak")).unwrap(),
        pinned("resources.pak")
    );
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.join("viewer").join(WINDOWS).join("layout.json")).unwrap(),
    )
    .unwrap();
    let entry = |suffix: &str| {
        manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["install_path"].as_str().unwrap().ends_with(suffix))
            .unwrap()
            .clone()
    };
    assert_eq!(entry("\\engine.dll")["sign"], "certificate-table");
    assert!(entry("\\engine.dll").get("stamp").is_none());
    assert!(entry("\\vendor.dll").get("sign").is_none());
    // Signed by anyone the runtime doesn't list: refused.
    osslsigncode(&stranger_cert, &stranger_key)
        .sign(&runtime.join("engine.dll"), "Engine")
        .unwrap();
    fx.pin();
    let err = package(&config, "dist-refused").unwrap_err().to_string();
    assert!(
        err.contains("engine.dll: arrives Authenticode-signed, but not by a publisher runtime \"engine\" allows"),
        "{err}"
    );
    // And with no publishers listed at all.
    std::fs::write(
        fx.project().join("seaworthy.toml"),
        config_text
            .split("\n[[product.viewer.runtime.publishers]]")
            .next()
            .unwrap(),
    )
    .unwrap();
    let err = package(&fx.config(), "dist-none").unwrap_err().to_string();
    assert!(err.contains("it lists none"), "{err}");
}
