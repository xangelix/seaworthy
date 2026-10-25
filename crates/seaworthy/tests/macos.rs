//! macOS outputs: `seaworthy.toml`'s macOS settings,
//! the aarch64-apple-darwin build plan, `verify`'s Mach-O checks and the
//! app bundle `layout` stages — over hand-written Mach-O images
//! (`common::Macho`). Signing and the disk image need macOS's own tools:
//! the Mac runner's end-to-end script covers them
//! (`scripts/launcher-e2e-macos.sh`); here, off a Mac, `package` refuses a
//! dmg by name, and `--platforms` leaves the dmg to the Mac.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::Path;

use common::{M1, MACOS_CPUS, Macho, cpulist, record, write};
use seaworthy::config::Config;
use seaworthy::inputs::MACOS;

/// A desktop product shipped as a dmg alone.
const DESKTOP: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "Views things."
executable = "AcmeTool"
core = "acme_core"
kind = "desktop"
outputs = ["dmg"]
updates.default = "off"

[product.viewer.macos]
bundle-id = "test.acme.viewer"
category = "public.app-category.utilities"
"#;

fn config(text: &str) -> Result<Config, String> {
    Config::parse(text).map_err(|e| e.to_string())
}

fn refused(text: &str, needle: &str) {
    let err = config(text).expect_err("refused");
    assert!(err.contains(needle), "{err}");
}

#[test]
fn the_macos_settings_are_validated() {
    let ok = config(DESKTOP).unwrap();
    assert_eq!(ok.defaults.macos_targets, ["apple-m4", "apple-m1"]);
    assert_eq!(ok.defaults.macos_minimum, "11.0");
    // The defaults: apple-m1 alone, macOS 11.0.
    let defaults =
        config(&DESKTOP.replace("macos-targets = [\"apple-m4\", \"apple-m1\"]\n", "")).unwrap();
    assert_eq!(defaults.defaults.macos_targets, ["apple-m1"]);
    refused(
        &DESKTOP.replace(
            "[product.viewer.macos]\nbundle-id = \"test.acme.viewer\"\ncategory = \"public.app-category.utilities\"\n",
            "",
        ),
        "a macOS output needs [product.<id>.macos]",
    );
    refused(
        &DESKTOP.replace("bundle-id = \"test.acme.viewer\"", "bundle-id = \"viewer\""),
        "macos.bundle-id",
    );
    refused(
        &DESKTOP.replace("public.app-category.utilities", "Utilities"),
        "macos.category",
    );
    refused(
        &DESKTOP.replace("[defaults]", "[defaults]\nmacos-minimum = \"10.15\""),
        "defaults.macos-minimum",
    );
    refused(
        &DESKTOP.replace(
            "display-name = \"Acme Viewer\"",
            "display-name = \".Acme Viewer\"",
        ),
        "product.viewer.display-name",
    );
    refused(
        &DESKTOP.replace("kind = \"desktop\"", "kind = \"tool\""),
        "dmg holds a desktop app",
    );
    refused(
        &DESKTOP.replace("outputs = [\"dmg\"]", "outputs = [\"zip\"]"),
        "set, but no output is for macOS",
    );
}

#[test]
fn a_desktop_apps_dmg_carries_no_helper_where_its_other_outputs_do() {
    // The console ships a helper (the MSI's interactive-users grant,
    // the Linux polkit rule) and a dmg, which updates by download: its Mac
    // build builds no helper, its Windows and Linux builds do.
    let text = DESKTOP
        .replace("updates.default = \"off\"", "helper = \"AcmeToolUpdate\"")
        .replace("outputs = [\"dmg\"]", "outputs = [\"dmg\", \"zip\"]")
        .replace(
            "channel = \"stable\"",
            "channel = \"stable\"\nrelease-signatures = [\"ml-dsa-87\"]",
        );
    let config = config(&text).unwrap();
    let mac =
        seaworthy::build_plan::render(&seaworthy::build_plan::plan(&config, MACOS, None).unwrap());
    assert!(!mac.contains("AcmeToolUpdate"), "{mac}");
    let windows = seaworthy::build_plan::render(
        &seaworthy::build_plan::plan(&config, "x86_64-pc-windows-msvc", None).unwrap(),
    );
    assert!(windows.contains("--bin AcmeToolUpdate"), "{windows}");
}

#[test]
fn the_macos_plan_builds_dylibs_for_the_deployment_target() {
    let config = config(DESKTOP).unwrap();
    let text =
        seaworthy::build_plan::render(&seaworthy::build_plan::plan(&config, MACOS, None).unwrap());
    let deployment = "--config env.MACOSX_DEPLOYMENT_TARGET.value=\"11.0\" --config env.MACOSX_DEPLOYMENT_TARGET.force=true";
    assert!(
        text.contains(&format!("build\tbase\t-\t--bin AcmeTool {deployment}")),
        "{text}"
    );
    for cpu in ["apple-m4", "apple-m1"] {
        assert!(
            text.contains(&format!(
                "build\t{cpu}\t-C target-cpu={cpu}\t-p acme_core {deployment}"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "copy\t{cpu}/{MACOS}/release/libacme_core.dylib\t{MACOS}/cores/{cpu}/libacme_core.dylib"
            )),
            "{text}"
        );
    }
    assert!(!text.contains("crt-static"), "{text}");
    // Cargo takes those arguments as the build step passes them (one word
    // each: an inline table is refused on the command line, as the Mac
    // runner's first run found), and the forced value reaches build scripts
    // over the job's own.
    if common::have("cargo", &["--version"]) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"deployment\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(
            dir.path().join("build.rs"),
            "fn main() { assert_eq!(std::env::var(\"MACOSX_DEPLOYMENT_TARGET\").as_deref(), Ok(\"11.0\")); }\n",
        )
        .unwrap();
        let out = std::process::Command::new("cargo")
            .current_dir(dir.path())
            .args(["build", "--quiet", "--offline", "--target-dir"])
            .arg(dir.path().join("target"))
            .args(deployment.split(' '))
            .env("MACOSX_DEPLOYMENT_TARGET", "99.0")
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // A dmg-only product needs no Linux or Windows build.
    assert!(
        seaworthy::build_plan::plan(&config, seaworthy::inputs::LINUX, None)
            .unwrap()
            .is_empty()
    );
}

/// The fixture's macOS artifacts under `dir/artifacts`, verified.
fn verified(config: &Config, dir: &Path) -> seaworthy::verify::Verified {
    let artifacts = dir.join("artifacts");
    common::acme_macos_artifacts(&artifacts);
    seaworthy::verify::verify(config, "viewer", &artifacts).expect("verifies")
}

fn findings(config: &Config, artifacts: &Path) -> String {
    seaworthy::verify::verify(config, "viewer", artifacts)
        .map(|_| String::new())
        .unwrap_or_else(|e| e.to_string())
}

#[test]
fn verify_holds_mach_o_binaries_to_the_platform() {
    let config = config(DESKTOP).unwrap();
    let dir = tempfile::tempdir().unwrap();
    verified(&config, dir.path());
    let artifacts = dir.path().join("artifacts");
    let core = format!("{MACOS}/cores/apple-m1/libacme_core.dylib");
    let core_record = || {
        vec![(
            "__DATA".into(),
            "__cpureq".into(),
            record(MACOS, "apple-m1", common::M1),
        )]
    };
    let cases: Vec<(Macho, &str)> = vec![
        (
            Macho {
                cputype: 0x0100_0007,
                sections: core_record(),
                ..Macho::default()
            },
            "not an arm64 binary",
        ),
        (
            Macho {
                executable: true,
                sections: core_record(),
                ..Macho::default()
            },
            "not a dynamic library (MH_DYLIB)",
        ),
        (
            Macho {
                sections: core_record(),
                dylibs: vec![
                    "/usr/lib/libSystem.B.dylib".into(),
                    "@rpath/libfoo.dylib".into(),
                    "/opt/homebrew/lib/libssl.3.dylib".into(),
                ],
                ..Macho::default()
            },
            "links @rpath/libfoo.dylib, /opt/homebrew/lib/libssl.3.dylib outside the system's libraries",
        ),
        (
            Macho {
                sections: core_record(),
                build_version: Some((1, (13, 0, 0))),
                ..Macho::default()
            },
            "needs macOS 13.0.0, newer than defaults.macos-minimum 11.0",
        ),
        (
            Macho {
                sections: core_record(),
                build_version: None,
                ..Macho::default()
            },
            "no LC_BUILD_VERSION",
        ),
        (
            Macho {
                sections: core_record(),
                build_version: Some((2, (11, 0, 0))),
                ..Macho::default()
            },
            "built for another platform than macOS",
        ),
        (
            Macho {
                sections: vec![(
                    "__DATA".into(),
                    "__cpureq".into(),
                    record(MACOS, "apple-m1", &["avx2", "neon"]),
                )],
                ..Macho::default()
            },
            "features seaworthy_levels has no row for (avx2)",
        ),
    ];
    for (image, needle) in cases {
        common::acme_macos_artifacts(&artifacts);
        write(&artifacts, &core, &image.build());
        let found = findings(&config, &artifacts);
        assert!(found.contains(needle), "{needle}: {found}");
    }
    // A universal binary is refused, whatever its slice holds.
    common::acme_macos_artifacts(&artifacts);
    let thin = Macho {
        sections: core_record(),
        ..Macho::default()
    }
    .build();
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat.extend_from_slice(&1_u32.to_be_bytes());
    fat.extend_from_slice(&common::CPU_TYPE_ARM64.to_be_bytes());
    fat.extend_from_slice(&0_u32.to_be_bytes());
    fat.extend_from_slice(&4096_u32.to_be_bytes());
    fat.extend_from_slice(&u32::try_from(thin.len()).unwrap().to_be_bytes());
    fat.extend_from_slice(&12_u32.to_be_bytes());
    fat.resize(4096, 0);
    fat.extend_from_slice(&thin);
    write(&artifacts, &core, &fat);
    let found = findings(&config, &artifacts);
    assert!(found.contains("universal"), "{found}");
    // The launcher's CPU list is held to macos-targets.
    common::acme_macos_artifacts(&artifacts);
    write(
        &artifacts,
        &format!("{MACOS}/launcher/AcmeTool"),
        &Macho {
            executable: true,
            sections: vec![(
                "__DATA".into(),
                "__cpulist".into(),
                cpulist("acme_core", &["apple-m1"]),
            )],
            ..Macho::default()
        }
        .build(),
    );
    let found = findings(&config, &artifacts);
    assert!(
        found.contains("seaworthy.toml's macos-targets are"),
        "{found}"
    );
}

#[test]
fn layout_stages_an_app_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    write(&project, "assets/fonts/a.ttf", b"font");
    let mut icns = b"icns".to_vec();
    icns.extend_from_slice(&[0, 0, 0, 8]);
    write(&project, "assets/viewer.icns", &icns);
    let text = format!(
        "{DESKTOP}icon = \"assets/viewer.icns\"\n\n[[product.viewer.files]]\nsource = \"assets/fonts\"\ndestination = \"share/fonts\"\n"
    );
    std::fs::write(project.join("seaworthy.toml"), &text).unwrap();
    let config = Config::load(&project.join("seaworthy.toml")).unwrap();
    let verified = verified(&config, dir.path());
    let layouts = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        &dir.path().join("dist"),
        seaworthy::layout::Options::default(),
    )
    .unwrap();
    assert_eq!(layouts.len(), 1);
    let layout = &layouts[0];
    assert_eq!(layout.install_root, "/Applications/Acme Viewer.app");
    let paths: Vec<&str> = layout
        .files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/Applications/Acme Viewer.app/Contents/MacOS/AcmeTool",
            "/Applications/Acme Viewer.app/Contents/Frameworks/libacme_core_apple-m4.dylib",
            "/Applications/Acme Viewer.app/Contents/Frameworks/libacme_core_apple-m1.dylib",
            "/Applications/Acme Viewer.app/Contents/Resources/share/fonts/a.ttf",
            "/Applications/Acme Viewer.app/Contents/Resources/AppIcon.icns",
        ]
    );
    for file in &layout.files {
        let relative = file.install_path.strip_prefix("/Applications/").unwrap();
        assert_eq!(file.staged, layout.tree.join(relative));
        assert!(file.staged.is_file());
    }
    // A data file landing on the icon is refused.
    let clash = format!(
        "{DESKTOP}icon = \"assets/viewer.icns\"\n\n[[product.viewer.files]]\nsource = \"assets/viewer.icns\"\ndestination = \"AppIcon.icns\"\n"
    );
    std::fs::write(project.join("seaworthy.toml"), &clash).unwrap();
    let config = Config::load(&project.join("seaworthy.toml")).unwrap();
    let err = seaworthy::layout::layout(
        &config,
        "viewer",
        &seaworthy::verify::verify(&config, "viewer", &dir.path().join("artifacts")).unwrap(),
        &dir.path().join("dist2"),
        seaworthy::layout::Options::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("the bundle's icon"), "{err}");
}

#[test]
fn the_info_plist_names_the_bundle_and_the_release() {
    let config = config(DESKTOP).unwrap();
    let product = &config.products["viewer"];
    let plist = seaworthy::macos::info_plist(product, &common::release(), "11.0", true).unwrap();
    for needle in [
        "<key>CFBundleExecutable</key>\n\t<string>AcmeTool</string>",
        "<key>CFBundleIdentifier</key>\n\t<string>test.acme.viewer</string>",
        "<key>CFBundleShortVersionString</key>\n\t<string>1.4.0</string>",
        "<key>CFBundleVersion</key>\n\t<string>812</string>",
        "<key>CFBundleIconFile</key>\n\t<string>AppIcon.icns</string>",
        "<key>LSApplicationCategoryType</key>\n\t<string>public.app-category.utilities</string>",
        "<key>LSMinimumSystemVersion</key>\n\t<string>11.0</string>",
        "<key>CFBundlePackageType</key>\n\t<string>APPL</string>",
    ] {
        assert!(plist.contains(needle), "{needle}\n{plist}");
    }
}

/// Off a Mac, a dmg is refused by name: codesign and hdiutil are macOS's.
#[cfg(not(target_os = "macos"))]
#[test]
fn off_a_mac_package_refuses_a_dmg_by_name() {
    let config = config(DESKTOP).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let verified = verified(&config, dir.path());
    let layouts = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        &dir.path().join("dist"),
        seaworthy::layout::Options::default(),
    )
    .unwrap();
    let err = seaworthy::package::package(
        &config,
        "viewer",
        &layouts,
        &dir.path().join("dist"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm: "nfpm".into(),
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains(
            "product viewer's dmg needs macOS's own codesign, hdiutil, pkgbuild and productbuild: package it on a Mac"
        ),
        "{err}"
    );
}

fn seaworthy(dir: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_seaworthy"))
        .current_dir(dir)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .env_remove("NFPM")
        .env_remove("SEAWORTHY_WIX")
        .output()
        .unwrap()
}

fn said(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `--platforms`: CI packages macOS on the Mac and everything else
/// on Linux, so a product with a tarball and a dmg packages its tarball
/// without any macOS artifact, and a dmg-only product is skipped there by
/// name; `--platforms macos` packages the dmg alone (refused by name off a
/// Mac). A product `--product` names but `--platforms` leaves empty, an
/// unknown platform and a repeated one are refused.
#[test]
fn platforms_split_the_mac_s_outputs_from_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let text = DESKTOP.replace("outputs = [\"dmg\"]", "outputs = [\"tar\", \"dmg\"]")
        + "\n[product.mac-only]\ndisplay-name = \"Acme Mac\"\ndescription = \"Macs only.\"\n\
           executable = \"AcmeTool\"\ncore = \"acme_core\"\nkind = \"desktop\"\noutputs = [\"dmg\"]\n\
           updates.default = \"off\"\n\n[product.mac-only.macos]\nbundle-id = \"test.acme.mac\"\n";
    std::fs::write(dir.path().join("seaworthy.toml"), &text).unwrap();
    // Linux and Windows artifacts alone: no macOS build here.
    common::acme_artifacts(&dir.path().join("artifacts"));
    let package = |out: &str, extra: &[&str]| {
        let mut args = vec![
            "package",
            "--no-strip",
            "--artifacts",
            "artifacts",
            "--out",
            out,
            "--release",
            "2.1.0",
            "--sequence",
            "7",
        ];
        args.extend_from_slice(extra);
        seaworthy(dir.path(), &args)
    };
    let rest = package("rest", &["--platforms", "linux,windows"]);
    assert!(rest.status.success(), "{}", said(&rest));
    assert!(
        said(&rest)
            .contains("--platforms linux,windows: product mac-only has no outputs there, skipped"),
        "{}",
        said(&rest)
    );
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.path().join("rest/viewer/packages.json")).unwrap(),
    )
    .unwrap();
    let kinds: Vec<&str> = listing["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["tar", "sbom"], "the dmg is the Mac's");
    assert!(!dir.path().join("rest/mac-only").exists());
    // Without --platforms every output is packaged: the macOS artifacts are
    // missing here.
    let all = package("all", &[]);
    assert_eq!(all.status.code(), Some(1), "{}", said(&all));
    assert!(said(&all).contains(MACOS), "{}", said(&all));
    let verify = seaworthy(
        dir.path(),
        &["verify", "--artifacts", "artifacts", "--platforms", "linux"],
    );
    assert!(verify.status.success(), "{}", said(&verify));
    #[cfg(not(target_os = "macos"))]
    {
        common::acme_macos_artifacts(&dir.path().join("artifacts"));
        let mac = package("mac", &["--platforms", "macos", "--product", "viewer"]);
        assert_eq!(mac.status.code(), Some(1), "{}", said(&mac));
        assert!(
            said(&mac).contains("product viewer's dmg needs macOS's own codesign, hdiutil"),
            "{}",
            said(&mac)
        );
    }
    let empty = package("x", &["--platforms", "windows", "--product", "mac-only"]);
    assert_eq!(empty.status.code(), Some(1), "{}", said(&empty));
    assert!(
        said(&empty).contains("product mac-only has no outputs for --platforms windows"),
        "{}",
        said(&empty)
    );
    for (platforms, says) in [
        ("bsd", "\"bsd\" isn't a platform (linux, windows, macos)"),
        ("linux,linux", "linux is named twice"),
        ("", "\"\" isn't a platform"),
    ] {
        let out = package("x", &["--platforms", platforms]);
        assert_eq!(out.status.code(), Some(2), "{platforms}: {}", said(&out));
        assert!(said(&out).contains(says), "{platforms}: {}", said(&out));
    }
}

/// A macOS service product: the collector's shape — root, the update
/// helper, a pkg beside a deb.
const SERVICE: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.agent]
display-name = "Acme Field Agent"
description = "The Acme agent."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
windows-directory = "Agent"
outputs = ["deb", "pkg"]
updates.default = "auto"

[product.agent.service]
name = "AcmeAgent"
account = "local-system"
arguments = ["service"]
restart-delays = ["15s", "60s"]
state-directory = "acme/agent"

[product.agent.macos]
bundle-id = "com.acme.agent"
"#;

#[test]
fn a_macos_service_ships_as_a_pkg() {
    let ok = config(SERVICE).unwrap();
    assert!(
        ok.products["agent"]
            .outputs
            .contains(&seaworthy::config::Output::Pkg)
    );
    // A pkg holds a service; a dmg a desktop app (which can't carry the
    // helper's daemon: the_macos_settings_are_validated).
    refused(
        &DESKTOP.replace("outputs = [\"dmg\"]", "outputs = [\"pkg\"]"),
        "pkg holds a macOS service",
    );
    refused(
        &SERVICE.replace("outputs = [\"deb\", \"pkg\"]", "outputs = [\"dmg\"]"),
        "dmg holds a desktop app",
    );
    // A sandbox user: not on macOS yet.
    refused(
        &(SERVICE.replace("account = \"local-system\"", "account = \"virtual\"")
            + "\n[product.agent.service.sandbox]\nuser = \"_acmeagent\"\n"),
        "a macOS service runs as root for now",
    );
}

#[test]
fn the_pkg_s_daemons_scripts_and_uninstaller() {
    use seaworthy::macos;
    let config = config(SERVICE).unwrap();
    let product = &config.products["agent"];
    let names = macos::pkg_names(&config, "agent", product).unwrap();
    assert_eq!(names.identifier, "com.acme.agent");
    assert_eq!(names.bundle, "/Applications/Acme Field Agent.app");
    assert_eq!(names.labels(), ["AcmeAgent-update", "AcmeAgent"]);
    assert_eq!(
        names.support,
        Path::new("/Library/Application Support/Acme/Agent")
    );
    assert_eq!(names.logs, Path::new("/Library/Logs/Acme/Agent"));
    // The service's daemon runs the launcher in the bundle, logging to its
    // file; the helper's watches the request file the helper's Product names.
    let daemons = macos::launch_daemons(&config, "agent", product).unwrap();
    assert_eq!(
        daemons.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>(),
        ["AcmeAgent", "AcmeAgent-update"]
    );
    for needle in [
        "<string>/Applications/Acme Field Agent.app/Contents/MacOS/AcmeTool</string>",
        "<string>service</string>",
        "<key>RunAtLoad</key>",
        "<string>/Library/Logs/Acme/Agent/AcmeAgent.log</string>",
    ] {
        assert!(daemons[0].1.contains(needle), "{needle}\n{}", daemons[0].1);
    }
    let request = config
        .update_product("agent", product)
        .unwrap()
        .macos_request_file()
        .unwrap();
    for needle in [
        "<string>/Applications/Acme Field Agent.app/Contents/MacOS/AcmeToolUpdate</string>"
            .to_owned(),
        format!(
            "<key>WatchPaths</key>\n\t<array>\n\t\t<string>{}</string>",
            request.display()
        ),
        "<string>/Library/Logs/Acme/Agent/AcmeAgent-update.log</string>".to_owned(),
    ] {
        assert!(daemons[1].1.contains(&needle), "{needle}\n{}", daemons[1].1);
    }
    // The scripts: quoted paths (spaces), the service stopped and started,
    // the helper loaded only when it isn't (it may be running the install).
    let pre = macos::preinstall(&names);
    assert!(
        pre.contains("/bin/launchctl bootout system/'AcmeAgent'"),
        "{pre}"
    );
    assert!(!pre.contains("AcmeAgent-update"), "{pre}");
    let post = macos::postinstall(&names);
    for needle in [
        "/bin/mkdir -p '/Library/Application Support/Acme/Agent/state' '/Library/Application Support/Acme/Agent/updates' '/Library/Logs/Acme/Agent'",
        "/bin/chmod 0700 '/Library/Application Support/Acme/Agent/state' '/Library/Application Support/Acme/Agent/updates'",
        "/bin/launchctl bootstrap system '/Library/LaunchDaemons/AcmeAgent.plist'",
        "if ! disabled 'AcmeAgent-update' && ! loaded 'AcmeAgent-update'; then",
    ] {
        assert!(post.contains(needle), "{needle}\n{post}");
    }
    assert!(
        !post.contains("bootout"),
        "postinstall never stops a daemon: {post}"
    );
    let uninstall = macos::uninstaller(&names);
    for needle in [
        "/bin/launchctl bootout system/'AcmeAgent-update'",
        "/bin/rm -f '/Library/LaunchDaemons/AcmeAgent.plist'",
        "/bin/rm -rf '/Applications/Acme Field Agent.app'",
        "/usr/sbin/pkgutil --forget 'com.acme.agent'",
        "/bin/rm -rf '/Library/Application Support/Acme/Agent' '/Library/Logs/Acme/Agent'",
    ] {
        assert!(uninstall.contains(needle), "{needle}\n{uninstall}");
    }
    // Every script parses, and passes shellcheck where it's installed.
    for (name, text) in [
        ("preinstall", &pre),
        ("postinstall", &post),
        ("uninstall", &uninstall),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        let parsed = std::process::Command::new("sh")
            .arg("-n")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            parsed.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&parsed.stderr)
        );
        if common::have("shellcheck", &["--version"]) {
            let checked = std::process::Command::new("shellcheck")
                .args(["-s", "sh"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                checked.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&checked.stdout)
            );
        }
    }
    // The bundle never relocates or version-checks; the distribution is
    // Apple Silicon, macos-minimum or later, the startup volume.
    let component = macos::component_plist(&names);
    for needle in [
        "<key>BundleIsRelocatable</key>\n\t\t<false/>",
        "<key>BundleIsVersionChecked</key>\n\t\t<false/>",
        "<string>Applications/Acme Field Agent.app</string>",
    ] {
        assert!(component.contains(needle), "{needle}\n{component}");
    }
    let distribution = macos::distribution(&names, "2.1.0-7", "11.0");
    for needle in [
        "hostArchitectures=\"arm64\"",
        "<os-version min=\"11.0\"/>",
        "enable_localSystem=\"true\"",
        "<pkg-ref id=\"com.acme.agent\" version=\"2.1.0-7\" onConclusion=\"none\">component.pkg</pkg-ref>",
    ] {
        assert!(distribution.contains(needle), "{needle}\n{distribution}");
    }
}

/// However the postinstall ends, it starts the daemons the preinstall
/// stopped, and a failure stays its status: run against stand-in tools
/// (`launchctl` answering that nothing is loaded, a `mkdir` that fails or
/// succeeds). The macOS install lane breaks a real one.
#[test]
fn the_postinstall_starts_the_service_however_it_ends() {
    use seaworthy::macos;
    use std::os::unix::fs::PermissionsExt as _;
    let config = config(SERVICE).unwrap();
    let product = &config.products["agent"];
    let names = macos::pkg_names(&config, "agent", product).unwrap();
    let post = macos::postinstall(&names);
    assert!(post.contains("trap start_daemons EXIT"), "{post}");
    let run = |mkdir_ok: bool, bootstrap_ok: bool| -> (i32, String) {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("launchctl.log");
        let stub = |name: &str, body: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path.to_string_lossy().into_owned()
        };
        let launchctl = stub(
            "launchctl",
            &format!(
                "echo \"$*\" >> '{}'\ncase \"$1\" in print) exit 113 ;; bootstrap) exit {} ;; *) exit 0 ;; esac",
                log.display(),
                u8::from(!bootstrap_ok)
            ),
        );
        let mkdir = stub(
            "mkdir",
            if mkdir_ok {
                "exit 0"
            } else {
                "echo 'mkdir: Permission denied' >&2; exit 1"
            },
        );
        let fine = stub("fine", "exit 0");
        let script = post
            .replace("/bin/launchctl", &launchctl)
            .replace("/bin/mkdir", &mkdir)
            .replace("/usr/sbin/chown", &fine)
            .replace("/bin/chmod", &fine);
        let path = dir.path().join("postinstall");
        std::fs::write(&path, script).unwrap();
        let status = std::process::Command::new("sh")
            .arg(&path)
            .args(["component.pkg", "/", "/"])
            .status()
            .unwrap();
        (
            status.code().unwrap(),
            std::fs::read_to_string(&log).unwrap_or_default(),
        )
    };
    let started = |log: &str| {
        log.contains("bootstrap system /Library/LaunchDaemons/AcmeAgent.plist")
            && log.contains("bootstrap system /Library/LaunchDaemons/AcmeAgent-update.plist")
    };
    let (code, log) = run(true, true);
    assert_eq!(code, 0, "{log}");
    assert!(started(&log), "{log}");
    // A directory it can't make: the daemons start anyway, the install fails.
    let (code, log) = run(false, true);
    assert_eq!(code, 1, "{log}");
    assert!(started(&log), "{log}");
    // A daemon launchd won't load fails the install.
    let (code, log) = run(true, false);
    assert_eq!(code, 1, "{log}");
}

/// Off a Mac, a pkg is refused by name like a dmg; the bundle it would
/// hold is laid out with the helper beside the launcher.
#[cfg(not(target_os = "macos"))]
#[test]
fn off_a_mac_package_refuses_a_pkg_by_name() {
    let config =
        config(&SERVICE.replace("outputs = [\"deb\", \"pkg\"]", "outputs = [\"pkg\"]")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    common::acme_macos_artifacts(&artifacts);
    write(
        &artifacts,
        &format!("{MACOS}/helper/AcmeToolUpdate"),
        &Macho {
            executable: true,
            ..Macho::default()
        }
        .build(),
    );
    let verified = seaworthy::verify::verify(&config, "agent", &artifacts).unwrap();
    let layouts = seaworthy::layout::layout(
        &config,
        "agent",
        &verified,
        &dir.path().join("dist"),
        seaworthy::layout::Options::default(),
    )
    .unwrap();
    assert!(
        layouts[0].files.iter().any(|f| f.install_path
            == "/Applications/Acme Field Agent.app/Contents/MacOS/AcmeToolUpdate")
    );
    let err = seaworthy::package::package(
        &config,
        "agent",
        &layouts,
        &dir.path().join("dist"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm: "nfpm".into(),
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("product agent's pkg needs macOS's own"),
        "{err}"
    );
}

/// fips on macOS: AWS-LC builds the module as a dylib off Linux,
/// so it ships once in the bundle's Contents/Frameworks (`sidecars.macos`),
/// each core loads it through `@rpath` with `@loader_path` as its search
/// path, and the module's own symbols meet the Linux checks.
#[test]
fn a_fips_product_ships_the_module_s_dylib_in_the_bundle() {
    let module = format!(
        "lib{}crypto.dylib",
        seaworthy_crypto::module::FIPS_SYMBOL_PREFIX
    );
    let fips = DESKTOP
        .replace("[defaults]", "[defaults]\nfips = true")
        .replace(
            "updates.default = \"off\"",
            "updates.default = \"off\"\nsidecars.macos = [\"libaws_lc_fips_*_crypto.dylib\"]",
        );
    let config_fips = config(&fips).unwrap();
    // The rules: fips with a macOS output needs the module's sidecar, and a
    // macOS sidecar needs a macOS output.
    refused(
        &DESKTOP.replace("[defaults]", "[defaults]\nfips = true"),
        "with fips, a macOS build ships the FIPS module's dylib",
    );
    refused(
        &fips
            .replace("outputs = [\"dmg\"]", "outputs = [\"tar\"]")
            .replace(
                "[product.viewer.macos]\nbundle-id = \"test.acme.viewer\"\ncategory = \"public.app-category.utilities\"\n",
                "",
            ),
        "sidecars.macos: set, but no output is for macOS",
    );
    // The plan: search paths, and the module copied from the first CPU's
    // build beside every core.
    let plan = seaworthy::build_plan::render(
        &seaworthy::build_plan::plan(&config_fips, MACOS, None).unwrap(),
    );
    assert!(
        plan.contains(
            "build\tbase\t-C link-arg=-Wl,-rpath,@executable_path/../Frameworks\t--bin AcmeTool"
        ),
        "{plan}"
    );
    for cpu in MACOS_CPUS {
        assert!(
            plan.contains(&format!(
                "build\t{cpu}\t-C target-cpu={cpu} -C link-arg=-Wl,-rpath,@loader_path\t-p acme_core"
            )),
            "{plan}"
        );
        assert!(
            plan.contains(&format!(
                "sidecars\tapple-m4/{MACOS}/release/build\tlibaws_lc_fips_*_crypto.dylib\t{MACOS}/cores/{cpu}"
            )),
            "{plan}"
        );
    }
    // verify: FIPS cores load the module through @rpath with @loader_path;
    // the module (a dylib with no symbol table here) meets the symbol check.
    let artifacts_for = |core_dylibs: &[&str], rpaths: &[&str]| {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        common::acme_macos_artifacts(&artifacts);
        for cpu in MACOS_CPUS {
            let mut features = M1.to_vec();
            if cpu == "apple-m4" {
                features.extend(["bf16", "i8mm", "v8.5a", "v8.6a", "v8.7a"]);
            }
            write(
                &artifacts,
                &format!("{MACOS}/cores/{cpu}/libacme_core.dylib"),
                &Macho {
                    sections: vec![(
                        "__DATA".into(),
                        "__cpureq".into(),
                        record(MACOS, cpu, &features),
                    )],
                    dylibs: core_dylibs.iter().map(|d| (*d).to_owned()).collect(),
                    rpaths: rpaths.iter().map(|r| (*r).to_owned()).collect(),
                    ..Macho::default()
                }
                .build(),
            );
            write(
                &artifacts,
                &format!("{MACOS}/cores/{cpu}/{module}"),
                &Macho::default().build(),
            );
        }
        (dir, artifacts)
    };
    let rpath_module = format!("@rpath/{module}");
    let good = ["/usr/lib/libSystem.B.dylib", rpath_module.as_str()];
    let (_keep, artifacts) = artifacts_for(&good, &["@loader_path"]);
    let found = findings(&config_fips, &artifacts);
    assert!(
        found.contains(&module) && found.contains("no symbol table"),
        "{found}"
    );
    assert!(
        !found.contains("libacme_core.dylib"),
        "the cores pass: {found}"
    );
    // A core without the search path, one without the module, one loading
    // a library that isn't a sidecar.
    let (_keep, artifacts) = artifacts_for(&good, &[]);
    assert!(findings(&config_fips, &artifacts).contains("has no @loader_path search path"));
    let (_keep, artifacts) = artifacts_for(&["/usr/lib/libSystem.B.dylib"], &["@loader_path"]);
    assert!(
        findings(&config_fips, &artifacts).contains(&format!("does not load {rpath_module}")),
        "{}",
        findings(&config_fips, &artifacts)
    );
    let (_keep, artifacts) = artifacts_for(
        &[rpath_module.as_str(), "@rpath/libssl.dylib"],
        &["@loader_path"],
    );
    assert!(findings(&config_fips, &artifacts).contains("@rpath/libssl.dylib"));
    // Without fips, the same sidecar verifies and lays out in
    // Contents/Frameworks, once.
    let plain = config(&fips.replace("fips = true\n", "")).unwrap();
    let (_keep, artifacts) = artifacts_for(&good, &["@loader_path"]);
    let verified = seaworthy::verify::verify(&plain, "viewer", &artifacts).unwrap();
    let out = tempfile::tempdir().unwrap();
    let layouts = seaworthy::layout::layout(
        &plain,
        "viewer",
        &verified,
        out.path(),
        seaworthy::layout::Options::default(),
    )
    .unwrap();
    let placed: Vec<&str> = layouts[0]
        .files
        .iter()
        .filter(|f| f.role == seaworthy::layout::Role::Sidecar)
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        placed,
        [format!(
            "/Applications/Acme Viewer.app/Contents/Frameworks/{module}"
        )]
    );
}
