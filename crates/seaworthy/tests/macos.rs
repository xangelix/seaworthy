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

use common::{M1, MACOS_CPUS, Macho, MachoSymbol, cpulist, record, write};
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
    for languages in [
        "[\"en\", \"en\"]",
        "[\"english\"]",
        "[\"pt-\"]",
        "[\"zh-Hans$\"]",
    ] {
        refused(
            &DESKTOP.replace(
                "bundle-id = \"test.acme.viewer\"",
                &format!("bundle-id = \"test.acme.viewer\"\nlocalizations = {languages}"),
            ),
            "macos.localizations",
        );
    }
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

/// An alias of the bundle's executable installs beside it in
/// `Contents/MacOS`, where the launcher finds the cores in `../Frameworks`;
/// the bundle's executable stays the launcher.
#[test]
fn an_alias_installs_beside_the_bundle_s_executable() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    let text = DESKTOP.replace(
        "core = \"acme_core\"",
        "core = \"acme_core\"\naliases = [\"acme-askpass\"]",
    );
    std::fs::create_dir_all(&project).unwrap();
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
    let paths: Vec<(&str, &seaworthy::layout::Role)> = layouts[0]
        .files
        .iter()
        .map(|f| (f.install_path.as_str(), &f.role))
        .collect();
    assert_eq!(
        paths[..2],
        [
            (
                "/Applications/Acme Viewer.app/Contents/MacOS/AcmeTool",
                &seaworthy::layout::Role::Launcher
            ),
            (
                "/Applications/Acme Viewer.app/Contents/MacOS/acme-askpass",
                &seaworthy::layout::Role::Alias
            ),
        ]
    );
    assert_eq!(
        layouts[0].launcher().unwrap().install_path,
        "/Applications/Acme Viewer.app/Contents/MacOS/AcmeTool"
    );
}

/// An alias of the bundle's executable is signed as that program is (the
/// hardened runtime, the entitlements) after the nested code and before the
/// bundle seals it, and its signature checked.
#[cfg(unix)]
#[test]
fn an_alias_is_signed_as_its_program_before_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let tools = mac_stubs(dir.path());
    let id = developer_id(dir.path());
    let bundle = dir.path().join("Acme Viewer.app");
    let core = bundle.join("Contents/Frameworks/libacme_core_apple-m1.dylib");
    let alias = bundle.join("Contents/MacOS/acme-askpass");
    for file in [&core, &alias] {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, b"code").unwrap();
    }
    let entitlements = dir.path().join("entitlements.plist");
    let signer = seaworthy::macos::MacSigner::DeveloperId {
        id: &id,
        team_id: TEAM,
        entitlements: Some(&entitlements),
    };
    seaworthy::macos::sign_bundle(
        &tools,
        &bundle,
        std::slice::from_ref(&core),
        std::slice::from_ref(&alias),
        &signer,
    )
    .unwrap();
    let keychain = id.keychain.as_ref().unwrap().display().to_string();
    let requirement = seaworthy::macos::developer_id_requirement(TEAM);
    let entitled = entitlements.display();
    let (core, alias, bundle) = (core.display(), alias.display(), bundle.display());
    assert_eq!(
        calls(dir.path()),
        [
            format!(
                "codesign|--force|--sign|{IDENTITY}|--timestamp|--options|runtime|--keychain|{keychain}|{core}"
            ),
            format!(
                "codesign|--force|--sign|{IDENTITY}|--timestamp|--options|runtime|--keychain|{keychain}|--entitlements|{entitled}|{alias}"
            ),
            format!(
                "codesign|--force|--sign|{IDENTITY}|--timestamp|--options|runtime|--keychain|{keychain}|--entitlements|{entitled}|{bundle}"
            ),
            format!("codesign|--verify|--strict|--test-requirement|={requirement}|{core}"),
            format!("codesign|--verify|--strict|--test-requirement|={requirement}|{alias}"),
            format!("codesign|--verify|--strict|--deep|--test-requirement|={requirement}|{bundle}"),
        ]
    );
}

#[test]
fn the_info_plist_names_the_bundle_and_the_release() {
    let config = config(DESKTOP).unwrap();
    let product = &config.products["viewer"];
    let plist = seaworthy::macos::info_plist(product, &common::release(), "11.0", true).unwrap();
    assert!(!plist.contains("CFBundleLocalizations"), "{plist}");
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
    // The app's languages, in order.
    let localized = Config::parse(&DESKTOP.replace(
        "bundle-id = \"test.acme.viewer\"",
        "bundle-id = \"test.acme.viewer\"\nlocalizations = [\"en\", \"pt-BR\", \"zh-Hans\"]",
    ))
    .unwrap();
    let plist = seaworthy::macos::info_plist(
        &localized.products["viewer"],
        &common::release(),
        "11.0",
        true,
    )
    .unwrap();
    assert!(
        plist.contains(
            "<key>CFBundleLocalizations</key>\n\t<array>\n\t\t<string>en</string>\n\
             \t\t<string>pt-BR</string>\n\t\t<string>zh-Hans</string>\n\t</array>\n"
        ),
        "{plist}"
    );
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

/// A macOS service product: the collector's shape — root (LocalSystem on
/// Windows, root under systemd, and root on macOS, each said explicitly),
/// the update helper, a pkg beside a deb.
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

[product.agent.service.macos]
account = "root"

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
    // macOS's identity is said explicitly: never root by omission.
    refused(
        &SERVICE.replace("[product.agent.service.macos]\naccount = \"root\"\n", ""),
        "required with a pkg output",
    );
    refused(
        &SERVICE.replace("account = \"root\"", "account = \"_acmeagent\""),
        "unknown variant",
    );
    refused(
        &SERVICE
            .replace("outputs = [\"deb\", \"pkg\"]", "outputs = [\"deb\"]")
            .replace(
                "[product.agent.macos]\nbundle-id = \"com.acme.agent\"\n",
                "",
            ),
        "set, but no output is a pkg",
    );
}

/// Each platform's identity is its own: a product shipping a pkg beside a
/// deb and an MSI runs as its virtual account on Windows and its sandbox
/// user under systemd, and as root only on macOS, where it says so (a pkg
/// creates no daemon account yet).
#[test]
fn a_pkg_beside_a_deb_and_an_msi_keeps_each_platform_s_identity() {
    let text = SERVICE
        .replace(
            "outputs = [\"deb\", \"pkg\"]",
            "outputs = [\"deb\", \"msi\", \"pkg\"]",
        )
        .replace("account = \"local-system\"", "account = \"virtual\"")
        .replace(
            "[product.agent.service.macos]",
            "[product.agent.service.sandbox]\nuser = \"acme-agent\"\n\n[product.agent.service.macos]",
        );
    let config = config(&text).unwrap();
    let product = &config.products["agent"];
    // Linux: the sandbox user.
    let spec = config
        .service_spec("agent", product, Path::new("/opt/acme/agent/AcmeTool"))
        .unwrap();
    let unit = seaworthy_service::render::systemd::unit(
        &spec,
        seaworthy_service::render::systemd::Scope::System,
    )
    .unwrap();
    assert!(unit.contains("\nUser=acme-agent\n"), "{unit}");
    // Windows: the virtual account.
    let record = seaworthy_service::render::windows::service_record(&spec).unwrap();
    assert_eq!(record.account, "NT SERVICE\\AcmeAgent");
    // macOS: root, explicitly — the LaunchDaemon names no user.
    let daemons = seaworthy::macos::launch_daemons(&config, "agent", product).unwrap();
    assert!(!daemons[0].1.contains("UserName"), "{}", daemons[0].1);
    let mac = config
        .macos_service_spec(
            "agent",
            product,
            Path::new("/Applications/x.app/Contents/MacOS/x"),
        )
        .unwrap();
    assert_eq!(mac.unix_identity, seaworthy_service::UnixIdentity::Root);
}

#[test]
fn the_pkg_s_daemons_scripts_and_uninstaller() {
    use seaworthy::macos;
    let config = config(SERVICE).unwrap();
    let product = &config.products["agent"];
    let names = macos::pkg_names(&config, "agent", product).unwrap();
    assert_eq!(names.identifier, "com.acme.agent");
    assert_eq!(
        names.bundle.as_deref(),
        Some("/Applications/Acme Field Agent.app")
    );
    assert_eq!(names.tool, None);
    assert!(names.links.is_empty() && names.conflicts.is_empty());
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
        "/bin/launchctl bootout \"system/$1\"",
        "unload 'AcmeAgent-update'",
        "unload 'AcmeAgent'",
        "/usr/bin/pgrep -f '^/usr/sbin/installer -pkg /Library/Application Support/Acme/Agent/updates/'",
        "/bin/rm -f '/Library/LaunchDaemons/AcmeAgent.plist'",
        "/bin/rm -rf '/Applications/Acme Field Agent.app'",
        "/usr/sbin/pkgutil --forget 'com.acme.agent'",
        "/bin/rm -rf '/Library/Application Support/Acme/Agent' '/Library/Logs/Acme/Agent'",
    ] {
        assert!(uninstall.contains(needle), "{needle}\n{uninstall}");
    }
    // The helper stops first, then the service; nothing is removed before
    // both have.
    let at = |needle: &str| uninstall.find(needle).unwrap();
    assert!(at("unload 'AcmeAgent-update'") < at("/usr/bin/pgrep"));
    assert!(at("/usr/bin/pgrep") < at("unload 'AcmeAgent'"));
    assert!(at("unload 'AcmeAgent'") < at("/bin/rm -f"));
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
    let component = macos::component_plist(&names).unwrap();
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
#[cfg(unix)]
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
    let fips = fips_desktop();
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
                    symbols: fips_core_symbols(),
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

// ---------------------------------------------------------------------------
// A FIPS core's symbol table
//
// Off Linux the module is a dylib: a core imports it, and nothing but the
// core's table shows the non-FIPS AWS-LC, which aws-lc-rs compiles into a
// FIPS build too, stayed out of the link.

const PREFIX: &str = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;

/// [`DESKTOP`] as a FIPS product, shipping the module's dylib.
fn fips_desktop() -> String {
    DESKTOP
        .replace("[defaults]", "[defaults]\nfips = true")
        .replace(
            "updates.default = \"off\"",
            "updates.default = \"off\"\nsidecars.macos = [\"libaws_lc_fips_*_crypto.dylib\"]",
        )
}

/// A FIPS core's table as a rustc cdylib's reads, built the normal way
/// (`strip = false`, the module's dylib, `aws-lc-sys` compiled but unused):
/// the module imported, its own code local, one export, and a debug map
/// naming the sys crates' object files.
fn fips_core_symbols() -> Vec<MachoSymbol> {
    vec![
        MachoSymbol::stab("/build/deps/libaws_lc_fips_sys-0123.rlib(aws_lc_fips_sys-0123.o)"),
        MachoSymbol::local("GCC_except_table0"),
        MachoSymbol::local("__ZN9aws_lc_rs4init17h0123456789abcdefE"),
        MachoSymbol::local("__ZN15aws_lc_fips_sys4init17h0123456789abcdefE"),
        MachoSymbol::local("__dyld_private"),
        MachoSymbol::export("_seaworthy_core_main"),
        MachoSymbol::import(&format!("_{PREFIX}CRYPTO_library_init")),
        MachoSymbol::import(&format!("_{PREFIX}EVP_sha256")),
        MachoSymbol::import("_memcpy"),
    ]
}

fn core_findings(symbols: Vec<MachoSymbol>) -> Vec<String> {
    seaworthy::verify::fips_macos_core_findings(
        &Macho {
            symbols,
            ..Macho::default()
        }
        .build(),
        PREFIX,
    )
}

#[test]
fn a_macos_fips_core_that_only_imports_the_module_passes() {
    assert_eq!(core_findings(fips_core_symbols()), Vec::<String>::new());
    // Neither what the linker adds nor a debug map entry is a symbol of
    // what's linked, whatever it names.
    let mut table = fips_core_symbols();
    table.push(MachoSymbol::local("__mh_dylib_header"));
    table.push(MachoSymbol::stab("_aws_lc_0_46_0_EVP_sha256"));
    assert_eq!(core_findings(table), Vec::<String>::new());
}

#[test]
fn a_macos_fips_core_defining_or_importing_another_provider_is_refused() {
    let cases: Vec<(MachoSymbol, &str)> = vec![
        // What a statically linked aws-lc-sys leaves in a cdylib: hidden, so
        // local; exported or imported, it's linked all the same.
        (
            MachoSymbol::local("_aws_lc_0_46_0_EVP_sha256"),
            "non-FIPS AWS-LC (aws-lc-sys) symbols, e.g. aws_lc_0_46_0_EVP_sha256",
        ),
        (
            MachoSymbol::export("_aws_lc_0_46_0_EVP_sha256"),
            "non-FIPS AWS-LC",
        ),
        (
            MachoSymbol::import("_aws_lc_0_46_0_EVP_sha256"),
            "non-FIPS AWS-LC",
        ),
        (
            MachoSymbol::local("_ring_core_0_17_14__x25519"),
            "ring symbols, e.g. ring_core_0_17_14__x25519",
        ),
        (
            MachoSymbol::local("_aws_lc_fips_0_13_9_SHA256"),
            "of a version other than",
        ),
        (
            MachoSymbol::import("_aws_lc_fips_0_13_9_SHA256"),
            "of a version other than",
        ),
        // An AWS-LC built without a prefix.
        (
            MachoSymbol::local("_awslc_version_string"),
            "unprefixed AWS-LC symbols, e.g. awslc_version_string",
        ),
        (
            MachoSymbol::local("_AWSLC_thread_local_clear"),
            "unprefixed AWS-LC",
        ),
        (
            MachoSymbol::local("_CRYPTO_library_init"),
            "unprefixed AWS-LC",
        ),
    ];
    for (symbol, needle) in cases {
        let name = symbol.name.clone();
        let mut table = fips_core_symbols();
        table.push(symbol);
        let found = core_findings(table);
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        assert!(found[0].contains(needle), "{name}: {found:?}");
    }
}

#[test]
fn a_macos_fips_core_defining_the_module_s_symbols_is_refused() {
    let name = format!("_{PREFIX}SHA256");
    let absolute = MachoSymbol {
        name: name.clone(),
        n_type: 0x03, // N_ABS | N_EXT
        n_sect: 0,
    };
    let indirect = MachoSymbol {
        name: name.clone(),
        n_type: 0x0b, // N_INDR | N_EXT
        n_sect: 0,
    };
    for symbol in [
        MachoSymbol::local(&name),
        MachoSymbol::export(&name),
        absolute,
        indirect,
    ] {
        let mut table = fips_core_symbols();
        table.push(symbol);
        let found = core_findings(table);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].contains(&format!("defines 1 {PREFIX}* symbols, e.g. {PREFIX}SHA256")),
            "{found:?}"
        );
    }
    // The module statically linked: nothing imported, everything defined.
    let table = vec![
        MachoSymbol::local(&format!("_{PREFIX}awslc_version_string")),
        MachoSymbol::local(&format!("_{PREFIX}EVP_sha256")),
        MachoSymbol::export("_seaworthy_core_main"),
    ];
    let found = core_findings(table);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("defines 2"), "{found:?}");
}

#[test]
fn a_macos_fips_core_importing_nothing_of_the_module_is_refused() {
    // It loads the dylib (the load check's), uses nothing from it.
    let table = fips_core_symbols()
        .into_iter()
        .filter(|s| !s.name.contains(PREFIX))
        .collect();
    let found = core_findings(table);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains(&format!("no {PREFIX}* symbols")),
        "{found:?}"
    );
    // Only another release's prefix is no import of the pinned one.
    let found = core_findings(vec![
        MachoSymbol::local("__ZN4core3fmt5write17h0123456789abcdefE"),
        MachoSymbol::import("_aws_lc_fips_0_13_9_SHA256"),
    ]);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].contains(&format!("no {PREFIX}* symbols")),
        "{found:?}"
    );
    assert!(found[1].contains("of a version other than"), "{found:?}");
}

/// A stripped Mach-O keeps a table: the imports and exports the loader
/// needs. What a static library brought in was local and is gone, so the
/// table alone would pass with the non-FIPS AWS-LC inside. Never a pass.
#[test]
fn a_stripped_macos_fips_core_is_refused_not_passed() {
    let stripped = || {
        vec![
            MachoSymbol::export("_seaworthy_core_main"),
            MachoSymbol::import(&format!("_{PREFIX}CRYPTO_library_init")),
            MachoSymbol::import(&format!("_{PREFIX}EVP_sha256")),
            MachoSymbol::import("_memcpy"),
        ]
    };
    // `-C strip=symbols` and `strip -x`: every import and export left.
    let found = core_findings(stripped());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("is stripped (no local symbols)"),
        "{found:?}"
    );
    // No table at all: the one finding too, not its consequences.
    let found = core_findings(Vec::new());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("is stripped (no local symbols)"),
        "{found:?}"
    );
    // A debug map isn't a symbol table, and the linker's own locals say
    // nothing about what was linked.
    let found = core_findings(
        [
            stripped(),
            vec![
                MachoSymbol::stab("_some_function"),
                MachoSymbol::local("__mh_dylib_header"),
                MachoSymbol::local("__dyld_private"),
            ],
        ]
        .concat(),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("is stripped (no local symbols)"),
        "{found:?}"
    );
    // What's still visible is reported beside it.
    let found = core_findings(
        [
            stripped(),
            vec![MachoSymbol::import("_aws_lc_0_46_0_EVP_sha256")],
        ]
        .concat(),
    );
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[1].contains("non-FIPS AWS-LC"), "{found:?}");
}

/// One leading `_` comes off, the C name's: a C name that starts with `_`
/// is another name.
#[test]
fn mach_o_names_lose_one_underscore() {
    for other in [
        "__aws_lc_0_46_0_EVP_sha256",
        "__ring_core_0_17_14__x25519",
        "__awslc_version_string",
        "__aws_lc_fips_0_13_9_SHA256",
        // A crate named like one, as a linker lists its mangled symbols.
        "__ZN9aws_lc_rs3aes3new17h0123456789abcdefE",
        "__RNvCs0123_9aws_lc_rs4init",
        "_aws_lc_rs_helper",
    ] {
        let mut table = fips_core_symbols();
        table.push(MachoSymbol::local(other));
        assert_eq!(core_findings(table), Vec::<String>::new(), "{other}");
    }
    // Nor is a name the module's after a second `_`.
    let mut table = fips_core_symbols();
    table.push(MachoSymbol::local(&format!("__{PREFIX}SHA256")));
    assert_eq!(core_findings(table), Vec::<String>::new());
}

#[test]
fn only_a_mach_o_file_is_a_macos_core() {
    let elf = common::Elf {
        symbols: vec![(format!("{PREFIX}EVP_sha256"), true)],
        ..common::Elf::default()
    }
    .build();
    assert_eq!(
        seaworthy::verify::fips_macos_core_findings(&elf, PREFIX),
        ["not a Mach-O file"]
    );
    let found = seaworthy::verify::fips_macos_core_findings(b"not an image", PREFIX);
    assert!(found[0].starts_with("not an object file"), "{found:?}");
}

/// `verify` holds every core of a FIPS product to it, and nothing else: the
/// module itself still meets the static-link checks, and the same core is
/// fine in a product that isn't FIPS.
#[test]
fn verify_reads_every_macos_fips_core_s_symbols() {
    let module = format!("lib{PREFIX}crypto.dylib");
    let module_image = |symbols: Vec<MachoSymbol>| {
        Macho {
            sections: vec![(
                "__TEXT".into(),
                "__text".into(),
                vec![0xc0, 0x03, 0x5f, 0xd6],
            )],
            symbols,
            ..Macho::default()
        }
        .build()
    };
    let good_module = || {
        module_image(vec![
            MachoSymbol::export(&format!("_{PREFIX}awslc_version_string")),
            MachoSymbol::export(&format!("_{PREFIX}EVP_sha256")),
        ])
    };
    let core_image = |cpu: &str, symbols: Vec<MachoSymbol>| {
        let mut features = M1.to_vec();
        if cpu == "apple-m4" {
            features.extend(["bf16", "i8mm", "v8.5a", "v8.6a", "v8.7a"]);
        }
        Macho {
            sections: vec![(
                "__DATA".into(),
                "__cpureq".into(),
                record(MACOS, cpu, &features),
            )],
            dylibs: vec![
                "/usr/lib/libSystem.B.dylib".into(),
                format!("@rpath/{module}"),
            ],
            rpaths: vec!["@loader_path".into()],
            symbols,
            ..Macho::default()
        }
        .build()
    };
    let tree = || {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        common::acme_macos_artifacts(&artifacts);
        for cpu in MACOS_CPUS {
            write(
                &artifacts,
                &format!("{MACOS}/cores/{cpu}/libacme_core.dylib"),
                &core_image(cpu, fips_core_symbols()),
            );
            write(
                &artifacts,
                &format!("{MACOS}/cores/{cpu}/{module}"),
                &good_module(),
            );
        }
        (dir, artifacts)
    };
    let fips = config(&fips_desktop()).unwrap();
    let plain = config(&fips_desktop().replace("fips = true\n", "")).unwrap();
    let (_keep, artifacts) = tree();
    assert_eq!(findings(&fips, &artifacts), "");

    // One bad core, whichever of them, is named with what's wrong; the rest
    // of the tree passes; and without fips the same core verifies.
    let mut foreign = fips_core_symbols();
    foreign.push(MachoSymbol::local("_aws_lc_0_46_0_EVP_sha256"));
    let mut copy = fips_core_symbols();
    copy.push(MachoSymbol::local(&format!("_{PREFIX}SHA256")));
    let stripped: Vec<MachoSymbol> = fips_core_symbols()
        .into_iter()
        .filter(|s| s.n_type != MachoSymbol::local("").n_type)
        .collect();
    for cpu in MACOS_CPUS {
        for (symbols, needle) in [
            (foreign.clone(), "non-FIPS AWS-LC (aws-lc-sys) symbols"),
            (copy.clone(), "symbols, e.g."),
            (stripped.clone(), "is stripped (no local symbols)"),
        ] {
            let (_keep, artifacts) = tree();
            let core = artifacts.join(format!("{MACOS}/cores/{cpu}/libacme_core.dylib"));
            write(
                &artifacts,
                &format!("{MACOS}/cores/{cpu}/libacme_core.dylib"),
                &core_image(cpu, symbols),
            );
            let found = findings(&fips, &artifacts);
            assert!(
                found.contains(&format!("{}: ", core.display())) && found.contains(needle),
                "{cpu}, {needle}: {found}"
            );
            assert_eq!(found.matches("libacme_core.dylib:").count(), 1, "{found}");
            assert_eq!(findings(&plain, &artifacts), "", "{cpu}, {needle}");
        }
    }

    // The module is held to the static-link checks, not the core's.
    let (_keep, artifacts) = tree();
    for cpu in MACOS_CPUS {
        write(
            &artifacts,
            &format!("{MACOS}/cores/{cpu}/{module}"),
            &module_image(vec![
                MachoSymbol::export(&format!("_{PREFIX}awslc_version_string")),
                MachoSymbol::export("_aws_lc_0_46_0_EVP_sha256"),
            ]),
        );
    }
    let found = findings(&fips, &artifacts);
    assert!(
        found.contains(&module) && found.contains("non-FIPS AWS-LC"),
        "{found}"
    );
    assert!(!found.contains("libacme_core.dylib:"), "{found}");
}

// ---------------------------------------------------------------------------
// Developer ID signing and notarization
//
// macOS's own tools sign and notarize; here, off a Mac, stand-ins record
// every call (one line each, arguments separated by `|`) and answer as the
// real ones do, so the calls and their order are checked on every host.
// The Mac runners' end-to-end lanes run the real tools.

const TEAM: &str = "ABCDE12345";
const IDENTITY: &str = "Developer ID Application: Acme Inc (ABCDE12345)";
const INSTALLER: &str = "Developer ID Installer: Acme Inc (ABCDE12345)";

/// Stand-ins for codesign, hdiutil, pkgbuild, productbuild, xcrun, spctl
/// and pkgutil in `dir/bin`, logging to `dir/calls`. `xcrun notarytool
/// submit` answers the status in `dir/notary-status` (default
/// `Accepted`); `codesign --verify` with a requirement fails while
/// `dir/wrong-team` exists.
#[cfg(unix)]
fn mac_stubs(dir: &Path) -> seaworthy::macos::Tools {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("calls");
    let stub = |name: &str, body: &str| {
        let path = bin.join(name);
        std::fs::write(
            &path,
            format!(
                "#!/bin/bash\n(IFS='|'; echo \"{name}|$*\") >> '{}'\n{body}\n",
                log.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    // The file a creating tool writes is its last argument.
    let create = "for last; do :; done; echo built > \"$last\"";
    seaworthy::macos::Tools {
        codesign: stub(
            "codesign",
            &format!(
                "case \" $* \" in *\" --test-requirement \"*) [ ! -e '{}' ] || {{ echo 'test-requirement: code failed to satisfy specified code requirement(s)' >&2; exit 3; }} ;; esac\nexit 0",
                dir.join("wrong-team").display()
            ),
        ),
        hdiutil: stub("hdiutil", create),
        pkgbuild: stub("pkgbuild", create),
        productbuild: stub("productbuild", create),
        xcrun: stub(
            "xcrun",
            &format!(
                "status=Accepted; [ ! -e '{status}' ] || status=$(cat '{status}')\n\
                 case \"$1 $2\" in\n\
                 'notarytool submit') echo \"{{\\\"id\\\":\\\"2efe2717-52ef-43a5-96dc-0797e4ca1041\\\",\\\"status\\\":\\\"$status\\\",\\\"message\\\":\\\"Processing complete\\\"}}\" ;;\n\
                 'notarytool log') echo '{{\"issues\":[{{\"message\":\"The binary is not signed with a valid Developer ID certificate.\"}}]}}' ;;\n\
                 esac\nexit 0",
                status = dir.join("notary-status").display()
            ),
        ),
        spctl: stub("spctl", "exit 0"),
        pkgutil: stub(
            "pkgutil",
            &format!(
                "printf 'Package \"x.pkg\":\\n   Status: signed by a developer certificate issued by Apple for distribution\\n   Certificate Chain:\\n    1. {INSTALLER}\\n       Expires: 2030-01-01\\n    2. Developer ID Certification Authority\\n'"
            ),
        ),
    }
}

#[cfg(unix)]
fn calls(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[cfg(unix)]
fn developer_id(dir: &Path) -> seaworthy::macos::DeveloperId {
    seaworthy::macos::DeveloperId {
        identity: IDENTITY.to_owned(),
        installer_identity: Some(INSTALLER.to_owned()),
        keychain: Some(dir.join("build.keychain-db")),
        notary_profile: "acme-notary".to_owned(),
        notary_timeout: std::time::Duration::from_secs(1800),
    }
}

/// `[defaults.apple] team-id`, `macos.entitlements` and `signing.toml`'s
/// `[apple]` are checked when they load.
#[test]
fn developer_id_settings_are_validated() {
    let pinned = DESKTOP.replace(
        "[product.viewer]",
        "[defaults.apple]\nteam-id = \"ABCDE12345\"\n\n[product.viewer]",
    );
    let ok = config(&pinned).unwrap();
    assert_eq!(ok.defaults.apple.as_ref().unwrap().team_id, TEAM);
    for team in ["abcde12345", "ABCDE1234", "ABCDE-2345", "ABCDE123456"] {
        refused(
            &pinned.replace("ABCDE12345", team),
            "defaults.apple.team-id",
        );
    }
    let entitled = DESKTOP.replace(
        "category = \"public.app-category.utilities\"",
        "category = \"public.app-category.utilities\"\nentitlements = \"macos/app.entitlements\"",
    );
    assert_eq!(
        config(&entitled).unwrap().products["viewer"]
            .macos
            .as_ref()
            .unwrap()
            .entitlements
            .as_deref(),
        Some(Path::new("macos/app.entitlements"))
    );
    for bad in ["../app.plist", "/etc/app.plist", "macos/app.xml"] {
        refused(
            &entitled.replace("macos/app.entitlements", bad),
            "macos.entitlements",
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let parse = |text: &str| -> Result<seaworthy::macos::DeveloperId, String> {
        let path = dir.path().join("signing.toml");
        std::fs::write(&path, text).unwrap();
        let (file, base) =
            seaworthy::sign::SigningConfig::load(&path).map_err(|e| e.to_string())?;
        file.apple
            .unwrap()
            .developer_id(&base)
            .map_err(|e| e.to_string())
    };
    let good = format!(
        "[apple]\nidentity = \"{IDENTITY}\"\ninstaller-identity = \"{INSTALLER}\"\nkeychain = \"ci.keychain-db\"\nnotary-profile = \"acme-notary\"\n"
    );
    let id = parse(&good).unwrap();
    assert_eq!(id.identity, IDENTITY);
    assert_eq!(
        id.keychain.as_deref(),
        Some(dir.path().join("ci.keychain-db").as_path())
    );
    assert_eq!(id.notary_timeout, seaworthy::macos::DEFAULT_NOTARY_TIMEOUT);
    // A certificate's SHA-1 names an identity too.
    let sha1 = good.replace(IDENTITY, "0123456789ABCDEF0123456789abcdef01234567");
    assert!(parse(&sha1).is_ok());
    for (from, to, why) in [
        (
            IDENTITY,
            "Apple Development: Acme (ABCDE12345)",
            "[apple] identity",
        ),
        (INSTALLER, IDENTITY, "[apple] installer-identity"),
        ("acme-notary", "acme notary", "[apple] notary-profile"),
        (
            "notary-profile = \"acme-notary\"\n",
            "notary-profile = \"acme-notary\"\ntimeout-seconds = 3001\n",
            "[apple] timeout-seconds",
        ),
        (
            "notary-profile = \"acme-notary\"\n",
            "notary-profile = \"acme-notary\"\ntimeout-seconds = 0\n",
            "[apple] timeout-seconds",
        ),
    ] {
        let err = parse(&good.replace(from, to)).unwrap_err();
        assert!(err.contains(why), "{to}: {err}");
    }
    // The profile is required: notarization isn't optional.
    let err = parse(&good.replace("notary-profile = \"acme-notary\"\n", "")).unwrap_err();
    assert!(err.contains("notary-profile"), "{err}");
}

/// With a Developer ID every Mach-O, then the bundle, is signed with the
/// identity, the hardened runtime and a secure timestamp (the entitlements
/// on the bundle's main executable alone), each signature checked against
/// the Developer ID requirement for the pinned team; the disk image is
/// signed, checked, notarized, stapled, validated and assessed, in that
/// order. Ad hoc stays as it was.
#[cfg(unix)]
#[test]
fn a_developer_id_signs_notarizes_and_staples_the_disk_image() {
    let dir = tempfile::tempdir().unwrap();
    let tools = mac_stubs(dir.path());
    let id = developer_id(dir.path());
    let bundle = dir.path().join("Acme Viewer.app");
    let core = bundle.join("Contents/Frameworks/libacme_core_apple-m1.dylib");
    std::fs::create_dir_all(core.parent().unwrap()).unwrap();
    std::fs::write(&core, b"core").unwrap();
    let entitlements = dir.path().join("entitlements.plist");
    let signer = seaworthy::macos::MacSigner::DeveloperId {
        id: &id,
        team_id: TEAM,
        entitlements: Some(&entitlements),
    };
    seaworthy::macos::sign_bundle(&tools, &bundle, std::slice::from_ref(&core), &[], &signer)
        .unwrap();
    let dmg = dir.path().join("acme-viewer.dmg");
    seaworthy::macos::build_dmg(
        &tools,
        &bundle,
        "Acme Viewer",
        &dmg,
        &dir.path().join("work"),
        &signer,
    )
    .unwrap();
    let keychain = id.keychain.as_ref().unwrap().display().to_string();
    let requirement = seaworthy::macos::developer_id_requirement(TEAM);
    assert!(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
    assert!(requirement.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
    let (core, bundle, dmg) = (core.display(), bundle.display(), dmg.display());
    let want = [
        format!(
            "codesign|--force|--sign|{IDENTITY}|--timestamp|--options|runtime|--keychain|{keychain}|{core}"
        ),
        format!(
            "codesign|--force|--sign|{IDENTITY}|--timestamp|--options|runtime|--keychain|{keychain}|--entitlements|{}|{bundle}",
            entitlements.display()
        ),
        format!("codesign|--verify|--strict|--test-requirement|={requirement}|{core}"),
        format!("codesign|--verify|--strict|--deep|--test-requirement|={requirement}|{bundle}"),
    ];
    let seen = calls(dir.path());
    assert_eq!(seen[..4], want, "{seen:#?}");
    assert!(
        seen[4].starts_with("hdiutil|create|-volname|Acme Viewer|"),
        "{seen:#?}"
    );
    assert_eq!(
        seen[5..],
        [
            format!("codesign|--force|--sign|{IDENTITY}|--timestamp|--keychain|{keychain}|{dmg}"),
            format!("codesign|--verify|--strict|--test-requirement|={requirement}|{dmg}"),
            format!(
                "xcrun|notarytool|submit|{dmg}|--keychain-profile|acme-notary|--keychain|{keychain}|--wait|--timeout|1800s|--output-format|json"
            ),
            format!("xcrun|stapler|staple|{dmg}"),
            format!("xcrun|stapler|validate|{dmg}"),
            format!(
                "spctl|--assess|--type|open|--context|context:primary-signature|--verbose|{dmg}"
            ),
        ],
        "{seen:#?}"
    );

    // Ad hoc: no identity, timestamp, runtime, requirement or notary.
    std::fs::remove_file(dir.path().join("calls")).unwrap();
    let adhoc = seaworthy::macos::MacSigner::AdHoc;
    let bundle_path = dir.path().join("Acme Viewer.app");
    seaworthy::macos::sign_bundle(&tools, &bundle_path, &[], &[], &adhoc).unwrap();
    assert_eq!(
        calls(dir.path()),
        [
            format!("codesign|--force|--sign|-|--timestamp=none|{bundle}"),
            format!("codesign|--verify|--strict|--deep|{bundle}"),
        ]
    );
}

/// A signature another team made fails the requirement: refused by name,
/// before anything is notarized. A rejected notarization names the
/// service's log, and nothing is stapled.
#[cfg(unix)]
#[test]
fn another_team_s_signature_and_a_rejected_notarization_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let tools = mac_stubs(dir.path());
    let id = developer_id(dir.path());
    let bundle = dir.path().join("Acme Viewer.app");
    std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    let signer = seaworthy::macos::MacSigner::DeveloperId {
        id: &id,
        team_id: TEAM,
        entitlements: None,
    };
    std::fs::write(dir.path().join("wrong-team"), "").unwrap();
    let err = seaworthy::macos::sign_bundle(&tools, &bundle, &[], &[], &signer)
        .unwrap_err()
        .to_string();
    std::fs::remove_file(dir.path().join("wrong-team")).unwrap();
    assert!(
        err.contains("not signed by a Developer ID Application identity of team ABCDE12345"),
        "{err}"
    );

    let dmg = dir.path().join("acme-viewer.dmg");
    std::fs::write(dir.path().join("notary-status"), "Invalid").unwrap();
    let err = seaworthy::macos::build_dmg(
        &tools,
        &bundle,
        "Acme Viewer",
        &dmg,
        &dir.path().join("work"),
        &signer,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("didn't accept"), "{err}");
    assert!(err.contains("status Invalid"), "{err}");
    assert!(
        err.contains("not signed with a valid Developer ID certificate"),
        "the service's log: {err}"
    );
    let seen = calls(dir.path());
    assert!(
        seen.iter().any(|c| c.starts_with("xcrun|notarytool|log|2efe2717-52ef-43a5-96dc-0797e4ca1041|--keychain-profile|acme-notary")),
        "{seen:#?}"
    );
    assert!(!seen.iter().any(|c| c.contains("stapler")), "{seen:#?}");
}

/// A service's pkg: `productbuild` signs it with the Developer ID Installer
/// identity, `pkgutil` must show that identity of the pinned team leading
/// the chain, then it's notarized, stapled and assessed for install.
/// Without an installer identity nothing runs.
#[cfg(unix)]
#[test]
fn a_developer_id_signs_and_notarizes_a_service_s_pkg() {
    let dir = tempfile::tempdir().unwrap();
    let tools = mac_stubs(dir.path());
    let mut id = developer_id(dir.path());
    let bundle = dir.path().join("Acme Agent.app");
    std::fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    let names = seaworthy::macos::PkgNames {
        display_name: "Acme Agent".to_owned(),
        identifier: "com.example.acme.agent".to_owned(),
        bundle: Some("/Applications/Acme Agent.app".to_owned()),
        tool: None,
        links: Vec::new(),
        conflicts: Vec::new(),
        service: Some("AcmeAgent".to_owned()),
        helper: None,
        support: "/Library/Application Support/Acme/Agent".into(),
        logs: "/Library/Logs/Acme/Agent".into(),
    };
    let pkg = dir.path().join("acme-agent.pkg");
    let build = |id: &seaworthy::macos::DeveloperId| {
        seaworthy::macos::build_pkg(
            &tools,
            &names,
            dir.path(),
            &[],
            "1.4.0",
            "11.0",
            &pkg,
            &dir.path().join("work"),
            &seaworthy::macos::MacSigner::DeveloperId {
                id,
                team_id: TEAM,
                entitlements: None,
            },
        )
    };
    build(&id).unwrap();
    let keychain = id.keychain.as_ref().unwrap().display().to_string();
    let pkg_shown = pkg.display();
    let seen = calls(dir.path());
    let productbuild = seen
        .iter()
        .find(|c| c.starts_with("productbuild|"))
        .unwrap();
    assert!(
        productbuild.ends_with(&format!(
            "|--sign|{INSTALLER}|--timestamp|--keychain|{keychain}|{pkg_shown}"
        )),
        "{productbuild}"
    );
    let after: Vec<&String> = seen
        .iter()
        .skip_while(|c| !c.starts_with("productbuild|"))
        .skip(1)
        .collect();
    assert_eq!(
        after,
        [
            &format!("pkgutil|--check-signature|{pkg_shown}"),
            &format!(
                "xcrun|notarytool|submit|{pkg_shown}|--keychain-profile|acme-notary|--keychain|{keychain}|--wait|--timeout|1800s|--output-format|json"
            ),
            &format!("xcrun|stapler|staple|{pkg_shown}"),
            &format!("xcrun|stapler|validate|{pkg_shown}"),
            &format!("spctl|--assess|--type|install|--verbose|{pkg_shown}"),
        ]
    );
    std::fs::remove_file(dir.path().join("calls")).unwrap();
    id.installer_identity = None;
    let err = build(&id).unwrap_err().to_string();
    assert!(err.contains("installer-identity"), "{err}");
    assert!(calls(dir.path()).is_empty(), "nothing ran");
}

/// `package --signing`: `[apple]` needs the pinned team, and a signed
/// release of macOS outputs needs `[apple]` (checked before anything is
/// packaged, on any host).
#[test]
fn a_signed_macos_release_needs_the_developer_id_and_its_team() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("seaworthy.toml"), DESKTOP).unwrap();
    std::fs::write(
        dir.path().join("signing.toml"),
        format!("[apple]\nidentity = \"{IDENTITY}\"\nnotary-profile = \"acme-notary\"\n"),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("artifacts")).unwrap();
    let package = |dir: &Path| {
        seaworthy(
            dir,
            &[
                "package",
                "--artifacts",
                "artifacts",
                "--out",
                "dist",
                "--release",
                "1.4.0",
                "--sequence",
                "7",
                "--platforms",
                "macos",
                "--signing",
                "signing.toml",
            ],
        )
    };
    let out = package(dir.path());
    assert!(!out.status.success());
    assert!(
        said(&out).contains("pins no Developer ID team: set defaults.apple.team-id"),
        "{}",
        said(&out)
    );
    std::fs::write(dir.path().join("signing.toml"), "").unwrap();
    let out = package(dir.path());
    assert!(!out.status.success());
    assert!(
        said(&out)
            .contains("product viewer ships macOS outputs (dmg) but signing.toml has no [apple]"),
        "{}",
        said(&out)
    );
}

/// The uninstaller run for real against stub tools (every absolute tool
/// path rewritten): it removes nothing until both daemons are unloaded, a
/// daemon that won't unload stops it with exit 1 and nothing removed, and
/// a service an in-flight install loads again is unloaded again.
#[cfg(unix)]
#[test]
fn the_uninstaller_stops_the_daemons_before_removing_anything() {
    use seaworthy::macos;
    let config = config(SERVICE).unwrap();
    let product = &config.products["agent"];
    let names = macos::pkg_names(&config, "agent", product).unwrap();
    let script = macos::uninstaller(&names);

    // `launchctl`: `print system/<label>` succeeds while <label>.loaded
    // exists; `bootout` removes it unless <label>.stuck exists, and a
    // <label>.reload file makes it come back once after its bootout.
    let run = |setup: &dyn Fn(&Path)| {
        let dir = tempfile::tempdir().unwrap();
        let stubs = dir.path().join("stubs");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&stubs).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let log = dir.path().join("calls");
        let stub = |name: &str, body: &str| {
            let path = stubs.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        let st = state.display();
        let lg = log.display();
        stub(
            "launchctl",
            &format!(
                "label=\"${{2#system/}}\"
                 case \"$1\" in
                   print) [ -e \"{st}/$label.loaded\" ] ;;
                   bootout)
                     echo \"bootout $label\" >> '{lg}'
                     [ -e \"{st}/$label.stuck\" ] && exit 5
                     rm -f \"{st}/$label.loaded\"
                     if [ -e \"{st}/$label.reload\" ]; then rm -f \"{st}/$label.reload\"; touch \"{st}/$label.comeback\"; fi ;;
                 esac"
            ),
        );
        // The comeback: the next `sleep` after a reload's bootout loads the
        // service again (an install daemon's postinstall, late).
        stub(
            "sleep",
            &format!(
                "for f in \"{st}\"/*.comeback; do [ -e \"$f\" ] || continue; \
                 l=\"${{f%.comeback}}\"; rm -f \"$f\"; touch \"$l.loaded\"; done"
            ),
        );
        stub("pgrep", "exit 1");
        stub("id", "echo 0");
        stub("rm", &format!("echo \"rm $*\" >> '{lg}'"));
        stub("pkgutil", &format!("echo \"pkgutil $*\" >> '{lg}'"));
        for label in ["AcmeAgent-update", "AcmeAgent"] {
            std::fs::write(state.join(format!("{label}.loaded")), "").unwrap();
        }
        setup(&state);
        let mut text = script.clone();
        for (tool, name) in [
            ("/bin/launchctl", "launchctl"),
            ("/usr/bin/pgrep", "pgrep"),
            ("/usr/bin/id", "id"),
            ("/bin/rm", "rm"),
            ("/usr/sbin/pkgutil", "pkgutil"),
            ("/bin/sleep", "sleep"),
        ] {
            text = text.replace(tool, &stubs.join(name).display().to_string());
        }
        let path = dir.path().join("uninstall");
        std::fs::write(&path, &text).unwrap();
        let out = std::process::Command::new("sh")
            .arg(&path)
            .arg("--purge")
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        (
            out.status.code(),
            calls,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // Both unload: the helper, then the service, then the removals.
    let (code, calls, _) = run(&|_| {});
    assert_eq!(code, Some(0), "{calls}");
    let helper = calls.find("bootout AcmeAgent-update").unwrap();
    let service = calls.find("bootout AcmeAgent\n").unwrap();
    let removed = calls.find("rm ").unwrap();
    assert!(helper < service && service < removed, "{calls}");

    // A service that won't unload: exit 1, nothing removed.
    let (code, calls, stderr) = run(&|state| {
        std::fs::write(state.join("AcmeAgent.stuck"), "").unwrap();
    });
    assert_eq!(code, Some(1), "{calls}");
    assert!(
        !calls.contains("rm "),
        "removed with a daemon loaded: {calls}"
    );
    assert!(stderr.contains("nothing was removed"), "{stderr}");

    // A service loaded again after its bootout (a late postinstall): it
    // is unloaded again, then everything is removed.
    let (code, calls, _) = run(&|state| {
        std::fs::write(state.join("AcmeAgent.reload"), "").unwrap();
    });
    assert_eq!(code, Some(0), "{calls}");
    assert_eq!(calls.matches("bootout AcmeAgent\n").count(), 2, "{calls}");
    assert!(calls.contains("rm "), "{calls}");
}
