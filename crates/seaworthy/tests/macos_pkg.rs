//! The macOS pkg of a tool, or of a product with cli programs: the
//! rules, the tool directory `layout` stages beside (or instead of) the
//! app bundle, the names, scripts and uninstaller the pkg carries, its
//! payload (`pkgbuild` run as a stand-in that records what it was handed)
//! and the tool directory's signatures. macOS's own tools run on the Mac
//! lanes; here, stand-ins.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::{Path, PathBuf};

use common::{M1, MACOS_CPUS, Macho, cpulist, record, write};
use seaworthy::config::Config;
use seaworthy::inputs::MACOS;
use seaworthy::layout::Role;

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme <packages@example.com>"
license = "MIT"
"#;

/// A command-line tool alone: no bundle, its programs in the tool
/// directory, linked into /usr/local/bin.
const TOOL: &str = r#"
[product.trove]
display-name = "Acme Trove"
description = "Packs Trove archives."
kind = "tool"
outputs = ["pkg", "deb"]
updates.default = "off"
conflicts = ["trove-lite"]

[[product.trove.programs]]
executable = "trove"
core = "trove_cli_core"
role = "cli"

[[product.trove.programs]]
executable = "trovectl"
core = "trove_ctl_core"
role = "cli"
command = "trove-ctl"

[product.trove.macos]
bundle-id = "com.example.acme.trove"

[product.trove-lite]
display-name = "Acme Trove Lite"
description = "Packs Trove archives, lightly."
executable = "trove"
core = "trove_cli_core"
kind = "tool"
outputs = ["pkg"]
updates.default = "off"

[product.trove-lite.macos]
bundle-id = "com.example.acme.trove-lite"
"#;

/// A desktop app with a command-line program: the app in its bundle, the
/// command in the tool directory, one pkg for both.
const MIXED: &str = r#"
[product.studio]
display-name = "Acme Studio"
description = "Edits Trove archives."
kind = "desktop"
outputs = ["pkg"]
updates.default = "off"

[[product.studio.programs]]
executable = "AcmeStudio"
core = "studio_app_core"
role = "gui"

[[product.studio.programs]]
executable = "studio"
core = "studio_cli_core"
role = "cli"

[product.studio.macos]
bundle-id = "com.example.acme.studio"
icon = "studio.icns"
"#;

fn parse(products: &str) -> Result<Config, String> {
    Config::parse(&format!("{DEFAULTS}{products}")).map_err(|e| e.to_string())
}

fn refused(products: &str, needle: &str) {
    let err = parse(products).expect_err("refused");
    assert!(err.contains(needle), "{err}");
}

#[test]
fn a_pkg_ships_a_tool_or_cli_programs_and_a_dmg_a_desktop_app_alone() {
    parse(TOOL).unwrap();
    parse(MIXED).unwrap();
    // A tool (single-program form) ships a pkg too.
    let lite = parse(TOOL).unwrap();
    assert!(!lite.products["trove-lite"].programs()[0].bundled);
    // A dmg can't install a cli program or its link.
    refused(
        &MIXED.replace("outputs = [\"pkg\"]", "outputs = [\"dmg\"]"),
        "dmg holds a desktop app's bundle alone: its cli programs, and their PATH links, need a pkg",
    );
    refused(
        &TOOL.replacen("outputs = [\"pkg\", \"deb\"]", "outputs = [\"dmg\"]", 1),
        "dmg holds a desktop app (kind = \"desktop\")",
    );
    // A desktop app alone stays a dmg.
    let app_only = MIXED.replace(
        "\n[[product.studio.programs]]\nexecutable = \"studio\"\ncore = \"studio_cli_core\"\nrole = \"cli\"\n",
        "",
    );
    parse(&app_only.replace("outputs = [\"pkg\"]", "outputs = [\"dmg\"]")).unwrap();
    refused(
        &app_only,
        "pkg holds a macOS service, a tool or a product's cli programs",
    );
    // A tool with an app: its bundle, in a pkg.
    let with_app = TOOL.replacen(
        "command = \"trove-ctl\"",
        "command = \"trove-ctl\"\n\n[[product.trove.programs]]\nexecutable = \"TroveApp\"\ncore = \"trove_app_core\"\nrole = \"gui\"",
        1,
    );
    let config = parse(&with_app).unwrap();
    assert_eq!(
        config.products["trove"]
            .bundled_program()
            .unwrap()
            .executable,
        "TroveApp"
    );
    // Without a bundle, nothing describes one.
    for (key, line) in [
        ("macos.icon", "icon = \"trove.icns\""),
        (
            "macos.category",
            "category = \"public.app-category.utilities\"",
        ),
        ("macos.localizations", "localizations = [\"en\"]"),
    ] {
        refused(
            &TOOL.replacen(
                "bundle-id = \"com.example.acme.trove\"",
                &format!("bundle-id = \"com.example.acme.trove\"\n{line}"),
                1,
            ),
            &format!("product.trove.{key}: describes the app bundle, and this product has none"),
        );
    }
    // Entitlements are the launchers': fine.
    parse(&TOOL.replacen(
        "bundle-id = \"com.example.acme.trove\"",
        "bundle-id = \"com.example.acme.trove\"\nentitlements = \"trove.entitlements\"",
        1,
    ))
    .unwrap();
}

/// With `fips`, a tool's macOS build ships the module's dylib too.
#[test]
fn a_fips_tools_pkg_ships_the_module() {
    refused(
        &TOOL.replacen("kind = \"tool\"", "kind = \"tool\"\nfips = true", 1),
        "product.trove.sidecars.macos: with fips",
    );
    parse(&TOOL.replacen(
        "kind = \"tool\"",
        "kind = \"tool\"\nfips = true\nsidecars.macos = [\"libaws_lc_fips_*_crypto.dylib\"]",
        1,
    ))
    .unwrap();
}

/// Every program's launcher and cores for macOS, and a helper and a
/// sidecar beside the cores, under `root`.
fn artifacts(config: &Config, id: &str, root: &Path, sidecar: Option<&str>) {
    let product = &config.products[id];
    for program in product.programs() {
        write(
            root,
            &format!("{MACOS}/launcher/{}", program.executable),
            &Macho {
                executable: true,
                sections: vec![(
                    "__DATA".into(),
                    "__cpulist".into(),
                    cpulist(&program.core, &MACOS_CPUS),
                )],
                rpaths: vec!["@executable_path/../Frameworks".into()],
                ..Macho::default()
            }
            .build(),
        );
        for cpu in MACOS_CPUS {
            let mut features = M1.to_vec();
            if cpu == "apple-m4" {
                features.extend(["bf16", "i8mm", "v8.5a", "v8.6a", "v8.7a"]);
            }
            let dir = format!("{MACOS}/cores/{}", program.build_dir(cpu));
            write(
                root,
                &format!("{dir}/lib{}.dylib", program.core),
                &Macho {
                    sections: vec![(
                        "__DATA".into(),
                        "__cpureq".into(),
                        record(MACOS, cpu, &features),
                    )],
                    dylibs: sidecar.iter().map(|s| format!("@rpath/{s}")).collect(),
                    rpaths: vec!["@loader_path".into()],
                    ..Macho::default()
                }
                .build(),
            );
            if let Some(sidecar) = sidecar {
                write(root, &format!("{dir}/{sidecar}"), &Macho::default().build());
            }
        }
    }
    if let Some(helper) = &product.helper {
        write(
            root,
            &format!("{MACOS}/helper/{helper}"),
            &Macho {
                executable: true,
                rpaths: vec!["@executable_path/../Frameworks".into()],
                ..Macho::default()
            }
            .build(),
        );
    }
}

fn lay_out(
    project: &Path,
    text: &str,
    id: &str,
    sidecar: Option<&str>,
) -> (Config, seaworthy::layout::Layout) {
    std::fs::write(project.join("seaworthy.toml"), format!("{DEFAULTS}{text}")).unwrap();
    let mut config = Config::load(&project.join("seaworthy.toml")).unwrap();
    // The Mac's share (`--platforms macos`).
    config.only_platforms(&[seaworthy::config::Platform::Macos]);
    let input = project.join("artifacts");
    artifacts(&config, id, &input, sidecar);
    let verified = seaworthy::verify::verify(&config, id, &input).expect("verifies");
    let mut layouts = seaworthy::layout::layout(
        &config,
        id,
        &verified,
        &project.join("dist"),
        seaworthy::layout::Options::default(),
    )
    .expect("lays out");
    assert_eq!(layouts.len(), 1);
    (config, layouts.remove(0))
}

/// A tool's programs install in its tool directory, laid out like a
/// bundle's Contents: launchers and the helper in bin/, cores (and the
/// sidecar) in Frameworks/, data in Resources/.
#[test]
fn a_tools_programs_install_in_its_tool_directory() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "data/readme.txt", b"read me");
    let text = TOOL.replacen(
        "updates.default = \"off\"\nconflicts",
        "sidecars.macos = [\"libextra.dylib\"]\nupdates.default = \"off\"\nconflicts",
        1,
    ) + "\n[[product.trove.files]]\nsource = \"data\"\ndestination = \"share\"\nplatforms = [\"macos\"]\n";
    let (_, layout) = lay_out(dir.path(), &text, "trove", Some("libextra.dylib"));
    assert_eq!(layout.install_root, "/usr/local/acme/trove");
    let files: Vec<(&str, &Role)> = layout
        .files
        .iter()
        .map(|f| (f.install_path.as_str(), &f.role))
        .collect();
    let core = |cpu: &str| Role::Core { cpu: cpu.into() };
    assert_eq!(
        files,
        [
            ("/usr/local/acme/trove/bin/trove", &Role::Launcher),
            ("/usr/local/acme/trove/bin/trovectl", &Role::Launcher),
            (
                "/usr/local/acme/trove/Frameworks/libtrove_cli_core_apple-m4.dylib",
                &core("apple-m4")
            ),
            (
                "/usr/local/acme/trove/Frameworks/libtrove_cli_core_apple-m1.dylib",
                &core("apple-m1")
            ),
            (
                "/usr/local/acme/trove/Frameworks/libtrove_ctl_core_apple-m4.dylib",
                &core("apple-m4")
            ),
            (
                "/usr/local/acme/trove/Frameworks/libtrove_ctl_core_apple-m1.dylib",
                &core("apple-m1")
            ),
            (
                "/usr/local/acme/trove/Frameworks/libextra.dylib",
                &Role::Sidecar
            ),
            (
                "/usr/local/acme/trove/Resources/share/readme.txt",
                &Role::Asset
            ),
        ]
    );
    // Staged at their install paths under the tree.
    for file in &layout.files {
        assert_eq!(
            file.staged,
            layout.tree.join(file.install_path.trim_start_matches('/'))
        );
        assert!(file.staged.is_file());
    }
}

/// A desktop app with a cli program: the app in its bundle, the program in
/// the tool directory; each root gets the sidecar beside its cores and the
/// data files under its resources; the icon is the bundle's.
#[test]
fn a_mixed_products_app_and_command_install_side_by_side() {
    let dir = tempfile::tempdir().unwrap();
    let mut icns = b"icns".to_vec();
    icns.extend_from_slice(&[0, 0, 0, 8]);
    write(dir.path(), "studio.icns", &icns);
    write(dir.path(), "data/a.txt", b"a");
    let text = MIXED.replacen(
        "updates.default = \"off\"",
        "updates.default = \"off\"\nsidecars.macos = [\"libextra.dylib\"]",
        1,
    ) + "\n[[product.studio.files]]\nsource = \"data\"\n";
    let (config, layout) = lay_out(dir.path(), &text, "studio", Some("libextra.dylib"));
    assert_eq!(layout.install_root, "/Applications/Acme Studio.app");
    let paths: Vec<&str> = layout
        .files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    let app = "/Applications/Acme Studio.app/Contents";
    let tool = "/usr/local/acme/studio";
    assert_eq!(
        paths,
        [
            format!("{app}/MacOS/AcmeStudio"),
            format!("{tool}/bin/studio"),
            format!("{app}/Frameworks/libstudio_app_core_apple-m4.dylib"),
            format!("{app}/Frameworks/libstudio_app_core_apple-m1.dylib"),
            format!("{tool}/Frameworks/libstudio_cli_core_apple-m4.dylib"),
            format!("{tool}/Frameworks/libstudio_cli_core_apple-m1.dylib"),
            format!("{app}/Frameworks/libextra.dylib"),
            format!("{tool}/Frameworks/libextra.dylib"),
            format!("{app}/Resources/data/a.txt"),
            format!("{tool}/Resources/data/a.txt"),
            format!("{app}/Resources/AppIcon.icns"),
        ]
    );
    for file in &layout.files {
        let expected = match file.install_path.strip_prefix("/Applications/") {
            Some(relative) => layout.tree.join(relative),
            None => layout.tree.join(file.install_path.trim_start_matches('/')),
        };
        assert_eq!(file.staged, expected);
        assert!(file.staged.is_file());
    }
    // The bundle's executable is the app.
    let plist =
        seaworthy::macos::info_plist(&config.products["studio"], &common::release(), "11.0", true)
            .unwrap();
    assert!(
        plist.contains("<key>CFBundleExecutable</key>\n\t<string>AcmeStudio</string>"),
        "{plist}"
    );
}

#[test]
fn the_pkgs_names_say_where_everything_installs() {
    let config = parse(TOOL).unwrap();
    let names = seaworthy::macos::pkg_names(&config, "trove", &config.products["trove"]).unwrap();
    assert_eq!(names.identifier, "com.example.acme.trove");
    assert_eq!(names.bundle, None);
    assert_eq!(names.tool.as_deref(), Some("/usr/local/acme/trove"));
    assert_eq!(
        names.links,
        [
            (
                "/usr/local/bin/trove".to_owned(),
                "/usr/local/acme/trove/bin/trove".to_owned()
            ),
            (
                "/usr/local/bin/trove-ctl".to_owned(),
                "/usr/local/acme/trove/bin/trovectl".to_owned()
            ),
        ]
    );
    assert_eq!(
        (names.service.as_deref(), names.helper.as_deref()),
        (None, None)
    );
    assert_eq!(names.uninstaller(), "/usr/local/acme/trove/uninstall");
    assert!(names.labels().is_empty());
    // The conflict both ways, by the other's pkg identifier.
    assert_eq!(
        names.conflicts,
        [seaworthy::macos::PkgConflict {
            identifier: "com.example.acme.trove-lite".to_owned(),
            display_name: "Acme Trove Lite".to_owned(),
            uninstaller: "/usr/local/acme/trove-lite/uninstall".to_owned(),
        }]
    );
    let lite =
        seaworthy::macos::pkg_names(&config, "trove-lite", &config.products["trove-lite"]).unwrap();
    assert_eq!(lite.conflicts[0].identifier, "com.example.acme.trove");
    // The single-program form links nothing on macOS (linux.command is
    // Linux's).
    assert!(lite.links.is_empty());
    assert!(
        seaworthy::macos::component_plist(&names).is_none(),
        "no bundle, nothing to pin"
    );
    let mixed = parse(MIXED).unwrap();
    let names = seaworthy::macos::pkg_names(&mixed, "studio", &mixed.products["studio"]).unwrap();
    assert_eq!(
        names.bundle.as_deref(),
        Some("/Applications/Acme Studio.app")
    );
    assert_eq!(names.tool.as_deref(), Some("/usr/local/acme/studio"));
    assert_eq!(
        names.uninstaller(),
        "/Applications/Acme Studio.app/Contents/Resources/uninstall"
    );
    assert_eq!(
        names.links,
        [(
            "/usr/local/bin/studio".to_owned(),
            "/usr/local/acme/studio/bin/studio".to_owned()
        )]
    );
}

fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

/// The scripts parse (and pass shellcheck where it's installed); the
/// preinstall refuses while a conflicting product's pkg is installed and
/// stops no service; the uninstaller removes the links only while they're
/// still its own, then the tool directory and the receipt.
#[cfg(unix)]
#[test]
fn a_tools_scripts_refuse_a_conflict_and_uninstall_what_it_installed() {
    let config = parse(TOOL).unwrap();
    let names = seaworthy::macos::pkg_names(&config, "trove", &config.products["trove"]).unwrap();
    let pre = seaworthy::macos::preinstall(&names);
    let post = seaworthy::macos::postinstall(&names);
    let uninstall = seaworthy::macos::uninstaller(&names);
    assert!(!pre.contains("launchctl"), "{pre}");
    assert!(!post.contains("launchctl"), "{post}");
    assert!(!uninstall.contains("launchctl bootout"), "{uninstall}");
    for needle in [
        "if [ \"$(/usr/bin/readlink '/usr/local/bin/trove')\" = '/usr/local/acme/trove/bin/trove' ]; then /bin/rm -f '/usr/local/bin/trove'; fi",
        "if [ \"$(/usr/bin/readlink '/usr/local/bin/trove-ctl')\" = '/usr/local/acme/trove/bin/trovectl' ]; then /bin/rm -f '/usr/local/bin/trove-ctl'; fi",
        "/bin/rm -rf '/usr/local/acme/trove'",
        "/usr/sbin/pkgutil --forget 'com.example.acme.trove'",
        "sudo '/usr/local/acme/trove/uninstall' [--purge]",
    ] {
        assert!(uninstall.contains(needle), "{needle}\n{uninstall}");
    }
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
    // The preinstall against a stand-in pkgutil: the conflicting
    // product's receipt there, the install refused, naming it; gone, the
    // install goes on.
    let run = |installed: bool| {
        let dir = tempfile::tempdir().unwrap();
        let pkgutil = stub(
            dir.path(),
            "pkgutil",
            &format!(
                "[ \"$1 $2\" = '--pkg-info com.example.acme.trove-lite' ] && exit {}\nexit 1",
                u8::from(!installed)
            ),
        );
        let path = dir.path().join("preinstall");
        std::fs::write(
            &path,
            pre.replace("/usr/sbin/pkgutil", &pkgutil.to_string_lossy()),
        )
        .unwrap();
        std::process::Command::new("sh")
            .arg(&path)
            .args(["component.pkg", "/", "/"])
            .output()
            .unwrap()
    };
    let refused = run(true);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(
            "Acme Trove can't be installed while Acme Trove Lite is installed: uninstall it first (sudo /usr/local/acme/trove-lite/uninstall)"
        ),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(run(false).status.code(), Some(0));
}

/// The uninstaller run against a scratch root: it removes a link that is
/// still its own and keeps one another product took over.
#[cfg(unix)]
#[test]
fn the_uninstaller_keeps_a_link_another_product_took_over() {
    let config = parse(TOOL).unwrap();
    let names = seaworthy::macos::pkg_names(&config, "trove", &config.products["trove"]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let at = |path: &str| root.join(path.trim_start_matches('/'));
    std::fs::create_dir_all(at("/usr/local/bin")).unwrap();
    std::fs::create_dir_all(at("/usr/local/acme/trove/bin")).unwrap();
    // trove still links into this product; trove-ctl was taken over.
    std::os::unix::fs::symlink(
        at("/usr/local/acme/trove/bin/trove"),
        at("/usr/local/bin/trove"),
    )
    .unwrap();
    std::os::unix::fs::symlink("/elsewhere/trove-ctl", at("/usr/local/bin/trove-ctl")).unwrap();
    let mut script = seaworthy::macos::uninstaller(&names);
    // Under the scratch root, as root, with the receipt tool stood in.
    for path in [
        "/usr/local/acme/trove/bin/trovectl",
        "/usr/local/acme/trove/bin/trove",
        "/usr/local/bin/trove-ctl",
        "/usr/local/bin/trove",
        "/usr/local/acme/trove",
        "/Library/Application Support/Acme/Trove",
        "/Library/Logs/Acme/Trove",
    ] {
        script = script.replace(&format!("'{path}'"), &format!("'{}'", at(path).display()));
    }
    let fine = stub(root, "fine", "exit 0");
    let root_id = stub(root, "id", "echo 0");
    let script = script
        .replace("/usr/sbin/pkgutil", &fine.to_string_lossy())
        .replace("/usr/bin/id", &root_id.to_string_lossy());
    let path = root.join("uninstall");
    std::fs::write(&path, script).unwrap();
    let out = std::process::Command::new("sh")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(std::fs::symlink_metadata(at("/usr/local/bin/trove")).is_err());
    assert!(std::fs::symlink_metadata(at("/usr/local/bin/trove-ctl")).is_ok());
    assert!(!at("/usr/local/acme/trove").exists());
}

/// Stand-ins for macOS's tools in `dir/bin`, logging every call to
/// `dir/calls`; the stand-in `pkgbuild` records the payload it was handed
/// (`find` of its `--root`, links with their targets) in `dir/payload`.
#[cfg(unix)]
fn mac_tools(dir: &Path) -> seaworthy::macos::Tools {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = dir.join("calls");
    let tool = |name: &str, body: &str| {
        stub(
            &bin,
            name,
            &format!(
                "(IFS='|'; echo \"{name}|$*\") >> '{}'\n{body}",
                log.display()
            ),
        )
    };
    let create = "for last; do :; done; echo built > \"$last\"";
    seaworthy::macos::Tools {
        codesign: tool("codesign", "exit 0"),
        hdiutil: tool("hdiutil", create),
        pkgbuild: tool(
            "pkgbuild",
            &format!(
                "(cd \"$2\" && find . | LC_ALL=C sort | while read -r p; do if [ -L \"$p\" ]; then echo \"$p -> $(readlink \"$p\")\"; else echo \"$p\"; fi; done) > '{}'\n{create}",
                dir.join("payload").display()
            ),
        ),
        productbuild: tool("productbuild", create),
        xcrun: tool("xcrun", "exit 0"),
        spctl: tool("spctl", "exit 0"),
        pkgutil: tool("pkgutil", "exit 0"),
    }
}

/// The pkg's payload: the tool directory at its install path, the links
/// into it, no bundle and so no component plist; with an app, the bundle
/// too, pinned.
#[cfg(unix)]
#[test]
fn the_pkg_carries_the_tool_directory_and_its_links() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let (config, layout) = lay_out(&project, TOOL, "trove", None);
    let tools = mac_tools(dir.path());
    let names = seaworthy::macos::pkg_names(&config, "trove", &config.products["trove"]).unwrap();
    seaworthy::macos::build_pkg(
        &tools,
        &names,
        &layout.tree,
        &[],
        "1.4.0",
        "11.0",
        &dir.path().join("acme-trove.pkg"),
        &dir.path().join("work"),
        &seaworthy::macos::MacSigner::AdHoc,
    )
    .unwrap();
    let payload = std::fs::read_to_string(dir.path().join("payload")).unwrap();
    for line in [
        "./usr/local/acme/trove/bin/trove",
        "./usr/local/acme/trove/bin/trovectl",
        "./usr/local/acme/trove/Frameworks/libtrove_cli_core_apple-m1.dylib",
        "./usr/local/bin/trove -> /usr/local/acme/trove/bin/trove",
        "./usr/local/bin/trove-ctl -> /usr/local/acme/trove/bin/trovectl",
    ] {
        assert!(payload.lines().any(|l| l == line), "{line}\n{payload}");
    }
    assert!(!payload.contains("Applications"), "{payload}");
    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
    let pkgbuild = calls.lines().find(|l| l.starts_with("pkgbuild|")).unwrap();
    assert!(!pkgbuild.contains("--component-plist"), "{pkgbuild}");
    assert!(
        pkgbuild.contains("|--identifier|com.example.acme.trove|--version|1.4.0|"),
        "{pkgbuild}"
    );
    // With an app: its bundle at /Applications, pinned by the component
    // plist, beside the tool directory.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let mut icns = b"icns".to_vec();
    icns.extend_from_slice(&[0, 0, 0, 8]);
    write(&project, "studio.icns", &icns);
    let (config, layout) = lay_out(&project, MIXED, "studio", None);
    let tools = mac_tools(dir.path());
    let names = seaworthy::macos::pkg_names(&config, "studio", &config.products["studio"]).unwrap();
    seaworthy::macos::build_pkg(
        &tools,
        &names,
        &layout.tree,
        &[],
        "1.4.0",
        "11.0",
        &dir.path().join("acme-studio.pkg"),
        &dir.path().join("work"),
        &seaworthy::macos::MacSigner::AdHoc,
    )
    .unwrap();
    let payload = std::fs::read_to_string(dir.path().join("payload")).unwrap();
    for line in [
        "./Applications/Acme Studio.app/Contents/MacOS/AcmeStudio",
        "./usr/local/acme/studio/bin/studio",
        "./usr/local/bin/studio -> /usr/local/acme/studio/bin/studio",
    ] {
        assert!(payload.lines().any(|l| l == line), "{line}\n{payload}");
    }
    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
    let pkgbuild = calls.lines().find(|l| l.starts_with("pkgbuild|")).unwrap();
    assert!(pkgbuild.contains("|--component-plist|"), "{pkgbuild}");
}

/// The tool directory's code, which no bundle seals, is signed binary by
/// binary under a Developer ID: the cores, sidecars and helper first, then
/// each launcher with the entitlements, every one checked against the
/// pinned team.
#[cfg(unix)]
#[test]
fn a_developer_id_signs_every_binary_of_the_tool_directory() {
    let dir = tempfile::tempdir().unwrap();
    let tools = mac_tools(dir.path());
    let launcher = dir.path().join("bin/trove");
    let core = dir
        .path()
        .join("Frameworks/libtrove_cli_core_apple-m1.dylib");
    let entitlements = dir.path().join("entitlements.plist");
    let id = seaworthy::macos::DeveloperId {
        identity: "Developer ID Application: Acme Inc (ABCDE12345)".to_owned(),
        installer_identity: None,
        keychain: None,
        notary_profile: "acme-notary".to_owned(),
        notary_timeout: std::time::Duration::from_secs(1800),
    };
    seaworthy::macos::sign_tool(
        &tools,
        std::slice::from_ref(&launcher),
        std::slice::from_ref(&core),
        &seaworthy::macos::MacSigner::DeveloperId {
            id: &id,
            team_id: "ABCDE12345",
            entitlements: Some(&entitlements),
        },
    )
    .unwrap();
    let calls: Vec<String> = std::fs::read_to_string(dir.path().join("calls"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let (core, launcher, entitlements) = (
        core.display().to_string(),
        launcher.display().to_string(),
        entitlements.display().to_string(),
    );
    assert_eq!(calls.len(), 4, "{calls:#?}");
    assert!(
        calls[0].ends_with(&format!("|--timestamp|--options|runtime|{core}")),
        "{}",
        calls[0]
    );
    assert!(
        calls[1].ends_with(&format!(
            "|--timestamp|--options|runtime|--entitlements|{entitlements}|{launcher}"
        )),
        "{}",
        calls[1]
    );
    for (call, file) in [(&calls[2], &core), (&calls[3], &launcher)] {
        assert!(
            call.starts_with("codesign|--verify|--strict|--test-requirement|")
                && call.contains("certificate leaf[subject.OU] = \"ABCDE12345\"")
                && call.ends_with(file.as_str()),
            "{call}"
        );
    }
}

/// Off a Mac, `package` refuses a tool's pkg by name, after laying out its
/// tool directory.
#[cfg(not(target_os = "macos"))]
#[test]
fn off_a_mac_package_refuses_a_tools_pkg() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let (config, layout) = lay_out(&project, TOOL, "trove", None);
    let err = seaworthy::package::package(
        &config,
        "trove",
        &[layout],
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
    assert!(err.contains("product trove's pkg"), "{err}");
}
