//! Desktop products: `[product.<id>.desktop]` (the menu entry, icons
//! and shortcuts), `[[product.<id>.files]]` (data files beside the
//! launcher) and `linux.command` (the `/usr/bin` link), through `layout`,
//! the Linux packages, the tarball, the zip and the MSI's `.wxs`.

// Unix only: these build and inspect packages with Unix tools, modes and
// links; the Windows lab builds and installs the real MSI.
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;
use std::process::Command;

use common::{artifact, golden, have, layout_for, layouts, nfpm, release, required, run};
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::layout::Role;
use seaworthy::linux::Source;
use seaworthy::package::Kind;

const CONFIG: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
maintainer = "Acme Packaging <pkg@acme.test>"
license = "MIT"

[product.viewer]
display-name = "Acme Viewer"
description = "Views Acme reports."
executable = "AcmeTool"
core = "acme_core"
kind = "desktop"
windows-directory = "Viewer"
sidecars.windows = ["extra_*.dll"]
outputs = ["msi", "zip", "deb", "rpm", "pacman", "tar"]
updates.default = "off"
upgrade-code = "{6a1f0c2e-3b4d-4e5f-9a6b-7c8d9e0f1a2b}"
linux.command = "acme-viewer"

[product.viewer.desktop]
linux-icons = ["icons/viewer-256.png", "icons/viewer-48.png", "icons/viewer.svg"]
windows-icon = "icons/viewer.ico"
desktop-shortcut = true
categories = ["Office", "Viewer"]
keywords = ["reports", "forensics"]
wm-class = "AcmeViewer"

[[product.viewer.files]]
source = "assets"
destination = "share"

[[product.viewer.files]]
source = "docs/LICENSE.txt"

[[product.viewer.files]]
source = "docs/windows-readme.txt"
destination = "README.txt"
platforms = ["windows"]
"#;

/// A PNG's first 33 bytes (signature, IHDR): all `layout` reads.
fn png(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// A one-image ICO.
fn ico() -> Vec<u8> {
    let mut bytes = vec![0, 0, 1, 0, 1, 0];
    bytes.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0, 4, 0, 0, 0, 22, 0, 0, 0]);
    bytes.extend_from_slice(&[0; 4]);
    bytes
}

/// `seaworthy.toml` (`text`) and its data files in a fresh directory.
fn project(text: &str) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    common::write(root, "icons/viewer-256.png", &png(256, 256));
    common::write(root, "icons/viewer-48.png", &png(48, 48));
    common::write(
        root,
        "icons/viewer.svg",
        b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
    );
    common::write(root, "icons/viewer.ico", &ico());
    common::write(root, "assets/fonts/Inter.ttf", b"a font");
    common::write(root, "assets/fonts/licenses/OFL.txt", b"a license");
    common::write(root, "assets/splash.png", &png(640, 480));
    common::write(root, "docs/LICENSE.txt", b"MIT");
    common::write(root, "docs/windows-readme.txt", b"read me");
    std::fs::write(root.join("seaworthy.toml"), text).unwrap();
    let config = Config::load(&root.join("seaworthy.toml")).unwrap();
    (dir, config)
}

/// A file outside every project directory (a link target).
fn outside_file() -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap().keep();
    let path = dir.join("outside.txt");
    std::fs::write(&path, b"outside").unwrap();
    path
}

fn layouts_of(config: &Config, out: &Path) -> Vec<seaworthy::layout::Layout> {
    layouts(config, "viewer", out)
}

fn relative<'a>(file: &'a seaworthy::layout::File, root: &str) -> &'a str {
    file.install_path.strip_prefix(root).unwrap()
}

#[test]
fn data_files_and_icons_are_laid_out_as_data() {
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());

    let linux = layout_for(&layouts, LINUX);
    let data: Vec<(&str, u32)> = linux
        .files
        .iter()
        .filter(|f| f.role == Role::Asset)
        .map(|f| (relative(f, "/opt/acme/viewer/"), f.mode))
        .collect();
    assert_eq!(
        data,
        [
            ("share/fonts/Inter.ttf", 0o644),
            ("share/fonts/licenses/OFL.txt", 0o644),
            ("share/splash.png", 0o644),
            ("LICENSE.txt", 0o644),
        ]
    );
    let icons: Vec<&str> = linux
        .desktop_files
        .iter()
        .map(|f| f.install_path.as_str())
        .collect();
    assert_eq!(
        icons,
        [
            "/usr/share/icons/hicolor/256x256/apps/acme-viewer.png",
            "/usr/share/icons/hicolor/48x48/apps/acme-viewer.png",
            "/usr/share/icons/hicolor/scalable/apps/acme-viewer.svg",
        ]
    );
    for file in linux.files.iter().chain(&linux.desktop_files) {
        // Staged where it installs, with the bytes the manifest names.
        let bytes = std::fs::read(&file.staged).unwrap();
        assert_eq!(seaworthy_crypto::digest::sha256_hex(&bytes), file.sha256);
        assert!(file.staged.starts_with(&linux.tree));
    }
    assert!(linux.icon.is_none());

    let windows = layout_for(&layouts, WINDOWS);
    let data: Vec<&str> = windows
        .files
        .iter()
        .filter(|f| f.role == Role::Asset)
        .map(|f| relative(f, "Acme\\Viewer\\"))
        .collect();
    assert_eq!(
        data,
        [
            "share\\fonts\\Inter.ttf",
            "share\\fonts\\licenses\\OFL.txt",
            "share\\splash.png",
            "LICENSE.txt",
            "README.txt",
        ]
    );
    assert!(windows.desktop_files.is_empty());
    let icon = windows.icon.as_ref().expect("the Windows icon");
    assert_eq!(icon.install_path, "Acme\\Viewer.ico");
    assert_eq!(icon.role, Role::Icon);
    assert_eq!(std::fs::read(&icon.staged).unwrap(), ico());

    // layout.json lists them all, with their roles.
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(linux.tree.parent().unwrap().join("layout.json")).unwrap(),
    )
    .unwrap();
    let roles: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["role"]["kind"].as_str().unwrap())
        .collect();
    assert_eq!(roles.iter().filter(|r| **r == "asset").count(), 4);
    assert_eq!(roles.iter().filter(|r| **r == "icon").count(), 3);
}

#[test]
fn the_linux_packages_carry_the_menu_entry_the_icons_and_the_link() {
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    let package =
        seaworthy::linux::linux_package(&config, "viewer", layout_for(&layouts, LINUX)).unwrap();
    let entry = package
        .files
        .iter()
        .find(|f| f.dst == "/usr/share/applications/acme-viewer.desktop")
        .expect("the menu entry");
    assert_eq!(entry.mode, 0o644);
    let Source::Generated(text) = &entry.source else {
        panic!("generated")
    };
    assert_eq!(
        text,
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.5\n\
         Name=Acme Viewer\n\
         Comment=Views Acme reports.\n\
         Exec=/opt/acme/viewer/AcmeTool\n\
         TryExec=/opt/acme/viewer/AcmeTool\n\
         Icon=acme-viewer\n\
         Terminal=false\n\
         Categories=Office;Viewer;\n\
         Keywords=reports;forensics;\n\
         StartupWMClass=AcmeViewer\n"
    );
    if have("desktop-file-validate", &["--help"]) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("acme-viewer.desktop");
        std::fs::write(&path, text).unwrap();
        run(Command::new("desktop-file-validate").arg(&path));
    } else {
        assert!(
            !required(),
            "desktop-file-validate is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1: desktop-file-utils)"
        );
    }
    for size in ["256x256", "48x48"] {
        assert!(
            package
                .files
                .iter()
                .any(|f| f.dst == format!("/usr/share/icons/hicolor/{size}/apps/acme-viewer.png")),
            "{size}"
        );
    }
    assert_eq!(package.links.len(), 1);
    assert_eq!(package.links[0].dst, "/usr/bin/acme-viewer");
    assert_eq!(package.links[0].target, "/opt/acme/viewer/AcmeTool");
    // The system's directories stay the system's.
    assert!(
        package
            .directories
            .iter()
            .all(|d| d.starts_with("/opt/acme")),
        "{:?}",
        package.directories
    );
    assert!(
        package
            .directories
            .contains(&"/opt/acme/viewer/share/fonts/licenses".to_owned())
    );
}

/// With media types, the menu entry names them (`MimeType`) and the
/// launcher takes the file it's opened with (`%f`); desktop-file-validate
/// accepts it.
#[test]
fn a_menu_entry_with_media_types_opens_the_chosen_files() {
    let text = CONFIG.replacen(
        "wm-class = \"AcmeViewer\"",
        "wm-class = \"AcmeViewer\"\nmime-types = [\"inode/directory\", \"application/x-acme-report\"]",
        1,
    );
    assert_ne!(text, CONFIG);
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    let package =
        seaworthy::linux::linux_package(&config, "viewer", layout_for(&layouts, LINUX)).unwrap();
    let Source::Generated(text) = &package
        .files
        .iter()
        .find(|f| f.dst.ends_with(".desktop"))
        .unwrap()
        .source
    else {
        panic!("generated")
    };
    assert!(
        text.contains("Exec=/opt/acme/viewer/AcmeTool %f\nTryExec=/opt/acme/viewer/AcmeTool\n"),
        "{text}"
    );
    assert!(
        text.contains("MimeType=inode/directory;application/x-acme-report;\n"),
        "{text}"
    );
    if have("desktop-file-validate", &["--help"]) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("acme-viewer.desktop");
        std::fs::write(&path, text).unwrap();
        run(Command::new("desktop-file-validate").arg(&path));
    } else {
        assert!(
            !required(),
            "desktop-file-validate is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1: desktop-file-utils)"
        );
    }
}

#[test]
fn a_menu_entry_escapes_what_the_specification_escapes() {
    let text = CONFIG.replacen(
        "display-name = \"Acme Viewer\"",
        "display-name = \" Acme \\\\ Viewer\"",
        1,
    );
    // The shortcut name can't hold a backslash: the MSI is left out here.
    let text = text.replacen(
        "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
        "outputs = [\"deb\"]",
        1,
    );
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    let package =
        seaworthy::linux::linux_package(&config, "viewer", layout_for(&layouts, LINUX)).unwrap();
    let Source::Generated(text) = &package
        .files
        .iter()
        .find(|f| f.dst.ends_with(".desktop"))
        .unwrap()
        .source
    else {
        panic!("generated")
    };
    assert!(text.contains("\nName=\\sAcme \\\\ Viewer\n"), "{text}");
    assert_eq!(package.links.len(), 1);
    // No icons, no command: no Icon line, no link.
    let text = CONFIG
        .replacen("linux.command = \"acme-viewer\"\n", "", 1)
        .replacen(
            "linux-icons = [\"icons/viewer-256.png\", \"icons/viewer-48.png\", \"icons/viewer.svg\"]\n",
            "",
            1,
        );
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let plain = layouts_of(&config, out.path());
    let package =
        seaworthy::linux::linux_package(&config, "viewer", layout_for(&plain, LINUX)).unwrap();
    assert!(package.links.is_empty());
    let Source::Generated(text) = &package
        .files
        .iter()
        .find(|f| f.dst.ends_with(".desktop"))
        .unwrap()
        .source
    else {
        panic!("generated")
    };
    assert!(!text.contains("Icon="), "{text}");
}

#[test]
fn the_tarball_and_the_zip_carry_the_data_files_and_no_desktop_files() {
    let Some(nfpm) = nfpm() else { return };
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let artifacts = common::build(&config, "viewer", out.path(), &nfpm, None);
    let tar = artifact(&artifacts, Kind::Tar);
    let listing = run(Command::new("tar").arg("--zstd").arg("-tvf").arg(&tar));
    for path in [
        "share/fonts/licenses/OFL.txt",
        "share/splash.png",
        "LICENSE.txt",
    ] {
        let line = listing
            .lines()
            .find(|l| l.ends_with(&format!("/{path}")))
            .unwrap_or_else(|| panic!("{path} in\n{listing}"));
        assert!(line.starts_with("-rw-r--r--"), "{line}");
    }
    assert!(!listing.contains("README.txt"), "{listing}");
    assert!(
        !listing.contains("hicolor") && !listing.contains(".desktop"),
        "{listing}"
    );
    if have("unzip", &["-v"]) {
        let zip = artifact(&artifacts, Kind::Zip);
        let listing = run(Command::new("unzip").arg("-l").arg(&zip));
        for path in ["share/fonts/Inter.ttf", "LICENSE.txt", "README.txt"] {
            assert!(listing.contains(path), "{path} in\n{listing}");
        }
        assert!(!listing.contains("Viewer.ico"), "{listing}");
    }
}

#[test]
fn a_deb_installs_the_link_the_entry_and_the_icons() {
    let Some(nfpm) = nfpm() else { return };
    if !have("dpkg-deb", &["--version"]) {
        assert!(!required(), "dpkg-deb is required");
        return;
    }
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let artifacts = common::build(&config, "viewer", out.path(), &nfpm, None);
    let deb = artifact(&artifacts, Kind::Deb);
    let listing = run(Command::new("dpkg-deb").arg("-c").arg(&deb));
    let line = |path: &str| {
        listing
            .lines()
            .find(|l| l.contains(&format!(".{path}")))
            .unwrap_or_else(|| panic!("{path} in\n{listing}"))
            .to_owned()
    };
    assert!(
        line("/usr/bin/acme-viewer").contains("-> /opt/acme/viewer/AcmeTool"),
        "{listing}"
    );
    assert!(line("/usr/bin/acme-viewer").starts_with('l'));
    assert!(line("/usr/share/applications/acme-viewer.desktop").starts_with("-rw-r--r--"));
    assert!(
        line("/usr/share/icons/hicolor/scalable/apps/acme-viewer.svg").starts_with("-rw-r--r--")
    );
    assert!(line("/opt/acme/viewer/share/fonts/Inter.ttf").starts_with("-rw-r--r--"));
    assert!(line("/opt/acme/viewer/AcmeTool").starts_with("-rwxr-xr-x"));
    // The icon theme owning the icon directories: recommended, not required.
    let recommends = run(Command::new("dpkg-deb")
        .arg("-f")
        .arg(&deb)
        .arg("Recommends"));
    assert_eq!(recommends.trim(), "hicolor-icon-theme");
    let depends = run(Command::new("dpkg-deb").arg("-f").arg(&deb).arg("Depends"));
    assert!(!depends.contains("hicolor"), "{depends}");
    // The rpm and the pacman package carry the same link.
    if have("rpm", &["--version"]) {
        let rpm = artifact(&artifacts, Kind::Rpm);
        let weak = run(Command::new("rpm").arg("-qp").arg("--recommends").arg(&rpm));
        assert!(
            weak.lines().any(|l| l.trim() == "hicolor-icon-theme"),
            "{weak}"
        );
        let strong = run(Command::new("rpm").arg("-qp").arg("--requires").arg(&rpm));
        assert!(!strong.contains("hicolor"), "{strong}");
        let listing = run(Command::new("rpm").arg("-qplv").arg(&rpm));
        assert!(
            listing.lines().any(|l| l.starts_with('l')
                && l.ends_with("/usr/bin/acme-viewer -> /opt/acme/viewer/AcmeTool")),
            "{listing}"
        );
    } else {
        assert!(!required(), "rpm is required");
    }
    if have("bsdtar", &["--version"]) {
        let pacman = artifact(&artifacts, Kind::Pacman);
        let info = run(Command::new("bsdtar")
            .arg("-xOf")
            .arg(&pacman)
            .arg(".PKGINFO"));
        assert!(!info.contains("hicolor"), "{info}");
        let listing = run(Command::new("bsdtar").arg("-tvf").arg(&pacman));
        assert!(
            listing.lines().any(|l| l.starts_with('l')
                && l.ends_with("usr/bin/acme-viewer -> /opt/acme/viewer/AcmeTool")),
            "{listing}"
        );
    } else {
        assert!(!required(), "bsdtar is required");
    }
}

/// `linux.replaces`: every format conflicts with and replaces the packages
/// the product supersedes (deb `Conflicts`/`Replaces`, rpm
/// `Conflicts`/`Obsoletes`, pacman `conflict`/`replaces`), so an install
/// removes them instead of failing on the link both ship.
#[test]
fn the_linux_packages_replace_what_the_product_supersedes() {
    let Some(nfpm) = nfpm() else { return };
    let text = CONFIG.replacen(
        "linux.command = \"acme-viewer\"\n",
        "linux.command = \"acme-viewer\"\nlinux.replaces = [\"acme-viewer-legacy\", \"viewer-bin\"]\n",
        1,
    );
    assert_ne!(text, CONFIG);
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let artifacts = common::build(&config, "viewer", out.path(), &nfpm, None);
    if have("dpkg-deb", &["--version"]) {
        let deb = artifact(&artifacts, Kind::Deb);
        for field in ["Conflicts", "Replaces"] {
            let value = run(Command::new("dpkg-deb").arg("-f").arg(&deb).arg(field));
            assert_eq!(value.trim(), "acme-viewer-legacy, viewer-bin", "{field}");
        }
    } else {
        assert!(!required(), "dpkg-deb is required");
    }
    if have("rpm", &["--version"]) {
        let rpm = artifact(&artifacts, Kind::Rpm);
        for query in ["--conflicts", "--obsoletes"] {
            let value = run(Command::new("rpm").arg("-qp").arg(query).arg(&rpm));
            let names: Vec<&str> = value.lines().map(str::trim).collect();
            assert_eq!(names, ["acme-viewer-legacy", "viewer-bin"], "{query}");
        }
    } else {
        assert!(!required(), "rpm is required");
    }
    if have("bsdtar", &["--version"]) {
        let pacman = artifact(&artifacts, Kind::Pacman);
        let info = run(Command::new("bsdtar")
            .arg("-xOf")
            .arg(&pacman)
            .arg(".PKGINFO"));
        for key in ["conflict", "replaces"] {
            let values: Vec<&str> = info
                .lines()
                .filter_map(|l| l.strip_prefix(&format!("{key} = ")))
                .collect();
            assert_eq!(
                values,
                ["acme-viewer-legacy", "viewer-bin"],
                "{key}\n{info}"
            );
        }
    } else {
        assert!(!required(), "bsdtar is required");
    }
}

#[test]
fn the_packages_are_reproducible_with_data_files_and_the_link() {
    let Some(nfpm) = nfpm() else { return };
    let (_project, config) = project(CONFIG);
    let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let first = common::build(&config, "viewer", one.path(), &nfpm, None);
    let second = common::build(&config, "viewer", two.path(), &nfpm, None);
    for kind in [
        Kind::Deb,
        Kind::Rpm,
        Kind::Pacman,
        Kind::Tar,
        Kind::Zip,
        Kind::Wxs,
    ] {
        assert_eq!(
            std::fs::read(artifact(&first, kind)).unwrap(),
            std::fs::read(artifact(&second, kind)).unwrap(),
            "{kind:?} differs between two builds"
        );
    }
}

#[test]
fn package_refuses_a_menu_entry_desktop_file_validate_refuses() {
    let Some(nfpm) = nfpm() else { return };
    if !have("desktop-file-validate", &["--help"]) {
        assert!(!required(), "desktop-file-validate is required");
        return;
    }
    // An unregistered category passes config; the validator refuses it.
    let text = CONFIG.replacen(
        "categories = [\"Office\", \"Viewer\"]",
        "categories = [\"Office\", \"NotACategory\"]",
        1,
    );
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    let err = seaworthy::package::package(
        &config,
        "viewer",
        &layouts,
        &out.path().join("packages"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm,
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .expect_err("refused")
    .to_string();
    assert!(err.contains("desktop-file-validate refuses it"), "{err}");
}

#[test]
fn the_wxs_matches_its_golden_file() {
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    let wxs =
        seaworthy::wix::wxs(&config, "viewer", layout_for(&layouts, WINDOWS), &release()).unwrap();
    golden("wix/desktop.wxs", &wxs);
    for wanted in [
        "<Icon Id=\"ProductIcon.ico\" SourceFile=\"!(bindpath.tree)\\Acme\\Viewer.ico\" />",
        "<Property Id=\"ARPPRODUCTICON\" Value=\"ProductIcon.ico\" />",
        "<StandardDirectory Id=\"ProgramMenuFolder\" />",
        "<StandardDirectory Id=\"DesktopFolder\" />",
        "WorkingDirectory=\"InstallDir\" Icon=\"ProductIcon.ico\" />",
    ] {
        assert!(wxs.contains(wanted), "{wanted} in\n{wxs}");
    }
    // Nested once each, every data file's component in its own directory.
    assert_eq!(wxs.matches("Name=\"fonts\"").count(), 1);
    assert_eq!(wxs.matches("Name=\"licenses\"").count(), 1);
    assert_eq!(wxs.matches("<Shortcut ").count(), 2);
    // Without the icon and the desktop shortcut: no Icon table, one shortcut.
    let text = CONFIG
        .replacen("windows-icon = \"icons/viewer.ico\"\n", "", 1)
        .replacen("desktop-shortcut = true\n", "", 1);
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let plain = layouts_of(&config, out.path());
    let wxs =
        seaworthy::wix::wxs(&config, "viewer", layout_for(&plain, WINDOWS), &release()).unwrap();
    assert!(
        !wxs.contains("<Icon ") && !wxs.contains("ARPPRODUCTICON"),
        "{wxs}"
    );
    assert_eq!(wxs.matches("<Shortcut ").count(), 1);
    assert!(!wxs.contains("Icon=\"ProductIcon.ico\""));
    // Markup in the description is escaped, and a long one cut to the
    // 255 characters Shortcut.Description holds.
    let long = format!("Views <Acme> & \\\"friends\\\" {}", "x".repeat(300));
    let text = CONFIG.replacen(
        "description = \"Views Acme reports.\"",
        &format!("description = \"{long}\""),
        1,
    );
    let (_project, config) = project(&text);
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts_of(&config, out.path());
    let wxs =
        seaworthy::wix::wxs(&config, "viewer", layout_for(&layouts, WINDOWS), &release()).unwrap();
    let shortcut = wxs.lines().find(|l| l.contains("<Shortcut ")).unwrap();
    let description = shortcut
        .split("Description=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap();
    assert!(
        description.starts_with("Views &lt;Acme&gt; &amp; &quot;friends&quot; x"),
        "{shortcut}"
    );
    let unescaped = description
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"");
    assert_eq!(unescaped.chars().count(), 255, "{unescaped}");
    assert!(unescaped.ends_with("..."));
}

/// `layout` of `text` with `edit` applied to the project directory first:
/// the error.
fn refused<R>(text: &str, edit: impl FnOnce(&Path) -> R, mentions: &str) {
    let (project, config) = project(text);
    edit(project.path());
    let input = tempfile::tempdir().unwrap();
    common::acme_artifacts(input.path());
    let verified = seaworthy::verify::verify(&config, "viewer", input.path()).unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = seaworthy::layout::layout(
        &config,
        "viewer",
        &verified,
        out.path(),
        seaworthy::layout::Options {
            strip: false,
            ..seaworthy::layout::Options::default()
        },
    )
    .expect_err("must be refused")
    .to_string();
    assert!(err.contains(mentions), "{mentions:?} not in {err}");
}

#[test]
fn data_files_carry_no_code_and_stay_inside_the_project() {
    let elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0\x01\0\0\0".to_vec();
    refused(
        CONFIG,
        |root| {
            let mut bytes = elf.clone();
            bytes.resize(4096, 0);
            common::write(root, "assets/tool.bin", &bytes);
        },
        "executable code",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "assets/tool.dll", &common::Pe::default().build());
        },
        "executable code (a PE image)",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "assets/tool", &[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1]);
        },
        "executable code (a Mach-O image)",
    );
    refused(
        CONFIG,
        |root| {
            std::os::unix::fs::symlink(outside_file(), root.join("assets/hostname")).unwrap();
        },
        "a link or a special file",
    );
    refused(
        CONFIG,
        |root| {
            std::fs::remove_file(root.join("docs/LICENSE.txt")).unwrap();
            std::os::unix::fs::symlink(outside_file(), root.join("docs/LICENSE.txt")).unwrap();
        },
        "resolves outside seaworthy.toml's directory",
    );
    refused(
        CONFIG,
        |root| {
            let outside = tempfile::tempdir().unwrap().keep();
            std::fs::write(outside.join("x.txt"), b"x").unwrap();
            std::fs::remove_dir_all(root.join("assets")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("assets")).unwrap();
        },
        "resolves outside seaworthy.toml's directory",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "assets/con.txt", b"a device name");
        },
        "a name both platforms don't accept",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "assets/a:b", b"a colon");
        },
        "a name both platforms don't accept",
    );
    refused(
        CONFIG,
        |root| {
            std::fs::remove_dir_all(root.join("assets")).unwrap();
            std::fs::create_dir(root.join("assets")).unwrap();
        },
        "an empty directory",
    );
    // A data file on the launcher's path (case-insensitively on Windows).
    refused(
        &CONFIG.replacen(
            "destination = \"README.txt\"",
            "destination = \"acmetool.EXE\"",
            1,
        ),
        |_| {},
        "two files would install as Acme\\Viewer\\acmetool.EXE",
    );
    // More code, links and names.
    refused(
        CONFIG,
        |root| {
            common::write(
                root,
                "assets/Main.class",
                &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65],
            )
        },
        "a Java class file",
    );
    refused(
        CONFIG,
        |root| {
            let fifo = root.join("assets/pipe");
            common::run(Command::new("mkfifo").arg(&fifo));
        },
        "a link or a special file",
    );
    refused(
        CONFIG,
        |root| {
            // A link to a file inside the project, named as a source.
            std::fs::remove_file(root.join("docs/LICENSE.txt")).unwrap();
            std::os::unix::fs::symlink(
                root.join("docs/windows-readme.txt"),
                root.join("docs/LICENSE.txt"),
            )
            .unwrap();
        },
        "a link (data files and icons are regular files and directories)",
    );
    refused(
        CONFIG,
        |root| {
            let big = std::fs::File::create(root.join("assets/big.bin")).unwrap();
            big.set_len(seaworthy::layout::MAX_DATA_FILE + 1).unwrap();
        },
        "past what a data file may have",
    );
    for name in ["trailing.", "dollar$sign", "VIEWER~1.DLL"] {
        refused(
            CONFIG,
            |root| common::write(root, &format!("assets/{name}"), b"x"),
            "a name both platforms don't accept",
        );
    }
    // Only where the host's file system holds such a name: macOS's APFS
    // refuses one outright (EILSEQ).
    if host_holds_non_utf8_names() {
        refused(
            CONFIG,
            |root| {
                use std::os::unix::ffi::OsStrExt as _;
                let name = std::ffi::OsStr::from_bytes(b"not-utf8-\xff");
                std::fs::write(root.join("assets").join(name), b"x").unwrap();
            },
            "a file name that isn't UTF-8",
        );
    }
    // A file where another entry puts a directory.
    refused(
        &CONFIG.replacen("destination = \"README.txt\"", "destination = \"Share\"", 1),
        |_| {},
        "would install as both a file and a directory",
    );
    // Past Windows' path limit: a long install directory, a deep file.
    refused(
        &CONFIG.replacen(
            "windows-directory = \"Viewer\"",
            &format!("windows-directory = \"{}\"", "V".repeat(60)),
            1,
        ),
        |root| {
            let deep = format!(
                "assets/{}/{}/{}/x.txt",
                "a".repeat(60),
                "b".repeat(60),
                "c".repeat(60)
            );
            common::write(root, &deep, b"x");
        },
        "past Windows' 259-character path limit",
    );
    // What Windows runs or acts on, on Windows (Linux ships it as data).
    for name in [
        "setup.ps1",
        "AcmeTool.exe.manifest",
        "desktop.ini",
        "Viewer.lnk",
    ] {
        refused(
            &CONFIG.replacen(
                "destination = \"README.txt\"",
                &format!("destination = \"{name}\""),
                1,
            ),
            |_| {},
            "a file Windows runs or acts on",
        );
    }
    // Hidden files ship only when asked for; version control data never.
    refused(
        CONFIG,
        |root| common::write(root, "assets/.env", b"SECRET=1"),
        "a hidden file; set `hidden = true`",
    );
    refused(
        &CONFIG.replacen(
            "destination = \"share\"",
            "destination = \"share\"\nhidden = true",
            1,
        ),
        |root| common::write(root, "assets/.git/config", b"[remote]"),
        "version control data never ships",
    );
}

#[test]
fn hidden_files_ship_when_asked_for() {
    let text = CONFIG.replacen(
        "destination = \"share\"",
        "destination = \"share\"\nhidden = true",
        1,
    );
    let (project, config) = project(&text);
    common::write(project.path(), "assets/.config/settings.toml", b"x = 1");
    let out = tempfile::tempdir().unwrap();
    let layouts = layouts(&config, "viewer", out.path());
    assert!(
        layout_for(&layouts, LINUX)
            .files
            .iter()
            .any(|f| f.install_path == "/opt/acme/viewer/share/.config/settings.toml")
    );
}

#[test]
fn a_product_of_too_many_data_files_is_refused() {
    // Three sources of 7,000 files each: each under the per-source cap, the
    // product over its own.
    let mut text = CONFIG.to_owned();
    for name in ["bulk-a", "bulk-b", "bulk-c"] {
        text.push_str(&format!(
            "\n[[product.viewer.files]]\nsource = \"{name}\"\nplatforms = [\"linux\"]\n"
        ));
    }
    refused(
        &text,
        |root| {
            for name in ["bulk-a", "bulk-b", "bulk-c"] {
                std::fs::create_dir_all(root.join(name)).unwrap();
                for n in 0..7_000 {
                    std::fs::write(root.join(format!("{name}/f{n:05}.txt")), b"x").unwrap();
                }
            }
        },
        "past what a product's data files may add up to",
    );
}

#[test]
fn a_directory_of_too_many_files_is_refused() {
    refused(
        CONFIG,
        |root| {
            for n in 0..=seaworthy::layout::MAX_DATA_FILES {
                std::fs::write(root.join(format!("assets/f{n:05}.txt")), b"x").unwrap();
            }
        },
        "files under one [[files]] source",
    );
}

#[test]
fn icons_are_checked_as_icons() {
    // Through a link out of the project, like a data file.
    refused(
        CONFIG,
        |root| {
            let outside = tempfile::tempdir().unwrap().keep();
            std::fs::copy(root.join("icons/viewer.ico"), outside.join("viewer.ico")).unwrap();
            std::fs::copy(
                root.join("icons/viewer-256.png"),
                outside.join("viewer-256.png"),
            )
            .unwrap();
            std::fs::copy(
                root.join("icons/viewer-48.png"),
                outside.join("viewer-48.png"),
            )
            .unwrap();
            std::fs::copy(root.join("icons/viewer.svg"), outside.join("viewer.svg")).unwrap();
            std::fs::remove_dir_all(root.join("icons")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("icons")).unwrap();
        },
        "resolves outside seaworthy.toml's directory",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer-256.png", &png(256, 128));
        },
        "a square PNG of a hicolor size",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer-256.png", &png(100, 100));
        },
        "a square PNG of a hicolor size",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer-48.png", &png(256, 256));
        },
        "a second 256x256 icon",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer.svg", b"not an image");
        },
        "not an SVG image",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer.ico", &png(48, 48));
        },
        "not an ICO file",
    );
    refused(
        CONFIG,
        |root| {
            common::write(root, "icons/viewer-48.png", &common::Pe::default().build());
        },
        "executable code",
    );
}

// ---- adopt-msi: an MSI WiX built on Windows from the .wxs,
// checked against the signed tree, signed and listed.

/// msitools, when installed (`wixl` builds the fixture MSIs, as WiX on the
/// Windows runner builds the real ones; `msiextract` and `msiinfo` read
/// them).
fn msitools() -> bool {
    let all = have("wixl", &["--version"])
        && have("msiextract", &["--version"])
        && have("msiinfo", &["--help"]);
    assert!(
        all || !required(),
        "msitools (wixl, msiextract, msiinfo) is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1)"
    );
    all
}

/// A change to the payload a fixture MSI carries, or to its tables.
enum Payload<'a> {
    AsTree,
    Extra(&'a str),
    Without(&'a str),
    Changed(&'a str),
    /// A registry value of its own: a program run at every logon.
    RunKey,
    /// The Start menu shortcut passes arguments.
    ShortcutArguments,
    /// The install location custom action sets another directory.
    ActionTarget,
}

/// An MSI of the packaged Windows tree under `dist/viewer/` (built with
/// wixl from the tree's layout.json, every file but the icon), at
/// `version` with `upgrade_code`, `payload` changed as asked. Its tables
/// carry what the viewer's .wxs declares beside the payload, as WiX builds
/// it (golden/wix/desktop.wxs): the install location custom action and
/// the two shortcuts with their registry key paths.
fn fixture_msi(
    dist: &Path,
    version: &str,
    upgrade_code: &str,
    payload: Payload,
) -> std::path::PathBuf {
    let layout_dir = dist.join("viewer").join(WINDOWS);
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout_dir.join("layout.json")).unwrap()).unwrap();
    let scratch = tempfile::tempdir().unwrap().keep();
    let mut files: Vec<(String, std::path::PathBuf)> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["role"]["kind"] != "icon")
        .map(|f| {
            let relative = f["install_path"]
                .as_str()
                .unwrap()
                .strip_prefix("Acme\\Viewer\\")
                .unwrap()
                .replace('\\', "/");
            (
                relative,
                layout_dir.join("tree").join(f["path"].as_str().unwrap()),
            )
        })
        .collect();
    let run_key = matches!(payload, Payload::RunKey);
    let shortcut_arguments = matches!(payload, Payload::ShortcutArguments);
    let action_target = matches!(payload, Payload::ActionTarget);
    match payload {
        Payload::AsTree | Payload::RunKey | Payload::ShortcutArguments | Payload::ActionTarget => {}
        Payload::Extra(relative) => {
            let path = scratch.join("extra");
            std::fs::write(&path, b"not in the tree").unwrap();
            files.push((relative.to_owned(), path));
        }
        Payload::Without(relative) => files.retain(|(r, _)| r != relative),
        Payload::Changed(relative) => {
            let path = scratch.join("changed");
            std::fs::write(&path, b"other bytes").unwrap();
            for (r, p) in &mut files {
                if r == relative {
                    *p = path.clone();
                }
            }
        }
    }
    // The v3 schema wixl reads: components inside their directories.
    #[derive(Default)]
    struct Dir {
        files: Vec<(String, std::path::PathBuf)>,
        dirs: std::collections::BTreeMap<String, Dir>,
    }
    let mut root = Dir::default();
    for (relative, path) in files {
        let mut parts: Vec<&str> = relative.split('/').collect();
        let name = parts.pop().unwrap().to_owned();
        let mut dir = &mut root;
        for part in parts {
            dir = dir.dirs.entry(part.to_owned()).or_default();
        }
        dir.files.push((name, path));
    }
    let mut xml = String::new();
    let mut refs = Vec::new();
    let mut n = 0;
    fn emit(dir: &Dir, xml: &mut String, refs: &mut Vec<String>, n: &mut usize) {
        for (name, path) in &dir.files {
            *n += 1;
            xml.push_str(&format!(
                "<Component Id=\"c{n}\" Guid=\"{{11111111-2222-4333-8444-{n:012}}}\" Win64=\"yes\"><File Id=\"f{n}\" Name=\"{name}\" Source=\"{}\" KeyPath=\"yes\" /></Component>",
                path.display()
            ));
            refs.push(format!("c{n}"));
        }
        for (name, sub) in &dir.dirs {
            *n += 1;
            xml.push_str(&format!("<Directory Id=\"d{n}\" Name=\"{name}\">"));
            emit(sub, xml, refs, n);
            xml.push_str("</Directory>");
        }
    }
    emit(&root, &mut xml, &mut refs, &mut n);
    // The launcher's file id, the shortcuts' target (the root's files come
    // first, in order).
    let launcher = root
        .files
        .iter()
        .position(|(name, _)| name == "AcmeTool.exe")
        .map(|i| format!("f{}", i + 1));
    // What the .wxs declares beside the payload.
    let location = if action_target {
        "[SystemFolder]"
    } else {
        "[InstallDir]"
    };
    let mut declared = format!(
        r#"<CustomAction Id="SetARPINSTALLLOCATION" Property="ARPINSTALLLOCATION" Value="{location}" />
    <InstallExecuteSequence><Custom Action="SetARPINSTALLLOCATION" After="CostFinalize" /></InstallExecuteSequence>
"#
    );
    if let Some(launcher) = &launcher {
        let arguments = if shortcut_arguments {
            " Arguments=\"--planted\""
        } else {
            ""
        };
        for (id, folder, guid) in [
            ("StartMenuShortcut", "ProgramMenuFolder", 901),
            ("DesktopShortcut", "DesktopFolder", 902),
        ] {
            let arguments = if id == "StartMenuShortcut" {
                arguments
            } else {
                ""
            };
            declared.push_str(&format!(
                r#"    <DirectoryRef Id="{folder}"><Component Id="{id}" Guid="{{11111111-2222-4333-8444-{guid:012}}}" Win64="yes"><Shortcut Id="{id}" Name="Acme Viewer" Description="Views Acme reports." Target="[#{launcher}]" WorkingDirectory="InstallDir"{arguments} /><RegistryValue Root="HKCU" Key="SOFTWARE\Acme\Viewer" Name="{id}" Type="integer" Value="1" KeyPath="yes" /></Component></DirectoryRef>
"#
            ));
            refs.push(id.to_owned());
        }
    }
    if run_key {
        declared.push_str(
            r#"    <DirectoryRef Id="InstallDir"><Component Id="planted" Guid="{11111111-2222-4333-8444-000000000903}" Win64="yes"><RegistryValue Root="HKLM" Key="SOFTWARE\Microsoft\Windows\CurrentVersion\Run" Name="planted" Type="string" Value="[InstallDir]AcmeTool.exe" KeyPath="yes" /></Component></DirectoryRef>
"#,
        );
        refs.push("planted".to_owned());
    }
    let feature: String = refs
        .iter()
        .map(|r| format!("<ComponentRef Id=\"{r}\" />"))
        .collect();
    let wxs = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Acme Viewer" Language="1033" Version="{version}" Manufacturer="Acme" UpgradeCode="{upgrade_code}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" />
    <Media Id="1" Cabinet="payload.cab" EmbedCab="yes" />
    {declared}
    <Directory Id="TARGETDIR" Name="SourceDir"><Directory Id="ProgramFiles64Folder" Name="PFiles64"><Directory Id="VendorDir" Name="Acme"><Directory Id="InstallDir" Name="Viewer">{xml}</Directory></Directory></Directory><Directory Id="ProgramMenuFolder" /><Directory Id="DesktopFolder" /></Directory>
    <Feature Id="Main" Level="1">{feature}</Feature>
  </Product>
</Wix>
"#
    );
    std::fs::write(scratch.join("fixture.wxs"), wxs).unwrap();
    let msi = scratch.join("fixture.msi");
    run(Command::new("wixl")
        .arg("-a")
        .arg("x64")
        .arg("-o")
        .arg(&msi)
        .arg(scratch.join("fixture.wxs")));
    msi
}

/// The viewer packaged unsigned under `<out>/dist`, with its MSI version
/// and UpgradeCode.
fn packaged(config: &Config, out: &Path) -> Option<(String, String)> {
    let nfpm = nfpm()?;
    common::build(config, "viewer", out, &nfpm, None);
    let version = common::release().package_versions().unwrap().msi;
    let upgrade = seaworthy::wix::upgrade_code(config, "viewer").unwrap();
    Some((version, upgrade))
}

/// `path` relative to the test's working directory, by their common
/// ancestor, as a CI job hands its paths to the CLI (`seaworthy-work/...`).
fn from_cwd(path: &Path) -> std::path::PathBuf {
    let cwd = std::env::current_dir().unwrap();
    let common = cwd
        .components()
        .zip(path.components())
        .take_while(|(a, b)| a == b)
        .count();
    let mut relative: std::path::PathBuf = cwd.components().skip(common).map(|_| "..").collect();
    relative.extend(path.components().skip(common));
    relative
}

fn adopt(
    config: &Config,
    out: &Path,
    msi: &Path,
) -> Result<Vec<seaworthy::package::Artifact>, seaworthy::DistError> {
    seaworthy::package::adopt_msi(
        config,
        "viewer",
        &out.join("dist"),
        msi,
        1_700_000_000,
        &seaworthy::package::Signing::default(),
        &seaworthy::package::MsiTools::default(),
    )
}

#[test]
fn an_msi_of_exactly_the_signed_tree_is_adopted_and_listed() {
    if !msitools() {
        return;
    }
    let (_project, config) = project(CONFIG);
    // Beside the working directory, so the relative paths below resolve
    // from it alone (one into /tmp climbs to / and resolves from anywhere).
    let out = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let Some((version, upgrade)) = packaged(&config, out.path()) else {
        return;
    };
    let msi = fixture_msi(
        &out.path().join("dist"),
        &version,
        &upgrade,
        Payload::AsTree,
    );
    // msitools run without seaworthy's environment (a release's holds the
    // signers' credentials): each records what it was given.
    let wrappers = tempfile::tempdir().unwrap();
    let wrapped = |tool: &str| {
        let path = wrappers.path().join(tool);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nenv >> '{}'\nexec {tool} \"$@\"\n",
                wrappers.path().join("env").display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    };
    // Relative paths: msitools run in scratch directories, and must still
    // find the MSI.
    let adopted = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &from_cwd(&out.path().join("dist")),
        &from_cwd(&msi),
        1_700_000_000,
        &seaworthy::package::Signing::default(),
        &seaworthy::package::MsiTools {
            msiextract: wrapped("msiextract"),
            msiinfo: wrapped("msiinfo"),
        },
    )
    .unwrap();
    let env = std::fs::read_to_string(wrappers.path().join("env")).unwrap();
    let names: std::collections::BTreeSet<&str> = env
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(n, _)| n)
        .collect();
    assert!(names.contains("PATH"), "{env}");
    // A tool's allowlisted environment alone (seaworthy::process::tool),
    // beside the runner's LC_ALL=C and the shell's own (PWD, SHLVL, _):
    // never a credential.
    let leaked: Vec<&&str> = names
        .iter()
        .filter(|n| {
            !["LC_ALL", "PWD", "OLDPWD", "SHLVL", "_"].contains(n)
                && seaworthy::process::tool_environment([((**n).into(), "".into())], None)
                    .is_empty()
        })
        .collect();
    assert!(leaked.is_empty(), "msitools were given {leaked:?}");
    let kinds: Vec<Kind> = adopted.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, [Kind::Msi, Kind::Sbom], "unsigned: no manifest");
    assert!(
        adopted[0]
            .path
            .ends_with("packages/acme-viewer-1.4.0-rc.2-812-windows-x86_64.msi")
    );
    assert_eq!(
        std::fs::read(&adopted[0].path).unwrap(),
        std::fs::read(&msi).unwrap()
    );
    // Listed as every artifact is, its SBOM naming the tree's files; an
    // unsigned build's listing says so.
    let listing = seaworthy::repo::read_listing(&out.path().join("dist/viewer")).unwrap();
    assert!(!listing.signed, "packaged without signers");
    for kind in [Kind::Msi, Kind::Sbom, Kind::Wxs, Kind::Deb, Kind::Zip] {
        assert!(
            listing.artifacts.iter().any(|a| a.kind == kind),
            "{kind:?} listed"
        );
    }
    let sbom = std::fs::read_to_string(&adopted[1].path).unwrap();
    assert!(
        sbom.contains("Inter.ttf") && sbom.contains("OFL.txt"),
        "{sbom}"
    );
    // Once only.
    let err = adopt(&config, out.path(), &msi).unwrap_err().to_string();
    assert!(err.contains("an MSI is already listed"), "{err}");
}

#[test]
fn an_msi_that_isnt_the_signed_tree_is_refused() {
    if !msitools() {
        return;
    }
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let Some((version, upgrade)) = packaged(&config, out.path()) else {
        return;
    };
    let dist = out.path().join("dist");
    for (msi, mentions) in [
        (
            fixture_msi(
                &dist,
                &version,
                &upgrade,
                Payload::Extra("share/planted.dll"),
            ),
            "carries PFiles64/Acme/Viewer/share/planted.dll, which the signed tree has no file for",
        ),
        (
            fixture_msi(&dist, &version, &upgrade, Payload::Without("LICENSE.txt")),
            "lacks PFiles64/Acme/Viewer/LICENSE.txt",
        ),
        (
            fixture_msi(&dist, &version, &upgrade, Payload::Changed("AcmeTool.exe")),
            "its PFiles64/Acme/Viewer/AcmeTool.exe isn't the signed tree's",
        ),
        (
            fixture_msi(&dist, "9.9.9", &upgrade, Payload::AsTree),
            "its ProductVersion is Some(\"9.9.9\")",
        ),
        (
            fixture_msi(
                &dist,
                &version,
                "{00000000-0000-4000-8000-000000000000}",
                Payload::AsTree,
            ),
            "its UpgradeCode is",
        ),
        // Its tables doing more than the .wxs declares.
        (
            fixture_msi(&dist, &version, &upgrade, Payload::RunKey),
            "registry value (\"2\", \"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\", \"planted\"",
        ),
        (
            fixture_msi(&dist, &version, &upgrade, Payload::ShortcutArguments),
            "a shortcut the .wxs doesn't declare: (\"ProgramMenuFolder\", \"Acme Viewer\", \"ProgramFiles64Folder/Acme/Viewer/AcmeTool.exe\", \"--planted\"",
        ),
        (
            fixture_msi(&dist, &version, &upgrade, Payload::ActionTarget),
            "custom action SetARPINSTALLLOCATION is (\"51\", \"ARPINSTALLLOCATION\", \"[SystemFolder]\")",
        ),
    ] {
        let err = adopt(&config, out.path(), &msi).unwrap_err().to_string();
        assert!(err.contains(mentions), "{mentions:?} not in {err}");
        // Nothing adopted: the next try starts clean.
        let listing = seaworthy::repo::read_listing(&dist.join("viewer")).unwrap();
        assert!(!listing.artifacts.iter().any(|a| a.kind == Kind::Msi));
    }
    // The tree changed after packaging: its layout.json no longer holds.
    let msi = fixture_msi(&dist, &version, &upgrade, Payload::AsTree);
    let staged = dist
        .join("viewer")
        .join(WINDOWS)
        .join("tree/Acme/Viewer/LICENSE.txt");
    std::fs::write(&staged, b"changed").unwrap();
    let err = adopt(&config, out.path(), &msi).unwrap_err().to_string();
    assert!(err.contains("changed since it was packaged"), "{err}");
}

#[test]
fn an_msi_adopts_as_its_release_was_packaged() {
    if !msitools() {
        return;
    }
    let (dir, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let Some((version, upgrade)) = packaged(&config, out.path()) else {
        return;
    };
    let msi = fixture_msi(
        &out.path().join("dist"),
        &version,
        &upgrade,
        Payload::AsTree,
    );
    // An unsigned release's MSI gets no manifest: a manifest signer is a
    // mistake.
    let key =
        seaworthy::sign::generate_key(seaworthy_updater::SignatureAlgorithm::MlDsa87).unwrap();
    let secret = dir.path().join("release.key");
    std::fs::write(&secret, format!("{}\n", *key.secret_hex)).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let signing = seaworthy::package::Signing {
        manifest: vec![Box::new(
            seaworthy::sign::LocalKey::from_file(
                seaworthy_updater::SignatureAlgorithm::MlDsa87,
                &secret,
            )
            .unwrap(),
        )],
        ..seaworthy::package::Signing::default()
    };
    let err = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &out.path().join("dist"),
        &msi,
        1_700_000_000,
        &signing,
        &seaworthy::package::MsiTools::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("the release was packaged unsigned: adopt its MSI unsigned"),
        "{err}"
    );
    // Nor is it adopted as a dev build's (--authenticode-only).
    let err = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &out.path().join("dist"),
        &msi,
        1_700_000_000,
        &seaworthy::package::Signing {
            authenticode_only: true,
            ..seaworthy::package::Signing::default()
        },
        &seaworthy::package::MsiTools::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("the build wasn't packaged as a dev build: adopt its MSI as it was packaged"),
        "{err}"
    );
    // A product without an msi output has nothing to adopt into.
    let text = CONFIG.replacen(
        "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
        "outputs = [\"zip\", \"deb\"]",
        1,
    );
    let (_other, zip_only) = project(&text);
    let err = adopt(&zip_only, out.path(), &msi).unwrap_err().to_string();
    assert!(err.contains("has no msi output"), "{err}");
}

#[test]
fn wix_puts_the_payload_where_adopt_looks_for_it() {
    // An MSI WiX 5.0.2 built from golden/wix/desktop.wxs over placeholder
    // files (rebuild it when that file's directories or the WiX pin
    // change): msiextract finds each file at PFiles64\<install path>, as
    // adopt_msi expects, and nothing else. wixl's fixtures above name that
    // directory themselves; this is WiX's own naming.
    if !msitools() {
        return;
    }
    let golden = common::manifest_dir().join("tests/golden/wix");
    let wxs = std::fs::read_to_string(golden.join("desktop.wxs")).unwrap();
    let expected: std::collections::BTreeSet<String> = wxs
        .split("Source=\"!(bindpath.tree)\\")
        .skip(1)
        .map(|rest| {
            format!(
                "PFiles64/{}",
                rest.split('"').next().unwrap().replace('\\', "/")
            )
        })
        .collect();
    let out = tempfile::tempdir().unwrap();
    run(Command::new("msiextract")
        .arg("-C")
        .arg(out.path())
        .arg(golden.join("desktop.msi")));
    let mut found = std::collections::BTreeSet::new();
    let mut stack = vec![out.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path.strip_prefix(out.path()).unwrap();
                found.insert(relative.to_string_lossy().into_owned());
            }
        }
    }
    assert_eq!(found, expected);
}

#[test]
fn wix_s_own_msi_of_the_wxs_is_adopted() {
    // WiX itself (SEAWORTHY_WIX: on the Windows runner, or under Wine
    // locally): the .wxs package wrote, built against the tree, adopted.
    // allow-std-env: the local WiX, as the package tests take it
    let Some(wix) = std::env::var_os("SEAWORTHY_WIX") else {
        eprintln!(
            "SKIPPED: SEAWORTHY_WIX is unset (WiX builds the real MSI on the Windows runner)"
        );
        return;
    };
    if !msitools() {
        return;
    }
    let (_project, config) = project(CONFIG);
    let out = tempfile::tempdir().unwrap();
    let Some(_) = packaged(&config, out.path()) else {
        return;
    };
    let base = out.path().join("dist/viewer");
    let wxs = std::fs::read_dir(base.join("packages"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "wxs"))
        .unwrap();
    let msi = out.path().join("viewer.msi");
    run(Command::new(&wix)
        .arg("build")
        .arg("-arch")
        .arg("x64")
        .arg("-bindpath")
        .arg(format!(
            "tree={}",
            base.join(WINDOWS).join("tree").display()
        ))
        .arg("-o")
        .arg(&msi)
        .arg(&wxs));
    for (table, wanted) in [
        ("Shortcut", "StartMenuShortcut"),
        ("Shortcut", "DesktopShortcut"),
        ("Icon", "ProductIcon.ico"),
        ("Property", "ARPPRODUCTICON"),
        ("Directory", "licenses"),
    ] {
        // In the scratch directory: an export writes a table's binary
        // columns (the Icon table's) to files beside it.
        let rows = run(Command::new("msiinfo")
            .current_dir(out.path())
            .arg("export")
            .arg(&msi)
            .arg(table));
        assert!(rows.contains(wanted), "{table}: {wanted} in\n{rows}");
    }
    let adopted = adopt(&config, out.path(), &msi).unwrap();
    assert_eq!(adopted[0].kind, Kind::Msi);
}

#[test]
fn a_signed_release_s_msi_is_signed_and_gets_its_manifest() {
    signed_release_msi_is_signed_and_gets_its_manifest(CONFIG);
}

/// An MSI-only product's signed release: its package step lists the .wxs
/// alone, nothing installable carries a manifest yet, and the adopted MSI
/// still gets one (the release was packaged signed and seaworthy.toml signs
/// manifests).
#[test]
fn an_msi_only_signed_release_s_msi_gets_its_manifest() {
    signed_release_msi_is_signed_and_gets_its_manifest(
        &CONFIG
            .replacen(
                "outputs = [\"msi\", \"zip\", \"deb\", \"rpm\", \"pacman\", \"tar\"]",
                "outputs = [\"msi\"]",
                1,
            )
            // Linux-only settings an MSI-only product can't carry.
            .replacen("linux.command = \"acme-viewer\"\n", "", 1),
    );
}

fn signed_release_msi_is_signed_and_gets_its_manifest(base: &str) {
    if !msitools() {
        return;
    }
    if !have("osslsigncode", &["--version"]) || !have("openssl", &["version"]) {
        assert!(!required(), "osslsigncode and openssl are required");
        return;
    }
    let Some(nfpm) = nfpm() else { return };
    // The identity seaworthy.toml pins, and the release key its manifests take.
    let keys = tempfile::tempdir().unwrap();
    let (cert, key) = (
        keys.path().join("codesign.pem"),
        keys.path().join("codesign.key"),
    );
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30",
        ])
        .args(["-subj", "/CN=Acme Test Code Signing/O=Acme"])
        .args([
            "-addext",
            "extendedKeyUsage=codeSigning",
            "-addext",
            "keyUsage=digitalSignature",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    let release_key =
        seaworthy::sign::generate_key(seaworthy_updater::SignatureAlgorithm::MlDsa87).unwrap();
    let secret = keys.path().join("release.key");
    std::fs::write(&secret, format!("{}\n", *release_key.secret_hex)).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let public = keys.path().join("release.pub");
    std::fs::write(&public, hex::encode(&release_key.public_key)).unwrap();
    let text = format!(
        "{}\n[defaults.authenticode]\nsubject = \"O=Acme,CN=Acme Test Code Signing\"\ntrust = \"{}\"\n",
        base.replacen(
            "license = \"MIT\"\n",
            &format!(
                "license = \"MIT\"\nrelease-signatures = [\"ml-dsa-87\"]\nrelease-keys = [{{ algorithm = \"ml-dsa-87\", public-key = \"{}\" }}]\n",
                public.display()
            ),
            1,
        ),
        cert.display()
    );
    let (_project, config) = project(&text);
    let signing = || seaworthy::package::Signing {
        manifest: vec![Box::new(
            seaworthy::sign::LocalKey::from_file(
                seaworthy_updater::SignatureAlgorithm::MlDsa87,
                &secret,
            )
            .unwrap(),
        )],
        authenticode: Some(Box::new(seaworthy::codesign::Osslsigncode {
            tool: "osslsigncode".into(),
            certificate: cert.clone(),
            key: key.clone(),
            timestamp_url: None,
            url: None,
            timeout: std::time::Duration::from_secs(120),
        })),
        ..seaworthy::package::Signing::default()
    };
    let out = tempfile::tempdir().unwrap();
    let laid_out = layouts(&config, "viewer", out.path());
    seaworthy::package::package(
        &config,
        "viewer",
        &laid_out,
        &out.path().join("dist"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm,
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &signing(),
    )
    .unwrap();
    let version = common::release().package_versions().unwrap().msi;
    let upgrade = seaworthy::wix::upgrade_code(&config, "viewer").unwrap();
    // The MSI of the signed tree (its binaries carry the pinned signature).
    let msi = fixture_msi(
        &out.path().join("dist"),
        &version,
        &upgrade,
        Payload::AsTree,
    );
    // A signed release's MSI is never adopted unsigned (manifests or not:
    // the listing records that the release was signed).
    let err = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &out.path().join("dist"),
        &msi,
        1_700_000_000,
        &seaworthy::package::Signing::default(),
        &seaworthy::package::MsiTools::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("the release was packaged signed: its MSI is Authenticode-signed too"),
        "{err}"
    );
    let adopted = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &out.path().join("dist"),
        &msi,
        1_700_000_000,
        &signing(),
        &seaworthy::package::MsiTools::default(),
    )
    .unwrap();
    let kinds: Vec<Kind> = adopted.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, [Kind::Msi, Kind::Manifest, Kind::Sbom]);
    assert!(
        seaworthy::repo::read_listing(&out.path().join("dist/viewer"))
            .unwrap()
            .signed,
        "the adopted listing is still the signed release's"
    );
    let verify = run(Command::new("osslsigncode")
        .arg("verify")
        .arg("-CAfile")
        .arg(&cert)
        .arg("-in")
        .arg(&adopted[0].path));
    assert!(verify.contains("Acme Test Code Signing"), "{verify}");
    // The manifest names the signed MSI's exact bytes, under the release key.
    let bytes = std::fs::read(&adopted[0].path).unwrap();
    let (manifest, _) = seaworthy_updater::ReleaseManifest::decode_signed(
        &std::fs::read(&adopted[1].path).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.size, bytes.len() as u64);
    assert_eq!(manifest.digest, manifest.digest_algorithm.hash(&bytes));
    seaworthy::repo::read_listing(&out.path().join("dist/viewer")).unwrap();
    // An unsigned adoption of a signed release: refused.
    let unsigned = fixture_msi(
        &out.path().join("dist"),
        &version,
        &upgrade,
        Payload::AsTree,
    );
    let err = adopt(&config, out.path(), &unsigned)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("an MSI is already listed") || err.contains("carries signed manifests"),
        "{err}"
    );
}

/// A dev build (`--authenticode-only`): its Windows binaries and its
/// MSI carry the pinned Authenticode signature, and nothing else is signed —
/// no manifest, so the update helper never installs it — and its listing
/// says so, so it adopts only as a dev build.
#[test]
fn a_dev_build_s_msi_is_authenticode_signed_alone() {
    if !msitools() {
        return;
    }
    if !have("osslsigncode", &["--version"]) || !have("openssl", &["version"]) {
        assert!(!required(), "osslsigncode and openssl are required");
        return;
    }
    let Some(nfpm) = nfpm() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (cert, key) = (
        keys.path().join("codesign.pem"),
        keys.path().join("codesign.key"),
    );
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30",
        ])
        .args(["-subj", "/CN=Acme Test Code Signing/O=Acme"])
        .args([
            "-addext",
            "extendedKeyUsage=codeSigning",
            "-addext",
            "keyUsage=digitalSignature",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    let text = format!(
        "{CONFIG}\n[defaults.authenticode]\nsubject = \"O=Acme,CN=Acme Test Code Signing\"\ntrust = \"{}\"\n",
        cert.display()
    );
    let (_project, config) = project(&text);
    let authenticode = || -> Box<dyn seaworthy::codesign::AuthenticodeSigner> {
        Box::new(seaworthy::codesign::Osslsigncode {
            tool: "osslsigncode".into(),
            certificate: cert.clone(),
            key: key.clone(),
            timestamp_url: None,
            url: None,
            timeout: std::time::Duration::from_secs(120),
        })
    };
    let dev = || seaworthy::package::Signing {
        authenticode: Some(authenticode()),
        authenticode_only: true,
        ..seaworthy::package::Signing::default()
    };
    assert!(dev().is_signed() && !dev().is_release());
    let out = tempfile::tempdir().unwrap();
    let laid_out = layouts(&config, "viewer", out.path());
    let packaged = seaworthy::package::package(
        &config,
        "viewer",
        &laid_out,
        &out.path().join("dist"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm,
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &dev(),
    )
    .unwrap();
    assert!(
        packaged.iter().all(|a| a.kind != Kind::Manifest),
        "no manifests: {packaged:?}"
    );
    let listing = seaworthy::repo::read_listing(&out.path().join("dist/viewer")).unwrap();
    assert!(listing.authenticode_only && !listing.signed);
    let version = common::release().package_versions().unwrap().msi;
    let upgrade = seaworthy::wix::upgrade_code(&config, "viewer").unwrap();
    let msi = fixture_msi(
        &out.path().join("dist"),
        &version,
        &upgrade,
        Payload::AsTree,
    );
    // Adopted as anything but a dev build: refused.
    let release = seaworthy::package::Signing {
        authenticode: Some(authenticode()),
        ..seaworthy::package::Signing::default()
    };
    for (signing, what) in [
        (seaworthy::package::Signing::default(), "unsigned"),
        (release, "as a release"),
    ] {
        let err = seaworthy::package::adopt_msi(
            &config,
            "viewer",
            &out.path().join("dist"),
            &msi,
            1_700_000_000,
            &signing,
            &seaworthy::package::MsiTools::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("the build was packaged as a dev build (Authenticode alone): adopt its MSI with --signing and --authenticode-only"),
            "{what}: {err}"
        );
    }
    let adopted = seaworthy::package::adopt_msi(
        &config,
        "viewer",
        &out.path().join("dist"),
        &msi,
        1_700_000_000,
        &dev(),
        &seaworthy::package::MsiTools::default(),
    )
    .unwrap();
    let kinds: Vec<Kind> = adopted.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, [Kind::Msi, Kind::Sbom]);
    let verify = run(Command::new("osslsigncode")
        .arg("verify")
        .arg("-CAfile")
        .arg(&cert)
        .arg("-in")
        .arg(&adopted[0].path));
    assert!(verify.contains("Acme Test Code Signing"), "{verify}");
    let listing = seaworthy::repo::read_listing(&out.path().join("dist/viewer")).unwrap();
    assert!(
        listing.authenticode_only && !listing.signed,
        "the adopted listing is still the dev build's"
    );
}

/// Whether this host's temporary directory takes a file name that isn't
/// UTF-8 (Linux's file systems do; macOS's APFS refuses one).
fn host_holds_non_utf8_names() -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let held = std::fs::write(
        tmp.path().join(std::ffi::OsStr::from_bytes(b"probe-\xff")),
        b"x",
    )
    .is_ok();
    if !held {
        eprintln!("SKIPPED: this file system refuses names that aren't UTF-8");
    }
    held
}
