//! `[[product.<id>.file-types]]`: every rule refusing what it should, and
//! what each platform installs. Linux: the shared-mime-info package, the
//! document icons, the menu entry's `MimeType` and `Exec` (the default
//! verb, `-- %f`), the KDE service menus (golden files; shared-mime-info's
//! own `update-mime-database` and desktop-file-validate read them when
//! installed). Windows: the ProgID, verbs and extensions as HKCR registry
//! values in the `.wxs` (a golden file with the MSI options), accepted
//! exactly by adopt-msi, and, with `SEAWORTHY_WIX`, built by WiX 5 into
//! registry rows alone (no advertised ProgId, Extension, Verb or MIME
//! row). macOS: the bundle's `CFBundleDocumentTypes` and UTI declarations
//! (a golden `Info.plist`) and the document icons in its resources.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{golden, have, program_layouts, release, run};
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, MACOS, WINDOWS};
use seaworthy::linux::Source;
use seaworthy::msi_check::{Table, expected_from_wxs, findings, parse_sql_export};

const DEFAULTS: &str = r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"
"#;

/// The several-programs fixture with two file types: its own archive
/// format (owner, magic, an extra verb) and a registered type it views.
const TROVE: &str = r#"
[product.trove]
display-name = "Acme Trove"
description = "Packs and unpacks Trove archives."
kind = "desktop"
windows-directory = "Trove"
outputs = ["deb", "rpm", "zip", "msi", "pkg"]
updates.default = "off"
upgrade-code = "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}"

[[product.trove.programs]]
executable = "trove"
core = "trove_cli_core"
role = "cli"

[[product.trove.programs]]
executable = "TroveGui"
core = "trove_gui_core"
role = "gui"

[product.trove.desktop]
linux-icons = ["icons/trove-48.png"]
windows-icon = "icons/trove.ico"
categories = ["Utility"]

[product.trove.macos]
bundle-id = "com.example.acme.trove"

[product.trove.msi]
install-scope = "either"
license = "license.rtf"
path = true
wer-exclude = ["TroveGui"]

[[product.trove.file-types]]
name = "Acme Trove archive"
extensions = ["trove", "trv"]
mime-type = "application/x-acme-trove"
magic = [{ offset = 0, string = "TROVE" }, { offset = 8, bytes = "89A0ff" }]
linux-icons = ["icons/trove-doc-48.png", "icons/trove-doc.svg"]
windows-icon = "icons/trove-doc.ico"
macos-icon = "icons/trove-doc.icns"
progid = "Acme.TroveArchive"
uti = { identifier = "com.example.trove-archive", conforms-to = ["public.data", "public.archive"] }
verbs = [
    { id = "open", label = "Open", default = true, arguments = ["--", "{path}"] },
    { id = "extract", label = "Extract here", arguments = ["--extract", "--", "{path}"] },
]

[[product.trove.file-types]]
name = "Comma-separated values"
extensions = ["csv"]
mime-type = "text/csv"
role = "viewer"
windows-icon = "icons/csv.ico"
macos-icon = "icons/csv.icns"
progid = "Acme.TroveCsv"
uti = { identifier = "public.comma-separated-values-text", conforms-to = ["public.text"] }
"#;

/// A PNG's signature and IHDR: all `layout` reads.
fn png(size: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

/// A one-image ICO, its pixels marked by `mark`.
fn ico(mark: u8) -> Vec<u8> {
    let mut bytes = vec![0, 0, 1, 0, 1, 0];
    bytes.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0, 4, 0, 0, 0, 22, 0, 0, 0]);
    bytes.extend_from_slice(&[mark; 4]);
    bytes
}

/// `products` loaded from a fresh project directory holding the icons and
/// the licence they name.
fn project(products: &str) -> (tempfile::TempDir, Config) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    common::write(root, "icons/trove-48.png", &png(48));
    common::write(root, "icons/trove-doc-48.png", &png(48));
    common::write(
        root,
        "icons/trove-doc.svg",
        b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
    );
    common::write(root, "icons/trove.ico", &ico(1));
    common::write(root, "icons/trove-doc.ico", &ico(2));
    common::write(root, "icons/csv.ico", &ico(3));
    common::write(root, "icons/trove-doc.icns", b"icns\0\0\0\x08");
    common::write(root, "icons/csv.icns", b"icns\0\0\0\x09");
    common::write(
        root,
        "license.rtf",
        b"{\\rtf1\\ansi Acme Trove licence.\\par}\n",
    );
    std::fs::write(root.join("seaworthy.toml"), format!("{DEFAULTS}{products}")).unwrap();
    let config = Config::load(&root.join("seaworthy.toml")).unwrap();
    (dir, config)
}

fn refused(products: &str, mentions: &str) {
    let err = Config::parse(&format!("{DEFAULTS}{products}"))
        .expect_err("must be refused")
        .to_string();
    assert!(err.contains(mentions), "expected {mentions:?} in: {err}");
}

fn edit(from: &str, to: &str) -> String {
    assert!(TROVE.contains(from), "{from:?} not in the fixture");
    TROVE.replacen(from, to, 1)
}

#[test]
fn file_types_are_validated() {
    Config::parse(&format!("{DEFAULTS}{TROVE}")).unwrap();
    let first = "product.trove.file-types[0]";
    for (from, to, wanted) in [
        // The program: the gui one, with its menu entry.
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"Acme.TroveArchive\"\nprogram = \"trove\"",
            "\"trove\" isn't the product's gui program (\"TroveGui\")",
        ),
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"Acme.TroveArchive\"\nprogram = \"nothing\"",
            "\"nothing\" names no program of the product",
        ),
        // Names, extensions, media types.
        (
            "name = \"Acme Trove archive\"",
            "name = \"Acme [Trove]\"",
            "file-types[0].name",
        ),
        (
            "name = \"Acme Trove archive\"",
            "name = \"\"",
            "file-types[0].name",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = []",
            "at least one",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = [\".trove\"]",
            "without the dot",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = [\"Trove\"]",
            "[a-z0-9][a-z0-9+_-]*",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = [\"trove\", \"trove\"]",
            "\"trove\" is claimed twice in the product",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = [\"exe\"]",
            "a type Windows runs or acts on",
        ),
        (
            "extensions = [\"trove\", \"trv\"]",
            "extensions = [\"lnk\"]",
            "a type Windows runs or acts on",
        ),
        (
            "extensions = [\"csv\"]",
            "extensions = [\"trv\"]",
            "\"trv\" is claimed twice in the product",
        ),
        (
            "mime-type = \"application/x-acme-trove\"",
            "mime-type = \"application\"",
            "a lowercase media type",
        ),
        (
            "mime-type = \"application/x-acme-trove\"",
            "mime-type = \"Application/x-Acme\"",
            "a lowercase media type",
        ),
        (
            "mime-type = \"application/x-acme-trove\"",
            "mime-type = \"application/zip\"",
            "an owner defines its type everywhere",
        ),
        (
            "mime-type = \"text/csv\"",
            "mime-type = \"application/x-acme-trove\"",
            "\"application/x-acme-trove\" is claimed twice",
        ),
        // Magic: an owner's, well formed.
        (
            "{ offset = 0, string = \"TROVE\" }",
            "{ offset = 0 }",
            "file-types[0].magic",
        ),
        (
            "{ offset = 0, string = \"TROVE\" }",
            "{ offset = 0, string = \"A\\\\B\" }",
            "file-types[0].magic",
        ),
        (
            "{ offset = 0, string = \"TROVE\" }",
            "{ offset = 70000, string = \"T\" }",
            "file-types[0].magic",
        ),
        (
            "{ offset = 8, bytes = \"89A0ff\" }",
            "{ offset = 8, bytes = \"89A\" }",
            "file-types[0].magic",
        ),
        (
            "{ offset = 8, bytes = \"89A0ff\" }",
            "{ offset = 8, bytes = \"zz\" }",
            "file-types[0].magic",
        ),
        (
            "role = \"viewer\"",
            "role = \"viewer\"\nmagic = [{ offset = 0, string = \"x\" }]",
            "only an owner defines how its type's content looks",
        ),
        // Icons for exactly the platforms built.
        (
            "linux-icons = [\"icons/trove-doc-48.png\", \"icons/trove-doc.svg\"]\n",
            "",
            "file-types[0].linux-icons: required with a Linux package",
        ),
        (
            "role = \"viewer\"",
            "role = \"viewer\"\nlinux-icons = [\"icons/x.png\"]",
            "only an owner's Linux package installs the type's icons",
        ),
        (
            "\"icons/trove-doc-48.png\", \"icons/trove-doc.svg\"",
            "\"icons/a.svg\", \"icons/b.svg\"",
            "at most one SVG",
        ),
        (
            "\"icons/trove-doc-48.png\", \"icons/trove-doc.svg\"",
            "\"../x.png\"",
            "file-types[0].linux-icons",
        ),
        (
            "windows-icon = \"icons/trove-doc.ico\"\n",
            "",
            "windows-icon: required with an msi output",
        ),
        (
            "windows-icon = \"icons/trove-doc.ico\"",
            "windows-icon = \"icons/trove-doc.png\"",
            "must be a .ico path",
        ),
        (
            "macos-icon = \"icons/trove-doc.icns\"\n",
            "",
            "macos-icon: required with a macOS output",
        ),
        // Identities.
        (
            "progid = \"Acme.TroveArchive\"\n",
            "",
            "progid: required with an msi output",
        ),
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"TroveArchive\"",
            "must be Vendor.Type",
        ),
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"Acme.Trove-Archive\"",
            "must be Vendor.Type",
        ),
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"1Acme.Trove\"",
            "must be Vendor.Type",
        ),
        (
            "progid = \"Acme.TroveArchive\"",
            "progid = \"Acme.TroveArchiveWithAVeryLongNameIndeed\"",
            "must be Vendor.Type",
        ),
        (
            "progid = \"Acme.TroveCsv\"",
            "progid = \"acme.trovearchive\"",
            "claimed twice in the product",
        ),
        (
            "uti = { identifier = \"com.example.trove-archive\", conforms-to = [\"public.data\", \"public.archive\"] }\n",
            "",
            "uti: required with a macOS output",
        ),
        (
            "identifier = \"com.example.trove-archive\"",
            "identifier = \"trove\"",
            "uti.identifier",
        ),
        (
            "identifier = \"com.example.trove-archive\"",
            "identifier = \"public.trove\"",
            "public.* and com.apple.* are Apple's",
        ),
        (
            "conforms-to = [\"public.data\", \"public.archive\"]",
            "conforms-to = []",
            "uti.conforms-to",
        ),
        (
            "conforms-to = [\"public.data\", \"public.archive\"]",
            "conforms-to = [\"public.data\", \"public.data\"]",
            "uti.conforms-to",
        ),
        // Verbs: one default, arguments ending -- {path}.
        (
            "{ id = \"open\", label = \"Open\", default = true,",
            "{ id = \"open\", label = \"Open\",",
            "exactly one is the default",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"--extract\", \"{path}\"]",
            "must end with \"--\", \"{path}\"",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"--\", \"{path}\", \"--x\"]",
            "must end with \"--\", \"{path}\"",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"{path}\", \"--\", \"{path}\"]",
            "must end with \"--\", \"{path}\"",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"--out=%1\", \"--\", \"{path}\"]",
            "\"--out=%1\" must be 1 to 64 characters",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"--to here\", \"--\", \"{path}\"]",
            "\"--to here\" must be",
        ),
        (
            "arguments = [\"--extract\", \"--\", \"{path}\"]",
            "arguments = [\"$(x)\", \"--\", \"{path}\"]",
            "must be 1 to 64",
        ),
        (
            "{ id = \"extract\",",
            "{ id = \"Extract\",",
            "\"Extract\" must be an id",
        ),
        (
            "{ id = \"extract\",",
            "{ id = \"open\",",
            "\"open\" must be an id",
        ),
        (
            "label = \"Extract here\"",
            "label = \"Extract; rm\"",
            "extract's label",
        ),
        (
            "{ id = \"open\", label = \"Open\", default = true, arguments = [\"--\", \"{path}\"] }",
            "{ id = \"open\", label = \"Open\", default = true, arguments = [\"--new\", \"--\", \"{path}\"] }",
            "every file type's default verb takes the same arguments",
        ),
    ] {
        let products = edit(from, to);
        let err = Config::parse(&format!("{DEFAULTS}{products}"))
            .expect_err(&format!("{to:?} must be refused"))
            .to_string();
        assert!(
            err.contains(wanted),
            "{to:?}: expected {wanted:?} in: {err}"
        );
        assert!(err.contains("product.trove.file-types["), "{err}");
    }
    // The second type's errors name it.
    let err = Config::parse(&format!(
        "{DEFAULTS}{}",
        edit("progid = \"Acme.TroveCsv\"", "progid = \"Csv\"")
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("product.trove.file-types[1].progid"), "{err}");
    assert!(!err.contains(first), "{err}");
    // A product without a gui program, or without its menu entry.
    let cli_only = edit(
        "[[product.trove.programs]]\nexecutable = \"TroveGui\"\ncore = \"trove_gui_core\"\nrole = \"gui\"\n",
        "",
    )
    .replace("[product.trove.desktop]\nlinux-icons = [\"icons/trove-48.png\"]\nwindows-icon = \"icons/trove.ico\"\ncategories = [\"Utility\"]\n", "")
    .replace("kind = \"desktop\"", "kind = \"tool\"")
    .replace("wer-exclude = [\"TroveGui\"]\n", "");
    refused(&cli_only, "a file type opens in the product's gui program");
    refused(
        &edit(
            "[product.trove.desktop]\nlinux-icons = [\"icons/trove-48.png\"]\nwindows-icon = \"icons/trove.ico\"\ncategories = [\"Utility\"]\n",
            "",
        ),
        "set [product.<id>.desktop]",
    );
    // A platform's identity set where the product doesn't build for it.
    refused(
        &edit("outputs = [\"deb\", \"rpm\", \"zip\", \"msi\", \"pkg\"]", "outputs = [\"deb\", \"rpm\", \"zip\", \"pkg\"]")
            .replace("[product.trove.msi]\ninstall-scope = \"either\"\nlicense = \"license.rtf\"\npath = true\nwer-exclude = [\"TroveGui\"]\n", "")
            .replace("upgrade-code = \"{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}\"\n", ""),
        "windows-icon: set, but the product has no msi output",
    );
    // A product claiming nothing is fine; a desktop entry's own media
    // type can't be a file type's too.
    refused(
        &edit(
            "categories = [\"Utility\"]",
            "categories = [\"Utility\"]\nmime-types = [\"text/csv\"]",
        ),
        "\"text/csv\" is claimed twice in the product",
    );
}

/// Two products of one `seaworthy.toml` claiming one extension, media
/// type, ProgID or UTI are refused, unless they conflict (never installed
/// together: one per crypto build).
#[test]
fn a_file_type_is_one_products_unless_they_conflict() {
    let other = TROVE
        .replace("[product.trove", "[product.trove-fips")
        .replace(
            "display-name = \"Acme Trove\"",
            "display-name = \"Acme Trove FIPS\"",
        )
        .replace(
            "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4B}",
            "{2B4E6A80-1C3D-4F5E-8A7B-9C0D1E2F3A4C}",
        )
        .replace("com.example.acme.trove\"", "com.example.acme.trove-fips\"")
        .replace(
            "windows-directory = \"Trove\"",
            "windows-directory = \"TroveFips\"",
        )
        .replace(
            "executable = \"trove\"",
            "executable = \"trove\"\ncommand = \"trove-fips\"",
        );
    let both = format!("{TROVE}{other}");
    refused(
        &both,
        "products trove and trove-fips share file-types.extensions \"trove\"",
    );
    let conflicting = both.replacen(
        "updates.default = \"off\"",
        "updates.default = \"off\"\nconflicts = [\"trove-fips\"]",
        1,
    );
    Config::parse(&format!("{DEFAULTS}{conflicting}")).unwrap();
}

/// The Linux package of `products`' trove, laid out under `dir`.
fn linux_package(config: &Config, dir: &Path) -> seaworthy::linux::LinuxPackage {
    let layouts = program_layouts(config, "trove", dir, true);
    let linux = layouts.iter().find(|l| l.triple == LINUX).unwrap();
    seaworthy::linux::linux_package(config, "trove", linux).unwrap()
}

fn generated<'a>(package: &'a seaworthy::linux::LinuxPackage, dst: &str) -> &'a str {
    let file = package
        .files
        .iter()
        .find(|f| f.dst == dst)
        .unwrap_or_else(|| panic!("no {dst}"));
    match &file.source {
        Source::Generated(text) => text,
        Source::Staged(_) => panic!("{dst} is staged"),
    }
}

/// Linux: the owner's shared-mime-info package (globs, magic), its
/// document icons in the theme's `mimetypes` context, the menu entry's
/// `MimeType` (both types) and `Exec` (the default verb: `-- %f`), and a
/// KDE service menu for the other verb. shared-mime-info's own compiler
/// reads the package; desktop-file-validate accepts the entry.
#[test]
fn linux_registers_the_types() {
    let (project, config) = project(TROVE);
    let out = tempfile::tempdir().unwrap();
    let package = linux_package(&config, out.path());
    let xml = generated(&package, "/usr/share/mime/packages/acme-trove.xml");
    golden("file-types/acme-trove.xml", xml);
    let entry = generated(&package, "/usr/share/applications/acme-trove.desktop");
    golden("file-types/acme-trove.desktop", entry);
    assert!(
        entry.contains("\nExec=/opt/acme/trove/TroveGui -- %f\n"),
        "{entry}"
    );
    assert!(
        entry.contains("\nMimeType=application/x-acme-trove;text/csv;\n"),
        "{entry}"
    );
    let menu = generated(
        &package,
        "/usr/share/kio/servicemenus/acme-trove-extract.desktop",
    );
    golden("file-types/acme-trove-extract.desktop", menu);
    // The document icons, named for the type; the viewer's type has none
    // (its owner's are the system's).
    let icons: Vec<&str> = package
        .files
        .iter()
        .map(|f| f.dst.as_str())
        .filter(|d| d.contains("/mimetypes/"))
        .collect();
    assert_eq!(
        icons,
        [
            "/usr/share/icons/hicolor/48x48/mimetypes/application-x-acme-trove.png",
            "/usr/share/icons/hicolor/scalable/mimetypes/application-x-acme-trove.svg",
        ]
    );
    seaworthy::linux::validate_desktop_entries(&package, out.path()).unwrap();
    if have("desktop-file-validate", &["--help"]) {
        let path = out.path().join("acme-trove.desktop");
        std::fs::write(&path, entry).unwrap();
        run(Command::new("desktop-file-validate").arg(&path));
    }
    // shared-mime-info's compiler, as the distributions' triggers run it:
    // the type, its globs and its magic in the database.
    if have("update-mime-database", &["-v"]) {
        let mime = out.path().join("mime");
        std::fs::create_dir_all(mime.join("packages")).unwrap();
        std::fs::write(mime.join("packages/acme-trove.xml"), xml).unwrap();
        run(Command::new("update-mime-database").arg(&mime));
        let globs = std::fs::read_to_string(mime.join("globs2")).unwrap();
        for glob in [
            "application/x-acme-trove:*.trove",
            "application/x-acme-trove:*.trv",
        ] {
            assert!(globs.contains(glob), "{glob}: {globs}");
        }
        assert!(mime.join("application/x-acme-trove.xml").is_file());
        let magic = std::fs::read(mime.join("magic")).unwrap();
        assert!(
            magic.windows(5).any(|w| w == b"TROVE"),
            "the magic database has the string match"
        );
        assert!(
            magic.windows(3).any(|w| w == [0x89, 0xA0, 0xFF]),
            "and the bytes match"
        );
    }
    // deb and rpm recommend shared-mime-info, whose trigger compiles the
    // package (no script of their own).
    let versions = release().package_versions().unwrap();
    for format in [
        seaworthy::config::Output::Deb,
        seaworthy::config::Output::Rpm,
    ] {
        let work = out.path().join(format.name());
        let path = seaworthy::nfpm::write_config(
            &config, "trove", &package, format, &versions, "", 0, &work,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let recommends: Vec<&str> = json["recommends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            recommends,
            ["hicolor-icon-theme", "shared-mime-info"],
            "{format:?}"
        );
        assert!(
            json.get("scripts").is_none(),
            "{format:?}: no package scripts"
        );
    }
    drop(project);
}

/// The `.wxs` of the fixture (every MSI option and both file types), as
/// golden: the ProgIDs, their document icons and verbs, each extension's
/// OpenWithProgids, the owner's default, content type and MIME entry, all
/// HKCR values; adopt-msi's model accepts it.
#[test]
fn windows_registers_the_types() {
    let (_project, config) = project(TROVE);
    let out = tempfile::tempdir().unwrap();
    let layouts = program_layouts(&config, "trove", out.path(), true);
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    // The document icons install beside the programs.
    for name in ["Acme.TroveArchive.ico", "Acme.TroveCsv.ico"] {
        assert!(
            windows
                .files
                .iter()
                .any(|f| f.install_path == format!("Acme\\Trove\\{name}")
                    && f.role == seaworthy::layout::Role::DocumentIcon),
            "{name}"
        );
    }
    let wxs = seaworthy::wix::wxs(&config, "trove", windows, &release()).unwrap();
    golden("wix/trove.wxs", &wxs);
    let expected = expected_from_wxs(&wxs).unwrap();
    drop(expected);
    let lines: Vec<&str> = wxs
        .lines()
        .filter(|l| l.contains("Root=\"HKCR\""))
        .collect();
    for wanted in [
        "Key=\"Acme.TroveArchive\" Type=\"string\" Value=\"Acme Trove archive\" KeyPath=\"yes\"",
        "Key=\"Acme.TroveArchive\\shell\" Type=\"string\" Value=\"open\"",
        "Key=\"Acme.TroveArchive\\shell\\extract\\command\" Type=\"string\" Value=\"&quot;[#f001_TroveGui.exe]&quot; --extract -- &quot;%1&quot;\"",
        "Key=\".trove\" Type=\"string\" Value=\"Acme.TroveArchive\"",
        "Key=\".trv\" Name=\"Content Type\" Type=\"string\" Value=\"application/x-acme-trove\"",
        "Key=\"MIME\\Database\\Content Type\\application/x-acme-trove\" Name=\"Extension\" Type=\"string\" Value=\".trove\"",
        "Key=\".csv\\OpenWithProgids\" Name=\"Acme.TroveCsv\"",
    ] {
        assert!(
            lines.iter().any(|l| l.contains(wanted)),
            "{wanted}: {lines:#?}"
        );
    }
    // A viewer never claims the extension.
    assert!(
        !lines.iter().any(|l| l.contains("Key=\".csv\" ")),
        "{lines:#?}"
    );
}

fn wix() -> Option<PathBuf> {
    let wix = std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from);
    if wix.is_none() {
        eprintln!(
            "SKIPPED: SEAWORTHY_WIX is unset (a wix binary, or a wrapper running it under Wine)"
        );
    }
    wix
}

/// Every table of `msi` adopt-msi reads.
fn tables(msi: &Path) -> BTreeMap<String, Table> {
    let listed = run(Command::new("msiinfo").arg("tables").arg(msi));
    let mut tables = BTreeMap::new();
    for name in listed.lines().map(str::trim).filter(|n| !n.is_empty()) {
        if !seaworthy::msi_check::is_read(name) {
            continue;
        }
        let output = Command::new("msiinfo")
            .args(["export", "-s"])
            .arg(msi)
            .arg(name)
            .output()
            .unwrap();
        tables.insert(
            name.to_owned(),
            parse_sql_export(&String::from_utf8(output.stdout).unwrap()).unwrap(),
        );
    }
    tables
}

/// WiX 5 builds the file types into plain registry rows under
/// HKEY_CLASSES_ROOT (root 0: HKLM's or HKCU's classes as the install's
/// scope is), never the advertising tables, and adopt-msi accepts exactly
/// them; a planted association (another ProgID's command) is refused.
#[test]
fn wix_builds_the_types_and_adopt_msi_accepts_them() {
    let Some(wix) = wix() else {
        return;
    };
    if !have("msiinfo", &["--version"]) {
        return;
    }
    let (project, config) = project(TROVE);
    let out = tempfile::tempdir().unwrap();
    let layouts = program_layouts(&config, "trove", out.path(), true);
    let windows = layouts.iter().find(|l| l.triple == WINDOWS).unwrap();
    let wxs = seaworthy::wix::wxs(&config, "trove", windows, &release()).unwrap();
    let source = out.path().join("trove.wxs");
    std::fs::write(&source, &wxs).unwrap();
    let msi = out.path().join("trove.msi");
    let mut bindpath = std::ffi::OsString::from("tree=");
    bindpath.push(&windows.tree);
    let output = Command::new(&wix)
        .current_dir(&windows.tree)
        .args(["build", "-arch", "x64", "-nologo", "-bindpath"])
        .arg(bindpath)
        .arg("-o")
        .arg(&msi)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "wix build: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut tables = tables(&msi);
    for advertising in ["ProgId", "Extension", "Verb", "MIME", "Class"] {
        assert!(
            tables.get(advertising).is_none_or(|t| t.rows.is_empty()),
            "{advertising} rows"
        );
    }
    let classes: Vec<_> = tables["Registry"]
        .rows
        .iter()
        .filter(|r| r["Root"] == "0")
        .collect();
    // The archive's ProgID, icon, shell and two verbs (a label and a
    // command each), and per extension its OpenWithProgids, default and
    // content type, and the MIME entry (14); the CSV viewer's ProgID, icon,
    // shell, open (label and command) and OpenWithProgids (6).
    let keys: Vec<String> = classes
        .iter()
        .map(|r| format!("{}|{}", r["Key"], r.get("Name").map_or("", String::as_str)))
        .collect();
    assert_eq!(classes.len(), 20, "{keys:#?}");
    let code = seaworthy::wix::upgrade_code(&config, "trove").unwrap();
    let expected = expected_from_wxs(&wxs).unwrap();
    let found = findings(&expected, &tables, &code);
    assert!(found.is_empty(), "{found:#?}");
    // A planted association: every .zip opened by the archive tool.
    let registry = tables.get_mut("Registry").unwrap();
    let mut planted = registry.rows[0].clone();
    for (column, value) in [
        ("Registry", "planted"),
        ("Root", "0"),
        ("Key", ".zip"),
        ("Value", "Acme.TroveArchive"),
    ] {
        planted.insert(column.to_owned(), value.to_owned());
    }
    planted.remove("Name");
    registry.rows.push(planted);
    let found = findings(&expected, &tables, &code);
    assert!(
        found
            .iter()
            .any(|f| f.contains("\"0\", \".zip\", \"\", \"Acme.TroveArchive\"")),
        "{found:#?}"
    );
    drop(project);
}

/// macOS: the bundle's `Info.plist` declares both types (golden: the
/// owner's exported UTI, the viewer's role and rank, the system's CSV UTI
/// never imported again) and the bundle carries their icons.
#[test]
fn macos_declares_the_types() {
    let (_project, config) = project(TROVE);
    let product = &config.products["trove"];
    let plist = seaworthy::macos::info_plist(product, &release(), "11.0", false).unwrap();
    golden("file-types/Info.plist", &plist);
    if have("xmllint", &["--version"]) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Info.plist");
        std::fs::write(&path, &plist).unwrap();
        run(Command::new("xmllint").arg("--noout").arg(&path));
    }
    assert!(!plist.contains("UTImportedTypeDeclarations"), "{plist}");
    let out = tempfile::tempdir().unwrap();
    let layouts = program_layouts(&config, "trove", out.path(), true);
    let macos = layouts.iter().find(|l| l.triple == MACOS).unwrap();
    for name in [
        "com.example.trove-archive.icns",
        "public.comma-separated-values-text.icns",
    ] {
        assert!(
            macos.files.iter().any(|f| f.install_path
                == format!("/Applications/Acme Trove.app/Contents/Resources/{name}")),
            "{name}"
        );
    }
    // An editor of a type someone else defines imports its UTI.
    let editor = TROVE
        .replace("role = \"viewer\"", "role = \"editor\"")
        .replace(
            "public.comma-separated-values-text",
            "com.example.other-csv",
        );
    let config = Config::parse(&format!("{DEFAULTS}{editor}")).unwrap();
    let plist =
        seaworthy::macos::info_plist(&config.products["trove"], &release(), "11.0", false).unwrap();
    assert!(
        plist.contains("<key>UTImportedTypeDeclarations</key>"),
        "{plist}"
    );
    assert!(plist.contains("<string>Default</string>"), "{plist}");
}

/// A document icon that isn't what it says is refused when laid out.
#[test]
fn document_icons_are_checked_as_icons() {
    for (path, bytes, wanted) in [
        (
            "icons/trove-doc.ico",
            b"not an icon".to_vec(),
            "not an ICO file",
        ),
        ("icons/trove-doc.icns", b"nope".to_vec(), "not an ICNS file"),
        (
            "icons/trove-doc-48.png",
            png(47),
            "a square PNG of a hicolor size",
        ),
    ] {
        let (project, config) = project(TROVE);
        common::write(project.path(), path, &bytes);
        let input = project.path().join("artifacts");
        common::program_artifacts(&config, "trove", &input, true);
        let verified = seaworthy::verify::verify(&config, "trove", &input).unwrap();
        let err = seaworthy::layout::layout(
            &config,
            "trove",
            &verified,
            &project.path().join("dist"),
            seaworthy::layout::Options {
                strip: false,
                ..seaworthy::layout::Options::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(wanted), "{path}: {wanted}: {err}");
    }
}
