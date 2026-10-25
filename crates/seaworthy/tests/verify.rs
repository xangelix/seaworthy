//! `verify` over synthetic artifact directories: a good tree passes, and
//! each defect is named, all of them in one report.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::{Path, PathBuf};

use common::{Elf, LOADER, Pe, cpulist, fips_symbols, record, write};
use seaworthy::DistError;
use seaworthy::config::Config;
use seaworthy::inputs::{LINUX, WINDOWS};

const CPUS: [&str; 3] = ["x86-64-v4", "x86-64-v3", "x86-64-v2"];
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

fn config(fips: bool) -> Config {
    Config::parse(&config_text(fips)).expect("valid config")
}

fn config_text(fips: bool) -> String {
    format!(
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
fips = {fips}
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.tool]
display-name = "Acme Tool"
description = "A tool."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
sidecars.windows = ["aws_lc_fips_*_crypto.dll"]
windows-directory = "Tool"
outputs = ["msi", "deb"]

[product.tool.service]
name = "AcmeToolService"
account = "local-system"
state-directory = "acme/tool"
"#
    )
}

struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    fn root(&self) -> &Path {
        self.dir.path()
    }
}

fn linux_core(cpu: &str) -> Elf {
    Elf {
        sections: vec![(".cpureq".into(), record(LINUX, cpu, V2))],
        symbols: fips_symbols(),
        needed: vec![
            "libc.so.6".into(),
            "libgcc_s.so.1".into(),
            "ld-linux-x86-64.so.2".into(),
        ],
        ..Elf::default()
    }
}

fn windows_core(cpu: &str) -> Pe {
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    Pe {
        sections: vec![(".cpureq".into(), record(WINDOWS, cpu, V2))],
        imports: vec![format!("{prefix}crypto.dll"), "kernel32.dll".into()],
        executable: false,
    }
}

/// A complete, valid artifact directory for the test config.
fn good_tree() -> Tree {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    let launcher = |triple: &str| (format!("{triple}/launcher"), cpulist("acme_core", &CPUS));
    let (l, list) = launcher(LINUX);
    write(
        root,
        &format!("{l}/AcmeTool"),
        &Elf {
            sections: vec![(".cpulist".into(), list.clone())],
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    write(
        root,
        &format!("{LINUX}/helper/AcmeToolUpdate"),
        &Elf {
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    let (w, list) = launcher(WINDOWS);
    write(
        root,
        &format!("{w}/AcmeTool.exe"),
        &Pe {
            sections: vec![(".cpulist".into(), list)],
            imports: vec!["kernel32.dll".into()],
            executable: true,
        }
        .build(),
    );
    write(
        root,
        &format!("{WINDOWS}/helper/AcmeToolUpdate.exe"),
        &Pe {
            imports: vec!["kernel32.dll".into()],
            executable: true,
            ..Pe::default()
        }
        .build(),
    );
    let crypto = Pe {
        sections: vec![(".text".into(), b"crypto".to_vec())],
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build();
    for cpu in CPUS {
        write(
            root,
            &format!("{LINUX}/cores/{cpu}/libacme_core.so"),
            &linux_core(cpu).build(),
        );
        write(
            root,
            &format!("{WINDOWS}/cores/{cpu}/acme_core.dll"),
            &windows_core(cpu).build(),
        );
        write(
            root,
            &format!("{WINDOWS}/cores/{cpu}/{prefix}crypto.dll"),
            &crypto,
        );
    }
    Tree { dir }
}

fn findings(tree: &Tree, fips: bool) -> Vec<String> {
    match seaworthy::verify::verify(&config(fips), "tool", tree.root()) {
        Ok(_) => Vec::new(),
        Err(DistError::Verify(findings)) => findings,
        Err(other) => panic!("not a verify error: {other}"),
    }
}

fn expect_one(tree: &Tree, fips: bool, mentions: &str) {
    let found = findings(tree, fips);
    assert!(
        found.iter().any(|f| f.contains(mentions)),
        "expected a finding mentioning {mentions:?}, got {found:#?}"
    );
}

fn core_path(tree: &Tree, triple: &str, cpu: &str) -> PathBuf {
    let file = if triple == WINDOWS {
        "acme_core.dll"
    } else {
        "libacme_core.so"
    };
    tree.root().join(triple).join("cores").join(cpu).join(file)
}

#[test]
fn a_complete_tree_verifies() {
    let tree = good_tree();
    let verified = seaworthy::verify::verify(&config(true), "tool", tree.root()).expect("verifies");
    assert_eq!(verified.platforms().len(), 2);
    let windows = verified
        .platforms()
        .iter()
        .find(|p| p.inputs.triple == WINDOWS)
        .unwrap();
    assert_eq!(windows.sidecars.len(), 1, "one copy of the one sidecar");
}

#[test]
fn every_finding_is_reported_together() {
    let tree = good_tree();
    std::fs::remove_file(core_path(&tree, LINUX, "x86-64-v4")).unwrap();
    std::fs::remove_file(core_path(&tree, WINDOWS, "x86-64-v2")).unwrap();
    let found = findings(&tree, true);
    assert!(found.len() >= 2, "{found:#?}");
}

#[test]
fn a_missing_core_or_helper_is_named() {
    let tree = good_tree();
    std::fs::remove_file(core_path(&tree, LINUX, "x86-64-v3")).unwrap();
    expect_one(&tree, true, "libacme_core.so");
    let tree = good_tree();
    std::fs::remove_file(tree.root().join(WINDOWS).join("helper/AcmeToolUpdate.exe")).unwrap();
    expect_one(&tree, true, "AcmeToolUpdate.exe");
}

#[test]
fn a_core_with_another_builds_record_is_refused() {
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v4/libacme_core.so"),
        &linux_core("x86-64-v3").build(),
    );
    expect_one(&tree, true, "built for CPU x86-64-v3");
    let tree = good_tree();
    let mut wrong = linux_core("x86-64-v4");
    wrong.sections = vec![(".cpureq".into(), record(WINDOWS, "x86-64-v4", V2))];
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v4/libacme_core.so"),
        &wrong.build(),
    );
    expect_one(&tree, true, "built for x86_64-pc-windows-msvc");
}

#[test]
fn an_unknown_feature_is_refused() {
    let tree = good_tree();
    let mut core = linux_core("x86-64-v2");
    core.sections = vec![(
        ".cpureq".into(),
        record(
            LINUX,
            "x86-64-v2",
            &["sse", "sse2", "x87", "fxsr", "warpdrive"],
        ),
    )];
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v2/libacme_core.so"),
        &core.build(),
    );
    expect_one(&tree, true, "warpdrive");
}

#[test]
fn a_core_without_a_record_is_refused() {
    let tree = good_tree();
    let mut core = linux_core("x86-64-v2");
    core.sections.clear();
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v2/libacme_core.so"),
        &core.build(),
    );
    expect_one(&tree, true, "no valid requirement record");
}

#[test]
fn the_launchers_cpu_list_must_match_the_targets() {
    let tree = good_tree();
    let swapped = cpulist("acme_core", &["x86-64-v3", "x86-64-v4", "x86-64-v2"]);
    write(
        tree.root(),
        &format!("{LINUX}/launcher/AcmeTool"),
        &Elf {
            sections: vec![(".cpulist".into(), swapped)],
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    expect_one(&tree, true, "same CPUs, same order");
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/launcher/AcmeTool"),
        &Elf {
            sections: vec![(".cpulist".into(), cpulist("other_core", &CPUS))],
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    expect_one(&tree, true, "names core \"other_core\"");
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/launcher/AcmeTool"),
        &Elf {
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    expect_one(&tree, true, "not a seaworthy launcher");
}

#[test]
fn windows_sidecars_must_be_identical_and_unique() {
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    let tree = good_tree();
    let other = Pe {
        sections: vec![(".text".into(), b"a per-target build".to_vec())],
        imports: vec![],
        executable: false,
    }
    .build();
    write(
        tree.root(),
        &format!("{WINDOWS}/cores/x86-64-v3/{prefix}crypto.dll"),
        &other,
    );
    expect_one(&tree, true, "must be identical across target builds");
    let tree = good_tree();
    std::fs::remove_file(
        tree.root()
            .join(format!("{WINDOWS}/cores/x86-64-v2/{prefix}crypto.dll")),
    )
    .unwrap();
    expect_one(&tree, true, "matches 0 files in the x86-64-v2 build");
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{WINDOWS}/cores/x86-64-v4/aws_lc_fips_9_9_9_crypto.dll"),
        b"x",
    );
    expect_one(&tree, true, "matches 2 files in the x86-64-v4 build");
}

#[test]
fn linux_fips_cores_pass_the_symbol_checks() {
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    let cases: Vec<(&str, Vec<(String, bool)>)> = vec![
        ("no symbol table", Vec::new()),
        ("not linked", vec![("main".into(), true)]),
        (
            "not a defined text symbol",
            vec![
                (format!("{prefix}awslc_version_string"), false),
                (format!("{prefix}RAND_bytes"), true),
            ],
        ),
        (
            "non-FIPS AWS-LC",
            [
                fips_symbols(),
                vec![("aws_lc_0_45_0_EVP_sha256".into(), true)],
            ]
            .concat(),
        ),
        (
            "ring symbols",
            [
                fips_symbols(),
                vec![("ring_core_0_17_14__x25519".into(), true)],
            ]
            .concat(),
        ),
        (
            "of a version other than",
            [
                fips_symbols(),
                vec![("aws_lc_fips_0_13_9_SHA256".into(), true)],
            ]
            .concat(),
        ),
    ];
    for (mentions, symbols) in cases {
        let tree = good_tree();
        let mut core = linux_core("x86-64-v3");
        core.symbols = symbols;
        write(
            tree.root(),
            &format!("{LINUX}/cores/x86-64-v3/libacme_core.so"),
            &core.build(),
        );
        expect_one(&tree, true, mentions);
        // The same core is fine in a non-FIPS product.
        assert!(
            findings(&tree, false).is_empty(),
            "{mentions}: non-FIPS {:#?}",
            findings(&tree, false)
        );
    }
}

#[test]
fn codegen_unit_file_symbols_are_not_module_symbols() {
    // rustc's STT_FILE entries name the codegen unit
    // (`aws_lc_fips_sys.<hash>-cgu.0`); `nm` never prints them, and they
    // must not read as "another AWS-LC FIPS module version". Found on a
    // real FIPS core in scripts/launcher-e2e.sh.
    let tree = good_tree();
    let mut core = linux_core("x86-64-v3");
    core.files = vec![
        "aws_lc_fips_sys.80e45444fb785bcd-cgu.0".into(),
        "ring_core.cgu.1".into(),
    ];
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v3/libacme_core.so"),
        &core.build(),
    );
    assert!(
        findings(&tree, true).is_empty(),
        "{:#?}",
        findings(&tree, true)
    );
}

/// Windows FIPS: every core imports the pinned module's crypto DLL, and the
/// sidecars ship every DLL of the module the cores import. The pinned
/// aws-lc-fips-sys 0.14 builds one DLL, `<prefix>crypto.dll`. The rule used
/// to demand a `<prefix>rust_wrapper.dll` too, which older releases built;
/// Acme's first Windows release build had none, so verify would have
/// refused a correct release. Now the cores' imports decide.
#[test]
fn windows_fips_sidecars_ship_the_module_dlls_the_cores_import() {
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    // The 0.14 shape (the good tree): one DLL, imported, shipped.
    let tree = good_tree();
    assert!(
        findings(&tree, true).is_empty(),
        "{:#?}",
        findings(&tree, true)
    );

    // A core that isn't a FIPS build of the pinned module.
    let mut core = windows_core("x86-64-v4");
    core.imports = vec!["kernel32.dll".into()];
    write(
        tree.root(),
        &format!("{WINDOWS}/cores/x86-64-v4/acme_core.dll"),
        &core.build(),
    );
    expect_one(&tree, true, &format!("does not import {prefix}crypto.dll"));

    // Another module version's DLL: the glob matches, the import doesn't.
    let tree = good_tree();
    for cpu in CPUS {
        let dir = tree.root().join(format!("{WINDOWS}/cores/{cpu}"));
        std::fs::rename(
            dir.join(format!("{prefix}crypto.dll")),
            dir.join("aws_lc_fips_0_13_9_crypto.dll"),
        )
        .unwrap();
    }
    expect_one(
        &tree,
        true,
        &format!("import the pinned FIPS module's {prefix}crypto.dll, but no sidecar ships it"),
    );

    // An older module's shape: the cores import a second DLL of the module.
    // Unshipped, it is refused; declared and shipped, it verifies.
    let tree = good_tree();
    let wrapper = format!("{prefix}rust_wrapper.dll");
    for cpu in CPUS {
        let mut core = windows_core(cpu);
        core.imports.push(wrapper.clone());
        write(
            tree.root(),
            &format!("{WINDOWS}/cores/{cpu}/acme_core.dll"),
            &core.build(),
        );
    }
    expect_one(
        &tree,
        true,
        &format!("import the pinned FIPS module's {wrapper}, but no sidecar ships it"),
    );
    let dll = Pe {
        sections: vec![(".text".into(), b"the wrapper".to_vec())],
        imports: vec![],
        executable: false,
    }
    .build();
    for cpu in CPUS {
        write(
            tree.root(),
            &format!("{WINDOWS}/cores/{cpu}/{wrapper}"),
            &dll,
        );
    }
    let declared = Config::parse(&config_text(true).replace(
        r#"sidecars.windows = ["aws_lc_fips_*_crypto.dll"]"#,
        r#"sidecars.windows = ["aws_lc_fips_*_crypto.dll", "aws_lc_fips_*_rust_wrapper.dll"]"#,
    ))
    .expect("valid config");
    let verified = seaworthy::verify::verify(&declared, "tool", tree.root());
    assert!(verified.is_ok(), "{verified:?}");
}

#[test]
fn windows_binaries_must_link_the_crt_statically() {
    let tree = good_tree();
    let mut core = windows_core("x86-64-v2");
    core.imports.push("VCRUNTIME140.dll".into());
    write(
        tree.root(),
        &format!("{WINDOWS}/cores/x86-64-v2/acme_core.dll"),
        &core.build(),
    );
    expect_one(
        &tree,
        true,
        "imports the dynamic C runtime (vcruntime140.dll)",
    );
}

#[test]
fn linux_binaries_need_only_the_base_system_unless_declared() {
    let tree = good_tree();
    let mut core = linux_core("x86-64-v4");
    core.needed.push("libssl.so.3".into());
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v4/libacme_core.so"),
        &core.build(),
    );
    expect_one(&tree, true, "needs libssl.so.3 beyond the base system");
}

/// Findings for the good tree with its Linux helper replaced by `image`,
/// under the glibc floor `floor` (`None`: the default).
fn findings_with_helper(image: &[u8], floor: Option<&str>) -> Vec<String> {
    let text = match floor {
        Some(floor) => config_text(true).replace(
            "outputs = [\"msi\", \"deb\"]",
            &format!("outputs = [\"msi\", \"deb\"]\nlinux.glibc = \"{floor}\""),
        ),
        None => config_text(true),
    };
    let config = Config::parse(&text).expect("valid config");
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/helper/AcmeToolUpdate"),
        image,
    );
    match seaworthy::verify::verify(&config, "tool", tree.root()) {
        Ok(_) => Vec::new(),
        Err(DistError::Verify(findings)) => findings,
        Err(other) => panic!("not a verify error: {other}"),
    }
}

/// The glibc-floor findings among `findings`.
fn glibc_findings(findings: &[String]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| f.contains("past the product's glibc floor"))
        .cloned()
        .collect()
}

/// A Linux core using initial-exec TLS is refused (the launcher's
/// dlopen can fail on it); a program may (its static TLS is allocated at
/// startup).
#[test]
fn a_linux_core_with_initial_exec_tls_is_refused() {
    let tree = good_tree();
    let mut core = linux_core("x86-64-v3");
    core.static_tls = true;
    write(
        tree.root(),
        &format!("{LINUX}/cores/x86-64-v3/libacme_core.so"),
        &core.build(),
    );
    expect_one(&tree, true, "uses initial-exec TLS (DF_STATIC_TLS)");

    let image = Elf {
        static_tls: true,
        ..Elf {
            needed: vec!["libc.so.6".into()],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
    }
    .build();
    assert!(
        !findings_with_helper(&image, None)
            .iter()
            .any(|f| f.contains("initial-exec TLS")),
        "a program's static TLS is the loader's to allocate"
    );
    assert!(seaworthy::verify::elf_static_tls(&image).unwrap());
    assert!(!seaworthy::verify::elf_static_tls(&linux_core("x86-64-v2").build()).unwrap());
}

/// A Linux helper needing these glibc versions (with their entry flags).
fn helper_needing(versions: &[(&str, u16)]) -> Vec<u8> {
    helper_importing(versions, &[])
}

/// A Linux helper needing these glibc versions, importing these functions
/// at those versions: `(symbol, version)`.
fn helper_importing(versions: &[(&str, u16)], imports: &[(&str, &str)]) -> Vec<u8> {
    Elf {
        needed: vec!["libc.so.6".into()],
        interp: Some(LOADER.into()),
        verneed: vec![(
            "libc.so.6".into(),
            versions
                .iter()
                .map(|(n, f)| ((*n).to_owned(), *f))
                .collect(),
        )],
        imports: imports
            .iter()
            .map(|(s, v)| ((*s).to_owned(), (*v).to_owned()))
            .collect(),
        ..Elf::default()
    }
    .build()
}

/// A refusal names each version's users, and for libm's `hypot` and
/// `hypotf` (glibc 2.35's new versions) points at `glibc_floor!`, the fix
/// that keeps the builder; other users get only the general advice.
#[test]
fn a_glibc_refusal_names_its_users_and_the_libm_fix() {
    let libm = helper_importing(
        &[("GLIBC_2.2.5", 0), ("GLIBC_2.35", 0)],
        &[
            ("hypot", "GLIBC_2.35"),
            ("hypotf", "GLIBC_2.35"),
            ("malloc", "GLIBC_2.2.5"),
        ],
    );
    let found = glibc_findings(&findings_with_helper(&libm, None));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].contains("GLIBC_2.35 (glibc 2.35: hypot, hypotf)"),
        "{}",
        found[0]
    );
    assert!(
        found[0].contains("seaworthy_launcher::glibc_floor!()"),
        "{}",
        found[0]
    );
    // Bound to the baseline (what glibc_floor! does): nothing to refuse.
    let fixed = helper_importing(
        &[("GLIBC_2.2.5", 0)],
        &[("hypot", "GLIBC_2.2.5"), ("hypotf", "GLIBC_2.2.5")],
    );
    assert_eq!(
        glibc_findings(&findings_with_helper(&fixed, None)),
        Vec::<String>::new()
    );
    // Another user of a newer glibc: no libm hint.
    let other = helper_importing(
        &[("GLIBC_2.2.5", 0), ("GLIBC_2.39", 0)],
        &[("pidfd_spawnp", "GLIBC_2.39")],
    );
    let found = glibc_findings(&findings_with_helper(&other, None));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].contains("GLIBC_2.39 (glibc 2.39: pidfd_spawnp)"),
        "{}",
        found[0]
    );
    assert!(!found[0].contains("glibc_floor"), "{}", found[0]);
    // hypot at the floor's version, with another user past it: the hint
    // follows only the users past the floor.
    let mixed = helper_importing(
        &[("GLIBC_2.2.5", 0), ("GLIBC_2.39", 0)],
        &[("hypot", "GLIBC_2.2.5"), ("pidfd_spawnp", "GLIBC_2.39")],
    );
    let found = glibc_findings(&findings_with_helper(&mixed, None));
    assert!(
        found.len() == 1 && !found[0].contains("glibc_floor"),
        "{found:#?}"
    );
}

/// Every entry of the version-needs table counts, as glibc's
/// loader checks them — numbered versions (three-part ones too), the ABI
/// markers no symbol uses, unknown names (refused) — except an entry
/// flagged `VER_FLG_WEAK` and `GLIBC_PRIVATE`.
#[test]
fn linux_binaries_must_run_on_the_glibc_floor() {
    const WEAK: u16 = 2;
    let ok = helper_needing(&[("GLIBC_2.2.5", 0), ("GLIBC_2.34", 0), ("GLIBC_PRIVATE", 0)]);
    assert_eq!(
        glibc_findings(&findings_with_helper(&ok, None)),
        Vec::<String>::new()
    );

    let too_new = helper_needing(&[("GLIBC_2.2.5", 0), ("GLIBC_2.39", 0)]);
    let found = glibc_findings(&findings_with_helper(&too_new, None));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(found[0].contains("GLIBC_2.39 (glibc 2.39)"), "{}", found[0]);
    assert!(found[0].contains("floor 2.34"), "{}", found[0]);
    assert_eq!(
        glibc_findings(&findings_with_helper(&too_new, Some("2.39"))),
        Vec::<String>::new(),
        "a floor at the need passes"
    );

    // Only the ENTRY's weak flag makes a version optional to the loader.
    let weak_entry = helper_needing(&[("GLIBC_2.34", 0), ("GLIBC_2.39", WEAK)]);
    assert_eq!(
        glibc_findings(&findings_with_helper(&weak_entry, None)),
        Vec::<String>::new()
    );

    // ABI markers: packed relative relocations need glibc 2.36.
    let relr = helper_needing(&[("GLIBC_2.34", 0), ("GLIBC_ABI_DT_RELR", 0)]);
    let found = glibc_findings(&findings_with_helper(&relr, None));
    assert!(
        found.len() == 1 && found[0].contains("GLIBC_ABI_DT_RELR (glibc 2.36)"),
        "{found:#?}"
    );
    assert_eq!(
        glibc_findings(&findings_with_helper(&relr, Some("2.36"))),
        Vec::<String>::new()
    );

    // A name this check doesn't know can't be shown to be old enough.
    for unknown in ["GLIBC_ABI_SOMETHING_NEW", "GLIBC_2.x", "GLIBC_2.34.1.9"] {
        let image = helper_needing(&[(unknown, 0)]);
        let found = glibc_findings(&findings_with_helper(&image, Some("2.99")));
        assert!(
            found.len() == 1 && found[0].contains("unknown to this check"),
            "{unknown}: {found:#?}"
        );
    }
}

/// The glibc floor on a real binary, the test's own executable: the newest glibc it
/// needs (as the loader checks, weak-only users included) sets the floor
/// it passes at; one release lower is refused, naming the version and a
/// user of it. Built against glibc 2.39 or newer, that newest need is
/// std's weakly referenced `pidfd_spawnp`'s `GLIBC_2.39`: weak users don't
/// make a version optional.
// The test's own executable is the ELF under test: glibc Linux only.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn a_real_binary_needs_every_version_its_table_names() {
    let image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let needs = seaworthy::verify::elf_glibc_needs(&image).unwrap();
    assert!(!needs.is_empty(), "a Rust binary needs glibc");
    for need in &needs {
        assert!(
            need.since.is_some(),
            "{} is unknown to the check",
            need.name
        );
        // A numbered version is in the table because symbols use it (weak
        // ones included); only an ABI marker has none.
        let marker = seaworthy::verify::GLIBC_ABI_MARKERS
            .iter()
            .any(|(name, _)| *name == need.name);
        assert!(
            marker || !need.symbols.is_empty(),
            "{} names no user",
            need.name
        );
    }
    let newest = needs.iter().max_by_key(|n| n.since).unwrap();
    let (major, minor) = newest.since.unwrap();
    assert_eq!(
        glibc_findings(&findings_with_helper(
            &image,
            Some(&format!("{major}.{minor}"))
        )),
        Vec::<String>::new(),
        "the newest need ({}) as the floor passes",
        newest.name
    );
    let below = glibc_findings(&findings_with_helper(
        &image,
        Some(&format!("{major}.{}", minor - 1)),
    ));
    assert_eq!(below.len(), 1, "{below:#?}");
    assert!(below[0].contains(&newest.name), "{}", below[0]);
    if let Some(user) = newest.symbols.iter().next() {
        assert!(below[0].contains(user.as_str()), "{}", below[0]);
    }
}

/// A dynamic binary whose section headers were stripped still runs (the
/// loader reads program headers), but its dependencies can't be read from
/// sections: refused rather than passed empty.
// The test's own executable is the ELF under test: glibc Linux only.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
fn a_dynamic_binary_without_section_headers_is_refused() {
    let mut image = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    // e_shoff (0x28), e_shnum (0x3c) and e_shstrndx (0x3e) zeroed.
    image[0x28..0x30].fill(0);
    image[0x3c..0x40].fill(0);
    let found = findings_with_helper(&image, None);
    assert!(
        found
            .iter()
            .any(|f| f.contains("no dynamic section (stripped section headers)")),
        "{found:#?}"
    );
}

/// The default floor is RHEL 9's glibc, 2.34 (the oldest the conformance
/// lane installs on), and an explicit `2.N` overrides it.
#[test]
fn the_default_glibc_floor_is_rhel_9s() {
    assert_eq!(seaworthy::config::DEFAULT_GLIBC_FLOOR, (2, 34));
    let config = config(true);
    let product = &config.products["tool"];
    assert_eq!(product.linux.glibc_floor(), (2, 34));
    let text = config_text(true).replace(
        "outputs = [\"msi\", \"deb\"]",
        "outputs = [\"msi\", \"deb\"]\nlinux.glibc = \"2.28\"",
    );
    let config = Config::parse(&text).expect("valid config");
    assert_eq!(config.products["tool"].linux.glibc_floor(), (2, 28));
}

#[test]
fn a_malformed_glibc_floor_is_refused() {
    // `+34` and overlong numbers: Rust's integer parse takes a leading `+`.
    for floor in ["2", "3.0", "2.x", "", "2.34.1", "2.+34", "+2.34", "2.12345"] {
        let text = config_text(true).replace(
            "outputs = [\"msi\", \"deb\"]",
            &format!("outputs = [\"msi\", \"deb\"]\nlinux.glibc = \"{floor}\""),
        );
        assert!(Config::parse(&text).is_err(), "{floor:?}");
    }
}

#[test]
fn binaries_must_be_the_platforms_format_and_kind() {
    // An ELF launcher shipped as the Windows .exe.
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{WINDOWS}/launcher/AcmeTool.exe"),
        &Elf {
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    expect_one(&tree, true, "not a 64-bit PE image");
    // A DLL where the Windows helper belongs.
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{WINDOWS}/helper/AcmeToolUpdate.exe"),
        &Pe {
            imports: vec!["kernel32.dll".into()],
            ..Pe::default()
        }
        .build(),
    );
    expect_one(&tree, true, "a DLL where an executable belongs");
    // A text file as the Linux helper.
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/helper/AcmeToolUpdate"),
        b"#!/bin/sh\necho not an ELF\n",
    );
    expect_one(&tree, true, "not a 64-bit ELF file");
    // A shared library without an interpreter as the Linux launcher.
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/launcher/AcmeTool"),
        &Elf {
            sections: vec![(".cpulist".into(), cpulist("acme_core", &CPUS))],
            ..Elf::default()
        }
        .build(),
    );
    expect_one(
        &tree,
        true,
        "not an executable (ET_EXEC, or ET_DYN with an interpreter)",
    );
    // An executable where a Windows core belongs.
    let tree = good_tree();
    let mut core = windows_core("x86-64-v3");
    core.executable = true;
    write(
        tree.root(),
        &format!("{WINDOWS}/cores/x86-64-v3/acme_core.dll"),
        &core.build(),
    );
    expect_one(&tree, true, "an executable where a DLL belongs");
}

#[cfg(unix)]
#[test]
fn artifacts_must_be_regular_files() {
    let tree = good_tree();
    let core = core_path(&tree, LINUX, "x86-64-v2");
    let elsewhere = tree.root().join("elsewhere.so");
    std::fs::rename(&core, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &core).unwrap();
    expect_one(&tree, true, "not a regular file");
}

#[test]
fn the_version_symbol_must_be_a_real_text_definition() {
    // `nm` shows these as W, D and a double-underscore name: the script
    // refuses all three, and so must the port.
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    let version = format!("{prefix}awslc_version_string");
    let rand = (format!("{prefix}RAND_bytes"), true);
    for core in [
        Elf {
            symbols: vec![rand.clone()],
            weak_symbols: vec![version.clone()],
            ..linux_core("x86-64-v3")
        },
        Elf {
            symbols: vec![rand.clone()],
            data_symbols: vec![version.clone()],
            ..linux_core("x86-64-v3")
        },
        Elf {
            symbols: vec![rand.clone(), (format!("__{version}"), true)],
            ..linux_core("x86-64-v3")
        },
    ] {
        let tree = good_tree();
        write(
            tree.root(),
            &format!("{LINUX}/cores/x86-64-v3/libacme_core.so"),
            &core.build(),
        );
        expect_one(&tree, true, "is not a defined text symbol");
    }
}

#[test]
fn a_sidecar_matched_by_two_globs_or_named_like_a_device_is_refused() {
    let base = config(true);
    // Two globs over one file.
    let mut doubled = base.clone();
    doubled
        .products
        .get_mut("tool")
        .unwrap()
        .sidecars
        .windows
        .push("aws_lc_fips_*_crypto*".into());
    let tree = good_tree();
    let found = match seaworthy::verify::verify(&doubled, "tool", tree.root()) {
        Err(DistError::Verify(f)) => f,
        other => panic!("{other:?}"),
    };
    assert!(
        found
            .iter()
            .any(|f| f.contains("matched by two sidecar globs")),
        "{found:#?}"
    );
    // A device name.
    let mut device = base;
    device
        .products
        .get_mut("tool")
        .unwrap()
        .sidecars
        .windows
        .push("aux.*".into());
    let tree = good_tree();
    let pe = Pe {
        executable: false,
        ..Pe::default()
    }
    .build();
    for cpu in CPUS {
        write(tree.root(), &format!("{WINDOWS}/cores/{cpu}/aux.dll"), &pe);
    }
    let found = match seaworthy::verify::verify(&device, "tool", tree.root()) {
        Err(DistError::Verify(f)) => f,
        other => panic!("{other:?}"),
    };
    assert!(
        found
            .iter()
            .any(|f| f.contains("not a Windows device name")),
        "{found:#?}"
    );
}

#[test]
fn a_core_no_cpu_would_choose_is_a_warning() {
    // Identical requirements: v3 and v2 can never be chosen over v4.
    let tree = good_tree();
    let verified = seaworthy::verify::verify(&config(true), "tool", tree.root()).unwrap();
    assert!(
        verified
            .warnings()
            .iter()
            .any(|w| w.contains("the x86-64-v3 core can never be chosen")),
        "{:#?}",
        verified.warnings()
    );
    // Strictly decreasing requirements: no warning.
    let tree = good_tree();
    let v4: Vec<&str> = [V2, &["avx", "avx2", "avx512f"]].concat();
    let v3: Vec<&str> = [V2, &["avx", "avx2"]].concat();
    for (cpu, features) in [("x86-64-v4", v4), ("x86-64-v3", v3)] {
        for triple in [LINUX, WINDOWS] {
            if triple == LINUX {
                let core = Elf {
                    sections: vec![(".cpureq".into(), record(LINUX, cpu, &features))],
                    ..linux_core(cpu)
                };
                write(
                    tree.root(),
                    &format!("{LINUX}/cores/{cpu}/libacme_core.so"),
                    &core.build(),
                );
            } else {
                let core = Pe {
                    sections: vec![(".cpureq".into(), record(WINDOWS, cpu, &features))],
                    ..windows_core(cpu)
                };
                write(
                    tree.root(),
                    &format!("{WINDOWS}/cores/{cpu}/acme_core.dll"),
                    &core.build(),
                );
            }
        }
    }
    let verified = seaworthy::verify::verify(&config(true), "tool", tree.root()).unwrap();
    assert!(verified.warnings().is_empty(), "{:#?}", verified.warnings());
}

#[test]
fn a_record_missing_an_implied_feature_is_refused() {
    // diamondrapids emits APX without --print cfg saying so: its record must
    // carry apxf (seaworthy_levels::IMPLIED_FEATURES).
    let text = r#"
[defaults]
vendor = "Acme"
targets = ["diamondrapids"]
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
"#;
    let config = Config::parse(text).unwrap();
    let tree = good_tree();
    write(
        tree.root(),
        &format!("{LINUX}/launcher/AcmeTool"),
        &Elf {
            sections: vec![(".cpulist".into(), cpulist("acme_core", &["diamondrapids"]))],
            interp: Some(LOADER.into()),
            ..Elf::default()
        }
        .build(),
    );
    let core = Elf {
        sections: vec![(
            ".cpureq".into(),
            record(LINUX, "diamondrapids", &["sse", "sse2", "fxsr", "x87"]),
        )],
        ..linux_core("diamondrapids")
    };
    write(
        tree.root(),
        &format!("{LINUX}/cores/diamondrapids/libacme_core.so"),
        &core.build(),
    );
    let found = match seaworthy::verify::verify(&config, "tool", tree.root()) {
        Err(DistError::Verify(f)) => f,
        other => panic!("{other:?}"),
    };
    assert!(found.iter().any(|f| f.contains("lacks apxf")), "{found:#?}");
}

/// `seaworthy glibc-check`: `verify`'s glibc rule for single files — the floor (default 2.34),
/// ABI markers, a chosen floor, exit codes.
#[test]
fn the_glibc_check_command_applies_verifys_rule_to_single_files() {
    let tmp = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: Vec<u8>| {
        let path = tmp.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let ok = write(
        "ok",
        helper_needing(&[("GLIBC_2.2.5", 0), ("GLIBC_2.34", 0)]),
    );
    let relr = write(
        "relr",
        helper_needing(&[("GLIBC_2.34", 0), ("GLIBC_ABI_DT_RELR", 0)]),
    );
    let too_new = write("new", helper_needing(&[("GLIBC_2.39", 0)]));
    let check = |args: &[&std::ffi::OsStr]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_seaworthy"))
            .arg("glibc-check")
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let (code, text) = check(&[ok.as_os_str()]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("ok — needs glibc 2.34 at most (floor 2.34)"),
        "{text}"
    );
    let (code, text) = check(&[ok.as_os_str(), relr.as_os_str()]);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("GLIBC_ABI_DT_RELR (glibc 2.36), past the glibc floor 2.34"),
        "{text}"
    );
    let (code, text) = check(&["--floor".as_ref(), "2.39".as_ref(), too_new.as_os_str()]);
    assert_eq!(code, Some(0), "{text}");
    let (code, text) = check(&[too_new.as_os_str()]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("GLIBC_2.39 (glibc 2.39)"), "{text}");
    // Usage: no file, a bad floor, an unknown option; an unreadable file.
    assert_eq!(check(&[]).0, Some(2));
    assert_eq!(
        check(&["--floor".as_ref(), "two".as_ref(), ok.as_os_str()]).0,
        Some(2)
    );
    assert_eq!(check(&["--strict".as_ref(), ok.as_os_str()]).0, Some(2));
    let (code, text) = check(&[tmp.path().join("missing").as_os_str()]);
    assert_eq!(code, Some(1), "{text}");
    assert!(text.contains("cannot read"), "{text}");
}
