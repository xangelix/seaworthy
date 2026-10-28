//! `post_link`: stripping, the version stamp and signing change nothing the
//! loader maps — checked over hand-built ELF and PE images, a real `strip`
//! when one is installed, and images tampered with after each step.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{CPUS, Elf, Pe, V2, record};
use object::read::elf::{ElfFile64, FileHeader as _, ProgramHeader as _};
use object::{Object as _, ObjectSection as _};
use seaworthy::inputs::{LINUX, WINDOWS};
use seaworthy::pe_version::{VersionInfo, stamp_version};
use seaworthy::post_link::{check_sign, check_stamp, check_strip};

// ---------------------------------------------------------------------------
// ELF

/// A core as a linker lays one out, with its symbol table (`symbols`) or
/// without it (stripped).
fn core(symbols: bool) -> Vec<u8> {
    Elf {
        sections: vec![(".cpureq".into(), record(LINUX, CPUS[1], V2))],
        needed: vec!["libc.so.6".into()],
        symbols: if symbols {
            vec![("seaworthy_core_main".into(), true)]
        } else {
            Vec::new()
        },
        files: if symbols {
            vec!["core.rs".into()]
        } else {
            Vec::new()
        },
        ..Elf::default()
    }
    .build()
}

/// `name`'s file offset in an ELF image.
fn elf_section(image: &[u8], name: &str) -> usize {
    let file = ElfFile64::<object::Endianness>::parse(image).unwrap();
    let section = file.section_by_name(name).unwrap();
    usize::try_from(section.file_range().unwrap().0).unwrap()
}

/// The file offset of program header `index`.
fn program_header(image: &[u8], index: usize) -> usize {
    usize::try_from(u64::from_le_bytes(image[32..40].try_into().unwrap())).unwrap() + 56 * index
}

/// The error `check` gives, as text.
fn refusal(result: Result<(), seaworthy::DistError>) -> String {
    result.expect_err("refused").to_string()
}

#[test]
fn stripping_the_symbol_tables_changes_nothing_loaded() {
    let (before, after) = (core(true), core(false));
    assert!(after.len() < before.len(), "the symbol tables are gone");
    check_strip(&before, &after).expect("only non-allocated sections changed");
    // And the identity, trivially.
    check_strip(&before, &before).unwrap();
}

#[test]
fn a_real_strip_changes_nothing_loaded() {
    for tool in ["strip", "llvm-strip"] {
        let ok = std::process::Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            eprintln!("SKIP: {tool} is not installed");
            continue;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libacme_core.so");
        let before = core(true);
        std::fs::write(&path, &before).unwrap();
        common::run(
            std::process::Command::new(tool)
                .arg("--strip-all")
                .arg(&path),
        );
        let after = std::fs::read(&path).unwrap();
        assert!(
            seaworthy::verify::fips_symbol_findings(&after, "x_")[0].starts_with("no symbol table"),
            "{tool} stripped the symbol table"
        );
        check_strip(&before, &after).unwrap_or_else(|e| panic!("{tool}: {e}"));
    }
}

#[test]
fn a_changed_allocated_section_is_refused_by_name() {
    let before = core(true);
    // Its contents.
    let mut after = core(false);
    let text = elf_section(&after, ".text");
    after[text + 3] ^= 0xff;
    let err = refusal(check_strip(&before, &after));
    assert!(
        err.contains(
            r#"stripping changed what the loader maps: section ".text"'s contents, at byte 0x3"#
        ),
        "{err}"
    );
    // Its address, in the section header (sh_addr, 16 bytes in).
    let mut after = core(false);
    let shoff = usize::try_from(u64::from_le_bytes(after[40..48].try_into().unwrap())).unwrap();
    let file = ElfFile64::<object::Endianness>::parse(&*after).unwrap();
    let index = file.section_by_name(".cpureq").unwrap().index().0;
    let addr = shoff + 64 * index + 16;
    after[addr] ^= 0x10;
    let err = refusal(check_strip(&before, &after));
    assert!(err.contains(r#"section ".cpureq"'s address"#), "{err}");
}

#[test]
fn a_changed_pt_load_is_refused() {
    let before = core(true);
    let file = ElfFile64::<object::Endianness>::parse(&*before).unwrap();
    let endian = file.endian();
    let load = file
        .elf_header()
        .program_headers(endian, &*before)
        .unwrap()
        .iter()
        .position(|ph| ph.p_type(endian) == object::elf::PT_LOAD)
        .unwrap();
    // Its flags (no longer executable) and, separately, its physical
    // address.
    for (field, change) in [(4, 0x01u8), (24, 0x01)] {
        let mut after = core(false);
        let at = program_header(&after, load) + field;
        after[at] ^= change;
        let err = refusal(check_strip(&before, &after));
        assert!(
            err.contains(&format!(
                "program header {load} (PT_LOAD at file offset 0x0"
            )),
            "{err}"
        );
    }
}

#[test]
fn a_changed_byte_outside_every_section_but_inside_a_pt_load_is_refused() {
    let before = core(true);
    let mut after = core(false);
    // Sections start 8-aligned: the first one whose end isn't leaves
    // padding the PT_LOAD maps (.dynstr's, here).
    let file = ElfFile64::<object::Endianness>::parse(&*before).unwrap();
    let gap = file
        .sections()
        .filter_map(|s| s.file_range())
        .map(|(start, size)| usize::try_from(start + size).unwrap())
        .find(|end| end % 8 != 0)
        .expect("a section leaving padding");
    after[gap] = 0xcc;
    let err = refusal(check_strip(&before, &after));
    assert!(
        err.contains(&format!(
            "the byte at file offset {gap:#x} (outside any section), which program header"
        )),
        "{err}"
    );
}

#[test]
fn a_changed_elf_header_field_is_refused_by_name() {
    let before = core(true);
    for (at, name) in [(24, "e_entry"), (48, "e_flags"), (18, "e_machine")] {
        let mut after = core(false);
        after[at] ^= 0x01;
        let err = refusal(check_strip(&before, &after));
        assert!(err.ends_with(&format!("the ELF header's {name}")), "{err}");
    }
}

#[test]
fn an_unreadable_image_is_refused_as_such() {
    let core = core(true);
    for (before, after, which) in [
        (&b"not an ELF image"[..], &core[..], "original"),
        (&core[..], &core[..40], "stripped"),
    ] {
        let err = refusal(check_strip(before, after));
        assert!(
            err.contains(&format!("stripping: the {which} image can't be read")),
            "{err}"
        );
    }
}

// ---------------------------------------------------------------------------
// PE

/// A core DLL as the fixture builds it.
fn dll() -> Vec<u8> {
    Pe {
        sections: vec![(".cpureq".into(), record(WINDOWS, CPUS[1], V2))],
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build()
}

fn stamp(image: &[u8]) -> Vec<u8> {
    stamp_version(
        image,
        &common::release(),
        &VersionInfo {
            company: "Acme",
            product: "Acme Tool",
            description: "Acme Tool (x86-64-v2)",
            file_name: "acme_core_x86-64-v2.dll",
            dll: true,
        },
    )
    .unwrap()
}

fn u32_at(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
}

fn u16_at(image: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(image[at..at + 2].try_into().unwrap())
}

/// The optional header's and the section table's offsets.
fn pe_offsets(image: &[u8]) -> (usize, usize) {
    let nt = u32_at(image, 0x3c) as usize;
    let optional_size = usize::from(u16_at(image, nt + 20));
    (nt + 24, nt + 24 + optional_size)
}

/// Section `name`'s header offset and its file data's offset.
fn pe_section(image: &[u8], name: &str) -> (usize, usize) {
    let (_, table) = pe_offsets(image);
    let count = usize::from(u16_at(image, u32_at(image, 0x3c) as usize + 6));
    (0..count)
        .map(|i| table + 40 * i)
        .find(|at| image[*at..*at + 8].starts_with(name.as_bytes()))
        .map(|at| (at, u32_at(image, at + 20) as usize))
        .unwrap()
}

/// `image` as an Authenticode signer leaves it: padded to 8 bytes, a
/// certificate table appended, the security data directory naming it.
fn sign(image: &[u8]) -> Vec<u8> {
    let mut out = image.to_vec();
    out.resize(out.len().next_multiple_of(8), 0);
    let table = out.len();
    let mut certificate = Vec::new();
    certificate.extend_from_slice(&24u32.to_le_bytes()); // dwLength
    certificate.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    certificate.extend_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    certificate.extend_from_slice(&[0x30; 16]);
    out.extend_from_slice(&certificate);
    let (optional, _) = pe_offsets(&out);
    let directory = optional + 112 + 4 * 8;
    out[directory..directory + 4].copy_from_slice(&u32::try_from(table).unwrap().to_le_bytes());
    out[directory + 4..directory + 8].copy_from_slice(&24u32.to_le_bytes());
    // A signer rewrites the checksum too.
    out[optional + 64] ^= 0x5a;
    out
}

#[test]
fn stamping_changes_only_the_resources() {
    let before = dll();
    let once = stamp(&before);
    check_stamp(&before, &once).expect("a section appended");
    assert_eq!(
        pe_offsets(&once),
        pe_offsets(&before),
        "the headers stay where they were"
    );
    // Stamping again rewrites that trailing resource section in place.
    let twice = stamp_version(
        &once,
        &seaworthy::version::Release::new("1.4.1", 900).unwrap(),
        &VersionInfo {
            company: "Acme",
            product: "Acme Tool",
            description: "Acme Tool (x86-64-v2)",
            file_name: "acme_core_x86-64-v2.dll",
            dll: true,
        },
    )
    .unwrap();
    assert_ne!(twice, once);
    check_stamp(&once, &twice).expect("the resource section rewritten in place");
}

#[test]
fn a_stamp_that_changes_a_section_is_refused_by_name() {
    let before = dll();
    // Its data.
    let mut after = stamp(&before);
    let (header, data) = pe_section(&after, ".cpureq");
    after[data + 5] ^= 0x01;
    let err = refusal(check_stamp(&before, &after));
    assert!(
        err.contains(&format!(
            r#"stamping changed what the loader maps: section ".cpureq"'s data, at file offset {:#x}"#,
            data + 5
        )),
        "{err}"
    );
    // Its address (VirtualAddress, 12 bytes into its header).
    let mut after = stamp(&before);
    after[header + 13] ^= 0x10;
    let err = refusal(check_stamp(&before, &after));
    assert!(
        err.contains(r#"section ".cpureq"'s VirtualAddress"#),
        "{err}"
    );
    // Its characteristics (made executable).
    let mut after = stamp(&before);
    after[header + 39] |= 0x20;
    let err = refusal(check_stamp(&before, &after));
    assert!(
        err.contains(r#"section ".cpureq"'s Characteristics"#),
        "{err}"
    );
}

#[test]
fn a_stamp_that_changes_a_header_field_is_refused_by_name() {
    let before = dll();
    let (optional, _) = pe_offsets(&before);
    for (at, name) in [
        (optional + 16, "the optional header's AddressOfEntryPoint"),
        (optional + 70, "the optional header's DllCharacteristics"),
        (optional + 24, "the optional header's ImageBase"),
        // The import table's data directory.
        (optional + 112 + 8, "data directory 1 (import table)"),
    ] {
        let mut after = stamp(&before);
        after[at] ^= 0x01;
        let err = refusal(check_stamp(&before, &after));
        assert!(err.ends_with(name), "{name}: {err}");
    }
}

#[test]
fn the_added_section_is_read_only_data_holding_the_resources() {
    let before = dll();
    let stamped = stamp(&before);
    let (header, _) = pe_section(&stamped, ".rsrc");
    // Executable.
    let mut after = stamped.clone();
    after[header + 39] |= 0x20;
    let err = refusal(check_stamp(&before, &after));
    assert!(
        err.contains(r#"the added section ".rsrc" isn't read-only initialized data"#),
        "{err}"
    );
    // Placed over the last original section in memory.
    let mut after = stamped.clone();
    after[header + 12..header + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    let err = refusal(check_stamp(&before, &after));
    assert!(err.contains("doesn't come after section"), "{err}");
    // The resource directory pointing elsewhere.
    let mut after = stamped;
    let (optional, _) = pe_offsets(&after);
    after[optional + 112 + 16..optional + 112 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    let err = refusal(check_stamp(&before, &after));
    assert!(
        err.contains(r#"the resource directory isn't in the added section ".rsrc""#),
        "{err}"
    );
}

#[test]
fn signing_adds_only_a_certificate_table() {
    let stamped = stamp(&dll());
    let signed = sign(&stamped);
    check_sign(&stamped, &signed).expect("only the certificate table added");
    // A sidecar is signed without a stamp: the same rule.
    let sidecar = dll();
    check_sign(&sidecar, &sign(&sidecar)).unwrap();
}

#[test]
fn a_signature_that_changes_more_is_refused() {
    let before = stamp(&dll());
    // A section's data.
    let mut after = sign(&before);
    let (_, data) = pe_section(&after, ".cpureq");
    after[data] ^= 0x01;
    let err = refusal(check_sign(&before, &after));
    assert!(
        err.contains(r#"signing changed what the loader maps: section ".cpureq"'s data"#),
        "{err}"
    );
    // A header field a signer never touches.
    let mut after = sign(&before);
    let (optional, _) = pe_offsets(&after);
    after[optional + 56] ^= 0x01;
    let err = refusal(check_sign(&before, &after));
    assert!(err.ends_with("the optional header's SizeOfImage"), "{err}");
    // No certificate table at all.
    let err = refusal(check_sign(&before, &before));
    assert!(err.ends_with("no certificate table was added"), "{err}");
    // A certificate table over the sections' data.
    let mut after = sign(&before);
    let (_, data) = pe_section(&after, ".cpureq");
    let directory = optional + 112 + 4 * 8;
    after[directory..directory + 4].copy_from_slice(&u32::try_from(data).unwrap().to_le_bytes());
    let err = refusal(check_sign(&before, &after));
    assert!(err.contains("overlaps the loaded data"), "{err}");
    // Past the end of the file.
    let mut after = sign(&before);
    after[directory + 4..directory + 8].copy_from_slice(&0x10_0000u32.to_le_bytes());
    let err = refusal(check_sign(&before, &after));
    assert!(err.ends_with("reaches past the end of the file"), "{err}");
}

#[test]
fn an_unreadable_pe_image_is_refused_as_such() {
    let image = dll();
    let err = refusal(check_stamp(b"MZ but nothing else", &image));
    assert!(
        err.contains("stamping: the original image can't be read"),
        "{err}"
    );
    let err = refusal(check_sign(&image, &image[..0x100]));
    assert!(
        err.contains("signing: the signed image can't be read"),
        "{err}"
    );
}

#[test]
fn a_windows_package_records_each_checked_step_in_layout_json() {
    // The Windows tree's launcher, cores and helper are stamped (no signer
    // here); the sidecar is neither stamped nor signed.
    let dir = tempfile::tempdir().unwrap();
    let config = seaworthy::config::Config::parse(
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.tool]
display-name = "Acme Tool"
description = "A tool."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "tool"
sidecars.windows = ["extra_*.dll"]
outputs = ["zip"]
"#,
    )
    .unwrap();
    let layouts = common::layouts(&config, "tool", dir.path());
    seaworthy::package::package(
        &config,
        "tool",
        &layouts,
        &dir.path().join("dist"),
        &seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm: std::path::PathBuf::from("nfpm"),
            wix: None,
            build: seaworthy::sign::BuildId::default(),
        },
        &seaworthy::package::Signing::default(),
    )
    .expect("packages");
    let windows = common::layout_for(&layouts, WINDOWS);
    let listing: serde_json::Value = serde_json::from_slice(
        &std::fs::read(windows.tree.parent().unwrap().join("layout.json")).unwrap(),
    )
    .unwrap();
    let files = listing["files"].as_array().unwrap();
    assert!(!files.is_empty());
    for file in files {
        let kind = file["role"]["kind"].as_str().unwrap();
        let stamped = matches!(kind, "launcher" | "core" | "helper");
        assert_eq!(
            file.get("stamp").and_then(|v| v.as_str()),
            stamped.then_some(seaworthy::post_link::STAMPED),
            "{file}"
        );
        assert!(file.get("sign").is_none(), "unsigned: {file}");
        assert!(file.get("strip").is_none(), "Windows: {file}");
    }
}
