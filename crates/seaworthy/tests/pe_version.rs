//! The version resource stamped into linked Windows binaries,
//! read back by a resource-tree and `VS_VERSIONINFO` reader written here
//! (independent of the writer), by `object`, by `llvm-readobj` and, for the
//! checksum, by `osslsigncode`. Plus: other resources survive, a second
//! stamp replaces the first, records stay readable, and every refusal.
//!
//! A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::BTreeMap;
use std::process::Command;

use common::{Pe, have, record, run};
use seaworthy::pe_version::{
    LANG_EN_US, RT_MANIFEST, RT_VERSION, VersionInfo, set_resource, stamp_version,
};
use seaworthy::version::Release;

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// (virtual address, virtual size, raw pointer, raw size) per section.
fn sections(pe: &[u8]) -> Vec<(u32, u32, u32, u32)> {
    let header = u32_at(pe, 0x3c) as usize;
    let count = u16_at(pe, header + 6) as usize;
    let optional_size = u16_at(pe, header + 20) as usize;
    let table = header + 24 + optional_size;
    (0..count)
        .map(|i| {
            let at = table + i * 40;
            (
                u32_at(pe, at + 12),
                u32_at(pe, at + 8),
                u32_at(pe, at + 20),
                u32_at(pe, at + 16),
            )
        })
        .collect()
}

fn offset(pe: &[u8], rva: u32) -> usize {
    for (va, vsize, raw, rsize) in sections(pe) {
        if rva >= va && rva < va + vsize.max(rsize) {
            return (raw + rva - va) as usize;
        }
    }
    panic!("RVA {rva:#x} in no section");
}

/// Every resource's data entry: (type, name, language) → (RVA, size,
/// code page).
fn data_entries(pe: &[u8]) -> BTreeMap<(u32, u32, u32), (u32, u32, u32)> {
    let header = u32_at(pe, 0x3c) as usize;
    let directories = header + 24 + 112;
    let (rva, size) = (u32_at(pe, directories + 16), u32_at(pe, directories + 20));
    let mut out = BTreeMap::new();
    if rva == 0 {
        return out;
    }
    assert!(size > 0);
    let base = offset(pe, rva);
    let entries = |dir: usize| -> Vec<(u32, u32)> {
        let n = u16_at(pe, base + dir + 12) as usize + u16_at(pe, base + dir + 14) as usize;
        (0..n)
            .map(|i| {
                (
                    u32_at(pe, base + dir + 16 + i * 8),
                    u32_at(pe, base + dir + 16 + i * 8 + 4),
                )
            })
            .collect()
    };
    for (ty, to_names) in entries(0) {
        assert_ne!(to_names & 0x8000_0000, 0, "type level is a directory");
        for (name, to_langs) in entries((to_names & 0x7fff_ffff) as usize) {
            assert_ne!(to_langs & 0x8000_0000, 0, "name level is a directory");
            for (lang, to_data) in entries((to_langs & 0x7fff_ffff) as usize) {
                assert_eq!(to_data & 0x8000_0000, 0, "language level is data");
                let entry = base + to_data as usize;
                out.insert(
                    (ty, name, lang),
                    (
                        u32_at(pe, entry),
                        u32_at(pe, entry + 4),
                        u32_at(pe, entry + 8),
                    ),
                );
            }
        }
    }
    out
}

/// Every resource: (type, name, language) → data.
fn resources(pe: &[u8]) -> BTreeMap<(u32, u32, u32), Vec<u8>> {
    data_entries(pe)
        .into_iter()
        .map(|(key, (rva, size, _))| {
            let at = offset(pe, rva);
            (key, pe[at..at + size as usize].to_vec())
        })
        .collect()
}

/// A `VS_VERSIONINFO` read back: the fixed file info's words and the
/// string table.
struct Version {
    file_ms: u32,
    file_ls: u32,
    flags: u32,
    file_type: u32,
    strings: BTreeMap<String, String>,
}

fn utf16z(b: &[u8], at: usize) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = at;
    loop {
        let u = u16_at(b, i);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (String::from_utf16(&units).unwrap(), i)
}

fn read_version(blob: &[u8]) -> Version {
    let (key, after) = utf16z(blob, 6);
    assert_eq!(key, "VS_VERSION_INFO");
    assert_eq!(
        u16_at(blob, 0) as usize,
        blob.len(),
        "wLength covers the blob"
    );
    assert_eq!(u16_at(blob, 2), 52);
    let fixed = after.next_multiple_of(4);
    assert_eq!(u32_at(blob, fixed), 0xFEEF_04BD);
    let mut strings = BTreeMap::new();
    // Walk children: StringFileInfo → StringTable → strings.
    let mut at = (fixed + 52).next_multiple_of(4);
    while at < blob.len() {
        let len = u16_at(blob, at) as usize;
        let (key, _) = utf16z(blob, at + 6);
        if key == "StringFileInfo" {
            let (_, table_key_end) = utf16z(blob, at + 6);
            let table = table_key_end.next_multiple_of(4);
            let table_len = u16_at(blob, table) as usize;
            let (lang, table_after) = utf16z(blob, table + 6);
            assert_eq!(lang, "040904B0");
            let mut s = table_after.next_multiple_of(4);
            while s < table + table_len {
                let slen = u16_at(blob, s) as usize;
                let (name, name_end) = utf16z(blob, s + 6);
                let (value, _) = utf16z(blob, name_end.next_multiple_of(4));
                strings.insert(name, value);
                s = (s + slen).next_multiple_of(4);
            }
        }
        at = (at + len).next_multiple_of(4);
    }
    Version {
        file_ms: u32_at(blob, fixed + 8),
        file_ls: u32_at(blob, fixed + 12),
        flags: u32_at(blob, fixed + 28),
        file_type: u32_at(blob, fixed + 36),
        strings,
    }
}

fn core_dll() -> Vec<u8> {
    Pe {
        sections: vec![(
            ".cpureq".into(),
            record("x86_64-pc-windows-msvc", "x86-64-v3", common::V2),
        )],
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build()
}

fn info(file_name: &str, dll: bool) -> VersionInfo<'_> {
    VersionInfo {
        company: "Acme",
        product: "Acme Agent",
        description: "Acme Agent core (x86-64-v3)",
        file_name,
        dll,
    }
}

#[test]
fn the_version_resource_reads_back_exactly() {
    let release = Release::new("1.4.0-rc.2", 812).unwrap();
    let stamped = stamp_version(
        &core_dll(),
        &release,
        &info("acme_core_x86-64-v3.dll", true),
    )
    .unwrap();
    let all = resources(&stamped);
    assert_eq!(all.keys().collect::<Vec<_>>(), [&(16, 1, 0x409)]);
    let v = read_version(&all[&(16, 1, 0x409)]);
    assert_eq!((v.file_ms, v.file_ls), ((1 << 16) | 4, 812));
    assert_eq!(v.flags, 0x2, "a pre-release");
    assert_eq!(v.file_type, 2, "VFT_DLL");
    let strings: Vec<(&str, &str)> = v
        .strings
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(
        strings,
        [
            ("CompanyName", "Acme"),
            ("FileDescription", "Acme Agent core (x86-64-v3)"),
            ("FileVersion", "1.4.0.812"),
            ("InternalName", "acme_core_x86-64-v3"),
            ("OriginalFilename", "acme_core_x86-64-v3.dll"),
            ("ProductName", "Acme Agent"),
            ("ProductVersion", "1.4.0-rc.2"),
        ]
    );
    // A release, an application, and a sequence past 16 bits (clamped).
    let release = Release::new("2.0.1", 70_000).unwrap();
    let app = Pe {
        executable: true,
        ..Pe::default()
    }
    .build();
    let v = read_version(
        &resources(&stamp_version(&app, &release, &info("AcmeTool.exe", false)).unwrap())
            [&(16, 1, 0x409)],
    );
    assert_eq!(
        (v.file_ms, v.file_ls, v.flags, v.file_type),
        ((2 << 16), (1 << 16) | 0xFFFF, 0, 1)
    );
}

#[test]
fn the_image_stays_valid_and_keeps_its_record() {
    let tmp = tempfile::tempdir().unwrap();
    let release = Release::new("1.4.0", 7).unwrap();
    let stamped = stamp_version(&core_dll(), &release, &info("acme_core.dll", true)).unwrap();
    let path = tmp.path().join("acme_core.dll");
    std::fs::write(&path, &stamped).unwrap();
    // object parses it, finds the new section and the resource directory.
    {
        use object::{Object as _, ObjectSection as _};
        let file = object::File::parse(&*stamped).unwrap();
        assert!(
            file.sections().any(|s| s.name() == Ok(".rsrc")),
            "a .rsrc section"
        );
    }
    let requirement = seaworthy_levels::read_requirement(&path).unwrap();
    assert_eq!(requirement.cpu, "x86-64-v3");
    // SizeOfImage covers the new section, rounded to the section alignment.
    let optional = u32_at(&stamped, 0x3c) as usize + 24;
    let alignment = u32_at(&stamped, optional + 32);
    let end = sections(&stamped)
        .iter()
        .map(|s| s.0 + s.1.max(s.3))
        .max()
        .unwrap();
    assert_eq!(
        u32_at(&stamped, optional + 56),
        end.div_ceil(alignment) * alignment
    );
    if have("llvm-readobj", &["--version"]) {
        let out = run(Command::new("llvm-readobj")
            .arg("--coff-resources")
            .arg(&path));
        assert!(out.contains("Type: VERSIONINFO (ID 16)"), "{out}");
        assert!(out.contains("Language: (ID 1033)"), "{out}");
    }
    // The PE checksum is the one Windows computes (osslsigncode recomputes it).
    if have("osslsigncode", &["--version"]) {
        // osslsigncode prints one "PE checksum" line when the stored value
        // is right, and current/calculated lines plus a warning otherwise.
        let out = Command::new("osslsigncode")
            .arg("verify")
            .arg("-in")
            .arg(&path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned()
            + &String::from_utf8_lossy(&out.stderr);
        assert!(text.lines().any(|l| l.starts_with("PE checksum")), "{text}");
        assert!(!text.contains("invalid PE checksum"), "{text}");
    }
}

#[test]
fn other_resources_survive_and_a_second_stamp_replaces_the_first() {
    let manifest =
        b"<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"/>".to_vec();
    let with_manifest = set_resource(&core_dll(), RT_MANIFEST, 1, LANG_EN_US, &manifest).unwrap();
    let once = stamp_version(
        &with_manifest,
        &Release::new("1.0.0", 1).unwrap(),
        &info("a.dll", true),
    )
    .unwrap();
    let twice = stamp_version(
        &once,
        &Release::new("1.1.0", 2).unwrap(),
        &info("a.dll", true),
    )
    .unwrap();
    let all = resources(&twice);
    assert_eq!(
        all.keys().collect::<Vec<_>>(),
        [&(16, 1, 0x409), &(24, 1, 0x409)]
    );
    assert_eq!(all[&(24, 1, 0x409)], manifest, "the manifest is untouched");
    let v = read_version(&all[&(16, 1, 0x409)]);
    assert_eq!(v.strings["FileVersion"], "1.1.0.2");
    assert_self_contained(&once);
    assert_self_contained(&twice);
    let _ = RT_VERSION;
}

/// Every data entry lies inside the resource data directory's range: the
/// tree and its data in one place, as a linker lays them out. Windows
/// refused to start a launcher stamped with its manifest and icons left in
/// the linker's `.rsrc` ("not a valid Win32 application").
fn assert_self_contained(pe: &[u8]) {
    let dir = resource_directory(pe);
    let (rva, size) = (u32_at(pe, dir), u32_at(pe, dir + 4));
    let entries = data_entries(pe);
    assert!(!entries.is_empty(), "resources to check");
    for (key, (data, len, _)) in entries {
        assert!(
            data >= rva && data + len <= rva + size,
            "{key:?} at {data:#x}+{len:#x} is outside the directory {rva:#x}+{size:#x}"
        );
    }
}

/// Every section's name.
fn section_names(pe: &[u8]) -> Vec<String> {
    let header = u32_at(pe, 0x3c) as usize;
    let table = header + 24 + u16_at(pe, header + 20) as usize;
    (0..u16_at(pe, header + 6) as usize)
        .map(|i| {
            String::from_utf8_lossy(&pe[table + i * 40..table + i * 40 + 8])
                .trim_end_matches('\0')
                .to_owned()
        })
        .collect()
}

/// The section header offset of the section at `va`.
fn section_header(pe: &[u8], va: u32) -> usize {
    let header = u32_at(pe, 0x3c) as usize;
    let table = header + 24 + u16_at(pe, header + 20) as usize;
    let index = sections(pe).iter().position(|s| s.0 == va).unwrap();
    table + index * 40
}

fn put32(pe: &mut [u8], at: usize, value: u32) {
    pe[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// The resource data directory's offset in the headers.
fn resource_directory(pe: &[u8]) -> usize {
    u32_at(pe, 0x3c) as usize + 24 + 112 + 2 * 8
}

#[test]
fn the_trailing_resource_section_is_rewritten_in_place_only_when_that_is_safe() {
    let release = Release::new("1.0.0", 1).unwrap();
    let stamp = |pe: &[u8]| stamp_version(pe, &release, &info("a.dll", true));
    let small = b"<assembly/>".to_vec();
    // `.idata` plus a small trailing `.rsrc` (one file-alignment block
    // each), with header room for one more section.
    let plain = Pe {
        sections: Vec::new(),
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build();
    let base = set_resource(&plain, RT_MANIFEST, 1, LANG_EN_US, &small).unwrap();
    let rsrc_va = u32_at(&base, resource_directory(&base));
    let count = sections(&base).len();
    let data_start = sections(&base).iter().map(|s| s.2 as usize).min().unwrap();
    // Safe: the section is rewritten, no header slot used, data carried.
    let in_place = stamp(&base).unwrap();
    assert_eq!(sections(&in_place).len(), count, "rewritten in place");
    assert_eq!(resources(&in_place)[&(24, 1, 0x409)], small);
    // Code in the section: a new section instead, the old one untouched.
    let mut code = base.clone();
    let at = section_header(&code, rsrc_va) + 36;
    let characteristics = u32_at(&code, at) | 0x2000_0020;
    put32(&mut code, at, characteristics);
    let out = stamp(&code).unwrap();
    assert_eq!(
        sections(&out).len(),
        count + 1,
        "never rewrite a section holding code"
    );
    assert_eq!(
        section_names(&out),
        [".idata", ".rsrc", ".rsrcv"],
        "a second, distinct name"
    );
    assert_eq!(
        &out[data_start..code.len()],
        &code[data_start..],
        "every old section's bytes kept"
    );
    assert_eq!(resources(&out)[&(24, 1, 0x409)], small);
    assert_self_contained(&out);
    // That used the last free header slot: with the new section marked as
    // code too, there's nowhere left to put the tree.
    let mut full = out.clone();
    let new_va = u32_at(&full, resource_directory(&full));
    let at = section_header(&full, new_va) + 36;
    let characteristics = u32_at(&full, at) | 0x2000_0020;
    put32(&mut full, at, characteristics);
    let err = stamp(&full).unwrap_err().to_string();
    assert!(err.contains("no room for another section header"), "{err}");
    // Another data directory (debug) pointing into it: a new section too.
    let mut shared = base.clone();
    let debug = u32_at(&shared, 0x3c) as usize + 24 + 112 + 6 * 8;
    put32(&mut shared, debug, rsrc_va + 0x10);
    put32(&mut shared, debug + 4, 0x10);
    assert_eq!(
        sections(&stamp(&shared).unwrap()).len(),
        count + 1,
        "never rewrite a shared section"
    );
    // ... also when the directory starts before the section and runs into it.
    put32(&mut shared, debug, rsrc_va - 0x10);
    put32(&mut shared, debug + 4, 0x20);
    assert_eq!(
        sections(&stamp(&shared).unwrap()).len(),
        count + 1,
        "an overlap is a share"
    );
    // Last in memory but not in the file (its raw block swapped with
    // `.idata`'s): the rewrite would truncate `.idata`, so a new section.
    let mut swapped = base.clone();
    let idata = sections(&swapped)
        .into_iter()
        .find(|s| s.0 != rsrc_va)
        .unwrap();
    let rsrc = sections(&swapped)
        .into_iter()
        .find(|s| s.0 == rsrc_va)
        .unwrap();
    assert_eq!(
        (idata.3, rsrc.3),
        (0x200, 0x200),
        "equal raw blocks to swap"
    );
    let (a, b) = (idata.2 as usize, rsrc.2 as usize);
    let block_a = swapped[a..a + 0x200].to_vec();
    let block_b = swapped[b..b + 0x200].to_vec();
    swapped[a..a + 0x200].copy_from_slice(&block_b);
    swapped[b..b + 0x200].copy_from_slice(&block_a);
    let (ha, hb) = (
        section_header(&swapped, idata.0),
        section_header(&swapped, rsrc_va),
    );
    put32(&mut swapped, ha + 20, b as u32);
    put32(&mut swapped, hb + 20, a as u32);
    let out = stamp(&swapped).unwrap();
    assert_eq!(sections(&out).len(), count + 1, "not rewritten in place");
    assert_eq!(&out[b..b + 0x200], &block_a, ".idata's bytes survive");
    assert_eq!(resources(&out)[&(24, 1, 0x409)], small);
    // Only a resource section is rewritten: a writable one, one
    // not named `.rsrc`, or one whose directory doesn't start it may hold
    // other data, which a rewrite would drop.
    let header = section_header(&base, rsrc_va);
    let mut writable = base.clone();
    let characteristics = u32_at(&writable, header + 36) | 0x8000_0000;
    put32(&mut writable, header + 36, characteristics);
    let mut renamed = base.clone();
    renamed[header..header + 8].copy_from_slice(b".data\0\0\0");
    let mut offset_dir = base.clone();
    let dir = resource_directory(&offset_dir);
    // The tree's own offsets are relative to the directory's start: moving
    // the directory 16 bytes in needs a tree that starts there, so build one.
    let mut moved = vec![0u8; 16];
    let tree = offset(&base, rsrc_va);
    let len = u32_at(&base, dir + 4) as usize;
    moved.extend_from_slice(&base[tree..tree + len]);
    offset_dir[tree..tree + moved.len()].copy_from_slice(&moved);
    put32(&mut offset_dir, dir, rsrc_va + 16);
    for (what, image) in [
        ("writable", &writable),
        ("renamed", &renamed),
        ("offset", &offset_dir),
    ] {
        let out = stamp(image).unwrap();
        assert_eq!(sections(&out).len(), count + 1, "{what}: a new section");
        assert_eq!(
            &out[data_start..image.len()],
            &image[data_start..],
            "{what}: the old bytes kept"
        );
    }
    // A resource directory of size 0 names no resources: the section it
    // points into may hold anything, so it's never rewritten.
    let mut unnamed = base.clone();
    let dir = resource_directory(&unnamed);
    put32(&mut unnamed, dir + 4, 0);
    let out = stamp(&unnamed).unwrap();
    assert_eq!(sections(&out).len(), count + 1, "a new section");
    assert_eq!(
        &out[data_start..unnamed.len()],
        &unnamed[data_start..],
        "the old section's bytes kept"
    );
    // An empty resource directory in a section with no file data: never
    // "rewritten" at file offset 0.
    let mut empty = base[..rsrc.2 as usize].to_vec();
    let h = section_header(&empty, rsrc_va);
    put32(&mut empty, h + 16, 0);
    put32(&mut empty, h + 20, 0);
    let dir = resource_directory(&empty);
    put32(&mut empty, dir + 4, 0);
    let out = stamp(&empty).unwrap();
    assert_eq!(&out[..2], b"MZ");
    assert_eq!(sections(&out).len(), count + 1);
    object::File::parse(&*out).unwrap();
    // Resource data past the image's last section: refused (there's nothing
    // to copy into the new tree). The tree is root → type → name → language
    // → data entry; follow the first entry at each level.
    let mut dangling = base.clone();
    let tree = offset(&dangling, rsrc_va);
    let mut at = tree;
    for _ in 0..3 {
        at = tree + (u32_at(&dangling, at + 16 + 4) & 0x7fff_ffff) as usize;
    }
    put32(&mut dangling, at, 0x0100_0000);
    let err = stamp(&dangling).unwrap_err().to_string();
    assert!(err.contains("within one section's file data"), "{err}");
    // Resource data running from `.idata`'s file data past its end: its
    // tail would be another section's bytes, or none.
    let mut straddling = base.clone();
    put32(&mut straddling, at, idata.0 + idata.3 - 4);
    let err = stamp(&straddling).unwrap_err().to_string();
    assert!(err.contains("within one section's file data"), "{err}");
}

#[test]
fn carried_over_resources_keep_their_code_page_and_empty_ones_stay_in_the_section() {
    // Found by `dist_pe`: a zero-length resource carried over pointed at the
    // tree's end, past the section's virtual size; and a carried-over
    // resource lost its code page.
    let plain = Pe {
        sections: Vec::new(),
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build();
    let one = set_resource(&plain, RT_MANIFEST, 1, LANG_EN_US, b"<assembly/>").unwrap();
    let mut base = set_resource(&one, RT_MANIFEST, 2, LANG_EN_US, b"").unwrap();
    let (rva, _, _) = data_entries(&base)[&(24, 1, 0x409)];
    // Patch the manifest's code page to 1252 in its data entry.
    let rsrc_va = u32_at(&base, resource_directory(&base));
    let tree = offset(&base, rsrc_va);
    let entry = (0..base.len() - 16)
        .step_by(4)
        .find(|at| *at >= tree && u32_at(&base, *at) == rva && u32_at(&base, *at + 4) == 11)
        .unwrap();
    put32(&mut base, entry + 8, 1252);
    let stamped = stamp_version(
        &base,
        &Release::new("1.0.0", 1).unwrap(),
        &info("a.dll", true),
    )
    .unwrap();
    assert_eq!(
        sections(&stamped).len(),
        sections(&base).len(),
        "rewritten in place (carried over)"
    );
    let entries = data_entries(&stamped);
    assert_eq!(entries[&(24, 1, 0x409)].2, 1252, "the code page survives");
    let (empty_rva, empty_size, _) = entries[&(24, 2, 0x409)];
    assert_eq!(empty_size, 0);
    let (va, virtual_size, _, _) = sections(&stamped)
        .into_iter()
        .find(|s| s.0 == rsrc_va)
        .unwrap();
    assert!(
        empty_rva >= va && empty_rva < va + virtual_size,
        "{empty_rva:#x} inside {va:#x}+{virtual_size:#x}"
    );
}

#[test]
fn a_resource_tree_listing_a_key_twice_is_refused() {
    // Found by `dist_pe`: with a second type-16 directory, the old version
    // resource stayed in force beside the new one.
    let plain = Pe {
        sections: Vec::new(),
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build();
    let two = set_resource(
        &set_resource(&plain, RT_VERSION, 1, LANG_EN_US, b"old").unwrap(),
        RT_MANIFEST,
        1,
        LANG_EN_US,
        b"<assembly/>",
    )
    .unwrap();
    let tree = offset(&two, u32_at(&two, resource_directory(&two)));
    assert_eq!(
        (u32_at(&two, tree + 16), u32_at(&two, tree + 24)),
        (16, 24),
        "the root lists types 16 and 24"
    );
    let mut twice = two.clone();
    put32(&mut twice, tree + 24, 16);
    let err = stamp_version(
        &twice,
        &Release::new("1.0.0", 1).unwrap(),
        &info("a.dll", true),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("lists one key twice"), "{err}");
    // An id past 16 bits is the same key to Windows (it reads the low word).
    let mut wide = two.clone();
    put32(&mut wide, tree + 16, 0x0001_0010);
    let err = stamp_version(
        &wide,
        &Release::new("1.0.0", 1).unwrap(),
        &info("a.dll", true),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("past 16 bits"), "{err}");
}

/// Every resource by `object`'s own reader: (type, name, language), ids
/// spelled `#<id>`, to (bytes, code page).
fn object_resources(pe: &[u8]) -> BTreeMap<(String, String, String), (Vec<u8>, u32)> {
    use object::LittleEndian as LE;
    use object::read::pe::{PeFile64, ResourceDirectoryEntryData, ResourceNameOrId};
    let file = PeFile64::parse(pe).unwrap();
    let sections = file.section_table();
    let directory = file
        .data_directories()
        .resource_directory(pe, &sections)
        .unwrap()
        .unwrap();
    let key = |entry: &object::pe::ImageResourceDirectoryEntry| match entry.name_or_id() {
        ResourceNameOrId::Id(id) => format!("#{id}"),
        ResourceNameOrId::Name(name) => name.to_string_lossy(directory).unwrap(),
    };
    let mut out = BTreeMap::new();
    for kind in directory.root().unwrap().entries {
        let ResourceDirectoryEntryData::Table(names) = kind.data(directory).unwrap() else {
            panic!("a type is a table")
        };
        for name in names.entries {
            let ResourceDirectoryEntryData::Table(languages) = name.data(directory).unwrap() else {
                panic!("a name is a table")
            };
            for language in languages.entries {
                let ResourceDirectoryEntryData::Data(entry) = language.data(directory).unwrap()
                else {
                    panic!("a language is data")
                };
                let bytes = sections
                    .pe_data_at(pe, entry.offset_to_data.get(LE))
                    .unwrap()[..entry.size.get(LE) as usize]
                    .to_vec();
                out.insert(
                    (key(kind), key(name), key(language)),
                    (bytes, entry.code_page.get(LE)),
                );
            }
        }
    }
    out
}

#[test]
fn a_real_linkers_resources_survive_stamping() {
    // An image lld laid out, with llvm-rc's resources (string
    // tables in two languages, a named RCDATA, a manifest), not one the
    // tests' own PE writer made.
    if !have("llvm-rc", &["/?"]) {
        return;
    }
    let sysroot = run(Command::new("rustc").args(["--print", "sysroot"]));
    let lld = std::path::Path::new(sysroot.trim())
        .join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
    if !have(&lld.to_string_lossy(), &["-flavor", "link", "--version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("app.manifest"),
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"/>",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("r.rc"),
        "1 24 \"app.manifest\"\nSTRINGTABLE\nBEGIN\n  1 \"first\"\n  2 \"second\"\nEND\n\
         LANGUAGE 0x07, 0x01\nSTRINGTABLE\nBEGIN\n  1 \"erste\"\nEND\n\
         LANGUAGE 0x09, 0x01\nNAMED RCDATA { \"named data\" }\n",
    )
    .unwrap();
    run(Command::new("llvm-rc").current_dir(tmp.path()).args([
        "-no-preprocess",
        "-fo",
        "r.res",
        "r.rc",
    ]));
    run(Command::new(&lld).current_dir(tmp.path()).args([
        "-flavor",
        "link",
        "/dll",
        "/noentry",
        "/machine:x64",
        "/out:t.dll",
        "r.res",
    ]));
    let dll = std::fs::read(tmp.path().join("t.dll")).unwrap();
    let before = object_resources(&dll);
    assert!(before.len() >= 4, "{:?}", before.keys());
    assert!(
        before.keys().any(|(_, name, _)| name == "NAMED"),
        "a named resource"
    );
    let release = Release::new("1.4.0", 3).unwrap();
    let stamped = stamp_version(&dll, &release, &info("t.dll", true)).unwrap();
    let mut after = object_resources(&stamped);
    let (blob, codepage) = after
        .remove(&("#16".into(), "#1".into(), "#1033".into()))
        .expect("a version resource");
    assert_eq!(
        (
            read_version(&blob).strings["FileVersion"].as_str(),
            codepage
        ),
        ("1.4.0.3", 0)
    );
    assert_eq!(
        after, before,
        "every other resource intact, code pages included"
    );
    assert_eq!(
        stamp_version(&stamped, &release, &info("t.dll", true)).unwrap(),
        stamped,
        "a fixed point"
    );
    let path = tmp.path().join("stamped.dll");
    std::fs::write(&path, &stamped).unwrap();
    if have("llvm-readobj", &["--version"]) {
        let out = run(Command::new("llvm-readobj")
            .arg("--coff-resources")
            .arg(&path));
        for expected in [
            "VERSIONINFO (ID 16)",
            "STRINGTABLE (ID 6)",
            "Name: NAMED",
            "MANIFEST (ID 24)",
        ] {
            assert!(out.contains(expected), "{expected}: {out}");
        }
    }
}

#[test]
fn a_launchers_resources_before_its_relocations_move_into_the_new_tree() {
    // The collector's launcher: an executable whose linker `.rsrc` (a UAC
    // manifest, an icon) sits before `.reloc`, so the tree goes into a new
    // section. Its data used to stay behind in `.rsrc`, outside the new
    // resource directory, and Windows refused to start the image (error
    // 193); Wine ran it.
    if !have("llvm-rc", &["/?"]) || !have("llvm-mc", &["--version"]) {
        return;
    }
    let sysroot = run(Command::new("rustc").args(["--print", "sysroot"]));
    let lld = std::path::Path::new(sysroot.trim())
        .join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
    if !have(&lld.to_string_lossy(), &["-flavor", "link", "--version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // Code, and a pointer to it: an absolute address, so a `.reloc` section.
    std::fs::write(
        tmp.path().join("main.s"),
        ".text\n.globl main\nmain:\n  xorl %eax, %eax\n  retq\n.data\nptr:\n  .quad main\n",
    )
    .unwrap();
    run(Command::new("llvm-mc").current_dir(tmp.path()).args([
        "-triple=x86_64-pc-windows-msvc",
        "-filetype=obj",
        "-o",
        "main.obj",
        "main.s",
    ]));
    // A 1x1 32-bit icon: the directory, one entry, the DIB (header, colour,
    // mask).
    let mut ico = Vec::new();
    for word in [0u16, 1, 1] {
        ico.extend_from_slice(&word.to_le_bytes());
    }
    ico.extend_from_slice(&[1, 1, 0, 0, 1, 0, 32, 0]);
    ico.extend_from_slice(&48u32.to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    for value in [40u32, 1, 2] {
        ico.extend_from_slice(&value.to_le_bytes());
    }
    ico.extend_from_slice(&[1, 0, 32, 0]);
    ico.extend_from_slice(&[0u8; 24]);
    ico.extend_from_slice(&[0x20, 0x40, 0x80, 0xff]);
    ico.extend_from_slice(&[0u8; 4]);
    std::fs::write(tmp.path().join("app.ico"), &ico).unwrap();
    std::fs::write(
        tmp.path().join("app.manifest"),
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\
         <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>\
         <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>\
         </requestedPrivileges></security></trustInfo></assembly>",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("r.rc"),
        "LANGUAGE 0x09, 0x01\n1 ICON \"app.ico\"\n1 24 \"app.manifest\"\n",
    )
    .unwrap();
    run(Command::new("llvm-rc").current_dir(tmp.path()).args([
        "-no-preprocess",
        "-fo",
        "r.res",
        "r.rc",
    ]));
    run(Command::new(&lld).current_dir(tmp.path()).args([
        "-flavor",
        "link",
        "/entry:main",
        "/subsystem:console",
        "/machine:x64",
        "/out:app.exe",
        "main.obj",
        "r.res",
    ]));
    let exe = std::fs::read(tmp.path().join("app.exe")).unwrap();
    assert!(
        section_names(&exe).ends_with(&[".rsrc".to_owned(), ".reloc".to_owned()]),
        "the launcher's layout: {:?}",
        section_names(&exe)
    );
    let before = object_resources(&exe);
    assert!(
        before.contains_key(&("#24".into(), "#1".into(), "#1033".into()))
            && before.contains_key(&("#3".into(), "#1".into(), "#1033".into()))
            && before.contains_key(&("#14".into(), "#1".into(), "#1033".into())),
        "a manifest, an icon and its group: {:?}",
        before.keys()
    );
    let release = Release::new("1.0.0-beta.3", 7).unwrap();
    let stamped = stamp_version(&exe, &release, &info("AcmeForensicCollector.exe", false)).unwrap();
    assert_eq!(
        section_names(&stamped),
        [section_names(&exe), vec![".rsrcv".to_owned()]].concat(),
        "a new section after .reloc"
    );
    assert_self_contained(&stamped);
    let mut after = object_resources(&stamped);
    let (blob, _) = after
        .remove(&("#16".into(), "#1".into(), "#1033".into()))
        .expect("a version resource");
    assert_eq!(
        read_version(&blob).strings["ProductVersion"],
        "1.0.0-beta.3"
    );
    assert_eq!(after, before, "the manifest and icon intact");
    // The relocations and the old section's bytes stay where the linker put
    // them.
    let reloc = u32_at(&exe, 0x3c) as usize + 24 + 112 + 5 * 8;
    assert_eq!(stamped[reloc..reloc + 8], exe[reloc..reloc + 8]);
    let first = sections(&exe).iter().map(|s| s.2 as usize).min().unwrap();
    assert_eq!(&stamped[first..exe.len()], &exe[first..]);
    assert_eq!(
        stamp_version(
            &stamped,
            &release,
            &info("AcmeForensicCollector.exe", false)
        )
        .unwrap(),
        stamped,
        "a fixed point"
    );
}

#[test]
fn images_it_cannot_edit_safely_are_refused() {
    let release = Release::new("1.0.0", 1).unwrap();
    let stamp = |pe: &[u8]| {
        stamp_version(pe, &release, &info("a.dll", true))
            .map(|_| ())
            .unwrap_err()
            .to_string()
    };
    // Not PE.
    assert!(stamp(b"\x7fELF not a pe").contains("not a PE image"));
    // Already signed: a certificate table.
    let mut signed = core_dll();
    let header = u32_at(&signed, 0x3c) as usize;
    let security = header + 24 + 112 + 4 * 8;
    signed[security..security + 4].copy_from_slice(&0x2000u32.to_le_bytes());
    signed[security + 4..security + 8].copy_from_slice(&0x10u32.to_le_bytes());
    assert!(
        stamp(&signed).contains("Authenticode-signed"),
        "{}",
        stamp(&signed)
    );
    // Data after the last section.
    let mut overlay = core_dll();
    overlay.extend_from_slice(b"trailing");
    assert!(stamp(&overlay).contains("data after its last section"));
    // Data directories past the optional header (found by the `dist_pe`
    // fuzz target): more than 16, or more than SizeOfOptionalHeader holds.
    for (count, optional_size) in [(17u32, 240u16), (16, 200), (5, 100)] {
        let mut bad = core_dll();
        let coff = u32_at(&bad, 0x3c) as usize + 4;
        bad[coff + 16..coff + 18].copy_from_slice(&optional_size.to_le_bytes());
        bad[coff + 20 + 108..coff + 20 + 112].copy_from_slice(&count.to_le_bytes());
        assert!(
            stamp(&bad).contains("don't fit the optional header"),
            "{count}/{optional_size}: {}",
            stamp(&bad)
        );
    }
    // Alignments outside the format's rules, and overlapping sections
    // (found by `dist_pe`).
    // (FileAlignment, SectionAlignment): past 64 KiB and below 512 B with
    // an otherwise consistent pair, not a power of two, and a section
    // alignment below the file alignment.
    for (file_alignment, section_alignment) in [
        (0x10_0000u32, 0x200_0000u32),
        (0x100, 0x1000),
        (0x300, 0x1000),
        (0x200, 0x100),
    ] {
        let mut aligned = core_dll();
        let optional = u32_at(&aligned, 0x3c) as usize + 24;
        aligned[optional + 36..optional + 40].copy_from_slice(&file_alignment.to_le_bytes());
        aligned[optional + 32..optional + 36].copy_from_slice(&section_alignment.to_le_bytes());
        let err = stamp(&aligned);
        assert!(
            err.contains("alignment outside"),
            "{file_alignment:#x}/{section_alignment:#x}: {err}"
        );
    }
    let mut overlapping = core_dll();
    let header = u32_at(&overlapping, 0x3c) as usize;
    let first = header + 24 + 240;
    overlapping[first + 8..first + 12].copy_from_slice(&0x40_0000u32.to_le_bytes());
    assert!(
        stamp(&overlapping).contains("overlap in memory"),
        "{}",
        stamp(&overlapping)
    );
    // SizeOfHeaders past the first section's data (found by `dist_pe`).
    let mut headers = core_dll();
    let optional = u32_at(&headers, 0x3c) as usize + 24;
    headers[optional + 60..optional + 64].copy_from_slice(&0xfeffu32.to_le_bytes());
    assert!(
        stamp(&headers).contains("SizeOfHeaders reaches into"),
        "{}",
        stamp(&headers)
    );
    // A COFF symbol table (an object file's leftovers; its data would sit
    // where the new section goes).
    let mut symbols = core_dll();
    let coff = u32_at(&symbols, 0x3c) as usize + 4;
    symbols[coff + 8..coff + 12].copy_from_slice(&0x400u32.to_le_bytes());
    assert!(
        stamp(&symbols).contains("COFF symbol table"),
        "{}",
        stamp(&symbols)
    );
    // A data directory reaching past the last section (found by the
    // `dist_pe` fuzz target): the new section would land under it.
    let mut dangling = core_dll();
    let debug = u32_at(&dangling, 0x3c) as usize + 24 + 112 + 6 * 8;
    dangling[debug..debug + 4].copy_from_slice(&0x0010_0000u32.to_le_bytes());
    dangling[debug + 4..debug + 8].copy_from_slice(&0x10u32.to_le_bytes());
    assert!(
        stamp(&dangling).contains("reaches past the image's last section"),
        "{}",
        stamp(&dangling)
    );
    // A 32-bit image.
    let mut pe32 = core_dll();
    let optional = u32_at(&pe32, 0x3c) as usize + 24;
    pe32[optional..optional + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    assert!(stamp(&pe32).contains("not PE32+"));
}
