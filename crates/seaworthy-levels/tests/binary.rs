//! Reading `.cpureq` and `.cpulist` out of real object files: ELF, PE and
//! Mach-O images (written by small hand-rolled builders below), read back
//! from memory and from disk (through the read cache), plus every refusal.
//!
//! The builders are hand-written on purpose: `object`'s writer features
//! would join the workspace's resolved dependency graph — and every crate's
//! SBOM — for test code alone.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use seaworthy_levels::{
    BinaryError, CPULIST_SECTION, RECORD_SECTION, cpu_list_from_bytes, read_cpu_list,
    read_requirement, requirement_from_bytes,
};

const RECORD: &[u8] = b"seaworthy-cpureq:1\ntarget=x86_64-unknown-linux-gnu\ncpu=x86-64-v3\nfeatures=avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave\n";
const CPULIST: &[u8] = b"seaworthy-cpulist:1\ncore=demo_core\ncpus=x86-64-v4,x86-64-v3,x86-64-v2\n";

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn put64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn n32(value: usize) -> u32 {
    u32::try_from(value).unwrap()
}
fn n64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

/// An ELF64 shared object (x86-64) carrying `sections` (name, bytes) as
/// allocated PROGBITS, plus `.shstrtab`.
fn elf(sections: &[(&str, &[u8])]) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut names = Vec::new();
    for (name, _) in sections {
        names.push(n32(shstrtab.len()));
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = n32(shstrtab.len());
    shstrtab.extend_from_slice(b".shstrtab\0");
    let mut body = Vec::new();
    let mut offsets = Vec::new();
    for (_, bytes) in sections {
        offsets.push(64 + body.len());
        body.extend_from_slice(bytes);
    }
    let shstrtab_offset = 64 + body.len();
    let shoff = (shstrtab_offset + shstrtab.len()).next_multiple_of(8);
    let count = sections.len() + 2; // null, the sections, .shstrtab
    let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    put16(&mut out, 3); // ET_DYN
    put16(&mut out, 62); // EM_X86_64
    put32(&mut out, 1); // EV_CURRENT
    put64(&mut out, 0); // e_entry
    put64(&mut out, 0); // e_phoff
    put64(&mut out, n64(shoff));
    put32(&mut out, 0); // e_flags
    put16(&mut out, 64); // e_ehsize
    put16(&mut out, 56); // e_phentsize
    put16(&mut out, 0); // e_phnum
    put16(&mut out, 64); // e_shentsize
    put16(&mut out, u16::try_from(count).unwrap());
    put16(&mut out, u16::try_from(count - 1).unwrap()); // e_shstrndx
    out.extend_from_slice(&body);
    out.extend_from_slice(&shstrtab);
    out.resize(shoff, 0);
    let mut header = |name: u32, kind: u32, flags: u64, offset: usize, size: usize| {
        put32(&mut out, name);
        put32(&mut out, kind);
        put64(&mut out, flags);
        put64(&mut out, 0); // sh_addr
        put64(&mut out, n64(offset));
        put64(&mut out, n64(size));
        put32(&mut out, 0); // sh_link
        put32(&mut out, 0); // sh_info
        put64(&mut out, 1); // sh_addralign
        put64(&mut out, 0); // sh_entsize
    };
    header(0, 0, 0, 0, 0);
    for ((offset, (_, bytes)), name) in offsets.iter().zip(sections).zip(&names) {
        header(*name, 1, 2, *offset, bytes.len()); // PROGBITS, SHF_ALLOC
    }
    header(shstrtab_name, 3, 0, shstrtab_offset, shstrtab.len()); // STRTAB
    out
}

/// A COFF object (what a compiler emits before linking): not an image a
/// launcher loads.
fn coff(section: &str, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put16(&mut out, 0x8664); // AMD64
    put16(&mut out, 1); // one section
    put32(&mut out, 0); // timestamp
    put32(&mut out, 0); // symbol table
    put32(&mut out, 0); // symbols
    put16(&mut out, 0); // no optional header
    put16(&mut out, 0); // characteristics
    let mut name = [0u8; 8];
    name[..section.len()].copy_from_slice(section.as_bytes());
    out.extend_from_slice(&name);
    put32(&mut out, 0); // virtual size
    put32(&mut out, 0); // virtual address
    put32(&mut out, n32(bytes.len()));
    put32(&mut out, 20 + 40); // raw data follows the table
    put32(&mut out, 0);
    put32(&mut out, 0);
    put16(&mut out, 0);
    put16(&mut out, 0);
    put32(&mut out, 0x4000_0040); // initialized data, readable
    out.extend_from_slice(bytes);
    out
}

/// A PE32+ DLL image with one data section per entry, each section's raw
/// data padded to the 512-byte file alignment as a linker pads it.
fn pe(sections: &[(&str, &[u8])]) -> Vec<u8> {
    const FILE_ALIGN: usize = 0x200;
    const SECTION_ALIGN: usize = 0x1000;
    const PE_AT: usize = 0x80;
    let headers = (PE_AT + 4 + 20 + 240 + 40 * sections.len()).next_multiple_of(FILE_ALIGN);
    let mut layout = Vec::new(); // (file offset, raw size, rva)
    let (mut offset, mut rva) = (headers, SECTION_ALIGN);
    for (_, bytes) in sections {
        let raw = bytes.len().next_multiple_of(FILE_ALIGN);
        layout.push((offset, raw, rva));
        offset += raw;
        rva += bytes.len().max(1).next_multiple_of(SECTION_ALIGN);
    }
    let mut out = vec![0u8; PE_AT];
    out[..2].copy_from_slice(b"MZ");
    out[0x3c..0x40].copy_from_slice(&n32(PE_AT).to_le_bytes());
    out.extend_from_slice(b"PE\0\0");
    put16(&mut out, 0x8664); // AMD64
    put16(&mut out, u16::try_from(sections.len()).unwrap());
    put32(&mut out, 0); // timestamp
    put32(&mut out, 0); // symbol table
    put32(&mut out, 0); // symbols
    put16(&mut out, 240); // PE32+ optional header size
    put16(&mut out, 0x2022); // executable image, large address aware, DLL
    put16(&mut out, 0x20b); // PE32+
    out.extend_from_slice(&[14, 0]); // linker version
    for _ in 0..5 {
        put32(&mut out, 0); // code / data sizes, entry point, base of code
    }
    put64(&mut out, 0x1_8000_0000); // image base
    put32(&mut out, n32(SECTION_ALIGN));
    put32(&mut out, n32(FILE_ALIGN));
    for _ in 0..6 {
        put16(&mut out, 6); // OS, image and subsystem versions
    }
    put32(&mut out, 0); // Win32 version
    put32(&mut out, n32(rva)); // size of image
    put32(&mut out, n32(headers)); // size of headers
    put32(&mut out, 0); // checksum
    put16(&mut out, 3); // console subsystem
    put16(&mut out, 0x0140); // dynamic base, NX compatible
    for value in [0x10_0000u64, 0x1000, 0x10_0000, 0x1000] {
        put64(&mut out, value); // stack and heap reserve / commit
    }
    put32(&mut out, 0); // loader flags
    put32(&mut out, 16); // data directories
    out.extend_from_slice(&[0; 16 * 8]);
    for ((name, bytes), (file_offset, raw, address)) in sections.iter().zip(&layout) {
        let mut short = [0u8; 8];
        short[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&short);
        put32(&mut out, n32(bytes.len())); // virtual size
        put32(&mut out, n32(*address));
        put32(&mut out, n32(*raw));
        put32(&mut out, n32(*file_offset));
        put32(&mut out, 0);
        put32(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put32(&mut out, 0x4000_0040); // initialized data, readable
    }
    out.resize(headers, 0);
    for ((_, bytes), (_, raw, _)) in sections.iter().zip(&layout) {
        let start = out.len();
        out.extend_from_slice(bytes);
        out.resize(start + raw, 0);
    }
    out
}

/// A 64-bit Mach-O dylib (arm64) carrying `sections` (segment, section,
/// bytes): one `LC_SEGMENT_64` per segment, in first-seen order, then an
/// empty `__LINKEDIT`, as every real Mach-O has (a segment with no sections:
/// object needs its `unaligned` feature to parse one).
fn macho(sections: &[(&str, &str, &[u8])]) -> Vec<u8> {
    fn name16(out: &mut Vec<u8>, name: &str) {
        let mut field = [0u8; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
    }
    let mut segments: Vec<&str> = Vec::new();
    for (segment, _, _) in sections {
        if !segments.contains(segment) {
            segments.push(segment);
        }
    }
    let commands_size: usize = segments
        .iter()
        .map(|segment| 72 + 80 * sections.iter().filter(|(s, _, _)| s == segment).count())
        .sum::<usize>()
        + 72;
    let header_size = 32 + commands_size;
    let mut out = Vec::new();
    put32(&mut out, 0xfeed_facf); // MH_MAGIC_64
    put32(&mut out, 0x0100_000c); // CPU_TYPE_ARM64
    put32(&mut out, 0); // CPU_SUBTYPE_ARM64_ALL
    put32(&mut out, 6); // MH_DYLIB
    put32(&mut out, n32(segments.len() + 1));
    put32(&mut out, n32(commands_size));
    put32(&mut out, 0); // flags
    put32(&mut out, 0); // reserved
    let mut data = Vec::new();
    for segment in &segments {
        let members: Vec<&(&str, &str, &[u8])> =
            sections.iter().filter(|(s, _, _)| s == segment).collect();
        let fileoff = header_size + data.len();
        let size: usize = members.iter().map(|(_, _, bytes)| bytes.len()).sum();
        put32(&mut out, 0x19); // LC_SEGMENT_64
        put32(&mut out, n32(72 + 80 * members.len()));
        name16(&mut out, segment);
        put64(&mut out, n64(fileoff)); // vmaddr
        put64(&mut out, n64(size)); // vmsize
        put64(&mut out, n64(fileoff));
        put64(&mut out, n64(size));
        put32(&mut out, 3); // maxprot: rw
        put32(&mut out, 3); // initprot
        put32(&mut out, n32(members.len()));
        put32(&mut out, 0); // flags
        for (_, section, bytes) in members {
            let offset = header_size + data.len();
            name16(&mut out, section);
            name16(&mut out, segment);
            put64(&mut out, n64(offset)); // addr
            put64(&mut out, n64(bytes.len()));
            put32(&mut out, n32(offset));
            put32(&mut out, 0); // align
            put32(&mut out, 0); // reloff
            put32(&mut out, 0); // nreloc
            put32(&mut out, 0); // flags: S_REGULAR
            put32(&mut out, 0);
            put32(&mut out, 0);
            put32(&mut out, 0);
            data.extend_from_slice(bytes);
        }
    }
    // __LINKEDIT, with no sections.
    put32(&mut out, 0x19);
    put32(&mut out, 72);
    name16(&mut out, "__LINKEDIT");
    put64(&mut out, n64(header_size + data.len())); // vmaddr
    put64(&mut out, 0); // vmsize
    put64(&mut out, n64(header_size + data.len())); // fileoff
    put64(&mut out, 0); // filesize
    put32(&mut out, 1); // maxprot: r
    put32(&mut out, 1); // initprot
    put32(&mut out, 0); // nsects
    put32(&mut out, 0); // flags
    assert_eq!(out.len(), header_size);
    out.extend_from_slice(&data);
    out
}

#[test]
fn a_record_reads_back_from_an_elf_image() {
    let image = elf(&[(RECORD_SECTION, RECORD)]);
    let record = requirement_from_bytes(&image).expect("reads");
    assert_eq!(record.cpu, "x86-64-v3");
    assert_eq!(record.features.len(), 20);
}

#[test]
fn a_record_reads_back_from_a_padded_pe_image() {
    let image = pe(&[
        (".text", &[0xC3][..]),
        (RECORD_SECTION, RECORD),
        (CPULIST_SECTION, CPULIST),
    ]);
    assert!(image.starts_with(b"MZ"));
    let record = requirement_from_bytes(&image).expect("reads despite file-alignment padding");
    assert_eq!(record.cpu, "x86-64-v3");
    let list = cpu_list_from_bytes(&image).expect("reads");
    assert_eq!(list.core, "demo_core");
    assert_eq!(list.cpus, ["x86-64-v4", "x86-64-v3", "x86-64-v2"]);
}

#[test]
fn files_are_read_through_the_cache() {
    let dir = std::env::temp_dir().join(format!("seaworthy_levels_binary_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let core = dir.join("core.so");
    let launcher = dir.join("launcher.exe");
    std::fs::write(&core, elf(&[(RECORD_SECTION, RECORD)])).unwrap();
    std::fs::write(&launcher, pe(&[(CPULIST_SECTION, CPULIST)])).unwrap();
    assert_eq!(read_requirement(&core).expect("reads").cpu, "x86-64-v3");
    assert_eq!(read_cpu_list(&launcher).expect("reads").core, "demo_core");
    assert!(matches!(
        read_requirement(&dir.join("missing.so")),
        Err(BinaryError::Io(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refusals_name_the_problem() {
    // No section.
    assert!(matches!(
        requirement_from_bytes(&elf(&[])),
        Err(BinaryError::NoSection(RECORD_SECTION))
    ));
    // Twice.
    assert!(matches!(
        requirement_from_bytes(&elf(&[(RECORD_SECTION, RECORD), (RECORD_SECTION, RECORD)])),
        Err(BinaryError::DuplicateSection(RECORD_SECTION))
    ));
    // Oversized.
    let big = vec![b'x'; 16 * 1024];
    assert!(matches!(
        requirement_from_bytes(&elf(&[(RECORD_SECTION, &big)])),
        Err(BinaryError::TooLarge(_))
    ));
    // Malformed contents.
    assert!(matches!(
        requirement_from_bytes(&elf(&[(RECORD_SECTION, b"seaworthy-cpureq:9\n")])),
        Err(BinaryError::Record(_))
    ));
    // A COFF object is not an image a launcher loads.
    assert!(matches!(
        requirement_from_bytes(&coff(RECORD_SECTION, RECORD)),
        Err(BinaryError::UnsupportedFormat("COFF object"))
    ));
    // Not an object at all.
    assert!(matches!(
        requirement_from_bytes(b"#!/bin/sh\necho not a core\n"),
        Err(BinaryError::NotAnObject(_))
    ));
}

#[test]
fn records_read_back_from_a_macho_image() {
    let record = b"seaworthy-cpureq:1\ntarget=aarch64-apple-darwin\ncpu=apple-m1\nfeatures=neon\n";
    let list = b"seaworthy-cpulist:1\ncore=demo_core\ncpus=apple-m1\n";
    let image = macho(&[
        ("__TEXT", "__text", &[0xc0, 0x03, 0x5f, 0xd6]),
        ("__DATA", "__cpureq", record),
        ("__DATA", "__cpulist", list),
    ]);
    let parsed = requirement_from_bytes(&image).unwrap();
    assert_eq!(parsed.target, "aarch64-apple-darwin");
    assert_eq!(parsed.cpu, "apple-m1");
    assert_eq!(parsed.features, ["neon"]);
    assert_eq!(cpu_list_from_bytes(&image).unwrap().cpus, ["apple-m1"]);
    // From disk, through the read cache.
    let dir = std::env::temp_dir().join(format!("seaworthy_levels_macho_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("libdemo_core_apple-m1.dylib");
    std::fs::write(&path, &image).unwrap();
    assert_eq!(read_requirement(&path).unwrap(), parsed);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn macho_refusals_name_the_section() {
    let record = b"seaworthy-cpureq:1\ntarget=aarch64-apple-darwin\ncpu=apple-m1\nfeatures=neon\n";
    // The right section name in another segment is not the record.
    let err = requirement_from_bytes(&macho(&[("__TEXT", "__cpureq", record)])).unwrap_err();
    assert!(
        matches!(err, BinaryError::NoSection("__DATA,__cpureq")),
        "{err}"
    );
    assert_eq!(
        err.to_string(),
        "no `__DATA,__cpureq` section (not built with seaworthy-launcher)"
    );
    // ELF's and PE's section name means nothing in a Mach-O.
    assert!(matches!(
        requirement_from_bytes(&macho(&[("__DATA", RECORD_SECTION, record)])),
        Err(BinaryError::NoSection("__DATA,__cpureq"))
    ));
    assert!(matches!(
        requirement_from_bytes(&macho(&[
            ("__DATA", "__cpureq", record),
            ("__DATA", "__cpureq", record)
        ])),
        Err(BinaryError::DuplicateSection("__DATA,__cpureq"))
    ));
    // A universal binary: refused, whatever its slices carry.
    let thin = macho(&[("__DATA", "__cpureq", record)]);
    let mut fat = Vec::new();
    fat.extend_from_slice(&0xcafe_babe_u32.to_be_bytes()); // FAT_MAGIC
    fat.extend_from_slice(&1_u32.to_be_bytes()); // nfat_arch
    fat.extend_from_slice(&0x0100_000c_u32.to_be_bytes()); // CPU_TYPE_ARM64
    fat.extend_from_slice(&0_u32.to_be_bytes());
    fat.extend_from_slice(&4096_u32.to_be_bytes()); // offset
    fat.extend_from_slice(&n32(thin.len()).to_be_bytes());
    fat.extend_from_slice(&12_u32.to_be_bytes()); // align (2^12)
    fat.resize(4096, 0);
    fat.extend_from_slice(&thin);
    let err = requirement_from_bytes(&fat).unwrap_err();
    assert!(
        matches!(
            err,
            BinaryError::UnsupportedFormat("universal (multi-architecture) Mach-O")
        ),
        "{err}"
    );
}

#[test]
fn error_messages_are_actionable() {
    let err = requirement_from_bytes(&elf(&[])).unwrap_err();
    assert_eq!(
        err.to_string(),
        "no `.cpureq` section (not built with seaworthy-launcher)"
    );
}
