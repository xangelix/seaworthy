//! Test support: minimal ELF, PE and Mach-O images, written by hand,
//! carrying exactly what `seaworthy verify` reads. These are record
//! sections, a symbol table and `DT_NEEDED` (ELF), record sections and an
//! import table (PE), and record sections, `LC_LOAD_DYLIB`s and
//! `LC_BUILD_VERSION` (Mach-O). Hand-written on purpose, like `seaworthy_levels`' test builders:
//! `object`'s writer would join the workspace's resolved dependency graph,
//! and every crate's SBOM, for test code alone.

#![allow(
    dead_code,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub(crate) mod repo_fixture;

use std::path::{Path, PathBuf};

use seaworthy::inputs::{LINUX, MACOS, WINDOWS};

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

/// A string table: `add` returns each name's offset.
#[derive(Default)]
struct Strtab(Vec<u8>);

impl Strtab {
    fn new() -> Self {
        Self(vec![0])
    }
    fn add(&mut self, name: &str) -> u32 {
        let at = n32(self.0.len());
        self.0.extend_from_slice(name.as_bytes());
        self.0.push(0);
        at
    }
}

/// What an ELF test image carries.
#[derive(Default, Clone)]
pub(crate) struct Elf {
    /// Allocated PROGBITS sections (`.cpureq`, `.cpulist`).
    pub(crate) sections: Vec<(String, Vec<u8>)>,
    /// `.symtab` entries: `(name, defined function in .text)`; an empty
    /// list writes no `.symtab` at all (a stripped binary).
    pub(crate) symbols: Vec<(String, bool)>,
    /// `DT_NEEDED` entries.
    pub(crate) needed: Vec<String>,
    /// `STT_FILE` symbols (what rustc emits per codegen unit), which `nm`
    /// never prints.
    pub(crate) files: Vec<String>,
    /// A `PT_INTERP` program header naming this loader: makes an `ET_DYN`
    /// image a (position-independent) executable.
    pub(crate) interp: Option<String>,
    /// Symbols defined in a writable data section rather than `.text`
    /// (`nm` type `D`), even if typed as functions.
    pub(crate) data_symbols: Vec<String>,
    /// Weak function definitions in `.text` (`nm` type `W`).
    pub(crate) weak_symbols: Vec<String>,
    /// A version-needs table (`.gnu.version_r`): per library, the version
    /// names it needs with each entry's flags (`VER_FLG_WEAK` = 2).
    pub(crate) verneed: Vec<(String, Vec<(String, u16)>)>,
    /// Undefined dynamic functions (`.dynsym`, `.gnu.version`), each bound
    /// to a version `verneed` names: `(symbol, version)`.
    pub(crate) imports: Vec<(String, String)>,
    /// `DT_FLAGS` = `DF_STATIC_TLS` (initial-exec TLS somewhere inside).
    pub(crate) static_tls: bool,
}

/// The SysV ELF hash of a version name (`vna_hash`).
fn elf_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = (h << 4).wrapping_add(u32::from(b));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

impl Elf {
    /// An ELF64 x86-64 shared object, laid out as a linker lays out a
    /// program: the allocated sections first, each at an address equal to
    /// its file offset, mapped by one `PT_LOAD` (with a `PT_DYNAMIC`), and
    /// the symbol tables after them, so a real `strip` removes only what
    /// isn't loaded.
    pub(crate) fn build(&self) -> Vec<u8> {
        // Sections, in order: null, user sections, [.interp], .data, .text,
        // .dynstr, [.dynsym, .gnu.version], [.gnu.version_r], .dynamic,
        // [.symtab, .strtab], .shstrtab.
        struct Section {
            name: u32,
            kind: u32,
            flags: u64,
            data: Vec<u8>,
            link: u32,
            info: u32,
            entsize: u64,
        }
        let mut shstrtab = Strtab::new();
        let mut sections: Vec<Section> = Vec::new();
        for (name, data) in &self.sections {
            sections.push(Section {
                name: shstrtab.add(name),
                kind: 1,
                flags: 2,
                data: data.clone(),
                link: 0,
                info: 0,
                entsize: 0,
            });
        }
        let interp_index = self.interp.as_ref().map(|loader| {
            let mut bytes = loader.as_bytes().to_vec();
            bytes.push(0);
            sections.push(Section {
                name: shstrtab.add(".interp"),
                kind: 1,
                flags: 2,
                data: bytes,
                link: 0,
                info: 0,
                entsize: 0,
            });
            sections.len()
        });
        let data_index = sections.len() + 1;
        sections.push(Section {
            name: shstrtab.add(".data"),
            kind: 1,
            flags: 3, // SHF_WRITE | SHF_ALLOC
            data: vec![0; 16],
            link: 0,
            info: 0,
            entsize: 0,
        });
        let text_index = sections.len() + 1;
        sections.push(Section {
            name: shstrtab.add(".text"),
            kind: 1,
            flags: 6,
            data: vec![0xc3; 16],
            link: 0,
            info: 0,
            entsize: 0,
        });
        let any_symbols = !self.symbols.is_empty()
            || !self.files.is_empty()
            || !self.data_symbols.is_empty()
            || !self.weak_symbols.is_empty();
        // `.symtab` and `.strtab`, pushed after every allocated section.
        let mut symbol_tables = None;
        let push_symbol_tables =
            |sections: &mut Vec<Section>,
             shstrtab: &mut Strtab,
             (symtab, strtab, first_global): (Vec<u8>, Vec<u8>, usize)| {
                let strtab_index = sections.len() + 2;
                sections.push(Section {
                    name: shstrtab.add(".symtab"),
                    kind: 2,
                    flags: 0,
                    data: symtab,
                    link: n32(strtab_index),
                    info: n32(first_global),
                    entsize: 24,
                });
                sections.push(Section {
                    name: shstrtab.add(".strtab"),
                    kind: 3,
                    flags: 0,
                    data: strtab,
                    link: 0,
                    info: 0,
                    entsize: 0,
                });
            };
        if any_symbols {
            let mut strtab = Strtab::new();
            let mut symtab = vec![0u8; 24]; // the null symbol
            for name in &self.files {
                put32(&mut symtab, strtab.add(name));
                symtab.push(4); // STB_LOCAL, STT_FILE
                symtab.push(0);
                put16(&mut symtab, 0xfff1); // SHN_ABS
                put64(&mut symtab, 0);
                put64(&mut symtab, 0);
            }
            let first_global = 1 + self.files.len();
            let mut symbol = |name: &str, info: u8, section: usize| {
                put32(&mut symtab, strtab.add(name));
                symtab.push(info);
                symtab.push(0);
                put16(&mut symtab, u16::try_from(section).unwrap());
                put64(&mut symtab, 0);
                put64(&mut symtab, 1);
            };
            for (name, text) in &self.symbols {
                // A text symbol is a global function in .text (nm `T`); the
                // others are global objects in .data (nm `D`).
                if *text {
                    symbol(name, (1 << 4) | 2, text_index);
                } else {
                    symbol(name, (1 << 4) | 1, data_index);
                }
            }
            for name in &self.data_symbols {
                symbol(name, (1 << 4) | 2, data_index); // STT_FUNC, but in .data
            }
            for name in &self.weak_symbols {
                symbol(name, (2 << 4) | 2, text_index); // STB_WEAK
            }
            symbol_tables = Some((symtab, strtab.0, first_global));
        }
        let mut dynstr = Strtab::new();
        let mut dynamic = Vec::new();
        for lib in &self.needed {
            put64(&mut dynamic, 1); // DT_NEEDED
            put64(&mut dynamic, u64::from(dynstr.add(lib)));
        }
        if self.static_tls {
            put64(&mut dynamic, 30); // DT_FLAGS
            put64(&mut dynamic, 0x10); // DF_STATIC_TLS
        }
        put64(&mut dynamic, 0); // DT_NULL
        put64(&mut dynamic, 0);
        // Elf64_Verneed (16 bytes) per library, its Elf64_Vernaux entries
        // (16 bytes each) right after it; version indexes from 2.
        let mut verneed = Vec::new();
        let mut index = 2u16;
        let mut indexes = std::collections::HashMap::new();
        for (n, (library, versions)) in self.verneed.iter().enumerate() {
            let last_file = n + 1 == self.verneed.len();
            put16(&mut verneed, 1); // vn_version
            put16(&mut verneed, u16::try_from(versions.len()).unwrap());
            put32(&mut verneed, dynstr.add(library));
            put32(&mut verneed, 16); // vn_aux
            put32(
                &mut verneed,
                if last_file {
                    0
                } else {
                    n32(16 + 16 * versions.len())
                },
            );
            for (m, (name, flags)) in versions.iter().enumerate() {
                put32(&mut verneed, elf_hash(name));
                put16(&mut verneed, *flags);
                put16(&mut verneed, index);
                indexes.insert(name.as_str(), index);
                index += 1;
                put32(&mut verneed, dynstr.add(name));
                put32(&mut verneed, if m + 1 == versions.len() { 0 } else { 16 });
            }
        }
        // Elf64_Sym (24 bytes) per import after the null symbol, and its
        // version index (Elf64_Versym, 2 bytes) in the same order.
        let mut dynsym = vec![0u8; 24];
        let mut versym = vec![0u8; 2];
        for (name, version) in &self.imports {
            put32(&mut dynsym, dynstr.add(name));
            dynsym.push((1 << 4) | 2); // STB_GLOBAL, STT_FUNC
            dynsym.push(0);
            put16(&mut dynsym, 0); // SHN_UNDEF
            put64(&mut dynsym, 0);
            put64(&mut dynsym, 0);
            put16(&mut versym, indexes[version.as_str()]);
        }
        let dynstr_index = sections.len() + 1;
        sections.push(Section {
            name: shstrtab.add(".dynstr"),
            kind: 3,
            flags: 2,
            data: dynstr.0,
            link: 0,
            info: 0,
            entsize: 0,
        });
        if !self.imports.is_empty() {
            let dynsym_index = sections.len() + 1;
            sections.push(Section {
                name: shstrtab.add(".dynsym"),
                kind: 11, // SHT_DYNSYM
                flags: 2,
                data: dynsym,
                link: n32(dynstr_index),
                info: 1, // the first non-local symbol
                entsize: 24,
            });
            sections.push(Section {
                name: shstrtab.add(".gnu.version"),
                kind: 0x6fff_ffff, // SHT_GNU_VERSYM
                flags: 2,
                data: versym,
                link: n32(dynsym_index),
                info: 0,
                entsize: 2,
            });
        }
        if !self.verneed.is_empty() {
            sections.push(Section {
                name: shstrtab.add(".gnu.version_r"),
                kind: 0x6fff_fffe, // SHT_GNU_VERNEED
                flags: 2,
                data: verneed,
                link: n32(dynstr_index),
                info: n32(self.verneed.len()),
                entsize: 0,
            });
        }
        sections.push(Section {
            name: shstrtab.add(".dynamic"),
            kind: 6,
            flags: 3,
            data: dynamic,
            link: n32(dynstr_index),
            info: 0,
            entsize: 16,
        });
        let dynamic_index = sections.len();
        if let Some(tables) = symbol_tables.take() {
            push_symbol_tables(&mut sections, &mut shstrtab, tables);
        }
        let shstrtab_name = shstrtab.add(".shstrtab");
        sections.push(Section {
            name: shstrtab_name,
            kind: 3,
            flags: 0,
            data: Vec::new(),
            link: 0,
            info: 0,
            entsize: 0,
        });
        let last = sections.len() - 1;
        sections[last].data = shstrtab.0;

        // A program header table right after the ELF header: PT_INTERP when
        // there is an interpreter, then PT_LOAD and PT_DYNAMIC.
        let phnum = usize::from(interp_index.is_some()) + 2;
        let phsize = 56 * phnum;
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for section in &sections {
            body.resize(body.len().next_multiple_of(8), 0);
            offsets.push(64 + phsize + body.len());
            body.extend_from_slice(&section.data);
        }
        let shoff = (64 + phsize + body.len()).next_multiple_of(8);
        // Everything allocated, from the ELF header on: what PT_LOAD maps.
        let load_end = sections
            .iter()
            .zip(&offsets)
            .filter(|(section, _)| section.flags & 2 != 0)
            .map(|(section, offset)| offset + section.data.len())
            .max()
            .unwrap_or(64 + phsize);
        let address = |flags: u64, offset: usize| if flags & 2 != 0 { n64(offset) } else { 0 };
        let count = sections.len() + 1;
        let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        put16(&mut out, 3); // ET_DYN
        put16(&mut out, 62); // EM_X86_64
        put32(&mut out, 1);
        put64(&mut out, 0); // e_entry
        put64(&mut out, 64); // e_phoff
        put64(&mut out, n64(shoff));
        put32(&mut out, 0);
        put16(&mut out, 64);
        put16(&mut out, 56);
        put16(&mut out, u16::try_from(phnum).unwrap()); // e_phnum
        put16(&mut out, 64);
        put16(&mut out, u16::try_from(count).unwrap());
        put16(&mut out, u16::try_from(count - 1).unwrap()); // .shstrtab is last
        if let Some(index) = interp_index {
            let (offset, size) = (offsets[index - 1], sections[index - 1].data.len());
            put32(&mut out, 3); // PT_INTERP
            put32(&mut out, 4); // PF_R
            put64(&mut out, n64(offset));
            put64(&mut out, address(2, offset));
            put64(&mut out, address(2, offset));
            put64(&mut out, n64(size));
            put64(&mut out, n64(size));
            put64(&mut out, 1);
        }
        {
            put32(&mut out, 1); // PT_LOAD
            put32(&mut out, 7); // PF_R | PF_W | PF_X
            put64(&mut out, 0);
            put64(&mut out, 0);
            put64(&mut out, 0);
            put64(&mut out, n64(load_end));
            put64(&mut out, n64(load_end));
            put64(&mut out, 0x1000);
            let (offset, size) = (
                offsets[dynamic_index - 1],
                sections[dynamic_index - 1].data.len(),
            );
            put32(&mut out, 2); // PT_DYNAMIC
            put32(&mut out, 6); // PF_R | PF_W
            put64(&mut out, n64(offset));
            put64(&mut out, n64(offset));
            put64(&mut out, n64(offset));
            put64(&mut out, n64(size));
            put64(&mut out, n64(size));
            put64(&mut out, 8);
        }
        out.extend_from_slice(&body);
        out.resize(shoff, 0);
        out.extend_from_slice(&[0u8; 64]); // the null section header
        for (section, offset) in sections.iter().zip(&offsets) {
            put32(&mut out, section.name);
            put32(&mut out, section.kind);
            put64(&mut out, section.flags);
            put64(&mut out, address(section.flags, *offset));
            put64(&mut out, n64(*offset));
            put64(&mut out, n64(section.data.len()));
            put32(&mut out, section.link);
            put32(&mut out, section.info);
            put64(&mut out, 8);
            put64(&mut out, section.entsize);
        }
        out
    }
}

/// What a PE test image carries.
#[derive(Default, Clone)]
pub(crate) struct Pe {
    /// Data sections (`.cpureq`, `.cpulist`).
    pub(crate) sections: Vec<(String, Vec<u8>)>,
    /// Imported DLL names (one function each).
    pub(crate) imports: Vec<String>,
    /// An executable (`.exe`) rather than a DLL.
    pub(crate) executable: bool,
}

impl Pe {
    /// A PE32+ x86-64 DLL image.
    pub(crate) fn build(&self) -> Vec<u8> {
        const FILE_ALIGN: usize = 0x200;
        const SECTION_ALIGN: usize = 0x1000;
        const PE_AT: usize = 0x80;
        let mut sections: Vec<(String, Vec<u8>)> = self.sections.clone();
        let idata_index = if self.imports.is_empty() {
            None
        } else {
            sections.push((".idata".to_owned(), Vec::new()));
            Some(sections.len() - 1)
        };
        let headers = (PE_AT + 4 + 20 + 240 + 40 * sections.len()).next_multiple_of(FILE_ALIGN);
        let mut rvas = Vec::new();
        let mut rva = SECTION_ALIGN;
        for (i, (_, data)) in sections.iter().enumerate() {
            rvas.push(rva);
            let size = if Some(i) == idata_index {
                0x1000
            } else {
                data.len().max(1)
            };
            rva += size.next_multiple_of(SECTION_ALIGN);
        }
        let image_size = rva;
        let mut import_dir = (0u32, 0u32);
        if let Some(index) = idata_index {
            let base = rvas[index];
            let n = self.imports.len();
            let descriptors = 20 * (n + 1);
            let mut idata = vec![0u8; descriptors];
            let mut desc = Vec::new();
            for lib in &self.imports {
                let hint_name = base + idata.len();
                put16(&mut idata, 0);
                idata.extend_from_slice(b"f\0");
                idata.resize(idata.len().next_multiple_of(8), 0);
                let ilt = base + idata.len();
                put64(&mut idata, n64(hint_name));
                put64(&mut idata, 0);
                let iat = base + idata.len();
                put64(&mut idata, n64(hint_name));
                put64(&mut idata, 0);
                let name = base + idata.len();
                idata.extend_from_slice(lib.as_bytes());
                idata.push(0);
                idata.resize(idata.len().next_multiple_of(8), 0);
                desc.push((ilt, name, iat));
            }
            for (i, (ilt, name, iat)) in desc.iter().enumerate() {
                let at = 20 * i;
                idata[at..at + 4].copy_from_slice(&n32(*ilt).to_le_bytes());
                idata[at + 12..at + 16].copy_from_slice(&n32(*name).to_le_bytes());
                idata[at + 16..at + 20].copy_from_slice(&n32(*iat).to_le_bytes());
            }
            import_dir = (n32(base), n32(descriptors));
            sections[index].1 = idata;
        }
        let mut layout = Vec::new();
        let mut offset = headers;
        for (_, data) in &sections {
            let raw = data.len().next_multiple_of(FILE_ALIGN);
            layout.push((offset, raw));
            offset += raw;
        }

        let mut out = vec![0u8; PE_AT];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3c..0x40].copy_from_slice(&n32(PE_AT).to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        put16(&mut out, 0x8664);
        put16(&mut out, u16::try_from(sections.len()).unwrap());
        put32(&mut out, 0);
        put32(&mut out, 0);
        put32(&mut out, 0);
        put16(&mut out, 240);
        // Executable image, large-address-aware, and the DLL flag for a DLL.
        put16(&mut out, if self.executable { 0x0022 } else { 0x2022 });
        put16(&mut out, 0x20b); // PE32+
        out.extend_from_slice(&[14, 0]);
        put32(&mut out, 0);
        put32(&mut out, 0);
        put32(&mut out, 0);
        put32(&mut out, 0); // entry point
        put32(&mut out, 0);
        put64(&mut out, 0x1_8000_0000);
        put32(&mut out, n32(SECTION_ALIGN));
        put32(&mut out, n32(FILE_ALIGN));
        for v in [6u16, 0, 0, 0, 6, 0] {
            put16(&mut out, v);
        }
        put32(&mut out, 0);
        put32(&mut out, n32(image_size));
        put32(&mut out, n32(headers));
        put32(&mut out, 0);
        put16(&mut out, 2); // GUI subsystem
        put16(&mut out, 0x160);
        for _ in 0..4 {
            put64(&mut out, 0x10_0000);
        }
        put32(&mut out, 0);
        put32(&mut out, 16);
        for i in 0..16 {
            if i == 1 {
                put32(&mut out, import_dir.0);
                put32(&mut out, import_dir.1);
            } else {
                put32(&mut out, 0);
                put32(&mut out, 0);
            }
        }
        for ((name, data), ((offset, raw), rva)) in sections.iter().zip(layout.iter().zip(&rvas)) {
            let mut bytes = [0u8; 8];
            bytes[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&bytes);
            put32(&mut out, n32(data.len().max(1)));
            put32(&mut out, n32(*rva));
            put32(&mut out, n32(*raw));
            put32(&mut out, n32(*offset));
            put32(&mut out, 0);
            put32(&mut out, 0);
            put16(&mut out, 0);
            put16(&mut out, 0);
            put32(&mut out, 0xc000_0040);
        }
        out.resize(headers, 0);
        for ((_, data), (_, raw)) in sections.iter().zip(&layout) {
            let start = out.len();
            out.extend_from_slice(data);
            out.resize(start + raw, 0);
        }
        out
    }
}

/// What a Mach-O test image carries (64-bit, little-endian).
#[derive(Clone)]
pub(crate) struct Macho {
    /// `MH_EXECUTE` (true) or `MH_DYLIB`.
    pub(crate) executable: bool,
    /// The CPU type (`CPU_TYPE_ARM64`, 0x0100000c).
    pub(crate) cputype: u32,
    /// Sections as `(segment, section, bytes)`: one `LC_SEGMENT_64` per
    /// segment, then an empty `__LINKEDIT` (every real Mach-O has a
    /// segment without sections).
    pub(crate) sections: Vec<(String, String, Vec<u8>)>,
    /// `LC_LOAD_DYLIB` install names.
    pub(crate) dylibs: Vec<String>,
    /// `LC_BUILD_VERSION`'s `(platform, minos)`, minos as
    /// `(major, minor, patch)`; `None` writes none.
    pub(crate) build_version: Option<(u32, (u32, u32, u32))>,
    /// `LC_RPATH` search paths.
    pub(crate) rpaths: Vec<String>,
}

/// `CPU_TYPE_ARM64`.
pub(crate) const CPU_TYPE_ARM64: u32 = 0x0100_000c;

impl Default for Macho {
    fn default() -> Self {
        Self {
            executable: false,
            cputype: CPU_TYPE_ARM64,
            sections: Vec::new(),
            dylibs: vec!["/usr/lib/libSystem.B.dylib".into()],
            build_version: Some((1, (11, 0, 0))),
            rpaths: Vec::new(),
        }
    }
}

impl Macho {
    fn name16(out: &mut Vec<u8>, name: &str) {
        let mut field = [0u8; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
    }

    /// The image.
    pub(crate) fn build(&self) -> Vec<u8> {
        let mut segments: Vec<&str> = Vec::new();
        for (segment, _, _) in &self.sections {
            if !segments.contains(&segment.as_str()) {
                segments.push(segment);
            }
        }
        let dylib_size = |name: &str| (24 + name.len() + 1).next_multiple_of(8);
        let mut commands = 0usize;
        let mut size = 0usize;
        for segment in &segments {
            commands += 1;
            size += 72
                + 80 * self
                    .sections
                    .iter()
                    .filter(|(s, _, _)| s == segment)
                    .count();
        }
        commands += 1; // __LINKEDIT
        size += 72;
        if self.build_version.is_some() {
            commands += 1;
            size += 24;
        }
        for dylib in &self.dylibs {
            commands += 1;
            size += dylib_size(dylib);
        }
        let rpath_size = |path: &str| (12 + path.len() + 1).next_multiple_of(8);
        for rpath in &self.rpaths {
            commands += 1;
            size += rpath_size(rpath);
        }
        let header_size = 32 + size;
        let mut out = Vec::new();
        put32(&mut out, 0xfeed_facf);
        put32(&mut out, self.cputype);
        put32(&mut out, 0);
        put32(&mut out, if self.executable { 2 } else { 6 });
        put32(&mut out, n32(commands));
        put32(&mut out, n32(size));
        put32(&mut out, 0);
        put32(&mut out, 0);
        let mut data = Vec::new();
        for segment in &segments {
            let members: Vec<&(String, String, Vec<u8>)> = self
                .sections
                .iter()
                .filter(|(s, _, _)| s == segment)
                .collect();
            let fileoff = header_size + data.len();
            let total: usize = members.iter().map(|(_, _, b)| b.len()).sum();
            put32(&mut out, 0x19);
            put32(&mut out, n32(72 + 80 * members.len()));
            Self::name16(&mut out, segment);
            put64(&mut out, n64(fileoff));
            put64(&mut out, n64(total));
            put64(&mut out, n64(fileoff));
            put64(&mut out, n64(total));
            put32(&mut out, 3);
            put32(&mut out, 3);
            put32(&mut out, n32(members.len()));
            put32(&mut out, 0);
            for (_, section, bytes) in members {
                let offset = header_size + data.len();
                Self::name16(&mut out, section);
                Self::name16(&mut out, segment);
                put64(&mut out, n64(offset));
                put64(&mut out, n64(bytes.len()));
                put32(&mut out, n32(offset));
                for _ in 0..7 {
                    put32(&mut out, 0);
                }
                data.extend_from_slice(bytes);
            }
        }
        put32(&mut out, 0x19);
        put32(&mut out, 72);
        Self::name16(&mut out, "__LINKEDIT");
        put64(&mut out, n64(header_size + data.len()));
        put64(&mut out, 0);
        put64(&mut out, n64(header_size + data.len()));
        put64(&mut out, 0);
        put32(&mut out, 1);
        put32(&mut out, 1);
        put32(&mut out, 0);
        put32(&mut out, 0);
        if let Some((platform, (major, minor, patch))) = self.build_version {
            put32(&mut out, 0x32);
            put32(&mut out, 24);
            put32(&mut out, platform);
            put32(&mut out, (major << 16) | (minor << 8) | patch);
            put32(&mut out, (major << 16) | (minor << 8) | patch);
            put32(&mut out, 0);
        }
        for dylib in &self.dylibs {
            let total = dylib_size(dylib);
            put32(&mut out, 0xc);
            put32(&mut out, n32(total));
            put32(&mut out, 24); // name offset
            put32(&mut out, 2); // timestamp
            put32(&mut out, 0x0001_0000);
            put32(&mut out, 0x0001_0000);
            let mut name = dylib.as_bytes().to_vec();
            name.resize(total - 24, 0);
            out.extend_from_slice(&name);
        }
        for rpath in &self.rpaths {
            let total = rpath_size(rpath);
            put32(&mut out, 0x8000_001c); // LC_RPATH
            put32(&mut out, n32(total));
            put32(&mut out, 12); // path offset
            let mut path = rpath.as_bytes().to_vec();
            path.resize(total - 12, 0);
            out.extend_from_slice(&path);
        }
        assert_eq!(out.len(), header_size);
        out.extend_from_slice(&data);
        out
    }
}

/// The macOS fixture CPUs (Apple Silicon), in preference order.
pub(crate) const MACOS_CPUS: [&str; 2] = ["apple-m4", "apple-m1"];
/// apple-m1's features, as a record lists them.
pub(crate) const M1: &[&str] = &[
    "aes", "crc", "dit", "dotprod", "dpb", "dpb2", "fcma", "fhm", "flagm", "flagm2", "fp16",
    "frintts", "jsconv", "lor", "lse", "lse2", "neon", "paca", "pacg", "pan", "pmuv3", "ras",
    "rcpc", "rcpc2", "rdm", "sb", "sha2", "sha3", "ssbs", "v8.1a", "v8.2a", "v8.3a", "v8.4a", "vh",
];

/// The acme product's macOS artifacts: launcher `AcmeTool` and core
/// `acme_core` for [`MACOS_CPUS`].
pub(crate) fn acme_macos_artifacts(root: &Path) {
    write(
        root,
        &format!("{MACOS}/launcher/AcmeTool"),
        &Macho {
            executable: true,
            sections: vec![(
                "__DATA".into(),
                "__cpulist".into(),
                cpulist("acme_core", &MACOS_CPUS),
            )],
            ..Macho::default()
        }
        .build(),
    );
    for cpu in MACOS_CPUS {
        let mut features = M1.to_vec();
        if cpu == "apple-m4" {
            features.extend(["bf16", "i8mm", "v8.5a", "v8.6a", "v8.7a"]);
        }
        write(
            root,
            &format!("{MACOS}/cores/{cpu}/libacme_core.dylib"),
            &Macho {
                sections: vec![(
                    "__DATA".into(),
                    "__cpureq".into(),
                    record(MACOS, cpu, &features),
                )],
                ..Macho::default()
            }
            .build(),
        );
    }
}

/// A `.cpureq` record.
pub(crate) fn record(triple: &str, cpu: &str, features: &[&str]) -> Vec<u8> {
    let mut sorted: Vec<&str> = features.to_vec();
    sorted.sort_unstable();
    format!(
        "seaworthy-cpureq:1\ntarget={triple}\ncpu={cpu}\nfeatures={}\n",
        sorted.join(",")
    )
    .into_bytes()
}

/// A `.cpulist` record.
pub(crate) fn cpulist(core: &str, cpus: &[&str]) -> Vec<u8> {
    format!(
        "seaworthy-cpulist:1\ncore={core}\ncpus={}\n",
        cpus.join(",")
    )
    .into_bytes()
}

/// The loader a Linux executable names.
pub(crate) const LOADER: &str = "/lib64/ld-linux-x86-64.so.2";

/// The FIPS module's symbols as a pinned static link leaves them.
pub(crate) fn fips_symbols() -> Vec<(String, bool)> {
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    vec![
        (format!("{prefix}awslc_version_string"), true),
        (format!("{prefix}RAND_bytes"), true),
        ("seaworthy_core_main".to_owned(), true),
    ]
}

/// Writes `bytes` at `dir/relative`, creating parents.
pub(crate) fn write(dir: &Path, relative: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

/// The fixture product's CPU targets, in preference order.
pub(crate) const CPUS: [&str; 2] = ["x86-64-v3", "x86-64-v2"];
/// x86-64-v2's features, as a record lists them.
pub(crate) const V2: &[&str] = &[
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

/// The artifact directory of the fixture product every layout and package
/// test uses: launcher `AcmeTool`, helper `AcmeToolUpdate`, core
/// `acme_core` for [`CPUS`], and the Windows sidecar `extra_1.dll`, for
/// both triples.
pub(crate) fn acme_artifacts(root: &Path) {
    let list = cpulist("acme_core", &CPUS);
    write(
        root,
        &format!("{LINUX}/launcher/AcmeTool"),
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
    write(
        root,
        &format!("{WINDOWS}/launcher/AcmeTool.exe"),
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
    let sidecar = Pe {
        sections: vec![(".text".into(), b"x".to_vec())],
        imports: vec![],
        executable: false,
    }
    .build();
    for cpu in CPUS {
        write(
            root,
            &format!("{LINUX}/cores/{cpu}/libacme_core.so"),
            &Elf {
                sections: vec![(".cpureq".into(), record(LINUX, cpu, V2))],
                needed: vec!["libc.so.6".into()],
                symbols: vec![("seaworthy_core_main".into(), true)],
                ..Elf::default()
            }
            .build(),
        );
        write(
            root,
            &format!("{WINDOWS}/cores/{cpu}/acme_core.dll"),
            &Pe {
                sections: vec![(".cpureq".into(), record(WINDOWS, cpu, V2))],
                imports: vec!["kernel32.dll".into()],
                executable: false,
            }
            .build(),
        );
        write(
            root,
            &format!("{WINDOWS}/cores/{cpu}/extra_1.dll"),
            &sidecar,
        );
    }
}

// ---------------------------------------------------------------------------
// Packaging test support (tests/package.rs, tests/wix.rs)

/// `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1`: a missing tool fails instead of
/// skipping (CI's gate sets it, with every tool installed).
pub(crate) fn required() -> bool {
    std::env::var_os("SEAWORTHY_REQUIRE_PACKAGE_TOOLS").is_some_and(|v| v == "1")
}

/// Whether `tool` runs (`tool probe…` exits 0); a skip is announced, and
/// fails under [`required`].
pub(crate) fn have(tool: &str, probe: &[&str]) -> bool {
    if cfg!(windows) && tool == "gpg" && !native_gpg() {
        eprintln!(
            "SKIPPED: gpg is an MSYS build (Git for Windows's), which reads C:\\ paths as relative"
        );
        return false;
    }
    let ok = std::process::Command::new(tool)
        .args(probe)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        assert!(
            !required(),
            "{tool} is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1) but not runnable"
        );
        eprintln!("SKIPPED: {tool} is not installed");
    }
    ok
}

/// Whether `gpg` is a native Windows build (Gpg4win), whose home is a drive
/// path. Git for Windows's MSYS gpg names a POSIX one (`/c/Users/…`,
/// `~/.gnupg`) and joins a `--homedir C:\…` onto its working directory.
fn native_gpg() -> bool {
    std::process::Command::new("gpg")
        .arg("--version")
        .output()
        .is_ok_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|line| line.strip_prefix("Home: "))
                .any(|home| home.get(1..3).is_some_and(|s| s == ":\\" || s == ":/"))
        })
}

/// Runs `cmd`, which must succeed; its stdout.
pub(crate) fn run(cmd: &mut std::process::Command) -> String {
    let out = cmd.output().expect("runs");
    assert!(
        out.status.success(),
        "{cmd:?} failed ({}): {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// The crate's directory.
pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Compares `actual` with `tests/golden/<name>`; `SEAWORTHY_BLESS=1`
/// writes it instead (review the diff).
pub(crate) fn golden(name: &str, actual: &str) {
    let path = manifest_dir().join("tests/golden").join(name);
    if std::env::var_os("SEAWORTHY_BLESS").is_some_and(|v| v == "1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (SEAWORTHY_BLESS=1 writes it)", path.display()));
    assert!(
        actual == expected,
        "{} differs (review, then SEAWORTHY_BLESS=1 rewrites it):\n{actual}",
        path.display()
    );
}

/// The fixture artifacts verified and laid out (unstripped: the fixture
/// binaries are hand-written) for product `id` under `out`.
pub(crate) fn layouts(
    config: &seaworthy::config::Config,
    id: &str,
    out: &Path,
) -> Vec<seaworthy::layout::Layout> {
    let input = out.join("artifacts");
    acme_artifacts(&input);
    let verified = seaworthy::verify::verify(config, id, &input).expect("verifies");
    seaworthy::layout::layout(
        config,
        id,
        &verified,
        &out.join("dist"),
        seaworthy::layout::Options {
            strip: false,
            ..seaworthy::layout::Options::default()
        },
    )
    .expect("lays out")
}

/// The layout for `triple`.
pub(crate) fn layout_for<'a>(
    layouts: &'a [seaworthy::layout::Layout],
    triple: &str,
) -> &'a seaworthy::layout::Layout {
    layouts.iter().find(|l| l.triple == triple).unwrap()
}

/// The `.wxs` lines holding any of `needles`: a failing assert's message,
/// in place of the whole document.
pub(crate) fn wxs_lines<'a>(wxs: &'a str, needles: &[&str]) -> Vec<&'a str> {
    wxs.lines()
        .filter(|l| needles.iter().any(|n| l.contains(n)))
        .collect()
}

/// The fixture release.
pub(crate) fn release() -> seaworthy::version::Release {
    seaworthy::version::Release::new("1.4.0-rc.2", 812).unwrap()
}

/// `$NFPM` (which must run), else the pinned copy `scripts/ci/install-nfpm.sh`
/// installs, else `nfpm` on `PATH`; `None` (announced) when none runs.
pub(crate) fn nfpm() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("NFPM") {
        let path = PathBuf::from(explicit);
        seaworthy::nfpm::tool_version(&path).expect("NFPM is set but doesn't run");
        return Some(path);
    }
    let pinned = manifest_dir().join("../../target/ci-tools/nfpm/nfpm");
    for candidate in [pinned, PathBuf::from("nfpm")] {
        if seaworthy::nfpm::tool_version(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    assert!(
        !required(),
        "nFPM is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1): run scripts/ci/install-nfpm.sh"
    );
    eprintln!("SKIPPED: nFPM not found (scripts/ci/install-nfpm.sh installs it)");
    None
}

/// Builds every output of product `id` from the fixture artifacts.
pub(crate) fn build(
    config: &seaworthy::config::Config,
    id: &str,
    out: &Path,
    nfpm: &Path,
    wix: Option<PathBuf>,
) -> Vec<seaworthy::package::Artifact> {
    build_as(config, id, out, nfpm, wix, "")
}

/// [`build`], naming the release's build metadata (`package --build`).
pub(crate) fn build_as(
    config: &seaworthy::config::Config,
    id: &str,
    out: &Path,
    nfpm: &Path,
    wix: Option<PathBuf>,
    build: &str,
) -> Vec<seaworthy::package::Artifact> {
    let layouts = layouts(config, id, out);
    seaworthy::package::package(
        config,
        id,
        &layouts,
        &out.join("dist"),
        &seaworthy::package::Options {
            release: release(),
            mtime: 1_700_000_000,
            nfpm: nfpm.to_path_buf(),
            wix,
            build: seaworthy::sign::BuildId {
                metadata: build.to_owned(),
            },
        },
        &seaworthy::package::Signing::default(),
    )
    .expect("packages")
}

/// The artifact of `kind`.
pub(crate) fn artifact(
    artifacts: &[seaworthy::package::Artifact],
    kind: seaworthy::package::Kind,
) -> PathBuf {
    artifacts
        .iter()
        .find(|a| a.kind == kind)
        .unwrap_or_else(|| panic!("no {kind:?} in {artifacts:?}"))
        .path
        .clone()
}

/// A throwaway gpg home with an RSA signing key, its agent killed on drop.
pub(crate) struct Keyring {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) fingerprint: String,
}

/// The gpg home's name: it holds an rpm macro, which `Gpg` must pass to
/// rpmsign literally (unescaped, rpm would run `echo y` and look for `gy`).
pub(crate) const HOME_NAME: &str = "g%(echo y)";

impl Keyring {
    pub(crate) fn new() -> Self {
        Self::with_algorithm("rsa3072", &[])
    }

    /// A key of `algorithm` (`rsa1024`, `ed25519`, `dsa2048`, …), with
    /// `extra` gpg options for its generation (`--cert-digest-algo SHA1`).
    pub(crate) fn with_algorithm(algorithm: &str, extra: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join(HOME_NAME);
        std::fs::create_dir(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        run(std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&home)
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(extra)
            .args([
                "--quick-gen-key",
                "Acme Packaging Test <pkg@acme.test>",
                algorithm,
                "sign",
                "never",
            ]));
        let listing = run(std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(&home)
            .args(["--list-keys", "--with-colons"]));
        let fingerprint = listing
            .lines()
            .find_map(|l| l.strip_prefix("fpr:"))
            .and_then(|l| l.split(':').nth(8))
            .unwrap()
            .to_owned();
        Self { dir, fingerprint }
    }

    pub(crate) fn home(&self) -> PathBuf {
        self.dir.path().join(HOME_NAME)
    }

    pub(crate) fn signer(&self) -> seaworthy::codesign::Gpg {
        seaworthy::codesign::Gpg {
            home: self.home(),
            key: self.fingerprint.clone(),
            gpg: PathBuf::from("gpg"),
            rpmsign: PathBuf::from("rpmsign"),
            timeout: std::time::Duration::from_secs(120),
        }
    }

    /// The secret key, armored (unprotected, as the key was made): what a
    /// custody system hands `[openpgp] secret-key-env`.
    pub(crate) fn export_secret(&self) -> String {
        run(std::process::Command::new("gpg")
            .arg("--homedir")
            .arg(self.home())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--armor",
                "--export-secret-keys",
            ])
            .arg(&self.fingerprint))
    }

    /// The public key, armored, written to `path`.
    pub(crate) fn export(&self, path: &Path) {
        std::fs::write(
            path,
            run(std::process::Command::new("gpg")
                .arg("--homedir")
                .arg(self.home())
                .args(["--armor", "--export"])
                .arg(&self.fingerprint)),
        )
        .unwrap();
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        let _ = std::process::Command::new("gpgconf")
            .arg("--homedir")
            .arg(self.home())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}
