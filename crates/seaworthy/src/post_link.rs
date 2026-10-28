//! Proof that the steps after a build change nothing the loader maps.
//!
//! `seaworthy` changes binaries after `verify` read them: `layout` strips
//! every Linux launcher, core and helper, and `package` stamps a version
//! resource into every Windows launcher, core and helper
//! ([`crate::pe_version`]) and Authenticode-signs every Windows binary, the
//! FIPS module's DLLs included. A product whose cores carry a FIPS module
//! relies on nothing after the build changing the module: its integrity
//! test covers bytes the loader maps. So each step's output is compared
//! with its input, and anything beyond the step's own change fails the
//! build, naming the section or header field:
//!
//! - [`check_strip`] (ELF): the ELF header (but the section header table's
//!   offset, count and name index), every program header, every byte a
//!   `PT_LOAD` maps from the file, and every `SHF_ALLOC` section a
//!   `PT_LOAD` maps (name, type, flags, address, size, file offset and
//!   contents) are unchanged. Stripping may drop sections that aren't
//!   loaded (symbols, debug information) and rewrite the section header
//!   table, nothing else.
//! - [`check_stamp`] (PE): every section's header and file data are
//!   unchanged, but for the resource section the stamp may rewrite in place
//!   (the last one, holding the resource directory, nothing executable or
//!   writable and no other data directory, whose size alone may change); a
//!   section added after every other is initialized read-only data holding
//!   the new resource directory; in the headers only the section count, the
//!   initialized-data and image sizes, the checksum and the resource data
//!   directory change.
//! - [`check_sign`] (PE): headers, section headers and section data are
//!   unchanged but for the checksum and the certificate table's data
//!   directory, which names a table past every section's data.
//!
//! The binaries are seaworthy's inputs, but they are read as untrusted
//! input: `object`'s bounded readers, no indexing, checked arithmetic, and
//! the `dist_post_link` fuzz target.

// Offsets come from the files: no indexing that can panic, no arithmetic
// that can overflow.
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::ops::Range;
use std::path::Path;

use object::LittleEndian as LE;
use object::elf::{FileHeader64, ProgramHeader64, SectionHeader64};
use object::pe::{ImageDosHeader, ImageNtHeaders64, ImageSectionHeader};
use object::read::elf::{FileHeader as _, ProgramHeader as _, SectionHeader as _, SectionTable};
use object::read::pe::{ImageNtHeaders as _, ImageOptionalHeader as _};

use crate::DistError;

/// `layout.json`'s `strip` for a binary [`check_strip`] passed: only
/// sections that aren't loaded were removed.
pub const STRIPPED: &str = "non-alloc";
/// `layout.json`'s `stamp` for a binary [`check_stamp`] passed: only the
/// resource section changed.
pub const STAMPED: &str = "resource-section";
/// `layout.json`'s `sign` for a binary [`check_sign`] passed: only the
/// certificate table was added.
pub const SIGNED: &str = "certificate-table";

/// `error`, about the file at `path`: a [`DistError::Layout`]'s message
/// after the path (any other error as it is).
#[must_use]
pub fn about(path: &Path, error: DistError) -> DistError {
    match error {
        DistError::Layout(message) => DistError::Layout(format!("{}: {message}", path.display())),
        other => other,
    }
}

/// A change to what the loader maps, by `step` ("stripping", …).
fn changed(step: &str, what: &str) -> DistError {
    DistError::Layout(format!("{step} changed what the loader maps: {what}"))
}

/// An input the check can't read: `which` image (`"original"`, …) of
/// `step`.
fn unreadable(step: &str, which: &str, why: &str) -> DistError {
    DistError::Layout(format!("{step}: the {which} image can't be read: {why}"))
}

/// `value` as a `usize` offset, or `None` past this host's address space.
fn offset(value: impl TryInto<usize>) -> Option<usize> {
    value.try_into().ok()
}

/// `start..start + len`, or `None` when it overflows.
fn span(start: usize, len: usize) -> Option<Range<usize>> {
    Some(start..start.checked_add(len)?)
}

/// Where `a` and `b` first differ outside `masked` (offsets into both), or
/// `None` when they are the same there. Slices of different lengths differ
/// where the shorter one ends.
fn difference(a: &[u8], b: &[u8], masked: &[Range<usize>]) -> Option<usize> {
    if masked.is_empty() && a == b {
        return None;
    }
    let first = a
        .iter()
        .zip(b)
        .enumerate()
        .find(|(at, (x, y))| x != y && !masked.iter().any(|m| m.contains(at)))
        .map(|(at, _)| at);
    first.or_else(|| (a.len() != b.len()).then(|| a.len().min(b.len())))
}

/// The name of the field at `at` in a table of `(start, name)`, sorted.
fn field(table: &[(usize, &'static str)], at: usize) -> &'static str {
    table
        .iter()
        .take_while(|(start, _)| *start <= at)
        .last()
        .map_or("?", |(_, name)| name)
}

// ---------------------------------------------------------------------------
// ELF

const STRIP: &str = "stripping";

/// The ELF64 header's size.
const EHDR: usize = 64;

/// The ELF header's fields, by offset.
const ELF_HEADER_FIELDS: [(usize, &str); 14] = [
    (0, "e_ident"),
    (16, "e_type"),
    (18, "e_machine"),
    (20, "e_version"),
    (24, "e_entry"),
    (32, "e_phoff"),
    (40, "e_shoff"),
    (48, "e_flags"),
    (52, "e_ehsize"),
    (54, "e_phentsize"),
    (56, "e_phnum"),
    (58, "e_shentsize"),
    (60, "e_shnum"),
    (62, "e_shstrndx"),
];

/// What stripping rewrites in the ELF header: `e_shoff`, `e_shnum` and
/// `e_shstrndx`.
const STRIP_REWRITES: [Range<usize>; 2] = [40..48, 60..64];

type Elf64 = FileHeader64<LE>;

/// More program headers than a linked program has (a handful): refused, so
/// the work stays bounded.
const MAX_SEGMENTS: usize = 4096;
/// More section headers than a linked program has (dozens): refused.
const MAX_SECTIONS: usize = 65_536;
/// The most characters of a section name a message quotes.
const MAX_NAME: usize = 64;

/// One ELF image, its headers read.
struct Elf<'data> {
    segments: &'data [ProgramHeader64<LE>],
    sections: SectionTable<'data, Elf64>,
    /// The `PT_LOAD`s' address ranges `(start, end)`, by start, each end
    /// the largest of its and every earlier one's: a range lies in a
    /// `PT_LOAD` exactly when it lies below that end at the last start at or
    /// below its own (one binary search).
    loads: Vec<(u64, u64)>,
}

impl<'data> Elf<'data> {
    fn parse(data: &'data [u8], which: &str) -> Result<Self, DistError> {
        let bad = |e: object::Error| {
            unreadable(
                STRIP,
                which,
                &format!("not a little-endian ELF64 image ({e})"),
            )
        };
        let header = Elf64::parse(data).map_err(bad)?;
        let endian = header.endian().map_err(bad)?;
        let segments = header.program_headers(endian, data).map_err(bad)?;
        let sections = header.sections(endian, data).map_err(bad)?;
        if segments.len() > MAX_SEGMENTS || sections.len() > MAX_SECTIONS {
            return Err(unreadable(
                STRIP,
                which,
                &format!(
                    "{} program headers and {} sections, more than a linked program has",
                    segments.len(),
                    sections.len()
                ),
            ));
        }
        // What the checks compare stays within twice the file: the
        // PT_LOADs' file ranges don't overlap in a linked program.
        let mapped = segments
            .iter()
            .filter(|s| s.p_type(LE) == object::elf::PT_LOAD)
            .fold(0u64, |sum, s| sum.saturating_add(s.p_filesz(LE)));
        if mapped > (data.len() as u64).saturating_mul(2) {
            return Err(unreadable(
                STRIP,
                which,
                "PT_LOADs whose file ranges overlap",
            ));
        }
        let mut loads: Vec<(u64, u64)> = segments
            .iter()
            .filter(|s| s.p_type(LE) == object::elf::PT_LOAD)
            .map(|s| {
                let start = s.p_vaddr(LE);
                (start, start.saturating_add(s.p_memsz(LE)))
            })
            .collect();
        loads.sort_unstable();
        let mut furthest = 0u64;
        for (_, end) in &mut loads {
            furthest = furthest.max(*end);
            *end = furthest;
        }
        Ok(Self {
            segments,
            sections,
            loads,
        })
    }

    /// Section `section`'s name, quoted, escaped and at most
    /// [`MAX_NAME`] characters (it comes from the file), or its index.
    fn name(&self, index: usize, section: &SectionHeader64<LE>) -> String {
        self.sections.section_name(LE, section).map_or_else(
            |_| format!("#{index}"),
            |name| {
                let name = String::from_utf8_lossy(name);
                let short: String = name.chars().take(MAX_NAME).collect();
                let cut = if short.len() < name.len() {
                    "\u{2026}"
                } else {
                    ""
                };
                format!("{short:?}{cut}")
            },
        )
    }

    /// The allocated sections a `PT_LOAD` maps, with their indexes, by
    /// address (then size and name): `strip` may reorder the section header
    /// table, which the loader never reads.
    fn loaded(&self) -> Vec<(usize, &'data SectionHeader64<LE>)> {
        let mut loaded: Vec<_> = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sh_flags(LE).contains(object::elf::SHF_ALLOC) && self.maps(s))
            .collect();
        loaded
            .sort_by_cached_key(|(index, s)| (s.sh_addr(LE), s.sh_size(LE), self.name(*index, s)));
        loaded
    }

    /// Whether a `PT_LOAD` maps `section`'s addresses (an allocated section
    /// no `PT_LOAD` maps is never loaded: in a linked program there is
    /// none).
    fn maps(&self, section: &SectionHeader64<LE>) -> bool {
        let (address, size) = (section.sh_addr(LE), section.sh_size(LE));
        let Some(end) = address.checked_add(size) else {
            return false;
        };
        // The PT_LOADs starting at or below the section's address.
        let below = self.loads.partition_point(|(start, _)| *start <= address);
        below
            .checked_sub(1)
            .and_then(|last| self.loads.get(last))
            .is_some_and(|(_, furthest)| end <= *furthest)
    }

    /// The section whose file data holds `at`, named.
    fn section_at(&self, at: usize) -> String {
        self.sections
            .iter()
            .enumerate()
            .find(|(_, s)| {
                s.file_range(LE).is_some_and(|(start, size)| {
                    offset(start)
                        .and_then(|start| span(start, offset(size)?))
                        .is_some_and(|range| range.contains(&at))
                })
            })
            .map_or_else(
                || "outside any section".to_owned(),
                |(index, s)| format!("in section {}", self.name(index, s)),
            )
    }
}

/// A program header's kind and place, for messages.
fn segment(index: usize, header: &ProgramHeader64<LE>) -> String {
    let kind = match header.p_type(LE) {
        object::elf::PT_LOAD => "PT_LOAD".to_owned(),
        object::elf::PT_DYNAMIC => "PT_DYNAMIC".to_owned(),
        object::elf::PT_INTERP => "PT_INTERP".to_owned(),
        object::elf::PT_TLS => "PT_TLS".to_owned(),
        object::elf::PT_GNU_RELRO => "PT_GNU_RELRO".to_owned(),
        other => format!("type {:#x}", other.0),
    };
    format!(
        "program header {index} ({kind} at file offset {:#x}, address {:#x})",
        header.p_offset(LE),
        header.p_vaddr(LE)
    )
}

/// Checks that stripping `before` into `after` (`strip --strip-all`) left
/// everything the loader maps as it was (the module docs list what is
/// compared).
///
/// # Errors
/// [`DistError::Layout`] naming the first change found (a section, a
/// program header, a mapped byte's file offset, an ELF header field), or
/// an image that isn't a readable little-endian ELF64 file.
pub fn check_strip(before: &[u8], after: &[u8]) -> Result<(), DistError> {
    let old = Elf::parse(before, "original")?;
    let new = Elf::parse(after, "stripped")?;
    // Every section the loader maps, by address: the most precise report.
    let (sections, kept) = (old.loaded(), new.loaded());
    for (n, &(index, a)) in sections.iter().enumerate() {
        let name = old.name(index, a);
        let Some(&(new_index, b)) = kept.get(n) else {
            return Err(changed(STRIP, &format!("section {name} is gone")));
        };
        let new_name = new.name(new_index, b);
        if new_name != name {
            return Err(changed(STRIP, &format!("section {name} is now {new_name}")));
        }
        for (what, x, y) in [
            (
                "type",
                u64::from(a.sh_type(LE).0),
                u64::from(b.sh_type(LE).0),
            ),
            ("flags", a.sh_flags(LE).0, b.sh_flags(LE).0),
            ("address", a.sh_addr(LE), b.sh_addr(LE)),
            ("size", a.sh_size(LE), b.sh_size(LE)),
        ] {
            if x != y {
                return Err(changed(
                    STRIP,
                    &format!("section {name}'s {what} ({x:#x}, now {y:#x})"),
                ));
            }
        }
        if a.sh_type(LE) != object::elf::SHT_NOBITS && a.sh_offset(LE) != b.sh_offset(LE) {
            return Err(changed(
                STRIP,
                &format!(
                    "section {name}'s file offset ({:#x}, now {:#x})",
                    a.sh_offset(LE),
                    b.sh_offset(LE)
                ),
            ));
        }
        let data = a
            .data(LE, before)
            .map_err(|e| unreadable(STRIP, "original", &format!("section {name}: {e}")))?;
        let new_data = b
            .data(LE, after)
            .map_err(|e| unreadable(STRIP, "stripped", &format!("section {name}: {e}")))?;
        if let Some(at) = difference(data, new_data, &[]) {
            return Err(changed(
                STRIP,
                &format!("section {name}'s contents, at byte {at:#x} of it"),
            ));
        }
    }
    if let Some(&(index, extra)) = kept.get(sections.len()) {
        return Err(changed(
            STRIP,
            &format!("a section was added: {}", new.name(index, extra)),
        ));
    }
    // Every program header, byte for byte.
    if old.segments.len() != new.segments.len() {
        return Err(changed(
            STRIP,
            &format!(
                "the program header count ({}, now {})",
                old.segments.len(),
                new.segments.len()
            ),
        ));
    }
    for (index, (a, b)) in old.segments.iter().zip(new.segments).enumerate() {
        if object::pod::bytes_of(a) != object::pod::bytes_of(b) {
            return Err(changed(STRIP, &segment(index, a)));
        }
    }
    // Every byte a PT_LOAD maps from the file, past the ELF header (below).
    for (index, a) in old.segments.iter().enumerate() {
        if a.p_type(LE) != object::elf::PT_LOAD {
            continue;
        }
        let range = offset(a.p_offset(LE))
            .zip(offset(a.p_filesz(LE)))
            .and_then(|(start, size)| span(start, size))
            .ok_or_else(|| unreadable(STRIP, "original", &segment(index, a)))?;
        let range = range.start.max(EHDR)..range.end;
        if range.is_empty() {
            continue;
        }
        let data = before.get(range.clone()).ok_or_else(|| {
            unreadable(
                STRIP,
                "original",
                &format!("{} reaches past the end of the file", segment(index, a)),
            )
        })?;
        let Some(new_data) = after.get(range.clone()) else {
            return Err(changed(
                STRIP,
                &format!("the file ends inside {}", segment(index, a)),
            ));
        };
        if let Some(at) = difference(data, new_data, &[]) {
            let at = range.start.saturating_add(at);
            return Err(changed(
                STRIP,
                &format!(
                    "the byte at file offset {at:#x} ({}), which {} maps",
                    old.section_at(at),
                    segment(index, a)
                ),
            ));
        }
    }
    // The ELF header, but what stripping rewrites.
    let header = before.get(..EHDR);
    let new_header = after.get(..EHDR);
    if let (Some(a), Some(b)) = (header, new_header)
        && let Some(at) = difference(a, b, &STRIP_REWRITES)
    {
        return Err(changed(
            STRIP,
            &format!("the ELF header's {}", field(&ELF_HEADER_FIELDS, at)),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PE

const STAMP: &str = "stamping";
const SIGN: &str = "signing";

/// `IMAGE_DIRECTORY_ENTRY_RESOURCE`.
const DIR_RESOURCE: usize = 2;
/// `IMAGE_DIRECTORY_ENTRY_SECURITY`: the certificate table.
const DIR_SECURITY: usize = 4;
/// A section header's size.
const SECTION_HEADER: usize = 40;
/// What a stamp's added section is: initialized data, read-only.
const RESOURCE_CHARACTERISTICS: u32 = 0x4000_0040;
/// `IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE`.
const CODE_OR_WRITABLE: u32 = 0x0000_0020 | 0x2000_0000 | 0x8000_0000;

/// The COFF header's fields, by offset into it.
const COFF_FIELDS: [(usize, &str); 7] = [
    (0, "Machine"),
    (2, "NumberOfSections"),
    (4, "TimeDateStamp"),
    (8, "PointerToSymbolTable"),
    (12, "NumberOfSymbols"),
    (16, "SizeOfOptionalHeader"),
    (18, "Characteristics"),
];

/// The PE32+ optional header's fields, by offset into it.
const OPTIONAL_FIELDS: [(usize, &str); 30] = [
    (0, "Magic"),
    (2, "MajorLinkerVersion"),
    (3, "MinorLinkerVersion"),
    (4, "SizeOfCode"),
    (8, "SizeOfInitializedData"),
    (12, "SizeOfUninitializedData"),
    (16, "AddressOfEntryPoint"),
    (20, "BaseOfCode"),
    (24, "ImageBase"),
    (32, "SectionAlignment"),
    (36, "FileAlignment"),
    (40, "MajorOperatingSystemVersion"),
    (42, "MinorOperatingSystemVersion"),
    (44, "MajorImageVersion"),
    (46, "MinorImageVersion"),
    (48, "MajorSubsystemVersion"),
    (50, "MinorSubsystemVersion"),
    (52, "Win32VersionValue"),
    (56, "SizeOfImage"),
    (60, "SizeOfHeaders"),
    (64, "CheckSum"),
    (68, "Subsystem"),
    (70, "DllCharacteristics"),
    (72, "SizeOfStackReserve"),
    (80, "SizeOfStackCommit"),
    (88, "SizeOfHeapReserve"),
    (96, "SizeOfHeapCommit"),
    (104, "LoaderFlags"),
    (108, "NumberOfRvaAndSizes"),
    (112, "DataDirectory"),
];

/// A section header's fields, by offset into it.
const SECTION_FIELDS: [(usize, &str); 10] = [
    (0, "Name"),
    (8, "VirtualSize"),
    (12, "VirtualAddress"),
    (16, "SizeOfRawData"),
    (20, "PointerToRawData"),
    (24, "PointerToRelocations"),
    (28, "PointerToLinenumbers"),
    (32, "NumberOfRelocations"),
    (34, "NumberOfLinenumbers"),
    (36, "Characteristics"),
];

/// The data directories' names.
const DIRECTORIES: [&str; 16] = [
    "export table",
    "import table",
    "resource table",
    "exception table",
    "certificate table",
    "base relocation table",
    "debug directory",
    "architecture",
    "global pointer",
    "TLS table",
    "load config table",
    "bound import table",
    "import address table",
    "delay import descriptor",
    "CLR runtime header",
    "reserved",
];

/// One PE32+ image, its headers' places read.
struct Pe<'data> {
    data: &'data [u8],
    /// The NT headers (`PE\0\0`).
    nt: usize,
    /// `SizeOfHeaders`: the headers the loader maps.
    headers: usize,
    /// The section table.
    table: usize,
    directory_count: usize,
    sections: &'data [ImageSectionHeader],
}

impl<'data> Pe<'data> {
    fn parse(data: &'data [u8], step: &str, which: &str) -> Result<Self, DistError> {
        let bad = |e: object::Error| unreadable(step, which, &format!("not a PE32+ image ({e})"));
        let dos = ImageDosHeader::parse(data).map_err(bad)?;
        let mut at = u64::from(dos.nt_headers_offset());
        let (nt_headers, directories) = ImageNtHeaders64::parse(data, &mut at).map_err(bad)?;
        let sections = nt_headers.sections(data, at).map_err(bad)?;
        let sections = sections.iter().as_slice();
        // What the checks compare stays within twice the file: sections'
        // file data don't overlap in a linked image.
        let raw = sections.iter().fold(0u64, |sum, s| {
            sum.saturating_add(u64::from(s.size_of_raw_data.get(LE)))
        });
        if raw > (data.len() as u64).saturating_mul(2) {
            return Err(unreadable(step, which, "sections whose file data overlap"));
        }
        let too_far = || unreadable(step, which, "an offset past this host's address space");
        Ok(Self {
            data,
            nt: offset(dos.nt_headers_offset()).ok_or_else(too_far)?,
            headers: offset(nt_headers.optional_header().size_of_headers()).ok_or_else(too_far)?,
            table: offset(at).ok_or_else(too_far)?,
            directory_count: directories.len(),
            sections,
        })
    }

    /// The COFF header's offset.
    fn coff(&self) -> Option<usize> {
        self.nt.checked_add(4)
    }

    /// The optional header's offset.
    fn optional(&self) -> Option<usize> {
        self.nt.checked_add(24)
    }

    /// Data directory `index`'s entry: its place in the file, and its RVA
    /// and size (zeros past the table).
    fn directory(&self, index: usize) -> Option<(Range<usize>, u32, u32)> {
        let at = self
            .optional()?
            .checked_add(112)?
            .checked_add(index.checked_mul(8)?)?;
        let place = span(at, 8)?;
        if index >= self.directory_count {
            return Some((place, 0, 0));
        }
        let entry = self.data.get(place.clone())?;
        let rva = u32::from_le_bytes(entry.get(..4)?.try_into().ok()?);
        let size = u32::from_le_bytes(entry.get(4..)?.try_into().ok()?);
        Some((place, rva, size))
    }

    /// A header field's place: `start` bytes into the optional header (or
    /// the COFF header, with `coff`), `len` long.
    fn field(&self, coff: bool, start: usize, len: usize) -> Option<Range<usize>> {
        let base = if coff { self.coff()? } else { self.optional()? };
        span(base.checked_add(start)?, len)
    }

    /// Section `index`'s header place in the file.
    fn section_header(&self, index: usize) -> Option<Range<usize>> {
        span(
            self.table.checked_add(index.checked_mul(SECTION_HEADER)?)?,
            SECTION_HEADER,
        )
    }

    /// A header byte's name: the structure and field it belongs to.
    fn header_field(&self, at: usize) -> String {
        let within = |start: Option<usize>, len: usize| {
            start
                .and_then(|start| Some((start, span(start, len)?)))
                .filter(|(_, range)| range.contains(&at))
                .map(|(start, _)| at.saturating_sub(start))
        };
        if at < 0x40 {
            return "the DOS header".to_owned();
        }
        if within(Some(self.nt), 4).is_some() {
            return "the PE signature".to_owned();
        }
        if let Some(at) = within(self.coff(), 20) {
            return format!("the COFF header's {}", field(&COFF_FIELDS, at));
        }
        if let Some(at) = within(self.optional(), 112) {
            return format!("the optional header's {}", field(&OPTIONAL_FIELDS, at));
        }
        let directories = self.optional().and_then(|o| o.checked_add(112));
        if let Some(at) = within(directories, self.directory_count.saturating_mul(8)) {
            let index = at.checked_div(8).unwrap_or_default();
            let name = DIRECTORIES.get(index).copied().unwrap_or("unknown");
            return format!("data directory {index} ({name})");
        }
        if let Some(at) = within(
            Some(self.table),
            self.sections
                .len()
                .saturating_add(1)
                .saturating_mul(SECTION_HEADER),
        ) {
            let index = at.checked_div(SECTION_HEADER).unwrap_or_default();
            let at = at.checked_rem(SECTION_HEADER).unwrap_or_default();
            return format!("section header {index}'s {}", field(&SECTION_FIELDS, at));
        }
        format!("the header byte at file offset {at:#x}")
    }

    /// The headers the loader maps.
    fn mapped_headers(&self) -> Option<&'data [u8]> {
        self.data.get(..self.headers)
    }

    /// A section's file data: `SizeOfRawData` bytes at `PointerToRawData`.
    fn raw(&self, section: &ImageSectionHeader) -> Option<&'data [u8]> {
        let size = offset(section.size_of_raw_data.get(LE))?;
        if size == 0 {
            return Some(&[]);
        }
        self.data
            .get(span(offset(section.pointer_to_raw_data.get(LE))?, size)?)
    }
}

/// A section's name, quoted and escaped (it comes from the file).
fn section_name(section: &ImageSectionHeader) -> String {
    let name = section.name.split(|b| *b == 0).next().unwrap_or_default();
    format!("{:?}", String::from_utf8_lossy(name))
}

/// Where a section ends in memory (`VirtualAddress` plus the larger of its
/// sizes) and in the file.
fn section_ends(section: &ImageSectionHeader) -> (u64, u64) {
    let virtual_size = section
        .virtual_size
        .get(LE)
        .max(section.size_of_raw_data.get(LE));
    (
        u64::from(section.virtual_address.get(LE)).saturating_add(u64::from(virtual_size)),
        u64::from(section.pointer_to_raw_data.get(LE))
            .saturating_add(u64::from(section.size_of_raw_data.get(LE))),
    )
}

/// Whether `[rva, rva + size)` lies in `section` in memory.
fn holds(section: &ImageSectionHeader, rva: u32, size: u32) -> bool {
    let start = u64::from(section.virtual_address.get(LE));
    let (end, _) = section_ends(section);
    u64::from(rva) >= start && u64::from(rva).saturating_add(u64::from(size)) <= end
}

/// The two images' headers in the same places.
fn same_places(step: &str, old: &Pe<'_>, new: &Pe<'_>) -> Result<(), DistError> {
    for (what, a, b) in [
        ("the NT headers' offset", old.nt, new.nt),
        ("SizeOfHeaders", old.headers, new.headers),
        ("the section table's offset", old.table, new.table),
        (
            "the number of data directories",
            old.directory_count,
            new.directory_count,
        ),
    ] {
        if a != b {
            return Err(changed(step, &format!("{what} ({a:#x}, now {b:#x})")));
        }
    }
    Ok(())
}

/// Section `index` (`a`, now `b`): its header unchanged but `masked`
/// (offsets into it), and its file data unchanged unless `data_may_change`.
fn same_section(
    step: &str,
    old: &Pe<'_>,
    new: &Pe<'_>,
    (a, b): (&ImageSectionHeader, &ImageSectionHeader),
    masked: &[Range<usize>],
    data_may_change: bool,
) -> Result<(), DistError> {
    let name = section_name(a);
    if let Some(at) = difference(object::pod::bytes_of(a), object::pod::bytes_of(b), masked) {
        return Err(changed(
            step,
            &format!("section {name}'s {}", field(&SECTION_FIELDS, at)),
        ));
    }
    if data_may_change {
        return Ok(());
    }
    let data = old.raw(a).ok_or_else(|| {
        unreadable(
            step,
            "original",
            &format!("section {name}'s data lies past the end of the file"),
        )
    })?;
    let Some(new_data) = new.raw(b) else {
        return Err(changed(
            step,
            &format!("the file ends inside section {name}'s data"),
        ));
    };
    if let Some(at) = difference(data, new_data, &[]) {
        return Err(changed(
            step,
            &format!(
                "section {name}'s data, at file offset {:#x}",
                u64::from(a.pointer_to_raw_data.get(LE)).saturating_add(at as u64)
            ),
        ));
    }
    Ok(())
}

/// The headers the loader maps unchanged but `masked`.
fn same_headers(
    step: &str,
    which: &str,
    old: &Pe<'_>,
    new: &Pe<'_>,
    masked: &[Range<usize>],
) -> Result<(), DistError> {
    let headers = old
        .mapped_headers()
        .ok_or_else(|| unreadable(step, "original", "SizeOfHeaders past the end of the file"))?;
    let Some(new_headers) = new.mapped_headers() else {
        return Err(changed(
            step,
            &format!("the {which} image ends inside its headers"),
        ));
    };
    if let Some(at) = difference(headers, new_headers, masked) {
        return Err(changed(step, &old.header_field(at)));
    }
    Ok(())
}

/// Checks that stamping a version resource into `before`
/// ([`crate::pe_version::stamp_version`]) left everything the loader maps
/// but the resources as it was (the module docs list what may change).
///
/// # Errors
/// [`DistError::Layout`] naming the first change found (a section's header
/// or data, the added section, a header field), or an image that isn't a
/// readable PE32+ file.
pub fn check_stamp(before: &[u8], after: &[u8]) -> Result<(), DistError> {
    let old = Pe::parse(before, STAMP, "original")?;
    let new = Pe::parse(after, STAMP, "stamped")?;
    same_places(STAMP, &old, &new)?;
    let count = old.sections.len();
    let appended = if new.sections.len() == count {
        false
    } else if Some(new.sections.len()) == count.checked_add(1) {
        true
    } else {
        return Err(changed(
            STAMP,
            &format!(
                "the section count ({count}, now {}): a stamp adds one section at most",
                new.sections.len()
            ),
        ));
    };
    let place = |range: Option<Range<usize>>| {
        range.ok_or_else(|| unreadable(STAMP, "original", "a header offset that overflows"))
    };
    let (resource_place, resource_rva, resource_size) = old
        .directory(DIR_RESOURCE)
        .ok_or_else(|| unreadable(STAMP, "original", "no resource data directory"))?;
    // What a stamp changes in the headers.
    let mut masked = vec![
        place(old.field(false, 8, 4))?,  // SizeOfInitializedData
        place(old.field(false, 56, 4))?, // SizeOfImage
        place(old.field(false, 64, 4))?, // CheckSum
        resource_place.clone(),
    ];
    if appended {
        masked.push(place(old.field(true, 2, 2))?); // NumberOfSections
        masked.push(place(old.section_header(count))?);
    }
    // The section a stamp may rewrite in place: the last one in memory and
    // in the file, starting with the resource directory, neither code nor
    // writable, and no other data directory pointing into it.
    let last_in_memory = old
        .sections
        .iter()
        .enumerate()
        .max_by_key(|(_, s)| s.virtual_address.get(LE));
    let file_end = old
        .sections
        .iter()
        .map(|s| section_ends(s).1)
        .max()
        .unwrap_or_default();
    let mut rewritable = None;
    if let (false, Some((index, last))) = (appended, last_in_memory)
        && resource_rva != 0
        && resource_size != 0
        && resource_rva == last.virtual_address.get(LE)
        && last.characteristics.get(LE).0 & CODE_OR_WRITABLE == 0
        && section_ends(last).1 == file_end
    {
        let mut alone = true;
        for directory in
            (0..old.directory_count).filter(|d| *d != DIR_RESOURCE && *d != DIR_SECURITY)
        {
            let (_, rva, size) = old.directory(directory).ok_or_else(|| {
                unreadable(STAMP, "original", "a data directory past the headers")
            })?;
            let start = u64::from(last.virtual_address.get(LE));
            let (end, _) = section_ends(last);
            if size != 0
                && u64::from(rva) < end
                && u64::from(rva).saturating_add(u64::from(size)) > start
            {
                alone = false;
            }
        }
        if alone {
            rewritable = Some(index);
            let header = place(old.section_header(index))?;
            // Its VirtualSize and SizeOfRawData.
            for field in [8..12, 16..20] {
                masked.push(place(
                    header
                        .start
                        .checked_add(field.start)
                        .zip(header.start.checked_add(field.end))
                        .map(|(start, end)| start..end),
                )?);
            }
        }
    }
    for (index, pair) in old.sections.iter().zip(new.sections).enumerate() {
        let rewritten = Some(index) == rewritable;
        let size_fields: &[Range<usize>] = if rewritten { &[8..12, 16..20] } else { &[] };
        same_section(STAMP, &old, &new, pair, size_fields, rewritten)?;
    }
    // Where the new resource directory is: in the added section, or in the
    // rewritten one; with neither, it may not move.
    let (_, new_rva, new_size) = new
        .directory(DIR_RESOURCE)
        .ok_or_else(|| unreadable(STAMP, "stamped", "no resource data directory"))?;
    if appended {
        let Some(added) = new.sections.get(count) else {
            return Err(changed(STAMP, "the added section is missing"));
        };
        let name = section_name(added);
        if added.characteristics.get(LE).0 != RESOURCE_CHARACTERISTICS {
            return Err(changed(
                STAMP,
                &format!(
                    "the added section {name} isn't read-only initialized data (characteristics {:#x})",
                    added.characteristics.get(LE).0
                ),
            ));
        }
        let start = (
            u64::from(added.virtual_address.get(LE)),
            u64::from(added.pointer_to_raw_data.get(LE)),
        );
        if let Some(other) = old.sections.iter().find(|s| {
            let (memory, file) = section_ends(s);
            start.0 < memory || (added.size_of_raw_data.get(LE) != 0 && start.1 < file)
        }) {
            return Err(changed(
                STAMP,
                &format!(
                    "the added section {name} doesn't come after section {}",
                    section_name(other)
                ),
            ));
        }
        if !holds(added, new_rva, new_size) || new_size == 0 {
            return Err(changed(
                STAMP,
                &format!("the resource directory isn't in the added section {name}"),
            ));
        }
    } else if let Some(index) = rewritable {
        let Some(section) = new.sections.get(index) else {
            return Err(changed(STAMP, "the rewritten resource section is missing"));
        };
        if !holds(section, new_rva, new_size) || new_size == 0 {
            return Err(changed(
                STAMP,
                &format!(
                    "the resource directory isn't in the rewritten section {}",
                    section_name(section)
                ),
            ));
        }
    } else {
        // Nothing added, nothing rewritable: the resources can't have moved.
        masked.retain(|range| *range != resource_place);
    }
    same_headers(STAMP, "stamped", &old, &new, &masked)
}

/// Checks that Authenticode-signing `before` left everything the loader
/// maps as it was: the same headers but the checksum and the certificate
/// table's data directory, the same section headers and data, and a
/// certificate table past every section's data.
///
/// # Errors
/// [`DistError::Layout`] naming the first change found, a missing or
/// misplaced certificate table, or an image that isn't a readable PE32+
/// file.
pub fn check_sign(before: &[u8], after: &[u8]) -> Result<(), DistError> {
    let old = Pe::parse(before, SIGN, "original")?;
    let new = Pe::parse(after, SIGN, "signed")?;
    same_places(SIGN, &old, &new)?;
    if old.sections.len() != new.sections.len() {
        return Err(changed(
            SIGN,
            &format!(
                "the section count ({}, now {})",
                old.sections.len(),
                new.sections.len()
            ),
        ));
    }
    for pair in old.sections.iter().zip(new.sections) {
        same_section(SIGN, &old, &new, pair, &[], false)?;
    }
    let (table_place, _, _) = old
        .directory(DIR_SECURITY)
        .ok_or_else(|| unreadable(SIGN, "original", "no certificate table directory"))?;
    let checksum = old
        .field(false, 64, 4)
        .ok_or_else(|| unreadable(SIGN, "original", "a header offset that overflows"))?;
    same_headers(SIGN, "signed", &old, &new, &[checksum, table_place])?;
    // The certificate table: present, in the file, after everything the
    // loader maps (its "RVA" is a file offset).
    let (_, table, size) = new
        .directory(DIR_SECURITY)
        .ok_or_else(|| unreadable(SIGN, "signed", "no certificate table directory"))?;
    if table == 0 || size == 0 {
        return Err(changed(SIGN, "no certificate table was added"));
    }
    let loaded_end = old
        .sections
        .iter()
        .map(|s| section_ends(s).1)
        .max()
        .unwrap_or_default()
        .max(old.headers as u64);
    if u64::from(table) < loaded_end {
        return Err(changed(
            SIGN,
            &format!(
                "the certificate table (file offset {table:#x}) overlaps the loaded data, which ends at {loaded_end:#x}"
            ),
        ));
    }
    if u64::from(table).saturating_add(u64::from(size)) > after.len() as u64 {
        return Err(changed(
            SIGN,
            "the certificate table reaches past the end of the file",
        ));
    }
    Ok(())
}
