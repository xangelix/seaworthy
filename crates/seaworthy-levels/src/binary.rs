//! Reading the records out of a binary without loading it.
//!
//! A core's requirement record lives in a `.cpureq` section and a
//! launcher's CPU list in a `.cpulist` section (both within PE's 8-character
//! section-name limit); on macOS, where a section belongs to a segment, in
//! `__DATA,__cpureq` and `__DATA,__cpulist`. [`read_requirement`] and
//! [`read_cpu_list`] parse the file through a read cache — the headers, the
//! section table, whatever the format parser needs (for ELF, the symbol
//! tables), and the one section; never the whole image, nothing executed,
//! memory bounded by the file's size — and accept exactly three formats:
//! ELF (Linux), PE (Windows) and a single-architecture Mach-O (macOS; a
//! universal binary is refused). The section must appear exactly once; its
//! raw size may exceed [`MAX_RECORD_BYTES`] by at most 4 KiB of
//! file-alignment padding, and the record inside it may not exceed
//! [`MAX_RECORD_BYTES`].

use std::fs::File;
use std::path::Path;

use object::{Object, ObjectSection, ReadCache};

use crate::record::{CpuList, MAX_RECORD_BYTES, RecordError, Requirement};

/// The section carrying a core's requirement record (ELF and PE).
pub const RECORD_SECTION: &str = ".cpureq";
/// The section carrying a launcher's CPU list (ELF and PE).
pub const CPULIST_SECTION: &str = ".cpulist";
/// The Mach-O segment both records live in.
pub const MACHO_SEGMENT: &str = "__DATA";
/// The Mach-O section carrying a core's requirement record (in
/// [`MACHO_SEGMENT`]: `__DATA,__cpureq`).
pub const MACHO_RECORD_SECTION: &str = "__cpureq";
/// The Mach-O section carrying a launcher's CPU list (`__DATA,__cpulist`).
pub const MACHO_CPULIST_SECTION: &str = "__cpulist";

/// Which record a section holds, named per format.
#[derive(Clone, Copy)]
struct Kind {
    /// The ELF and PE section name.
    section: &'static str,
    /// The Mach-O section name, in [`MACHO_SEGMENT`].
    macho: &'static str,
    /// `segment,section`, for messages about a Mach-O.
    macho_label: &'static str,
}

const RECORD: Kind = Kind {
    section: RECORD_SECTION,
    macho: MACHO_RECORD_SECTION,
    macho_label: "__DATA,__cpureq",
};

const CPULIST: Kind = Kind {
    section: CPULIST_SECTION,
    macho: MACHO_CPULIST_SECTION,
    macho_label: "__DATA,__cpulist",
};

/// Why a record could not be read from a binary.
#[derive(Debug)]
pub enum BinaryError {
    /// The file could not be opened or read.
    Io(std::io::Error),
    /// Not a parseable object file.
    NotAnObject(String),
    /// An object file, but neither ELF nor PE (the format's name).
    UnsupportedFormat(&'static str),
    /// The section is absent: not a core (or launcher) built with
    /// seaworthy-launcher.
    NoSection(&'static str),
    /// The section appears more than once.
    DuplicateSection(&'static str),
    /// The section is larger than a record can be.
    TooLarge(u64),
    /// The section's contents are not a valid record.
    Record(RecordError),
}

impl core::fmt::Display for BinaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read the file: {e}"),
            Self::NotAnObject(e) => write!(f, "not an executable or library: {e}"),
            Self::UnsupportedFormat(format) => {
                write!(
                    f,
                    "{format} binaries are not supported (ELF, PE and Mach-O only)"
                )
            }
            Self::NoSection(name) => {
                write!(f, "no `{name}` section (not built with seaworthy-launcher)")
            }
            Self::DuplicateSection(name) => {
                write!(f, "the `{name}` section appears more than once")
            }
            Self::TooLarge(size) => write!(
                f,
                "a {size}-byte record section exceeds {MAX_RECORD_BYTES} bytes"
            ),
            Self::Record(e) => write!(f, "malformed record: {e}"),
        }
    }
}

impl std::error::Error for BinaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Record(e) => Some(e),
            _ => None,
        }
    }
}

/// The bytes of the `kind` section of the object file `data`.
fn section_bytes<'data, R: object::ReadRef<'data>>(
    data: R,
    kind: Kind,
) -> Result<Vec<u8>, BinaryError> {
    if matches!(
        object::FileKind::parse(data),
        Ok(object::FileKind::MachOFat32 | object::FileKind::MachOFat64)
    ) {
        return Err(BinaryError::UnsupportedFormat(
            "universal (multi-architecture) Mach-O",
        ));
    }
    let file = object::File::parse(data).map_err(|e| BinaryError::NotAnObject(e.to_string()))?;
    let macho = match file.format() {
        object::BinaryFormat::Elf | object::BinaryFormat::Pe => false,
        object::BinaryFormat::MachO => true,
        object::BinaryFormat::Coff => return Err(BinaryError::UnsupportedFormat("COFF object")),
        object::BinaryFormat::Wasm => return Err(BinaryError::UnsupportedFormat("WebAssembly")),
        object::BinaryFormat::Xcoff => return Err(BinaryError::UnsupportedFormat("XCOFF")),
        _ => return Err(BinaryError::UnsupportedFormat("this")),
    };
    let (name, label) = if macho {
        (kind.macho, kind.macho_label)
    } else {
        (kind.section, kind.section)
    };
    let mut matches = file.sections().filter(|section| {
        section.name() == Ok(name) && (!macho || section.segment_name() == Ok(Some(MACHO_SEGMENT)))
    });
    let section = matches.next().ok_or(BinaryError::NoSection(label))?;
    if matches.next().is_some() {
        return Err(BinaryError::DuplicateSection(label));
    }
    let limit = u64::try_from(MAX_RECORD_BYTES).unwrap_or(u64::MAX);
    // A PE section's raw size is rounded up to the file alignment (typically
    // 512 bytes): allow that much padding past the record limit.
    let padded_limit = limit.saturating_add(4096);
    if section.size() > padded_limit {
        return Err(BinaryError::TooLarge(section.size()));
    }
    let bytes = section
        .data()
        .map_err(|e| BinaryError::NotAnObject(e.to_string()))?;
    // Trailing NUL padding is not part of the record.
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let record = bytes.get(..end).unwrap_or_default();
    if record.len() > MAX_RECORD_BYTES {
        return Err(BinaryError::TooLarge(
            u64::try_from(record.len()).unwrap_or(u64::MAX),
        ));
    }
    Ok(record.to_vec())
}

fn file_section(path: &Path, kind: Kind) -> Result<Vec<u8>, BinaryError> {
    let file = File::open(path).map_err(BinaryError::Io)?;
    let cache = ReadCache::new(file);
    section_bytes(&cache, kind)
}

/// Reads and parses the requirement record of the core at `path`.
///
/// # Errors
/// [`BinaryError`]: unreadable, not ELF, PE or a single-architecture
/// Mach-O, no (or a repeated, or an oversized) `.cpureq` section
/// (`__DATA,__cpureq` in a Mach-O), or a malformed record.
pub fn read_requirement(path: &Path) -> Result<Requirement, BinaryError> {
    let bytes = file_section(path, RECORD)?;
    Requirement::parse(&bytes).map_err(BinaryError::Record)
}

/// Reads and parses the CPU list of the launcher at `path`.
///
/// # Errors
/// As [`read_requirement`], for the `.cpulist` section (`__DATA,__cpulist`
/// in a Mach-O).
pub fn read_cpu_list(path: &Path) -> Result<CpuList, BinaryError> {
    let bytes = file_section(path, CPULIST)?;
    CpuList::parse(&bytes).map_err(BinaryError::Record)
}

/// [`read_requirement`] over an in-memory image.
///
/// # Errors
/// As [`read_requirement`].
pub fn requirement_from_bytes(image: &[u8]) -> Result<Requirement, BinaryError> {
    let bytes = section_bytes(image, RECORD)?;
    Requirement::parse(&bytes).map_err(BinaryError::Record)
}

/// [`read_cpu_list`] over an in-memory image.
///
/// # Errors
/// As [`read_cpu_list`].
pub fn cpu_list_from_bytes(image: &[u8]) -> Result<CpuList, BinaryError> {
    let bytes = section_bytes(image, CPULIST)?;
    CpuList::parse(&bytes).map_err(BinaryError::Record)
}
