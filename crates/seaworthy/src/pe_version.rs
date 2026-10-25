//! A version resource stamped into a linked Windows binary:
//! `VS_VERSIONINFO` with the release's file and product
//! versions, the vendor, the product's name and the file's own name.
//!
//! Rust binaries carry no version resource. Without one, Windows Installer
//! falls back to its rules for unversioned files (modification dates), and
//! Explorer, Defender and inventory tools can't tell one build from
//! another. `seaworthy` never compiles, so it adds the resource to the
//! linked image, before Authenticode signing:
//!
//! - The image's resource tree (or an empty one) is rebuilt with the
//!   version entry (type 16, id 1, language en-US) replaced, in a new
//!   section appended after the last one. Every other resource (an icon, a
//!   UAC manifest) is copied into it with its data, as a linker lays a tree
//!   out: the directory and all its data in one section, inside the
//!   resource data directory's range. The old section stays mapped, unread.
//!   (Windows refused to start an executable whose manifest and icons were
//!   left behind in the linker's `.rsrc`, "not a valid Win32 application",
//!   although Wine ran it.) When the resource directory is already the
//!   image's last section and nothing else lives there (a section this
//!   module wrote, or a linker's trailing `.rsrc`), that section is
//!   rewritten in place instead, so stamping again never needs more header
//!   room.
//! - The headers are updated: the section count, `SizeOfImage`,
//!   `SizeOfInitializedData`, the resource data directory, and the PE
//!   checksum.
//! - Refused rather than risked: an image that isn't PE32+ AMD64, one
//!   already Authenticode-signed (stamping would break the signature), one
//!   with data after its last section (a COFF symbol table, an overlay),
//!   one whose data directories don't fit its optional header or reach
//!   past its last section, one whose `SizeOfHeaders` reaches into a
//!   section's data, one breaking the format's alignment rules or with
//!   sections overlapping in memory, and one without room for one more
//!   section header before its first section's data.
//!
//! `FileVersion` is `major.minor.patch.sequence` (the sequence clamped to
//! the 16 bits the field holds), `ProductVersion` the release as written
//! (`1.4.0-rc.2`), and a pre-release sets `VS_FF_PRERELEASE`.

use crate::DistError;
use crate::version::Release;

/// `RT_VERSION`.
pub const RT_VERSION: u16 = 16;
/// `RT_MANIFEST`.
pub const RT_MANIFEST: u16 = 24;
/// en-US.
pub const LANG_EN_US: u16 = 0x0409;

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS: u16 = 0x20b;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const SECTION_HEADER: usize = 40;
/// `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ`.
const RSRC_CHARACTERISTICS: u32 = 0x4000_0040;

fn refused(why: &str) -> DistError {
    DistError::Layout(format!("version resource: {why}"))
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, DistError> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| refused("truncated image"))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, DistError> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| refused("truncated image"))
}

fn put_u16(b: &mut [u8], at: usize, value: u16) -> Result<(), DistError> {
    b.get_mut(at..at + 2)
        .ok_or_else(|| refused("truncated image"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(b: &mut [u8], at: usize, value: u32) -> Result<(), DistError> {
    b.get_mut(at..at + 4)
        .ok_or_else(|| refused("truncated image"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align(value: u64, to: u64) -> Result<u64, DistError> {
    if to == 0 || !to.is_power_of_two() {
        return Err(refused("an alignment that isn't a power of two"));
    }
    value
        .checked_add(to - 1)
        .map(|v| v & !(to - 1))
        .ok_or_else(|| refused("an overflowing size"))
}

fn to_u32(value: u64) -> Result<u32, DistError> {
    u32::try_from(value).map_err(|_| refused("an image over 4 GiB"))
}

fn to_usize(value: u32) -> Result<usize, DistError> {
    usize::try_from(value).map_err(|_| refused("an offset beyond this host's address space"))
}

/// The headers' offsets.
struct Layout {
    coff: usize,
    optional: usize,
    sections: usize,
    count: usize,
    section_alignment: u32,
    file_alignment: u32,
    size_of_headers: u32,
    directories: usize,
    directory_count: u32,
}

#[derive(Clone, Copy)]
struct Section {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
}

fn layout(pe: &[u8]) -> Result<Layout, DistError> {
    if pe.get(..2) != Some(b"MZ") {
        return Err(refused("not a PE image"));
    }
    let header = to_usize(u32_at(pe, 0x3c)?)?;
    if pe.get(header..header + 4) != Some(b"PE\0\0") {
        return Err(refused("not a PE image"));
    }
    let coff = header + 4;
    if u16_at(pe, coff)? != IMAGE_FILE_MACHINE_AMD64 {
        return Err(refused("not an AMD64 image"));
    }
    let count = usize::from(u16_at(pe, coff + 2)?);
    let optional_size = usize::from(u16_at(pe, coff + 16)?);
    let optional = coff + 20;
    if u16_at(pe, optional)? != PE32_PLUS {
        return Err(refused("not PE32+"));
    }
    let directory_count = u32_at(pe, optional + 108)?;
    if directory_count <= u32::try_from(DIR_SECURITY).unwrap_or(4) {
        return Err(refused("too few data directories"));
    }
    // The data directories end inside the optional header: past it they
    // would be the section table, and writing the resource entry would
    // overwrite a section header.
    if directory_count > 16 || optional_size < 112 + 8 * to_usize(directory_count)? {
        return Err(refused(
            "data directories that don't fit the optional header",
        ));
    }
    Ok(Layout {
        coff,
        optional,
        sections: optional + optional_size,
        count,
        section_alignment: u32_at(pe, optional + 32)?,
        file_alignment: u32_at(pe, optional + 36)?,
        size_of_headers: u32_at(pe, optional + 60)?,
        directories: optional + 112,
        directory_count,
    })
}

fn sections(pe: &[u8], l: &Layout) -> Result<Vec<Section>, DistError> {
    (0..l.count)
        .map(|i| {
            let at = l.sections + i * SECTION_HEADER;
            let mut name = [0u8; 8];
            name.copy_from_slice(
                pe.get(at..at + 8)
                    .ok_or_else(|| refused("a truncated section table"))?,
            );
            Ok(Section {
                name,
                virtual_size: u32_at(pe, at + 8)?,
                virtual_address: u32_at(pe, at + 12)?,
                raw_size: u32_at(pe, at + 16)?,
                raw_pointer: u32_at(pe, at + 20)?,
                characteristics: u32_at(pe, at + 36)?,
            })
        })
        .collect()
}

fn directory(pe: &[u8], l: &Layout, index: usize) -> Result<(u32, u32), DistError> {
    let at = l.directories + index * 8;
    Ok((u32_at(pe, at)?, u32_at(pe, at + 4)?))
}

/// An RVA's file offset.
fn rva_offset(sections: &[Section], rva: u32) -> Option<usize> {
    sections.iter().find_map(|s| {
        let size = s.virtual_size.max(s.raw_size);
        (rva >= s.virtual_address
            && rva - s.virtual_address < size
            && rva - s.virtual_address < s.raw_size)
            .then(|| s.raw_pointer.checked_add(rva - s.virtual_address))
            .flatten()
            .and_then(|offset| usize::try_from(offset).ok())
    })
}

// ---------------------------------------------------------------------------
// The resource tree

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    // Named entries sort before id entries, names by code units.
    Name(Vec<u16>),
    Id(u32),
}

#[derive(Clone, Debug)]
enum Node {
    Dir(Vec<(Key, Node)>),
    /// A data entry: its bytes (read from the image, or new) and code page.
    Data {
        data: Vec<u8>,
        codepage: u32,
    },
}

const MAX_DEPTH: usize = 3;
const MAX_ENTRIES: usize = 4096;

/// A data entry's bytes, which must lie within one section's file data
/// (empty data has none to read).
fn data_at(pe: &[u8], secs: &[Section], rva: u32, size: u32) -> Result<Vec<u8>, DistError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let at = secs
        .iter()
        .find_map(|s| {
            let start = rva.checked_sub(s.virtual_address)?;
            (u64::from(start) + u64::from(size) <= u64::from(s.raw_size))
                .then(|| u64::from(s.raw_pointer) + u64::from(start))
        })
        .ok_or_else(|| refused("resource data that isn't within one section's file data"))?;
    let at = usize::try_from(at).map_err(|_| refused("a bad resource offset"))?;
    pe.get(at..at + to_usize(size)?)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| refused("resource data past the end of the image"))
}

/// The tree at `offset` from the directory at file offset `base`, its data
/// read. `budget` bounds the entries; `bytes` the data copied, at the
/// image's size (a tree's data entries never share bytes, so more means a
/// tree built to make the copy huge).
fn parse_dir(
    pe: &[u8],
    secs: &[Section],
    base: usize,
    offset: usize,
    depth: usize,
    budget: &mut usize,
    bytes: &mut usize,
) -> Result<Node, DistError> {
    if depth >= MAX_DEPTH {
        return Err(refused("a resource tree deeper than type/name/language"));
    }
    let at = base
        .checked_add(offset)
        .ok_or_else(|| refused("a bad resource offset"))?;
    let named = usize::from(u16_at(pe, at + 12)?);
    let ids = usize::from(u16_at(pe, at + 14)?);
    let total = named + ids;
    *budget = budget
        .checked_sub(total)
        .ok_or_else(|| refused("too many resource entries"))?;
    let mut entries = Vec::with_capacity(total);
    for i in 0..total {
        let entry = at + 16 + i * 8;
        let name = u32_at(pe, entry)?;
        let target = u32_at(pe, entry + 4)?;
        let key = if name & 0x8000_0000 != 0 {
            let string = base + to_usize(name & 0x7fff_ffff)?;
            let len = usize::from(u16_at(pe, string)?);
            let units = (0..len)
                .map(|j| u16_at(pe, string + 2 + j * 2))
                .collect::<Result<Vec<_>, _>>()?;
            Key::Name(units)
        } else if name > 0xFFFF {
            // Windows reads an id as its low 16 bits: 0x10001 is id 1, and
            // keeping it apart would leave two entries for one key.
            return Err(refused("a resource id past 16 bits"));
        } else {
            Key::Id(name)
        };
        let node = if target & 0x8000_0000 != 0 {
            parse_dir(
                pe,
                secs,
                base,
                to_usize(target & 0x7fff_ffff)?,
                depth + 1,
                budget,
                bytes,
            )?
        } else {
            let entry = base + to_usize(target)?;
            let size = u32_at(pe, entry + 4)?;
            *bytes = bytes
                .checked_sub(to_usize(size)?)
                .ok_or_else(|| refused("resource data larger than the image"))?;
            Node::Data {
                data: data_at(pe, secs, u32_at(pe, entry)?, size)?,
                codepage: u32_at(pe, entry + 8)?,
            }
        };
        entries.push((key, node));
    }
    // One entry per key at every level: with two, a reader would take
    // either, and replacing one would leave the other in force.
    let mut keys: Vec<&Key> = entries.iter().map(|(key, _)| key).collect();
    keys.sort();
    if keys.windows(2).any(|pair| pair.first() == pair.last()) {
        return Err(refused("a resource directory lists one key twice"));
    }
    Ok(Node::Dir(entries))
}

fn dir_entries(node: &mut Node) -> Result<&mut Vec<(Key, Node)>, DistError> {
    match node {
        Node::Dir(entries) => Ok(entries),
        _ => Err(refused("a resource data entry where a directory belongs")),
    }
}

/// Sets `type/name/lang` to `data` in `root`, replacing every entry of that
/// type and name (whatever its language).
fn set(
    root: &mut Node,
    type_id: u16,
    name_id: u16,
    lang: u16,
    data: Vec<u8>,
) -> Result<(), DistError> {
    let types = dir_entries(root)?;
    let type_key = Key::Id(u32::from(type_id));
    if !types.iter().any(|(k, _)| *k == type_key) {
        types.push((type_key.clone(), Node::Dir(Vec::new())));
    }
    let (_, type_dir) = types
        .iter_mut()
        .find(|(k, _)| *k == type_key)
        .ok_or_else(|| refused("internal"))?;
    let names = dir_entries(type_dir)?;
    let name_key = Key::Id(u32::from(name_id));
    names.retain(|(k, _)| *k != name_key);
    names.push((
        name_key,
        Node::Dir(vec![(
            Key::Id(u32::from(lang)),
            Node::Data { data, codepage: 0 },
        )]),
    ));
    Ok(())
}

/// The serialized tree: directories first, then data entries, then name
/// strings, then the data (each piece 8-aligned), with RVAs relative to
/// `section_rva`.
fn serialize(root: &Node, section_rva: u32) -> Result<Vec<u8>, DistError> {
    // Pass 1: sizes and offsets, breadth first.
    fn sorted(entries: &[(Key, Node)]) -> Vec<&(Key, Node)> {
        let mut v: Vec<&(Key, Node)> = entries.iter().collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
    let mut dirs: Vec<&Node> = vec![root];
    let mut i = 0;
    while let Some(node) = dirs.get(i).copied() {
        if let Node::Dir(entries) = node {
            for (_, child) in sorted(entries) {
                if matches!(child, Node::Dir(_)) {
                    dirs.push(child);
                }
            }
        }
        i += 1;
    }
    let dir_size = |node: &Node| match node {
        Node::Dir(entries) => 16 + 8 * entries.len(),
        _ => 0,
    };
    let mut dir_offsets = Vec::with_capacity(dirs.len());
    let mut cursor = 0usize;
    for node in &dirs {
        dir_offsets.push(cursor);
        cursor += dir_size(node);
    }
    // Leaves and names in the same traversal order.
    let mut leaves: Vec<&Node> = Vec::new();
    let mut names: Vec<&Vec<u16>> = Vec::new();
    for node in &dirs {
        if let Node::Dir(entries) = node {
            for (key, child) in sorted(entries) {
                if let Key::Name(units) = key {
                    names.push(units);
                }
                if !matches!(child, Node::Dir(_)) {
                    leaves.push(child);
                }
            }
        }
    }
    let leaves_offset = cursor.next_multiple_of(8);
    let names_offset = leaves_offset + 16 * leaves.len();
    let mut name_offsets = Vec::with_capacity(names.len());
    let mut cursor = names_offset;
    for units in &names {
        name_offsets.push(cursor);
        cursor += 2 + 2 * units.len();
    }
    let mut data_offsets = Vec::with_capacity(leaves.len());
    let mut cursor = cursor.next_multiple_of(8);
    for (l, leaf) in leaves.iter().enumerate() {
        match leaf {
            // Empty data points at its own data entry: an address inside
            // the section (the tree's end may be just past it).
            Node::Data { data, .. } if data.is_empty() => data_offsets.push(leaves_offset + 16 * l),
            Node::Data { data, .. } => {
                data_offsets.push(cursor);
                cursor = (cursor + data.len()).next_multiple_of(8);
            }
            Node::Dir(_) => return Err(refused("internal")),
        }
    }
    let total = cursor;
    // Pass 2: write.
    let mut out = vec![0u8; total];
    let w32 =
        |out: &mut Vec<u8>, at: usize, v: u32| -> Result<(), DistError> { put_u32(out, at, v) };
    let off32 = |v: usize| u32::try_from(v).map_err(|_| refused("a resource tree over 4 GiB"));
    let mut leaf_index = 0;
    let mut name_index = 0;
    let mut child_dir = 1;
    for (d, node) in dirs.iter().enumerate() {
        let Node::Dir(entries) = node else { continue };
        let at = dir_offsets[d];
        let named = entries
            .iter()
            .filter(|(k, _)| matches!(k, Key::Name(_)))
            .count();
        put_u16(
            &mut out,
            at + 12,
            u16::try_from(named).map_err(|_| refused("too many named entries"))?,
        )?;
        put_u16(
            &mut out,
            at + 14,
            u16::try_from(entries.len() - named).map_err(|_| refused("too many id entries"))?,
        )?;
        for (e, (key, child)) in sorted(entries).into_iter().enumerate() {
            let entry = at + 16 + e * 8;
            match key {
                Key::Id(id) => w32(&mut out, entry, *id)?,
                Key::Name(_) => {
                    w32(
                        &mut out,
                        entry,
                        0x8000_0000 | off32(name_offsets[name_index])?,
                    )?;
                    name_index += 1;
                }
            }
            if matches!(child, Node::Dir(_)) {
                w32(
                    &mut out,
                    entry + 4,
                    0x8000_0000 | off32(dir_offsets[child_dir])?,
                )?;
                child_dir += 1;
            } else {
                w32(&mut out, entry + 4, off32(leaves_offset + 16 * leaf_index)?)?;
                leaf_index += 1;
            }
        }
    }
    for (l, leaf) in leaves.iter().enumerate() {
        let at = leaves_offset + 16 * l;
        let Node::Data { data, codepage } = leaf else {
            return Err(refused("internal"));
        };
        let offset = data_offsets[l];
        out[offset..offset + data.len()].copy_from_slice(data);
        let rva = section_rva
            .checked_add(off32(offset)?)
            .ok_or_else(|| refused("an RVA over 4 GiB"))?;
        w32(&mut out, at, rva)?;
        w32(&mut out, at + 4, off32(data.len())?)?;
        w32(&mut out, at + 8, *codepage)?;
    }
    for (n, units) in names.iter().enumerate() {
        let at = name_offsets[n];
        put_u16(
            &mut out,
            at,
            u16::try_from(units.len()).map_err(|_| refused("a long resource name"))?,
        )?;
        for (j, unit) in units.iter().enumerate() {
            put_u16(&mut out, at + 2 + 2 * j, *unit)?;
        }
    }
    Ok(out)
}

/// The PE checksum (`CheckSumMappedFile`'s algorithm): 16-bit one's
/// complement sum of the image with the checksum field taken as zero, plus
/// the file length.
fn checksum(pe: &[u8], field: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, chunk) in pe.chunks(2).enumerate() {
        if i * 2 == field || i * 2 == field + 2 {
            continue;
        }
        let word = u64::from(chunk[0]) | chunk.get(1).map_or(0, |b| u64::from(*b) << 8);
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    u32::try_from(sum + pe.len() as u64).unwrap_or(0)
}

/// `pe` with resource `type_id/name_id/lang` set to `data`, every other
/// resource kept.
///
/// # Errors
/// [`DistError::Layout`] for an image the module refuses (see the module
/// docs) or a malformed resource tree.
pub fn set_resource(
    pe: &[u8],
    type_id: u16,
    name_id: u16,
    lang: u16,
    data: &[u8],
) -> Result<Vec<u8>, DistError> {
    let l = layout(pe)?;
    let secs = sections(pe, &l)?;
    let (security_rva, security_size) = directory(pe, &l, DIR_SECURITY)?;
    if security_rva != 0 || security_size != 0 {
        return Err(refused(
            "the image is Authenticode-signed; stamp before signing",
        ));
    }
    if u32_at(pe, l.coff + 8)? != 0 {
        return Err(refused(
            "the image carries a COFF symbol table after its sections",
        ));
    }
    let raw_end = secs
        .iter()
        .map(|s| u64::from(s.raw_pointer) + u64::from(s.raw_size))
        .max()
        .unwrap_or(u64::from(l.size_of_headers));
    if raw_end != pe.len() as u64 {
        return Err(refused("the image has data after its last section"));
    }
    // The PE format's own rules, which every linker keeps: FileAlignment a
    // power of two from 512 to 64 KiB, SectionAlignment a power of two at
    // least that, and sections that don't overlap in memory.
    if !(0x200..=0x1_0000).contains(&l.file_alignment)
        || !l.file_alignment.is_power_of_two()
        || !l.section_alignment.is_power_of_two()
        || l.section_alignment < l.file_alignment
    {
        return Err(refused(
            "a file or section alignment outside the PE format's rules",
        ));
    }
    let mut by_address: Vec<&Section> = secs.iter().collect();
    by_address.sort_by_key(|s| s.virtual_address);
    for pair in by_address.windows(2) {
        if let [a, b] = pair
            && u64::from(a.virtual_address) + u64::from(a.virtual_size.max(a.raw_size))
                > u64::from(b.virtual_address)
        {
            return Err(refused("sections that overlap in memory"));
        }
    }
    // Where the image's sections end in memory: a new section goes after
    // it, so no data directory may reach past it (one that did would point
    // into the new resource tree).
    let virtual_end = secs
        .iter()
        .map(|s| u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size)))
        .max()
        .unwrap_or(0)
        .max(u64::from(l.size_of_headers));
    for d in 0..to_usize(l.directory_count.min(16))? {
        // The certificate table's "RVA" is a file offset (and refused above).
        if d == DIR_SECURITY {
            continue;
        }
        let (rva, size) = directory(pe, &l, d)?;
        if size != 0 && u64::from(rva) + u64::from(size) > virtual_end {
            return Err(refused(
                "a data directory reaches past the image's last section",
            ));
        }
    }
    let (rsrc_rva, rsrc_size) = directory(pe, &l, DIR_RESOURCE)?;
    // Rewrite the last section in place only when it is a resource section
    // and nothing else: named `.rsrc` (or this module's `.rsrcv`), starting
    // with the resource directory, neither code nor writable, and no other
    // data directory pointing into it. Anything else in it would be lost.
    // It must also be the last section in the file, with file data after
    // the headers: the rewrite truncates the file at its start.
    let last = secs
        .iter()
        .enumerate()
        .max_by_key(|(_, s)| s.virtual_address)
        .map(|(i, s)| (i, *s));
    let replace = match last {
        Some((index, section))
            if rsrc_rva != 0
                && rsrc_size != 0
                && rsrc_rva == section.virtual_address
                && (&section.name == b".rsrc\0\0\0" || &section.name == b".rsrcv\0\0")
                && section.characteristics & 0x8000_0000 == 0 // MEM_WRITE
                && section.raw_size != 0
                && section.raw_pointer >= l.size_of_headers
                && u64::from(section.raw_pointer) + u64::from(section.raw_size) == raw_end =>
        {
            let code = section.characteristics & 0x2000_0020 != 0; // MEM_EXECUTE | CNT_CODE
            let mut shared = false;
            for d in 0..to_usize(l.directory_count.min(16))? {
                if d == DIR_RESOURCE {
                    continue;
                }
                let (rva, size) = directory(pe, &l, d)?;
                let start = u64::from(section.virtual_address);
                let end = start + u64::from(section.virtual_size.max(section.raw_size));
                if size != 0 && u64::from(rva) < end && u64::from(rva) + u64::from(size) > start {
                    shared = true;
                }
            }
            (!code && !shared).then_some((index, section))
        }
        _ => None,
    };
    // Room for one more section header, in zeroed header padding.
    let table_end = l.sections + l.count * SECTION_HEADER;
    let first_data = secs
        .iter()
        .filter(|s| s.raw_size != 0)
        .map(|s| to_usize(s.raw_pointer))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .min()
        .unwrap_or(to_usize(l.size_of_headers)?);
    // The headers end before any section's data (a linker sets
    // SizeOfHeaders to the first section's file offset or less).
    if to_usize(l.size_of_headers)? > first_data {
        return Err(refused("SizeOfHeaders reaches into a section's data"));
    }
    if replace.is_none()
        && (table_end + SECTION_HEADER > to_usize(l.size_of_headers)?.min(first_data)
            || pe
                .get(table_end..table_end + SECTION_HEADER)
                .is_none_or(|b| b.iter().any(|x| *x != 0)))
    {
        return Err(refused("no room for another section header"));
    }
    // The current tree, or an empty one.
    let mut root = if rsrc_rva == 0 || rsrc_size == 0 {
        Node::Dir(Vec::new())
    } else {
        let base = rva_offset(&secs, rsrc_rva)
            .ok_or_else(|| refused("the resource directory isn't in a section"))?;
        parse_dir(
            pe,
            &secs,
            base,
            0,
            0,
            &mut MAX_ENTRIES.clone(),
            &mut pe.len(),
        )?
    };
    set(&mut root, type_id, name_id, lang, data.to_vec())?;
    // Where the tree goes: the replaced section's slot, or a new one after
    // the last section (and never inside the headers).
    let (va, raw_pointer, header, old_raw) = match replace {
        Some((index, section)) => (
            section.virtual_address,
            section.raw_pointer,
            l.sections + index * SECTION_HEADER,
            section.raw_size,
        ),
        None => (
            to_u32(align(virtual_end, u64::from(l.section_alignment))?)?,
            to_u32(align(raw_end, u64::from(l.file_alignment))?)?,
            table_end,
            0,
        ),
    };
    let tree = serialize(&root, va)?;
    let tree_len = u64::try_from(tree.len()).map_err(|_| refused("a huge tree"))?;
    let raw_size = to_u32(align(tree_len, u64::from(l.file_alignment))?)?;
    let mut out = pe.to_vec();
    out.resize(to_usize(raw_pointer)?, 0);
    out.extend_from_slice(&tree);
    out.resize(to_usize(raw_pointer)? + to_usize(raw_size)?, 0);
    if replace.is_none() {
        let has_rsrc = (0..l.count).any(|i| {
            let at = l.sections + i * SECTION_HEADER;
            pe.get(at..at + 8) == Some(b".rsrc\0\0\0".as_slice())
        });
        let name: &[u8; 8] = if has_rsrc {
            b".rsrcv\0\0"
        } else {
            b".rsrc\0\0\0"
        };
        out[header..header + 8].copy_from_slice(name);
        put_u32(&mut out, header + 36, RSRC_CHARACTERISTICS)?;
        put_u16(
            &mut out,
            l.coff + 2,
            u16::try_from(l.count + 1).map_err(|_| refused("too many sections"))?,
        )?;
    }
    put_u32(&mut out, header + 8, to_u32(tree_len)?)?;
    put_u32(&mut out, header + 12, va)?;
    put_u32(&mut out, header + 16, raw_size)?;
    put_u32(&mut out, header + 20, raw_pointer)?;
    let image_end = align(u64::from(va) + tree_len, u64::from(l.section_alignment))?;
    put_u32(&mut out, l.optional + 56, to_u32(image_end)?)?;
    let initialized = u32_at(&out, l.optional + 8)?;
    put_u32(
        &mut out,
        l.optional + 8,
        initialized.saturating_sub(old_raw).saturating_add(raw_size),
    )?;
    put_u32(&mut out, l.directories + DIR_RESOURCE * 8, va)?;
    put_u32(
        &mut out,
        l.directories + DIR_RESOURCE * 8 + 4,
        to_u32(tree_len)?,
    )?;
    let field = l.optional + 64;
    if field % 2 != 0 {
        return Err(refused("a misaligned optional header"));
    }
    let sum = checksum(&out, field);
    put_u32(&mut out, field, sum)?;
    let _ = l.directory_count;
    Ok(out)
}

/// Whether `pe` carries an Authenticode signature (a certificate table).
///
/// # Errors
/// [`DistError::Layout`] for an image that isn't PE32+ AMD64.
pub fn is_signed(pe: &[u8]) -> Result<bool, DistError> {
    let l = layout(pe)?;
    let (offset, size) = directory(pe, &l, DIR_SECURITY)?;
    Ok(offset != 0 || size != 0)
}

/// What a version resource names.
#[derive(Debug, Clone)]
pub struct VersionInfo<'a> {
    /// The vendor (`CompanyName`).
    pub company: &'a str,
    /// The product's display name (`ProductName`).
    pub product: &'a str,
    /// What this file is (`FileDescription`).
    pub description: &'a str,
    /// The file name (`OriginalFilename`; `InternalName` is its stem).
    pub file_name: &'a str,
    /// Whether the file is a DLL (`VFT_DLL`) rather than an application.
    pub dll: bool,
}

fn utf16z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One version node: header, key, padding, value, padding, children.
fn node(
    key: &str,
    value: &[u8],
    value_length: u16,
    text: bool,
    children: &[Vec<u8>],
) -> Result<Vec<u8>, DistError> {
    let mut out = vec![0u8; 6];
    for unit in utf16z(key) {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.resize(out.len().next_multiple_of(4), 0);
    out.extend_from_slice(value);
    for child in children {
        out.resize(out.len().next_multiple_of(4), 0);
        out.extend_from_slice(child);
    }
    let length = u16::try_from(out.len()).map_err(|_| refused("a version resource over 64 KiB"))?;
    put_u16(&mut out, 0, length)?;
    put_u16(&mut out, 2, value_length)?;
    put_u16(&mut out, 4, u16::from(text))?;
    Ok(out)
}

fn string(key: &str, value: &str) -> Result<Vec<u8>, DistError> {
    let units = utf16z(value);
    let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    node(
        key,
        &bytes,
        u16::try_from(units.len()).map_err(|_| refused("a long version string"))?,
        true,
        &[],
    )
}

/// The `VS_VERSIONINFO` blob for `release`.
///
/// # Errors
/// [`DistError::Layout`] for a release past the fields' 16 bits (MSI's
/// limits already refuse those) or a blob over 64 KiB.
pub fn version_blob(release: &Release, info: &VersionInfo<'_>) -> Result<Vec<u8>, DistError> {
    let v = &release.version;
    let word = |n: u64| u16::try_from(n).map_err(|_| refused("a version number past 65535"));
    let build = u16::try_from(release.sequence).unwrap_or(u16::MAX);
    let (major, minor, patch) = (word(v.major)?, word(v.minor)?, word(v.patch)?);
    let ms = (u32::from(major) << 16) | u32::from(minor);
    let ls = (u32::from(patch) << 16) | u32::from(build);
    let mut fixed = Vec::with_capacity(52);
    for value in [
        0xFEEF_04BDu32,                        // dwSignature
        0x0001_0000,                           // dwStrucVersion
        ms,                                    // dwFileVersionMS
        ls,                                    // dwFileVersionLS
        ms,                                    // dwProductVersionMS
        ls,                                    // dwProductVersionLS
        0x3F,                                  // dwFileFlagsMask
        if v.pre.is_some() { 0x2 } else { 0 }, // VS_FF_PRERELEASE
        0x0004_0004,                           // VOS_NT_WINDOWS32
        if info.dll { 2 } else { 1 },          // VFT_DLL / VFT_APP
        0,                                     // dwFileSubtype
        0,                                     // dwFileDateMS
        0,                                     // dwFileDateLS
    ] {
        fixed.extend_from_slice(&value.to_le_bytes());
    }
    let file_version = format!("{major}.{minor}.{patch}.{build}");
    let stem = info
        .file_name
        .rsplit_once('.')
        .map_or(info.file_name, |(stem, _)| stem);
    let strings = [
        string("CompanyName", info.company)?,
        string("FileDescription", info.description)?,
        string("FileVersion", &file_version)?,
        string("InternalName", stem)?,
        string("OriginalFilename", info.file_name)?,
        string("ProductName", info.product)?,
        string("ProductVersion", &v.to_string())?,
    ];
    let table = node("040904B0", &[], 0, true, &strings)?;
    let string_info = node("StringFileInfo", &[], 0, true, &[table])?;
    let translation = node("Translation", &[0x09, 0x04, 0xB0, 0x04], 4, false, &[])?;
    let var_info = node("VarFileInfo", &[], 0, true, &[translation])?;
    node(
        "VS_VERSION_INFO",
        &fixed,
        52,
        false,
        &[string_info, var_info],
    )
}

/// `pe` with its version resource set for `release` (see the module docs).
///
/// # Errors
/// As [`set_resource`] and [`version_blob`].
pub fn stamp_version(
    pe: &[u8],
    release: &Release,
    info: &VersionInfo<'_>,
) -> Result<Vec<u8>, DistError> {
    set_resource(pe, RT_VERSION, 1, LANG_EN_US, &version_blob(release, info)?)
}
