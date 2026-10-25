//! Reproducible archives of a laid-out tree: the Linux tarball
//! (`.tar.zst`) and the Windows zip.
//!
//! Both are written here, not through general-purpose archive crates. The
//! formats needed are small (ustar headers; zip local headers, central
//! directory and end record with deflate), and writing them directly makes
//! every byte deterministic:
//!
//! - entries sorted by path;
//! - every timestamp the caller's (`SOURCE_DATE_EPOCH`; zip holds
//!   1980-01-01 to 2107-12-31 and clamps to that range);
//! - owner and group `root` (0/0);
//! - modes from the caller (the layout's 0755; directories 0755).
//!
//! The same tree always gives the same archive, byte for byte.
//! `tests/archive.rs` reads both back with the system's `tar`/`bsdtar` and
//! checks names, modes, sizes and contents.
//!
//! Limits: tar entry names up to 255 bytes (ustar's prefix + name split)
//! and files under 8 GiB (ustar's size field); zip files under 4 GiB and
//! 65,535 entries (no zip64). A core is tens of megabytes; anything
//! larger is refused, never truncated.

/// One entry: a path relative to the archive root (`/`-separated, no
/// leading `/`), its mode and its bytes (`None` for a directory).
#[derive(Debug, Clone)]
pub struct Entry {
    /// The path inside the archive.
    pub path: String,
    /// The Unix mode (permission bits).
    pub mode: u32,
    /// The file's bytes; `None` for a directory.
    pub data: Option<Vec<u8>>,
}

/// Why an archive couldn't be written.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// A name the format can't hold.
    #[error(
        "{0:?} can't be an archive entry name (empty, absolute, `..`, a backslash, or over 255 bytes)"
    )]
    Name(String),
    /// A file too large for the format.
    #[error("{0} is too large for the archive format")]
    TooLarge(String),
    /// Two entries with one path.
    #[error("{0:?} is in the archive twice")]
    Duplicate(String),
    /// Compression failed.
    #[error("compression: {0}")]
    Compress(String),
}

fn check_name(path: &str, max: usize) -> Result<(), ArchiveError> {
    let bad = path.is_empty()
        || path.len() > max
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || path.chars().any(char::is_control);
    if bad {
        Err(ArchiveError::Name(path.to_owned()))
    } else {
        Ok(())
    }
}

/// The entries sorted by path; a path given twice is refused.
fn sorted(entries: &[Entry]) -> Result<Vec<&Entry>, ArchiveError> {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some(pair) = sorted
        .windows(2)
        .find(|pair| pair.first().map(|e| &e.path) == pair.get(1).map(|e| &e.path))
    {
        let path = pair.first().map(|e| e.path.clone()).unwrap_or_default();
        return Err(ArchiveError::Duplicate(path));
    }
    Ok(sorted)
}

// ---------------------------------------------------------------------------
// tar (ustar) + zstd

/// Writes `value` as `width - 1` octal digits and a NUL; `false` when it
/// doesn't fit (never truncated).
fn octal(field: &mut [u8], value: u64) -> bool {
    let Some(digits) = field.len().checked_sub(1) else {
        return false;
    };
    let text = format!("{value:0digits$o}");
    if text.len() != digits {
        return false;
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    true
}

/// Splits a ustar name into (prefix, name): the name field holds 100
/// bytes, the prefix 155, joined by a `/` that neither stores. The split
/// is at the first `/` that leaves at most 100 bytes after it, so the
/// name part is never empty (a directory's trailing `/` stays in it).
fn ustar_split(name: &str) -> Option<(&str, &str)> {
    if name.len() <= 100 {
        return Some(("", name));
    }
    let bytes = name.as_bytes();
    let last = bytes.len().checked_sub(1)?;
    let at = bytes
        .iter()
        .enumerate()
        .position(|(i, b)| *b == b'/' && i < last && bytes.len() - i - 1 <= 100)?;
    // `at` indexes an ASCII '/', so both slices are on char boundaries.
    (at <= 155).then(|| (&name[..at], &name[at + 1..]))
}

fn tar_header(
    path: &str,
    mode: u32,
    size: u64,
    directory: bool,
    mtime: u64,
) -> Result<[u8; 512], ArchiveError> {
    check_name(path, 255)?;
    let mut header = [0u8; 512];
    let name = if directory {
        format!("{path}/")
    } else {
        path.to_owned()
    };
    let (prefix, base) = ustar_split(&name).ok_or_else(|| ArchiveError::Name(path.to_owned()))?;
    header[..base.len()].copy_from_slice(base.as_bytes());
    let fits = octal(&mut header[100..108], u64::from(mode & 0o7777))
        && octal(&mut header[108..116], 0) // uid
        && octal(&mut header[116..124], 0) // gid
        && octal(&mut header[136..148], mtime);
    if !fits {
        return Err(ArchiveError::TooLarge(format!("{path}'s timestamp")));
    }
    if !octal(&mut header[124..136], size) {
        return Err(ArchiveError::TooLarge(path.to_owned()));
    }
    header[148..156].fill(b' '); // checksum placeholder
    header[156] = if directory { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u64 = header.iter().map(|b| u64::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(text.as_bytes());
    Ok(header)
}

/// A ustar archive of `entries`, compressed with zstd (level 19).
///
/// # Errors
/// [`ArchiveError`] for a name the format can't hold, or a compression
/// failure.
pub fn tar_zst(entries: &[Entry], mtime: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut tar = Vec::new();
    for entry in sorted(entries)? {
        let size = entry.data.as_ref().map_or(0, Vec::len);
        let size = u64::try_from(size).map_err(|_| ArchiveError::TooLarge(entry.path.clone()))?;
        let header = tar_header(&entry.path, entry.mode, size, entry.data.is_none(), mtime)?;
        tar.extend_from_slice(&header);
        if let Some(data) = &entry.data {
            tar.extend_from_slice(data);
            tar.resize(tar.len().next_multiple_of(512), 0);
        }
    }
    tar.extend_from_slice(&[0u8; 1024]); // two zero blocks end the archive
    zstd::bulk::compress(&tar, 19).map_err(|e| ArchiveError::Compress(e.to_string()))
}

// ---------------------------------------------------------------------------
// zip (deflate)

/// CRC-32 (IEEE 802.3, the zip and gzip checksum).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    const fn table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut n = 0;
        while n < 256 {
            let mut c = n as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[n] = c;
            n += 1;
        }
        table
    }
    const TABLE: [u32; 256] = table();
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc = TABLE[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

/// A UTC civil date and time: (year, month, day, hour, minute, second).
pub type Civil = (u64, u64, u64, u64, u64, u64);

/// The UTC civil date and time of a Unix timestamp (Howard Hinnant's
/// days-to-civil algorithm, for dates from 1970 on).
#[must_use]
pub fn civil(unix: u64) -> Civil {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day, secs / 3600, secs % 3600 / 60, secs % 60)
}

/// RFC 3339 for a Unix timestamp (`1980-01-01T00:00:00Z`), as nFPM's
/// `mtime` takes it.
#[must_use]
pub fn rfc3339(unix: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// The earliest time a zip holds: 1980-01-01T00:00:00Z.
pub const ZIP_EPOCH: u64 = 315_532_800;

/// The latest time a zip holds: 2107-12-31T23:59:58Z.
pub const ZIP_END: u64 = 4_354_819_198;

/// MS-DOS time and date for a Unix timestamp, clamped to what a zip
/// holds (1980 to 2107, two-second resolution).
fn dos_time(unix: u64) -> (u16, u16) {
    let (y, mo, d, h, mi, s) = civil(unix.clamp(ZIP_EPOCH, ZIP_END));
    // In range after the clamp: year - 1980 <= 127, every other field
    // within its bit width.
    let field = |v: u64| u16::try_from(v).unwrap_or(0);
    let date = (field(y - 1980) << 9) | (field(mo) << 5) | field(d);
    let time = (field(h) << 11) | (field(mi) << 5) | field(s / 2);
    (time, date)
}

/// A zip archive of `entries`, files deflated, with Unix modes in the
/// external attributes (`unzip` and Explorer both read it).
///
/// # Errors
/// [`ArchiveError`] for a name the format can't hold, or a file of 4 GiB
/// or more.
pub fn zip(entries: &[Entry], mtime: u64) -> Result<Vec<u8>, ArchiveError> {
    let (time, date) = dos_time(mtime);
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    for entry in sorted(entries)? {
        check_name(&entry.path, 65_535)?;
        let directory = entry.data.is_none();
        let name = if directory {
            format!("{}/", entry.path)
        } else {
            entry.path.clone()
        };
        let raw = entry.data.as_deref().unwrap_or(&[]);
        let too_large =
            |n: usize| u32::try_from(n).map_err(|_| ArchiveError::TooLarge(entry.path.clone()));
        let (method, stored) = if directory {
            (0u16, Vec::new())
        } else {
            (8u16, miniz_oxide::deflate::compress_to_vec(raw, 9))
        };
        let crc = crc32(raw);
        let offset = too_large(out.len())?;
        let (compressed, size) = (too_large(stored.len())?, too_large(raw.len())?);
        let name_len =
            u16::try_from(name.len()).map_err(|_| ArchiveError::Name(entry.path.clone()))?;
        // Local file header.
        let mut local = Vec::with_capacity(30 + name.len());
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&time.to_le_bytes());
        local.extend_from_slice(&date.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&compressed.to_le_bytes());
        local.extend_from_slice(&size.to_le_bytes());
        local.extend_from_slice(&name_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // no extra field
        local.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&local);
        out.extend_from_slice(&stored);
        // Central directory record.
        let kind = if directory { 0o040_000 } else { 0o100_000 };
        let external = ((kind | (entry.mode & 0o7777)) << 16) | if directory { 0x10 } else { 0 };
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes()); // made by Unix, 2.0
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&time.to_le_bytes());
        central.extend_from_slice(&date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&compressed.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&external.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        count = count
            .checked_add(1)
            .ok_or_else(|| ArchiveError::TooLarge("the entry count".to_owned()))?;
    }
    let central_offset =
        u32::try_from(out.len()).map_err(|_| ArchiveError::TooLarge("the archive".to_owned()))?;
    let central_size = u32::try_from(central.len())
        .map_err(|_| ArchiveError::TooLarge("the directory".to_owned()))?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // no comment
    Ok(out)
}
