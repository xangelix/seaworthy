//! `dist_archive` — seaworthy's reproducible archive writers (the Linux
//! tarball and the Windows zip) over arbitrary entry lists, each archive
//! read back by an independent reader written here.
//!
//! Input: entries separated by `\n`, at most 24. An entry's first byte
//! picks directory (`d`) or file (anything else) and its mode; the rest is
//! `path` or `path=contents` (UTF-8, or the input is skipped).
//! Invariants: nothing panics; tar refuses a name only when ustar can't
//! hold it, and zip accepts every name tar accepts. What either writer
//! accepts reads back exactly: every ustar header's checksum verifies, its
//! prefix and name rejoin to the entry's path (with a trailing `/` for a
//! directory), its size, mode, owner and data are the entry's, in path
//! order, and two zero blocks end it; every zip entry's local header and
//! central record agree, its CRC-32 matches, and it inflates to the
//! entry's bytes.

use seaworthy::archive::{ArchiveError, Entry, crc32, tar_zst, zip};

fn entries(data: &[u8]) -> Option<Vec<Entry>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut entries = Vec::new();
    for line in text.split('\n').take(24) {
        let mut chars = line.chars();
        let Some(kind) = chars.next() else { continue };
        let rest = chars.as_str();
        let mode = 0o600 | (u32::from(kind) & 0o177);
        if kind == 'd' {
            entries.push(Entry {
                path: rest.to_owned(),
                mode: 0o755,
                data: None,
            });
        } else {
            let (path, contents) = rest.split_once('=').unwrap_or((rest, ""));
            entries.push(Entry {
                path: path.to_owned(),
                mode,
                data: Some(contents.as_bytes().to_vec()),
            });
        }
    }
    Some(entries)
}

/// The rules a name must meet in both formats (the writers' own check,
/// restated): relative, `/`-separated, no empty, `.` or `..` segment, no
/// backslash or control character.
fn plain(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Whether ustar's 100-byte name and 155-byte prefix can hold `name`.
fn ustar_fits(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() <= 100 {
        return true;
    }
    (0..b.len().saturating_sub(1)).any(|i| b[i] == b'/' && i <= 155 && b.len() - i - 1 <= 100)
}

fn octal(field: &[u8]) -> u64 {
    let text = std::str::from_utf8(field).unwrap().trim_end_matches('\0');
    u64::from_str_radix(text, 8).unwrap()
}

fn check_tar(sorted: &[&Entry], compressed: &[u8]) {
    let tar = zstd::bulk::decompress(compressed, 64 << 20).expect("our zstd decompresses");
    assert_eq!(tar.len() % 512, 0);
    let mut at = 0;
    for entry in sorted {
        let header = &tar[at..at + 512];
        let mut sum: u64 = header.iter().map(|b| u64::from(*b)).sum();
        sum =
            sum - header[148..156].iter().map(|b| u64::from(*b)).sum::<u64>() + 8 * u64::from(b' ');
        assert_eq!(octal(&header[148..154]), sum, "header checksum");
        let field = |r: std::ops::Range<usize>| {
            let f = &header[r];
            String::from_utf8(f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())].to_vec())
                .unwrap()
        };
        let (name, prefix) = (field(0..100), field(345..500));
        let joined = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let directory = entry.data.is_none();
        let want = if directory {
            format!("{}/", entry.path)
        } else {
            entry.path.clone()
        };
        assert_eq!(joined, want, "the name rejoins");
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(header[156], if directory { b'5' } else { b'0' });
        assert_eq!(octal(&header[100..107]), u64::from(entry.mode & 0o7777));
        assert_eq!(
            (octal(&header[108..115]), octal(&header[116..123])),
            (0, 0),
            "root-owned"
        );
        let size = usize::try_from(octal(&header[124..135])).unwrap();
        let data = entry.data.as_deref().unwrap_or(&[]);
        assert_eq!(size, data.len());
        at += 512;
        assert_eq!(&tar[at..at + size], data);
        at += size.next_multiple_of(512);
    }
    assert_eq!(tar.len() - at, 1024, "two zero blocks end it");
    assert!(tar[at..].iter().all(|b| *b == 0));
}

fn u16_at(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn check_zip(sorted: &[&Entry], z: &[u8]) {
    let end = z.len() - 22;
    assert_eq!(u32_at(z, end), 0x0605_4b50, "end record");
    assert_eq!(u16_at(z, end + 10), sorted.len());
    let mut central = u32_at(z, end + 16) as usize;
    assert_eq!(
        central + u32_at(z, end + 12) as usize,
        end,
        "the directory ends at the end record"
    );
    for entry in sorted {
        assert_eq!(u32_at(z, central), 0x0201_4b50);
        let name_len = u16_at(z, central + 28);
        let name = std::str::from_utf8(&z[central + 46..central + 46 + name_len]).unwrap();
        let directory = entry.data.is_none();
        assert_eq!(
            name,
            if directory {
                format!("{}/", entry.path)
            } else {
                entry.path.clone()
            }
        );
        let (crc, csize, size) = (
            u32_at(z, central + 16),
            u32_at(z, central + 20) as usize,
            u32_at(z, central + 24) as usize,
        );
        let external = u32_at(z, central + 38);
        assert_eq!(external >> 16 & 0o7777, entry.mode & 0o7777);
        let local = u32_at(z, central + 42) as usize;
        assert_eq!(u32_at(z, local), 0x0403_4b50);
        assert_eq!(
            &z[local + 14..local + 26],
            &z[central + 16..central + 28],
            "local and central agree"
        );
        assert_eq!(u16_at(z, local + 26), name_len);
        let start = local + 30 + name_len;
        let stored = &z[start..start + csize];
        let data = entry.data.as_deref().unwrap_or(&[]);
        let plain = if u16_at(z, central + 10) == 8 {
            miniz_oxide::inflate::decompress_to_vec(stored).expect("inflates")
        } else {
            stored.to_vec()
        };
        assert_eq!(plain, data);
        assert_eq!((size, crc), (data.len(), crc32(data)));
        central += 46 + name_len;
    }
}

pub fn run(data: &[u8]) {
    let Some(entries) = entries(data) else { return };
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let duplicate = sorted.windows(2).any(|w| w[0].path == w[1].path);
    let tar = tar_zst(&entries, 1_700_000_000);
    let zipped = zip(&entries, 1_700_000_000);
    let all_plain = entries.iter().all(|e| plain(&e.path));
    match &tar {
        Ok(bytes) => {
            assert!(all_plain && !duplicate);
            check_tar(&sorted, bytes);
            assert!(zipped.is_ok(), "zip accepts what tar accepts");
        }
        Err(ArchiveError::Duplicate(_)) => assert!(duplicate),
        Err(ArchiveError::Name(_)) => assert!(
            !all_plain
                || entries.iter().any(|e| {
                    let name = if e.data.is_none() {
                        format!("{}/", e.path)
                    } else {
                        e.path.clone()
                    };
                    e.path.len() > 255 || !ustar_fits(&name)
                }),
            "tar refused a name ustar can hold"
        ),
        Err(e) => panic!("unexpected {e}"),
    }
    if let Ok(bytes) = &zipped {
        assert!(all_plain && !duplicate);
        check_zip(&sorted, bytes);
    }
}
