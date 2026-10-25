//! [`StoragePath`]: a validated, portable, traversal-proof relative object
//! key.
//!
//! The same validation governs every key the client writes, reads, lists
//! or deletes, and it is conservative on purpose: a key that is valid here
//! can also be materialized safely as a relative path on any filesystem a
//! published repository may be mirrored to, and no key can escape a root.

use std::fmt;

use super::StorageError;

/// Maximum path length in bytes (the S3 key limit; well above any portable
/// filesystem component sum we care about).
pub const MAX_PATH_BYTES: usize = 1024;

/// Windows-reserved device names (case-insensitive, with or without an
/// extension): not portable, so rejected in every segment.
const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
    "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

/// A validated relative object path.
///
/// Validation (all at construction; the type is unforgeable afterwards):
///
/// - never absolute, never empty, never ends in `/`;
/// - no `.` / `..` / empty segments (no traversal, one canonical form);
/// - no control bytes (`0x00..=0x1F`, `0x7F`);
/// - no Windows-unsafe characters (`< > : " | ? * \\`): backslash is a
///   separator on Windows, so it is rejected everywhere;
/// - no Windows-reserved device-name segments (`CON`, `NUL`, `COM1`,
///   `CONIN$`, `CONOUT$`, …);
/// - no segment ending in `.` or a space: Windows strips both, so `a.`
///   and `a` would name ONE file there (two keys, one object);
/// - the final segment never matches `.upload-*.tmp`: that namespace is
///   reserved for a filesystem mirror's upload temporaries, which such a
///   mirror hides from listings and reaps, so an object wearing it would
///   silently vanish there;
/// - ASCII only (one conservative alphabet, the same on every backend);
/// - at most [`MAX_PATH_BYTES`] bytes.
///
/// `/` is the only separator. **Case is significant**: `Report.pdf` and
/// `report.pdf` are distinct keys.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoragePath(String);

impl StoragePath {
    /// Validate `path` into a [`StoragePath`].
    ///
    /// # Errors
    /// [`StorageError::InvalidPath`] on any rule violation (see the type
    /// docs).
    pub fn new(path: impl AsRef<str>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        let reject = |why: &str| StorageError::InvalidPath(format!("{path:?}: {why}"));

        if path.is_empty() {
            return Err(reject("empty path"));
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(reject("path too long"));
        }
        if path.starts_with('/') {
            return Err(reject("absolute paths are not allowed"));
        }
        if path.ends_with('/') {
            return Err(reject("trailing '/' is not allowed"));
        }
        if !path.is_ascii() {
            // Non-ASCII keys are legal on S3, but one conservative alphabet
            // keeps keys interchangeable with filesystem paths everywhere.
            return Err(reject("only ASCII paths are portable across backends"));
        }
        for segment in path.split('/') {
            if segment.is_empty() {
                return Err(reject("empty segment ('//')"));
            }
            if segment == "." || segment == ".." {
                return Err(reject("'.' and '..' segments are not allowed"));
            }
            for &byte in segment.as_bytes() {
                if byte <= 0x1F || byte == 0x7F {
                    return Err(reject("control bytes are not allowed"));
                }
                if matches!(byte, b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' | b'\\') {
                    return Err(reject("character is not portable across backends"));
                }
            }
            // Windows (and SMB shares) silently strip a trailing dot or
            // space: `report.` and `report` would alias one file.
            if segment.ends_with(['.', ' ']) {
                return Err(reject(
                    "segment ends in '.' or a space (aliases on Windows)",
                ));
            }
            let stem = segment.split('.').next().unwrap_or(segment);
            if RESERVED_NAMES
                .iter()
                .any(|name| stem.eq_ignore_ascii_case(name))
            {
                return Err(reject("segment is a reserved device name"));
            }
        }
        // The upload-temporary namespace is reserved in the FINAL segment:
        // a filesystem mirror mints its temporaries as `.upload-*.tmp` next
        // to the object, hides that pattern from listings and deletes
        // stale matches. Only the final segment collides (temporaries are
        // files).
        if path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(".upload-") && name.ends_with(".tmp"))
        {
            return Err(reject(
                "final segment is in the reserved .upload-*.tmp temp namespace",
            ));
        }
        Ok(Self(path.to_owned()))
    }

    /// The validated path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path segments (`/`-separated).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The final segment (the "file name").
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }
}

impl fmt::Display for StoragePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for StoragePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StoragePath({:?})", self.0)
    }
}

impl TryFrom<String> for StoragePath {
    type Error = StorageError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for StoragePath {
    type Error = StorageError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StoragePath> for String {
    fn from(value: StoragePath) -> Self {
        value.0
    }
}

impl AsRef<str> for StoragePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_portable_paths() {
        for good in [
            "a",
            "a/b/c.bin",
            "scan-2026/org_123/report-09.04.tar.zst",
            "a b/c+d,e=f'g(h)i[j]k{l}m;n#o%p@q!r`s~t&u^v$w",
        ] {
            StoragePath::new(good).unwrap_or_else(|e| panic!("{good:?} must be valid: {e}"));
        }
    }

    #[test]
    fn rejects_traversal_and_unportable_paths() {
        for bad in [
            "",
            "/abs",
            "a/",
            "a//b",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "../etc/passwd",
            "a\\b",
            "C:/autoexec.bat",
            "a:b",
            "a<b",
            "a>b",
            "a|b",
            "a?b",
            "a*b",
            "a\"b",
            "CON",
            "con.txt",
            "a/NUL/b",
            "aux",
            "COM1",
            "lpt9.dat",
            "CONIN$",
            "conout$.txt",
            "a.",
            "a ",
            "dir./x",
            "dir /x",
            "a\0b",
            "a\nb",
            "a\u{7f}b",
            "héllo",
        ] {
            assert!(
                StoragePath::new(bad).is_err(),
                "{bad:?} must be rejected as invalid"
            );
        }
    }

    #[test]
    fn rejects_overlong_paths() {
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert!(matches!(
            StoragePath::new(&long),
            Err(StorageError::InvalidPath(_))
        ));
        StoragePath::new("a".repeat(MAX_PATH_BYTES)).expect("at the cap is fine");
    }

    #[test]
    fn upload_temp_namespace_is_reserved() {
        // A filesystem mirror's upload temporaries are `.upload-*.tmp` in
        // the object directory; the mirror hides that pattern and reaps
        // stale matches, so an object allowed to wear it would vanish
        // there. The pattern is reserved in the FINAL segment.
        for bad in [".upload-x.tmp", "backups/.upload-2026.tmp", ".upload-.tmp"] {
            assert!(
                matches!(StoragePath::new(bad), Err(StorageError::InvalidPath(_))),
                "{bad:?} is the reserved temp namespace"
            );
        }
        // Near-misses and non-final segments stay legal (a DIRECTORY named
        // `.upload-x.tmp` never collides: temporaries are files).
        for good in [
            "backups/.upload-2026.bak",
            ".upload-x.tmp.bak",
            "a/.upload-x.tmp/b.bin",
            "upload-1.tmp",
            ".uploads/x.tmp",
        ] {
            StoragePath::new(good).unwrap_or_else(|e| panic!("{good:?} must stay valid: {e}"));
        }
    }

    #[test]
    fn accessors_and_conversions() {
        let path = StoragePath::new("apt/dists/stable/InRelease").expect("valid");
        assert_eq!(path.file_name(), "InRelease");
        assert_eq!(
            path.segments().collect::<Vec<_>>(),
            ["apt", "dists", "stable", "InRelease"]
        );
        assert_eq!(
            format!("{path:?}"),
            "StoragePath(\"apt/dists/stable/InRelease\")"
        );
        assert_eq!(String::from(path.clone()), "apt/dists/stable/InRelease");
        assert_eq!(
            StoragePath::try_from("apt/dists/stable/InRelease").ok(),
            Some(path)
        );
        assert!(StoragePath::try_from(String::from("../x")).is_err());
    }
}
