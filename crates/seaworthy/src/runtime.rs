//! Bundled runtimes (`[[product.<id>.runtime]]`): third-party native code and
//! its data, shipped beside a product's own binaries and pinned file by file.
//!
//! A runtime's files arrive in `<artifacts>/<triple>/runtime/<name>/`, laid
//! out as they install under the runtime's `destination`. Its pin list
//! (`pins`, `sha256sum`'s format) names every file with its SHA-256: `verify`
//! refuses a runtime directory holding anything else, missing anything, or
//! holding other bytes ([`read_pins`] parses the list).

use std::path::Path;

use crate::DistError;

/// The most files one runtime may hold.
pub const MAX_RUNTIME_FILES: usize = 20_000;

/// The largest pin list read (2 MiB).
pub const MAX_PINS_BYTES: u64 = 2 * 1024 * 1024;

/// One pinned file: its path in the runtime and its SHA-256 (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Its path, relative to the runtime directory, `/`-separated.
    pub path: String,
    /// Its SHA-256, 64 lowercase hex characters.
    pub sha256: String,
}

/// A path inside a runtime: relative, `/`-separated segments of printable
/// ASCII (no `\\`, no control characters, no `$`), none of them empty, `.`
/// or `..`, at most 255 bytes.
#[must_use]
pub fn is_runtime_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| (0x20..0x7F).contains(&b) && b != b'\\' && b != b'$')
        })
}

/// Parses a pin list: `<64 lowercase hex>  <path>` per line (`sha256sum`'s
/// text form; ` *<path>`, its binary form, too), blank lines and `#` comments
/// skipped. Every path once, each a [`is_runtime_path`], at most
/// [`MAX_RUNTIME_FILES`] of them, at least one.
///
/// # Errors
/// A message naming the first refused line.
pub fn parse_pins(text: &str) -> Result<Vec<Pin>, String> {
    let mut pins: Vec<Pin> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line_no = n.saturating_add(1);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |why: &str| format!("line {line_no}: {why}");
        let (digest, rest) = line
            .split_at_checked(64)
            .ok_or_else(|| bad("not `<sha256>  <path>`"))?;
        if !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad("the digest isn't 64 lowercase hex characters"));
        }
        let path = rest
            .strip_prefix("  ")
            .or_else(|| rest.strip_prefix(" *"))
            .ok_or_else(|| bad("not `<sha256>  <path>` (two spaces, or ` *`)"))?;
        if !is_runtime_path(path) {
            return Err(bad(&format!(
                "{path:?} isn't a path in the runtime (relative, `/`-separated, plain segments of printable ASCII)"
            )));
        }
        if !seen.insert(path.to_owned()) {
            return Err(bad(&format!("{path:?} is pinned twice")));
        }
        if pins.len() >= MAX_RUNTIME_FILES {
            return Err(bad(&format!("more than {MAX_RUNTIME_FILES} files")));
        }
        pins.push(Pin {
            path: path.to_owned(),
            sha256: digest.to_owned(),
        });
    }
    if pins.is_empty() {
        return Err("it pins no file".to_owned());
    }
    // A path can't be both a file and a directory.
    for pin in &pins {
        let mut prefix = String::new();
        for segment in pin.path.split('/') {
            if !prefix.is_empty() && seen.contains(&prefix) {
                return Err(format!(
                    "{prefix:?} is pinned as a file and is the directory of {:?}",
                    pin.path
                ));
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
        }
    }
    Ok(pins)
}

/// Reads `runtime`'s pin list from `dir` (`seaworthy.toml`'s directory): a
/// regular file inside it, at most [`MAX_PINS_BYTES`], that [`parse_pins`]
/// accepts, naming every per-file setting's path.
///
/// # Errors
/// [`DistError::Io`], or [`DistError::Config`] naming the runtime and why.
pub fn read_pins(
    dir: &Path,
    id: &str,
    runtime: &crate::config::Runtime,
) -> Result<Vec<Pin>, DistError> {
    let at = |why: String| {
        DistError::Config(format!(
            "product.{id}.runtime {:?} ({}): pins {}: {why}",
            runtime.name,
            runtime.platform.name(),
            runtime.pins.display()
        ))
    };
    let bytes = crate::layout::read_project_file_limited(dir, &runtime.pins, MAX_PINS_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| at("not UTF-8 text".to_owned()))?;
    let pins = parse_pins(text).map_err(at)?;
    for file in &runtime.files {
        if !pins.iter().any(|pin| pin.path == file.path) {
            return Err(at(format!(
                "pins no {:?}, which runtime.files names",
                file.path
            )));
        }
    }
    Ok(pins)
}

/// The deepest directory a runtime's tree may nest.
pub const MAX_RUNTIME_DEPTH: usize = 16;

/// Every file below a runtime's directory, sorted by path: `(path relative
/// to it, /-separated; the file)`. Nothing is followed: a link, a special
/// file, a name that isn't a [`is_runtime_path`] segment, more than
/// [`MAX_RUNTIME_FILES`] files or [`MAX_RUNTIME_DEPTH`] levels is refused.
///
/// # Errors
/// Why the directory is refused.
pub fn walk(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    let meta =
        std::fs::symlink_metadata(dir).map_err(|e| format!("the runtime's directory: {e}"))?;
    if !meta.is_dir() {
        return Err("the runtime's directory isn't a directory (a link or a file?)".to_owned());
    }
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new(), 0_usize)];
    while let Some((path, prefix, depth)) = stack.pop() {
        let entries = std::fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .filter(|n| is_runtime_path(n))
                .ok_or_else(|| {
                    format!(
                        "{}: a name a runtime can't hold (plain printable ASCII)",
                        entry.path().display()
                    )
                })?
                .to_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            if kind.is_dir() {
                if depth.saturating_add(1) >= MAX_RUNTIME_DEPTH {
                    return Err(format!(
                        "{}: deeper than {MAX_RUNTIME_DEPTH} levels",
                        entry.path().display()
                    ));
                }
                stack.push((entry.path(), relative, depth.saturating_add(1)));
            } else if kind.is_file() {
                if out.len() >= MAX_RUNTIME_FILES {
                    return Err(format!("more than {MAX_RUNTIME_FILES} files"));
                }
                out.push((relative, entry.path()));
            } else {
                return Err(format!(
                    "{}: a link or a special file (a runtime holds regular files and directories)",
                    entry.path().display()
                ));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// What a runtime file is, by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Image {
    /// An ELF image (`\x7fELF`).
    Elf,
    /// A PE image (`MZ`).
    Pe,
    /// A Mach-O image (thin or universal).
    MachO,
    /// Anything else: data.
    Data,
}

impl Image {
    /// What `bytes` start as.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        match bytes.get(..4) {
            Some([0x7f, b'E', b'L', b'F']) => Self::Elf,
            Some([b'M', b'Z', ..]) => Self::Pe,
            Some([0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe]) => Self::MachO,
            _ => Self::Data,
        }
    }

    /// Whether it is native code (the default mode is then 0755).
    #[must_use]
    pub fn is_code(self) -> bool {
        self != Self::Data
    }
}

/// Resolves one `DT_RUNPATH` entry of a binary that installs in `place`
/// (its directory relative to the install root, `/`-separated, `""` for the
/// root) to a directory relative to the install root: the entry must be
/// `$ORIGIN` (or `${ORIGIN}`), optionally followed by `/` and plain segments,
/// `.` and `..`, never leaving the install root. Anything else (an absolute
/// path, another token, an empty entry) is refused: a bundled library is
/// found only beside the binary that needs it, never wherever the machine's
/// own libraries are.
///
/// # Errors
/// Why the entry is refused.
pub fn resolve_origin(place: &str, entry: &str) -> Result<String, String> {
    let rest = ["$ORIGIN", "${ORIGIN}"]
        .iter()
        .find_map(|origin| {
            let rest = entry.strip_prefix(origin)?;
            (rest.is_empty() || rest.starts_with('/')).then_some(rest)
        })
        .ok_or_else(|| format!("{entry:?} isn't $ORIGIN-relative"))?;
    let mut dirs: Vec<&str> = place.split('/').filter(|s| !s.is_empty()).collect();
    for segment in rest.split('/').filter(|s| !s.is_empty()) {
        match segment {
            "." => {}
            ".." => {
                if dirs.pop().is_none() {
                    return Err(format!("{entry:?} leaves the install root"));
                }
            }
            _ if segment.contains('$') => {
                return Err(format!("{entry:?} names another token ({segment})"));
            }
            _ => dirs.push(segment),
        }
    }
    Ok(dirs.join("/"))
}

/// The directory part of an install path (`lib/libcef.so` → `lib`, a file
/// at the root → `""`).
#[must_use]
pub fn parent_of(install: &str) -> &str {
    install.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The file name part of an install path.
#[must_use]
pub fn name_of(install: &str) -> &str {
    install.rsplit_once('/').map_or(install, |(_, name)| name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn sha256sum_output_parses() {
        let text = format!("# CEF 154\n\n{D}  libcef.so\n{D} *locales/en-US.pak\n");
        let pins = parse_pins(&text).unwrap();
        assert_eq!(
            pins,
            [
                Pin {
                    path: "libcef.so".into(),
                    sha256: D.into()
                },
                Pin {
                    path: "locales/en-US.pak".into(),
                    sha256: D.into()
                }
            ]
        );
    }

    #[test]
    fn every_bad_line_is_refused_by_number() {
        for (text, mentions) in [
            (String::new(), "pins no file"),
            ("# only a comment\n".to_owned(), "pins no file"),
            (format!("{}  libcef.so\n", &D[1..]), "line 1"),
            (
                format!("{}  libcef.so\n", D.to_uppercase()),
                "lowercase hex",
            ),
            (format!("{D} libcef.so\n"), "two spaces"),
            (format!("{D}\tlibcef.so\n"), "two spaces"),
            (format!("{D}  ../libcef.so\n"), "isn't a path"),
            (format!("{D}  /libcef.so\n"), "isn't a path"),
            (format!("{D}  a//b\n"), "isn't a path"),
            (format!("{D}  a\\b\n"), "isn't a path"),
            (format!("{D}  $HOME\n"), "isn't a path"),
            (format!("{D}  \n"), "isn't a path"),
            (format!("{D}  a\n{D}  a\n"), "line 2: \"a\" is pinned twice"),
            (
                format!("{D}  a\n{D}  a/b\n"),
                "pinned as a file and is the directory",
            ),
            (format!("{D}  é\n"), "isn't a path"),
        ] {
            let err = parse_pins(&text).expect_err(&text);
            assert!(err.contains(mentions), "{text:?}: {err}");
        }
    }

    #[test]
    fn origin_entries_resolve_inside_the_install_root_only() {
        assert_eq!(resolve_origin("lib", "$ORIGIN").unwrap(), "lib");
        assert_eq!(resolve_origin("lib", "${ORIGIN}").unwrap(), "lib");
        assert_eq!(resolve_origin("lib", "$ORIGIN/").unwrap(), "lib");
        assert_eq!(resolve_origin("", "$ORIGIN/lib").unwrap(), "lib");
        assert_eq!(
            resolve_origin("lib", "$ORIGIN/../lib/./cef").unwrap(),
            "lib/cef"
        );
        assert_eq!(resolve_origin("libexec", "$ORIGIN/..").unwrap(), "");
        for (place, bad) in [
            ("lib", "/usr/lib"),
            ("lib", "/opt/acme/lib"),
            ("lib", ""),
            ("lib", "$ORIGINAL"),
            ("lib", "$LIB"),
            ("lib", "$ORIGIN/$PLATFORM"),
            ("lib", "$ORIGIN/../.."),
            ("", "$ORIGIN/.."),
            ("lib", "lib"),
            ("lib", "./lib"),
        ] {
            assert!(resolve_origin(place, bad).is_err(), "{place:?} {bad:?}");
        }
    }

    #[test]
    fn images_are_told_by_their_magic() {
        assert_eq!(Image::of(b"\x7fELF\x02"), Image::Elf);
        assert_eq!(Image::of(b"MZ\x90\x00"), Image::Pe);
        assert_eq!(Image::of(&[0xcf, 0xfa, 0xed, 0xfe]), Image::MachO);
        assert_eq!(Image::of(&[0xca, 0xfe, 0xba, 0xbe]), Image::MachO);
        assert_eq!(Image::of(b"{\"file_format_version\""), Image::Data);
        assert_eq!(Image::of(b""), Image::Data);
        assert_eq!(parent_of("lib/locales/en-US.pak"), "lib/locales");
        assert_eq!(parent_of("chrome-sandbox"), "");
        assert_eq!(name_of("lib/libcef.so"), "libcef.so");
    }

    #[test]
    fn runtime_paths_are_plain() {
        assert!(is_runtime_path("locales/en-US.pak"));
        assert!(is_runtime_path("chrome-sandbox"));
        for bad in [
            "",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "/a",
            "a/",
            "a\\b",
            "a\u{7f}",
            &"x".repeat(256),
        ] {
            assert!(!is_runtime_path(bad), "{bad:?}");
        }
    }
}
