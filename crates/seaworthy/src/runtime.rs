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
