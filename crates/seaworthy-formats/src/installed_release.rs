//! The installed release record: which release a product's install tree is,
//! written by the seaworthy CLI into the tree of every product with
//! first-paint probation (`<install root>/seaworthy-release`), read by the
//! update helper (the version token of the release it may have to go back
//! to) and by the app (whether the release it runs is on probation).
//!
//! **The format** (`seaworthy-installed-release:1`) is four lines of text,
//! in this order, each `key value` after the tag:
//!
//! ```text
//! seaworthy-installed-release:1
//! version 1.4.0-rc.2
//! sequence 812
//! build a1b2c3d4
//! ```
//!
//! `build` is the version token's build metadata, `-` for none. The parser
//! is strict and canonical: a record is accepted only when it re-encodes to
//! exactly its own bytes, at most [`MAX_INSTALLED_RELEASE_BYTES`] of them.
//! The file is in the install tree, which only the package manager (root,
//! an administrator) writes; readers still treat it as input.

use crate::FormatError;
use crate::release::Release;

/// The record's file name, in the install root.
pub const INSTALLED_RELEASE_FILE: &str = "seaworthy-release";

/// The format's tag (its first line).
pub const INSTALLED_RELEASE_TAG: &str = "seaworthy-installed-release:1";

/// The largest record a reader accepts.
pub const MAX_INSTALLED_RELEASE_BYTES: usize = 512;

/// The longest build metadata (the seaworthy CLI's `--build` limit).
pub const MAX_BUILD_LEN: usize = 64;

/// Which release an install tree is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRelease {
    /// The release (version and sequence).
    pub release: Release,
    /// The version token's build metadata (`a1b2c3d4`), empty for none.
    pub build: String,
}

/// Whether `text` is build metadata as the seaworthy CLI accepts it:
/// dot-separated non-empty identifiers of `[A-Za-z0-9-]`, at most
/// [`MAX_BUILD_LEN`] bytes. Empty is no metadata.
#[must_use]
pub fn is_build_metadata(text: &str) -> bool {
    text.is_empty()
        || (text.len() <= MAX_BUILD_LEN
            && text.split('.').all(|identifier| {
                !identifier.is_empty()
                    && identifier
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}

fn malformed(why: &str) -> FormatError {
    FormatError::Resolve(format!("not an installed release record: {why}"))
}

impl InstalledRelease {
    /// The record of `release` built as `build` (empty for none).
    ///
    /// # Errors
    /// [`FormatError::Resolve`] for build metadata outside
    /// [`is_build_metadata`], or a token past the version gate.
    pub fn new(release: Release, build: &str) -> Result<Self, FormatError> {
        if !is_build_metadata(build) {
            return Err(malformed("the build isn't build metadata"));
        }
        let record = Self {
            release,
            build: build.to_owned(),
        };
        crate::validate_version(&record.token())?;
        Ok(record)
    }

    /// The version token a release manifest names: `<version>` or
    /// `<version>+<build>`.
    #[must_use]
    pub fn token(&self) -> String {
        if self.build.is_empty() {
            self.release.version.to_string()
        } else {
            format!("{}+{}", self.release.version, self.build)
        }
    }

    /// The record's text.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{INSTALLED_RELEASE_TAG}\nversion {}\nsequence {}\nbuild {}\n",
            self.release.version,
            self.release.sequence,
            if self.build.is_empty() {
                "-"
            } else {
                self.build.as_str()
            }
        )
    }

    /// A record from its text (see the module docs).
    ///
    /// # Errors
    /// [`FormatError::Resolve`]: too large, another tag, a line out of
    /// place, a bad value, or text that isn't the record's own encoding.
    pub fn parse(text: &str) -> Result<Self, FormatError> {
        if text.len() > MAX_INSTALLED_RELEASE_BYTES {
            return Err(malformed("too large"));
        }
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(INSTALLED_RELEASE_TAG) {
            return Err(malformed("another format"));
        }
        let mut field = |key: &str| {
            lines
                .next()
                .and_then(|line| line.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix(' '))
                .ok_or_else(|| malformed("a line out of place"))
        };
        let version = field("version")?;
        let sequence = field("sequence")?;
        let build = field("build")?;
        if lines.next().is_some() {
            return Err(malformed("a line too many"));
        }
        let sequence: u64 = sequence
            .parse()
            .map_err(|_| malformed("the sequence isn't a number"))?;
        let release =
            Release::new(version, sequence).map_err(|e| malformed(&format!("the release: {e}")))?;
        let build = if build == "-" { "" } else { build };
        let record = Self::new(release, build)?;
        // Canonical: `v1.0.0`, `01`, a missing final newline… never pass.
        if record.encode() != text {
            return Err(malformed("not in canonical form"));
        }
        Ok(record)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn record(version: &str, sequence: u64, build: &str) -> InstalledRelease {
        InstalledRelease::new(Release::new(version, sequence).unwrap(), build).unwrap()
    }

    #[test]
    fn a_record_round_trips_and_names_its_token() {
        let rc = record("1.4.0-rc.2", 812, "a1b2c3d4");
        let text = rc.encode();
        assert_eq!(
            text,
            "seaworthy-installed-release:1\nversion 1.4.0-rc.2\nsequence 812\nbuild a1b2c3d4\n"
        );
        assert_eq!(InstalledRelease::parse(&text).unwrap(), rc);
        assert_eq!(rc.token(), "1.4.0-rc.2+a1b2c3d4");
        let plain = record("2.0.0", 1, "");
        assert!(plain.encode().ends_with("build -\n"));
        assert_eq!(InstalledRelease::parse(&plain.encode()).unwrap(), plain);
        assert_eq!(plain.token(), "2.0.0");
    }

    #[test]
    fn anything_else_is_refused() {
        let good = record("1.4.0", 812, "abc").encode();
        let mut bad: Vec<String> = vec![
            String::new(),
            good.replace(INSTALLED_RELEASE_TAG, "seaworthy-installed-release:2"),
            good.trim_end().to_owned(),
            format!("{good}extra 1\n"),
            good.replace("version 1.4.0", "version v1.4.0"),
            good.replace("version 1.4.0", "version 1.4"),
            good.replace("version 1.4.0", "version 1.4.0+abc"),
            good.replace("sequence 812", "sequence 0812"),
            good.replace("sequence 812", "sequence 0"),
            good.replace("sequence 812", "sequence -1"),
            good.replace("sequence 812", "sequence 99999999999999999999999"),
            good.replace("build abc", "build a..b"),
            good.replace("build abc", "build a_b"),
            good.replace("build abc", "build "),
            good.replace("build abc", &format!("build {}", "a".repeat(65))),
            good.replace("\nsequence 812\nbuild abc", "\nbuild abc\nsequence 812"),
            good.replace(' ', "  "),
            good.replace('\n', "\r\n"),
            good.replace("version", "Version"),
            "x".repeat(MAX_INSTALLED_RELEASE_BYTES + 1),
        ];
        bad.push(format!("{good}\n"));
        for text in bad {
            assert!(InstalledRelease::parse(&text).is_err(), "{text:?}");
        }
        assert!(InstalledRelease::new(Release::new("1.0.0", 1).unwrap(), "a+b").is_err());
    }

    #[test]
    fn build_metadata_is_semvers() {
        for good in ["", "a", "a1b2", "0a1b2c3.dirty", "x-y.1"] {
            assert!(is_build_metadata(good), "{good:?}");
        }
        for bad in [".", "a.", ".a", "a..b", "a_b", "a+b", "é", &"a".repeat(65)] {
            assert!(!is_build_metadata(bad), "{bad:?}");
        }
    }
}
