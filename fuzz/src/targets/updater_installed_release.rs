//! `updater_installed_release` — the installed release record
//! (`seaworthy_formats::InstalledRelease::parse`), which the update helper
//! (root, LocalSystem) and the app read from a product's install tree.
//!
//! Input: the record's bytes (as text, lossy).
//!
//! Invariants:
//! - an accepted record is its own canonical encoding, byte for byte;
//! - its token passes the version gate and names the record's version.

use seaworthy_formats::InstalledRelease;

/// Runs one input (see the module docs).
pub fn run(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let Ok(record) = InstalledRelease::parse(&text) else {
        return;
    };
    assert_eq!(record.encode(), text, "an accepted record is canonical");
    let token = record.token();
    assert!(seaworthy_formats::validate_version(&token).is_ok());
    assert!(token.starts_with(&record.release.version.to_string()));
    assert_eq!(InstalledRelease::parse(&record.encode()).unwrap(), record);
}
