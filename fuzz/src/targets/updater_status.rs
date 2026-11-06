//! `updater_status` — the update helper's status record
//! (`seaworthy_updater::UpdateStatus::parse`), which an app reads from the
//! helper's staging directory.
//!
//! Input: the record's bytes (as text, lossy).
//!
//! Invariants:
//! - an accepted record re-encodes to text that parses to the same record
//!   (bar the time's sub-millisecond part, which the format doesn't keep);
//! - an accepted record's detail has no control character and fits its
//!   bound, and its version passes the version gate.

use seaworthy_updater::status::{MAX_DETAIL_BYTES, UpdateStatus};

/// Runs one input (see the module docs).
pub fn run(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let Ok(status) = UpdateStatus::parse(&text) else {
        return;
    };
    assert!(status.detail.len() <= MAX_DETAIL_BYTES);
    assert!(!status.detail.chars().any(|c| c.is_ascii_control()));
    if let Some(version) = &status.version {
        assert!(seaworthy_formats::validate_version(version).is_ok());
    }
    let again = UpdateStatus::parse(&status.encode()).expect("its own encoding parses");
    assert_eq!(again, status, "a round trip changes nothing");
}
