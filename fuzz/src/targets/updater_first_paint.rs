//! `updater_first_paint` — first-paint probation's records: the app's
//! markers and the helper's notice (`seaworthy_updater::first_paint`), which
//! cross a privilege boundary (a user writes the markers, root or
//! LocalSystem reads them), and the helper's own probation record and
//! rejected tokens.
//!
//! Input: `[mode][bytes]` (as text, lossy). Mode 0: `Marker::parse`; 1:
//! `Notice::parse`; 2: the probation record; 3: the rejected tokens.
//!
//! Invariant: an accepted record is its own canonical encoding, byte for
//! byte (no two texts mean one record, and nothing is dropped).

use seaworthy_updater::first_paint::{Marker, Notice};

/// Runs one input (see the module docs).
pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(bytes);
    let again = match mode % 4 {
        0 => Marker::parse(&text).ok().map(|marker| marker.encode()),
        1 => Notice::parse(&text).ok().map(|notice| notice.encode()),
        2 => seaworthy_updater::__fuzz::probation_record(&text),
        _ => seaworthy_updater::__fuzz::rejected_tokens(&text),
    };
    if let Some(again) = again {
        assert_eq!(again, text, "an accepted record is canonical");
    }
}
