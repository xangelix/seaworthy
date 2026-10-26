//! `lab_request` — `seaworthy-lab`'s request-head parser: the bytes a lab
//! server reads from whoever connects, to the route it serves.
//!
//! Input: the raw request head (any bytes).
//!
//! Invariants:
//! - `head_len` finds the first blank line (`\r\n\r\n`), or none;
//! - a parsed request is `GET` or `HEAD`, and the required-version
//!   endpoint is only ever `GET`;
//! - a file route is a non-empty relative path of plain components only
//!   (no root, prefix, `.` or `..`), none empty, none carrying NUL, a
//!   control character, a backslash or a colon: joined to a root, it stays
//!   below it on every platform;
//! - a file route never names the lab's reserved `_lab` prefix;
//! - parsing is deterministic, and the percent-decoder is idempotent on
//!   what it accepts when the result carries no `%`.

use std::path::Component;

use seaworthy_lab::request::{self, Method, Route};

pub fn run(data: &[u8]) {
    let found = request::head_len(data);
    let expected = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4);
    assert_eq!(found, expected, "head_len");

    let parsed = request::parse(data);
    assert_eq!(parsed, request::parse(data), "parse is deterministic");
    let Ok(request) = parsed else { return };
    match request.route {
        Route::RequiredVersion => assert_eq!(request.method, Method::Get),
        Route::File(path) => {
            let mut components = 0;
            for component in path.components() {
                let Component::Normal(part) = component else {
                    panic!("a non-plain component in {path:?}");
                };
                let part = part.to_str().expect("UTF-8");
                assert!(!part.is_empty());
                assert!(
                    !part
                        .bytes()
                        .any(|b| b < 0x20 || b == 0x7f || b == b'\\' || b == b':'),
                    "{part:?}"
                );
                components += 1;
            }
            assert!(components > 0, "an empty file route");
            assert!(
                path.components().next() != Some(Component::Normal("_lab".as_ref())),
                "a file route under the reserved prefix: {path:?}"
            );
        }
    }

    // The decoder on its own: whatever it accepts carries no control
    // character or backslash, and decoding again (when nothing is left to
    // decode) changes nothing.
    let text = crate::text(data);
    if let Ok(decoded) = request::decode_path(&text) {
        assert!(!decoded.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\'));
        if !decoded.contains('%') {
            assert_eq!(request::decode_path(&decoded).as_deref(), Ok(decoded.as_str()));
        }
    }
}
