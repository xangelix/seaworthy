//! `dist_post_link` — seaworthy's post-link checks (`post_link::check_strip`,
//! `check_stamp`, `check_sign`), which read two images each, over arbitrary
//! pairs and over the pairs the real steps make.
//!
//! Input: `[mode][before's length: u32 LE][before][after]`; with a length
//! past the input, the rest is both images. Mode 0 strips, 1 stamps, 2
//! signs.
//!
//! Invariants: nothing panics. An ELF image compared with itself is never
//! "changed". `stamp_version` checks its own output, so a stamp it refuses is
//! never refused for a change, and one it makes passes `check_stamp`; that
//! stamp with a certificate table appended (as a signer leaves it) passes
//! `check_sign`. A refusal for a change is told by its message's fixed
//! start: the file's own text (a section's name) only ever follows it.

use seaworthy::DistError;
use seaworthy::pe_version::{VersionInfo, stamp_version};
use seaworthy::post_link::{check_sign, check_stamp, check_strip};
use seaworthy::version::Release;

/// Whether `error` is `step`'s refusal for a change (not an unreadable
/// image or another refusal).
fn changed(error: &DistError, step: &str) -> bool {
    matches!(error, DistError::Layout(message)
        if message.starts_with(&format!("{step} changed what the loader maps")))
}

/// `image` as an Authenticode signer leaves it: padded to 8 bytes, a
/// certificate table appended, the security data directory naming it.
/// `None` for an image whose headers can't be found.
fn sign(image: &[u8]) -> Option<Vec<u8>> {
    let lfanew = usize::try_from(u32::from_le_bytes(image.get(0x3c..0x40)?.try_into().ok()?)).ok()?;
    let directory = lfanew.checked_add(24 + 112 + 4 * 8)?;
    let mut out = image.to_vec();
    out.resize(out.len().next_multiple_of(8), 0);
    let table = u32::try_from(out.len()).ok()?;
    out.extend_from_slice(&24u32.to_le_bytes()); // dwLength
    out.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
    out.extend_from_slice(&0x0002u16.to_le_bytes()); // PKCS_SIGNED_DATA
    out.extend_from_slice(&[0x30; 16]);
    out.get_mut(directory..directory + 4)?.copy_from_slice(&table.to_le_bytes());
    out.get_mut(directory + 4..directory + 8)?.copy_from_slice(&24u32.to_le_bytes());
    Some(out)
}

pub fn run(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Some(length) = rest.get(..4) else {
        return;
    };
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    let rest = &rest[4..];
    let (before, after) = if length <= rest.len() {
        rest.split_at(length)
    } else {
        (rest, rest)
    };
    match mode % 3 {
        0 => {
            let _ = check_strip(before, after);
            if let Err(e) = check_strip(before, before) {
                assert!(
                    !changed(&e, "stripping"),
                    "an image compared with itself: {e}"
                );
            }
        }
        1 => {
            let _ = check_stamp(before, after);
            let release = Release::new("1.4.0", 812).expect("a valid release");
            let info = VersionInfo {
                company: "Acme",
                product: "Acme Agent",
                description: "Acme Agent core",
                file_name: "acme_core.dll",
                dll: true,
            };
            match stamp_version(before, &release, &info) {
                Ok(stamped) => {
                    check_stamp(before, &stamped).expect("a stamp changes only the resources");
                    if let Some(signed) = sign(&stamped) {
                        check_sign(&stamped, &signed)
                            .expect("a certificate table appended changes nothing loaded");
                    }
                }
                Err(e) => assert!(
                    !changed(&e, "stamping"),
                    "stamping tripped its own check: {e}"
                ),
            }
        }
        _ => {
            let _ = check_sign(before, after);
        }
    }
}
