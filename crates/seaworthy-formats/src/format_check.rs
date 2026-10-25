//! The format check on a verified package.
//!
//! Verification proves the staged bytes are the ones the signed manifest
//! names; it doesn't prove they are a package of the format the manifest
//! says. A release mistake (an HTML error page captured by CI, a tarball in
//! the deb slot, a zero-byte upload) would otherwise verify and reach the
//! package manager. The check reads only the header (the first
//! [`HEADER_BYTES`], which the update helper takes from the same pass that
//! hashes the file).

use crate::{ArtifactFormat, FormatError};

/// How much of the staged file the check looks at.
pub const HEADER_BYTES: usize = 4096;

/// Checks `header` (the first bytes of a staged package) against the
/// format its signed manifest names, before anything hands the file to an
/// installer. The magic each format starts with:
///
/// - deb: an `ar` archive whose first member is `debian-binary`, `2.x`;
/// - rpm: the lead (`ed ab ee db`), version 3 or 4, a binary package;
/// - pacman and the tarball: a zstd frame (the seaworthy CLI compresses
///   both with zstd);
/// - zip: a local file header (`PK\x03\x04`);
/// - MSI: a compound file (`d0 cf 11 e0 a1 b1 1a e1`);
/// - pkg: a xar archive (`xar!`), as every flat package is.
///
/// # Errors
/// [`FormatError::WrongFormat`] naming what did not match.
pub fn check_package(header: &[u8], format: ArtifactFormat) -> Result<(), FormatError> {
    check(header, format).map_err(|reason| FormatError::WrongFormat { reason })
}

fn check(header: &[u8], format: ArtifactFormat) -> Result<(), String> {
    const ZSTD: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
    if header.is_empty() {
        return Err("the artifact is empty".into());
    }
    match format {
        ArtifactFormat::Deb => {
            // `!<arch>\n`, then a 60-byte member header whose 16-byte name
            // is `debian-binary` (GNU ar may end it with `/`), then the
            // member's content.
            let name = header.get(8..24).ok_or("deb: truncated ar header")?;
            if !header.starts_with(b"!<arch>\n") {
                return Err("deb: not an ar archive".into());
            }
            let name = std::str::from_utf8(name).unwrap_or_default().trim_end();
            if name.trim_end_matches('/') != "debian-binary" {
                return Err("deb: the first member is not debian-binary".into());
            }
            if !header.get(68..).is_some_and(|rest| rest.starts_with(b"2.")) {
                return Err("deb: debian-binary is not format 2.x".into());
            }
            Ok(())
        }
        ArtifactFormat::Rpm => {
            let Some(&[m0, m1, m2, m3, version, _, t0, t1]) = header.first_chunk::<8>() else {
                return Err("rpm: truncated lead".into());
            };
            if [m0, m1, m2, m3] != [0xed, 0xab, 0xee, 0xdb] {
                return Err("rpm: no rpm lead".into());
            }
            if !matches!(version, 3 | 4) {
                return Err(format!("rpm: lead version {version} (expected 3 or 4)"));
            }
            if [t0, t1] != [0, 0] {
                return Err("rpm: not a binary package".into());
            }
            Ok(())
        }
        ArtifactFormat::Pacman | ArtifactFormat::Tar => {
            if !header.starts_with(ZSTD) {
                return Err(format!("{format}: not a zstd stream"));
            }
            Ok(())
        }
        ArtifactFormat::Zip => {
            if !header.starts_with(b"PK\x03\x04") {
                return Err("zip: no local file header".into());
            }
            Ok(())
        }
        ArtifactFormat::Msi => {
            if !header.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
                return Err("msi: not a compound file".into());
            }
            Ok(())
        }
        ArtifactFormat::Pkg => {
            if !header.starts_with(b"xar!") {
                return Err("pkg: not a xar archive".into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_must_start_with_their_formats_magic() {
        use crate::ArtifactFormat::{Deb, Msi, Pacman, Pkg, Rpm, Tar, Zip};
        let mut deb =
            b"!<arch>\ndebian-binary   1700000000  0     0     100644  4         `\n2.0\n".to_vec();
        assert_eq!(deb.len(), 72);
        let rpm = [0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0, 0, 1];
        let zstd = [0x28, 0xb5, 0x2f, 0xfd, 0, 0];
        let zip = *b"PK\x03\x04rest";
        let msi = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0];
        let xar = *b"xar!\x00\x1c\x00\x01";
        let html = b"<html>error</html>".to_vec();
        for (format, good) in [
            (Deb, deb.clone()),
            (Rpm, rpm.to_vec()),
            (Pacman, zstd.to_vec()),
            (Tar, zstd.to_vec()),
            (Zip, zip.to_vec()),
            (Msi, msi.to_vec()),
            (Pkg, xar.to_vec()),
        ] {
            assert!(check_package(&good, format).is_ok(), "{format}");
            assert!(check_package(&html, format).is_err(), "{format}");
            assert!(
                matches!(
                    check_package(&[], format),
                    Err(FormatError::WrongFormat { reason }) if reason == "the artifact is empty"
                ),
                "{format}"
            );
        }
        // Every format refuses every other format's magic.
        for (format, other) in [
            (Deb, rpm.to_vec()),
            (Rpm, zstd.to_vec()),
            (Pacman, zip.to_vec()),
            (Zip, msi.to_vec()),
            (Msi, deb.clone()),
            (Pkg, zip.to_vec()),
            (Zip, xar.to_vec()),
        ] {
            assert!(check_package(&other, format).is_err(), "{format}");
        }
        // GNU ar's `/`-terminated member name is a deb too; another first
        // member, or a debian-binary that isn't 2.x, is not.
        deb[8..24].copy_from_slice(b"debian-binary/  ");
        assert!(check_package(&deb, Deb).is_ok());
        let mut control_first = deb.clone();
        control_first[8..24].copy_from_slice(b"control.tar.zst ");
        assert!(check_package(&control_first, Deb).is_err());
        let mut v3 = deb.clone();
        v3[68] = b'3';
        assert!(check_package(&v3, Deb).is_err());
        assert!(check_package(&deb[..20], Deb).is_err());
        // A source rpm, an unknown lead version, or a truncated lead.
        let mut source = rpm;
        source[7] = 1;
        assert!(check_package(&source, Rpm).is_err());
        let mut v9 = rpm;
        v9[4] = 9;
        assert!(check_package(&v9, Rpm).is_err());
        assert!(check_package(&rpm[..7], Rpm).is_err());
    }
}
