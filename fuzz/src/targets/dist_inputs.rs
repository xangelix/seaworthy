//! `dist_inputs` — seaworthy's parsers: the release version (from a CI tag
//! or variable) and `seaworthy.toml`, plus the ELF/PE readers `verify` runs over
//! artifacts.
//!
//! Input: `[mode][bytes]`. Mode 0: `Version::parse` over the bytes as text;
//! mode 1: `Config::parse`; mode 2: `fips_symbol_findings`, `elf_needed` and
//! `pe_imports` over the bytes as a binary image.
//! Invariants: nothing panics; an accepted version displays back to text
//! that parses identically, orders consistently with itself, and spells
//! every package format (or is refused by MSI's limits with a typed error).

use std::cmp::Ordering;

use seaworthy::config::Config;
use seaworthy::verify::{elf_needed, fips_symbol_findings, pe_imports};
use seaworthy::version::{Release, Version};

pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            let Ok(text) = std::str::from_utf8(bytes) else {
                return;
            };
            if let Ok(version) = Version::parse(text) {
                let again =
                    Version::parse(&version.to_string()).expect("a displayed version re-parses");
                assert_eq!(again, version, "a version re-parses identically");
                assert_eq!(version.cmp(&version), Ordering::Equal);
                let release = Release {
                    version,
                    sequence: 1,
                };
                if let Ok(spelled) = release.package_versions() {
                    assert!(
                        !spelled.deb.contains(' ') && !spelled.pacman_pkgver.contains('-'),
                        "{spelled:?}"
                    );
                }
            }
        }
        1 => {
            if let Ok(text) = std::str::from_utf8(bytes) {
                let _ = Config::parse(text);
            }
        }
        _ => {
            let _ = fips_symbol_findings(bytes, "aws_lc_fips_0_14_2_");
            let _ = elf_needed(bytes);
            let _ = pe_imports(bytes);
        }
    }
}
