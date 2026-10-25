//! Gives the launcher fixture's Windows (MSVC) build the resources a
//! product's launcher carries: an icon and a UAC manifest, linked into the
//! linker's `.rsrc`, which `.reloc` follows — the layout a packaging tool's
//! version stamp must handle when it rebuilds that tree in a new section (a
//! stamp that left the manifest and icons behind in `.rsrc` made Windows
//! refuse a product's launcher, "not a valid Win32 application", although
//! Wine ran it).
//!
//! The `.res` is written here, no resource compiler needed: the desktop
//! fixture's `icons/viewer.ico` (`RT_ICON` and `RT_GROUP_ICON`) and an
//! `asInvoker` manifest (`RT_MANIFEST`), all en-US.

use std::path::PathBuf;

const ICO: &str = "../desktop/icons/viewer.ico";
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

/// One `.res` entry: the header (ordinal type and name, en-US) and the
/// data, each padded to 4 bytes.
fn entry(res: &mut Vec<u8>, kind: u16, name: u16, data: &[u8]) {
    let size = u32::try_from(data.len()).expect("a small resource");
    res.extend_from_slice(&size.to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes());
    for ordinal in [kind, name] {
        res.extend_from_slice(&0xFFFFu16.to_le_bytes());
        res.extend_from_slice(&ordinal.to_le_bytes());
    }
    res.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    res.extend_from_slice(&0x1030u16.to_le_bytes()); // MOVEABLE | PURE | DISCARDABLE
    res.extend_from_slice(&0x0409u16.to_le_bytes());
    res.extend_from_slice(&[0u8; 8]); // Version, Characteristics
    res.extend_from_slice(data);
    res.resize(res.len().next_multiple_of(4), 0);
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={ICO}");
    let target = |var: &str| std::env::var(var).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") != "windows" || target("CARGO_CFG_TARGET_ENV") != "msvc" {
        return;
    }
    let ico = std::fs::read(ICO).expect("the desktop fixture's icon");
    let u16_at = |at: usize| u16::from_le_bytes([ico[at], ico[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes([ico[at], ico[at + 1], ico[at + 2], ico[at + 3]]);
    let count = u16_at(4);
    // The empty entry every .res starts with (no flags, no language), then
    // one RT_ICON per image and the RT_GROUP_ICON listing them (the .ico's
    // directory, each image offset replaced by its RT_ICON id).
    let mut res = vec![0u8; 32];
    res[4] = 0x20;
    res[8..10].copy_from_slice(&[0xFF, 0xFF]);
    res[12..14].copy_from_slice(&[0xFF, 0xFF]);
    let mut group = ico[..6].to_vec();
    for i in 0..count {
        let at = 6 + 16 * usize::from(i);
        let (len, offset) = (u32_at(at + 8) as usize, u32_at(at + 12) as usize);
        entry(&mut res, 3, i + 1, &ico[offset..offset + len]);
        group.extend_from_slice(&ico[at..at + 12]);
        group.extend_from_slice(&(i + 1).to_le_bytes());
    }
    entry(&mut res, 14, 1, &group);
    entry(&mut res, 24, 1, MANIFEST.as_bytes());
    let out =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR")).join("demo.res");
    std::fs::write(&out, res).expect("write demo.res");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}
