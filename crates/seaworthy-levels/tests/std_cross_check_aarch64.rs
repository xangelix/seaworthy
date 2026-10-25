//! The live Mac (Apple Silicon), checked against std's own detector and
//! the Apple M1 baseline: every [`Signal::AppleM1`] row must be present (or
//! no `apple-m1` core could ever load), and for every name stable
//! `is_aarch64_feature_detected!` accepts the table must agree with std.
//!
//! std's macro answers `true` without asking the OS for a feature the
//! binary was compiled with — and this test, built for `aarch64-apple-darwin`,
//! is built for `apple-m1`. So on the baseline the comparison only checks
//! that the table has it too; beyond it (`bf16`, `bti`, `i8mm`, `mte`,
//! `rand`, `sm4`, `sve`, `sve2`) std reads the same `sysctl` keys the table
//! does. (Which is how the first run found `FEAT_SSBS` reading 0 in a
//! macOS virtual machine while std said `ssbs`: from the compile-time cfg.)

#![cfg(all(target_arch = "aarch64", target_os = "macos"))]
#![allow(clippy::panic)]

use seaworthy_levels::{AARCH64_FEATURES, Host, Signal, lookup_aarch64};

macro_rules! std_detected {
    ($($name:tt),+ $(,)?) => {
        [$(($name, std::arch::is_aarch64_feature_detected!($name))),+]
    };
}

#[test]
fn the_live_mac_has_the_m1_baseline() {
    let host = Host::detect();
    let missing: Vec<&str> = AARCH64_FEATURES
        .iter()
        .filter(|f| matches!(f.signal, Signal::AppleM1(_)) && !host.has(f.name))
        .map(|f| f.name)
        .collect();
    assert!(missing.is_empty(), "the M1 baseline lacks {missing:?}");
    for feature in AARCH64_FEATURES
        .iter()
        .filter(|f| f.signal == Signal::Never)
    {
        assert!(!host.has(feature.name), "{}: a Never row", feature.name);
    }
}

#[test]
fn the_table_agrees_with_std_on_every_stable_name() {
    let std = std_detected![
        "aes", "bf16", "bti", "crc", "dit", "dotprod", "dpb", "dpb2", "fcma", "fhm", "flagm",
        "fp16", "frintts", "i8mm", "jsconv", "lse", "lse2", "mte", "neon", "paca", "pacg", "rand",
        "rcpc", "rcpc2", "rdm", "sb", "sha2", "sha3", "sm4", "ssbs", "sve", "sve2",
    ];
    let host = Host::detect();
    let mut disagreements = Vec::new();
    for (name, std_says) in std {
        lookup_aarch64(name).unwrap_or_else(|| panic!("{name}: no row"));
        let ours = host.has(name);
        if ours != std_says {
            disagreements.push(format!("{name}: {ours} here, {std_says} per std"));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}
