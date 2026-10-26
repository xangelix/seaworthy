//! The aarch64 feature table: one row per aarch64 target-feature name the
//! pinned rustc (1.99.1) can enable through `-C target-cpu`, with how macOS
//! reports it.
//!
//! **The vocabulary** is the 71 names `rustc --print cfg` reports, with
//! `RUSTC_BOOTSTRAP=1`, across every aarch64 CPU rustc 1.99.1 knows on
//! `aarch64-apple-darwin` (the 84 it lists, plus the `apple-m1`, `apple-m2`
//! and `apple-m3` aliases it doesn't). `tests/vocabulary.rs` re-derives it
//! from the toolchain in use and fails on any name without a row.
//!
//! **The signals** follow the standard library's own detector for Darwin
//! (`library/std_detect/src/detect/os/darwin/aarch64.rs` in rust-src
//! 1.99.1): the same `sysctl` keys, combined the same way — `aes` needs
//! `FEAT_AES` and `FEAT_PMULL`, `sha2` `FEAT_SHA1`, `FEAT_SHA256` and
//! AdvSIMD, `sha3` `FEAT_SHA512`, `FEAT_SHA3` and AdvSIMD, `mte` `FEAT_MTE`
//! and `FEAT_MTE2`, `paca` and `pacg` `FEAT_PAuth` — and stricter for
//! `neon`, which also needs `hw.optional.floatingpoint` (rustc's `neon`
//! implies `fp-armv8`). One divergence: std 1.99 also takes
//! `hw.optional.arm.AdvSIMD` for AdvSIMD; this table reads
//! `hw.optional.AdvSIMD` alone, which every macOS since 11 defines (were a
//! macOS to drop it, `sha2` and `sha3` would under-report, never
//! over-report; `neon` is in the M1 baseline). Detection runs on macOS only (Apple Silicon, the one
//! aarch64 platform the launcher supports); elsewhere every aarch64 feature
//! is absent.
//!
//! **The Apple M1 baseline** ([`Signal::AppleM1`]). macOS 11 defines none of
//! the `hw.optional.arm.FEAT_*` keys (macOS 12 added them), and some features
//! have no key at all (`lor`, `pan`, `ras`, `vh`, `pmuv3`, `v8.1a`–`v8.4a`).
//! Every arm64 Mac is an Apple M1 or later, and every later chip's features
//! contain the M1's (rustc's `apple-m2` to `apple-m5` each extend
//! `apple-m1`), so the M1's features — exactly what rustc enables for
//! `apple-m1`, which `tests/vocabulary.rs` checks — are present on any arm64
//! macOS. Where macOS does define a feature's key, it must not read 0 —
//! except for `ssbs` and `dit`, which consult no key: both are processor
//! state controls (`MSR SSBS`, `MSR DIT`) that compiled Rust code never
//! executes, and macOS reports `FEAT_SSBS` as 0 inside a
//! Virtualization.framework guest (a macOS virtual machine, such as a CI
//! runner's) though the chip has it — a key that would refuse an `apple-m1`
//! core over an instruction the core doesn't contain. (The A12Z Developer Transition Kit
//! predates the M1 and ran pre-release macOS 11 only: not supported.)
//!
//! **No signal, never present** ([`Signal::Never`]). A feature beyond the
//! M1's that macOS reports no key for — the architecture versions `v8.5a`
//! and later, SVE, FP8 — is never present: a core built for a CPU above
//! `apple-m1` (whose record carries `v8.5a` or later) is skipped, and the
//! launcher falls back to the product's next core. A product ships
//! `apple-m1` (one Apple Silicon core per release until a split pays for
//! itself); a row's rule is what has to change before one does.

/// How macOS reports an aarch64 feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Part of the Apple M1 baseline (see the module docs): present on every
    /// arm64 Mac, unless one of these keys is defined and reads 0. An empty
    /// list: a feature macOS has no key for.
    AppleM1(&'static [&'static str]),
    /// Present when every key reads non-zero; a key the running macOS
    /// doesn't define reads as absent.
    Sysctl(&'static [&'static str]),
    /// Nothing macOS reports: never present.
    Never,
}

/// One row of the aarch64 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Arm64Feature {
    /// The rustc/LLVM target-feature name, as `--print cfg` reports it.
    pub name: &'static str,
    /// How macOS reports it.
    pub signal: Signal,
}

const fn m1(name: &'static str, keys: &'static [&'static str]) -> Arm64Feature {
    Arm64Feature {
        name,
        signal: Signal::AppleM1(keys),
    }
}

const fn key(name: &'static str, keys: &'static [&'static str]) -> Arm64Feature {
    Arm64Feature {
        name,
        signal: Signal::Sysctl(keys),
    }
}

const fn never(name: &'static str) -> Arm64Feature {
    Arm64Feature {
        name,
        signal: Signal::Never,
    }
}

/// AdvSIMD, which `neon`, `sha2` and `sha3` need (defined since macOS 11).
const ADVSIMD: &str = "hw.optional.AdvSIMD";

/// The table, in name order.
pub const AARCH64_FEATURES: [Arm64Feature; 71] = [
    m1(
        "aes",
        &["hw.optional.arm.FEAT_AES", "hw.optional.arm.FEAT_PMULL"],
    ),
    key("bf16", &["hw.optional.arm.FEAT_BF16"]),
    key("bti", &["hw.optional.arm.FEAT_BTI"]),
    // std also accepts the pre-FEAT key macOS 11 defines.
    m1(
        "crc",
        &["hw.optional.arm.FEAT_CRC32", "hw.optional.armv8_crc32"],
    ),
    key("cssc", &["hw.optional.arm.FEAT_CSSC"]),
    // A PSTATE control compiled code never sets (see the module docs).
    m1("dit", &[]),
    m1("dotprod", &["hw.optional.arm.FEAT_DotProd"]),
    m1("dpb", &["hw.optional.arm.FEAT_DPB"]),
    m1("dpb2", &["hw.optional.arm.FEAT_DPB2"]),
    key("ecv", &["hw.optional.arm.FEAT_ECV"]),
    never("faminmax"),
    m1("fcma", &["hw.optional.arm.FEAT_FCMA"]),
    m1("fhm", &["hw.optional.arm.FEAT_FHM"]),
    m1("flagm", &["hw.optional.arm.FEAT_FlagM"]),
    m1("flagm2", &["hw.optional.arm.FEAT_FlagM2"]),
    m1("fp16", &["hw.optional.arm.FEAT_FP16"]),
    never("fp8"),
    never("fp8dot2"),
    never("fp8dot4"),
    never("fp8fma"),
    m1("frintts", &["hw.optional.arm.FEAT_FRINTTS"]),
    key("hbc", &["hw.optional.arm.FEAT_HBC"]),
    key("i8mm", &["hw.optional.arm.FEAT_I8MM"]),
    m1("jsconv", &["hw.optional.arm.FEAT_JSCVT"]),
    m1("lor", &[]),
    m1("lse", &["hw.optional.arm.FEAT_LSE"]),
    m1("lse2", &["hw.optional.arm.FEAT_LSE2"]),
    never("lut"),
    never("mops"),
    key(
        "mte",
        &["hw.optional.arm.FEAT_MTE", "hw.optional.arm.FEAT_MTE2"],
    ),
    m1("neon", &[ADVSIMD, "hw.optional.floatingpoint"]),
    m1("paca", &["hw.optional.arm.FEAT_PAuth"]),
    m1("pacg", &["hw.optional.arm.FEAT_PAuth"]),
    m1("pan", &[]),
    m1("pmuv3", &[]),
    never("rand"),
    m1("ras", &[]),
    m1("rcpc", &["hw.optional.arm.FEAT_LRCPC"]),
    m1("rcpc2", &["hw.optional.arm.FEAT_LRCPC2"]),
    never("rcpc3"),
    m1("rdm", &["hw.optional.arm.FEAT_RDM"]),
    m1("sb", &["hw.optional.arm.FEAT_SB"]),
    m1(
        "sha2",
        &[
            "hw.optional.arm.FEAT_SHA1",
            "hw.optional.arm.FEAT_SHA256",
            ADVSIMD,
        ],
    ),
    m1(
        "sha3",
        &[
            "hw.optional.arm.FEAT_SHA512",
            "hw.optional.arm.FEAT_SHA3",
            ADVSIMD,
        ],
    ),
    never("sm4"),
    key("sme", &["hw.optional.arm.FEAT_SME"]),
    key("sme-b16b16", &["hw.optional.arm.FEAT_SME_B16B16"]),
    key("sme-f16f16", &["hw.optional.arm.FEAT_SME_F16F16"]),
    key("sme-f64f64", &["hw.optional.arm.FEAT_SME_F64F64"]),
    key("sme-i16i64", &["hw.optional.arm.FEAT_SME_I16I64"]),
    key("sme2", &["hw.optional.arm.FEAT_SME2"]),
    key("sme2p1", &["hw.optional.arm.FEAT_SME2p1"]),
    never("spe"),
    // A PSTATE control compiled code never sets; FEAT_SSBS reads 0 in a
    // Virtualization.framework guest (see the module docs).
    m1("ssbs", &[]),
    never("sve"),
    key("sve-b16b16", &["hw.optional.arm.FEAT_SVE_B16B16"]),
    never("sve2"),
    m1("v8.1a", &[]),
    m1("v8.2a", &[]),
    m1("v8.3a", &[]),
    m1("v8.4a", &[]),
    never("v8.5a"),
    never("v8.6a"),
    never("v8.7a"),
    never("v8.8a"),
    never("v9.1a"),
    never("v9.2a"),
    never("v9.3a"),
    never("v9a"),
    m1("vh", &[]),
    key("wfxt", &["hw.optional.arm.FEAT_WFxT"]),
];

/// The aarch64 row for `name`, or `None` for a name the table does not know
/// (never treated as present).
#[must_use]
pub fn lookup_aarch64(name: &str) -> Option<&'static Arm64Feature> {
    AARCH64_FEATURES.iter().find(|feature| feature.name == name)
}

/// The position of `name` in [`AARCH64_FEATURES`].
pub(crate) fn index_of(name: &str) -> Option<usize> {
    AARCH64_FEATURES
        .iter()
        .position(|feature| feature.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_well_formed_and_sorted() {
        let names: Vec<&str> = AARCH64_FEATURES.iter().map(|f| f.name).collect();
        assert!(names.iter().all(|name| crate::is_feature_name(name)));
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "rows unique and in name order");
        assert_eq!(names.len(), 71);
    }

    #[test]
    fn every_key_is_a_hw_optional_sysctl() {
        for feature in &AARCH64_FEATURES {
            let keys: &[&str] = match feature.signal {
                Signal::AppleM1(keys) | Signal::Sysctl(keys) => keys,
                Signal::Never => &[],
            };
            for key in keys {
                assert!(key.starts_with("hw.optional."), "{}: {key}", feature.name);
            }
            if let Signal::Sysctl(keys) = feature.signal {
                assert!(
                    !keys.is_empty(),
                    "{}: a Sysctl row names its keys",
                    feature.name
                );
            }
        }
    }

    #[test]
    fn lookup_finds_rows_and_refuses_unknown_names() {
        assert_eq!(
            lookup_aarch64("neon").map(|f| f.signal),
            Some(Signal::AppleM1(&[ADVSIMD, "hw.optional.floatingpoint"]))
        );
        assert_eq!(lookup_aarch64("sve").map(|f| f.signal), Some(Signal::Never));
        assert!(lookup_aarch64("avx2").is_none());
        assert_eq!(index_of("aes"), Some(0));
    }
}
