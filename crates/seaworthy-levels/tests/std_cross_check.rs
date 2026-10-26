//! The live CPU, checked row by row against std's own detector for every
//! name stable `is_x86_feature_detected!` accepts (57 of the 75 on rustc
//! 1.99.1). Of the other 18, `clflushopt`, `lahfsahf`, `prfchw` and `x87`
//! are set in the recorded fixtures (`tests/fixtures.rs`); the AMX and AVX10
//! families, `apxf`, `fma4`, `movrs` and `xop` — on no recorded CPU — are
//! covered by the synthetic CPUs in `detect.rs`'s unit tests.
//!
//! The rule: the table may never report a feature std rejects (that would
//! be over-reporting — a fault waiting to happen); and for rows that follow
//! std exactly ([`Reference::StdDetect`]) it must agree with std. The rows
//! marked [`Reference::Stricter`] may report a feature absent where std
//! reports it present (on a normal host with AVX enabled they agree too).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::panic)]

use seaworthy_levels::{Host, Reference, lookup};

macro_rules! std_detected {
    ($($name:tt),+ $(,)?) => {
        [$(($name, std::arch::is_x86_feature_detected!($name))),+]
    };
}

#[test]
fn the_table_agrees_with_std_on_every_stable_name() {
    let std = std_detected![
        "adx",
        "aes",
        "avx",
        "avx2",
        "avx512bf16",
        "avx512bitalg",
        "avx512bw",
        "avx512cd",
        "avx512dq",
        "avx512f",
        "avx512fp16",
        "avx512ifma",
        "avx512vbmi",
        "avx512vbmi2",
        "avx512vl",
        "avx512vnni",
        "avx512vp2intersect",
        "avx512vpopcntdq",
        "avxifma",
        "avxneconvert",
        "avxvnni",
        "avxvnniint16",
        "avxvnniint8",
        "bmi1",
        "bmi2",
        "cmpxchg16b",
        "ermsb",
        "f16c",
        "fma",
        "fxsr",
        "gfni",
        "kl",
        "lzcnt",
        "movbe",
        "pclmulqdq",
        "popcnt",
        "rdrand",
        "rdseed",
        "sha",
        "sha512",
        "sm3",
        "sm4",
        "sse",
        "sse2",
        "sse3",
        "sse4.1",
        "sse4.2",
        "sse4a",
        "ssse3",
        "tbm",
        "vaes",
        "vpclmulqdq",
        "widekl",
        "xsave",
        "xsavec",
        "xsaveopt",
        "xsaves",
    ];
    assert_eq!(std.len(), 57);
    let host = Host::detect();
    let mut disagreements = Vec::new();
    for (name, std_says) in std {
        let row = lookup(name).unwrap_or_else(|| panic!("{name}: no row"));
        let ours = host.has(name);
        if ours && !std_says {
            disagreements.push(format!(
                "{name}: present here, absent per std (over-reporting)"
            ));
        } else if ours != std_says && row.reference == Reference::StdDetect {
            disagreements.push(format!("{name}: {ours} here, {std_says} per std"));
        }
    }
    assert!(disagreements.is_empty(), "{disagreements:#?}");
}

#[test]
fn every_x86_64_cpu_runs_the_baseline() {
    let host = Host::detect();
    for name in ["x87", "fxsr", "sse", "sse2"] {
        assert!(host.has(name), "{name} is part of x86-64 itself");
    }
}
