//! Recorded CPUs: real hardware and qemu-user's TCG models, replayed
//! through the detector. Each fixture must detect EXACTLY its feature set
//! (a regression lock on every row and gate), and run exactly the x86-64
//! levels it should — the launcher's core-selection decision.
//!
//! The dumps in `tests/fixtures/` were recorded with
//! `examples/cpuid_dump.rs` (natively, and under `qemu-x86_64 -cpu <model>`
//! — TCG implements a subset of each model: no AVX-512, AMX, GFNI or
//! VPCLMULQDQ, so `x86-64-v4` is covered by the native Zen 5 dump).

#![allow(clippy::expect_used, clippy::panic)]

use seaworthy_levels::{Host, Requirement, Snapshot};

fn host(fixture: &str) -> Host {
    let path = format!(
        "{}/tests/fixtures/{fixture}.cpuid",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    Host::from_source(&Snapshot::parse(&text).unwrap_or_else(|e| panic!("{path}: {e}")))
}

/// What each recorded CPU detects, in table order.
const EXPECTED: [(&str, &str); 12] = [
    ("qemu-qemu64", "x87,fxsr,sse,sse2,sse3,cmpxchg16b,lahfsahf"),
    ("qemu-conroe", "x87,fxsr,sse,sse2,sse3,ssse3,lahfsahf"),
    (
        "qemu-nehalem",
        "x87,fxsr,sse,sse2,sse3,ssse3,cmpxchg16b,sse4.1,sse4.2,popcnt,lahfsahf",
    ),
    (
        "qemu-sandybridge",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,cmpxchg16b,sse4.1,sse4.2,popcnt,aes,xsave,avx,xsaveopt,lahfsahf",
    ),
    (
        "qemu-haswell",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,xsaveopt,lahfsahf,lzcnt",
    ),
    (
        "qemu-skylake-client",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,rdseed,adx,xsaveopt,lahfsahf,lzcnt,prfchw",
    ),
    (
        "qemu-icelake-server",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,rdseed,adx,clflushopt,vaes,xsaveopt,lahfsahf,lzcnt,prfchw",
    ),
    (
        "qemu-sapphirerapids",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,rdseed,adx,clflushopt,sha,vaes,xsaveopt,lahfsahf,lzcnt,prfchw",
    ),
    (
        "qemu-epyc",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,rdseed,adx,clflushopt,sha,xsaveopt,lahfsahf,lzcnt,sse4a,prfchw",
    ),
    (
        "qemu-epyc-genoa",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,rdseed,adx,clflushopt,sha,vaes,xsaveopt,lahfsahf,lzcnt,sse4a,prfchw",
    ),
    // Hygon: the AMD-defined extended bits (sse4a) count for its vendor too.
    (
        "qemu-dhyana",
        "x87,fxsr,sse,sse2,sse3,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,rdseed,adx,clflushopt,xsaveopt,lahfsahf,lzcnt,sse4a,prfchw",
    ),
    (
        "zen5-ryzen-9950x3d",
        "x87,fxsr,sse,sse2,sse3,pclmulqdq,ssse3,fma,cmpxchg16b,sse4.1,sse4.2,movbe,popcnt,aes,xsave,avx,f16c,rdrand,bmi1,avx2,bmi2,ermsb,avx512f,avx512dq,rdseed,adx,avx512ifma,clflushopt,avx512cd,sha,avx512bw,avx512vl,avx512vbmi,avx512vbmi2,gfni,vaes,vpclmulqdq,avx512vnni,avx512bitalg,avx512vpopcntdq,avx512vp2intersect,avxvnni,avx512bf16,xsaveopt,xsavec,xsaves,lahfsahf,lzcnt,sse4a,prfchw",
    ),
];

#[test]
fn each_recorded_cpu_detects_exactly_its_features() {
    for (fixture, expected) in EXPECTED {
        let detected: Vec<&str> = host(fixture).names().collect();
        assert_eq!(detected.join(","), expected, "{fixture}");
    }
}

/// The feature sets rustc 1.98.1 enables for the x86-64 levels
/// (`RUSTC_BOOTSTRAP=1 rustc --print cfg -C target-cpu=<level>`).
const LEVELS: [(&str, &str); 4] = [
    ("x86-64", "fxsr,sse,sse2,x87"),
    (
        "x86-64-v2",
        "cmpxchg16b,fxsr,lahfsahf,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87",
    ),
    (
        "x86-64-v3",
        "avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave",
    ),
    (
        "x86-64-v4",
        "avx,avx2,avx512bw,avx512cd,avx512dq,avx512f,avx512vl,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave",
    ),
];

fn level(cpu: &str, features: &str) -> Requirement {
    Requirement::parse(
        format!(
            "seaworthy-cpureq:1\ntarget=x86_64-unknown-linux-gnu\ncpu={cpu}\nfeatures={features}\n"
        )
        .as_bytes(),
    )
    .expect("a level record parses")
}

/// The highest level each recorded CPU runs — what a launcher with the
/// default `x86-64-v4, x86-64-v3, x86-64-v2` order would choose (`x86-64`
/// = below the v2 floor: exit 78).
const BEST_LEVEL: [(&str, &str); 12] = [
    ("qemu-qemu64", "x86-64"),
    ("qemu-conroe", "x86-64"),
    ("qemu-nehalem", "x86-64-v2"),
    ("qemu-sandybridge", "x86-64-v2"),
    ("qemu-haswell", "x86-64-v3"),
    ("qemu-skylake-client", "x86-64-v3"),
    ("qemu-icelake-server", "x86-64-v3"),
    ("qemu-sapphirerapids", "x86-64-v3"),
    ("qemu-epyc", "x86-64-v3"),
    ("qemu-epyc-genoa", "x86-64-v3"),
    ("qemu-dhyana", "x86-64-v3"),
    ("zen5-ryzen-9950x3d", "x86-64-v4"),
];

#[test]
fn each_recorded_cpu_runs_exactly_the_levels_it_should() {
    for (fixture, best) in BEST_LEVEL {
        let host = host(fixture);
        let best_index = LEVELS
            .iter()
            .position(|(cpu, _)| *cpu == best)
            .expect("a level");
        for (index, (cpu, features)) in LEVELS.iter().enumerate() {
            let verdict = host.assess(&level(cpu, features), "x86_64-unknown-linux-gnu");
            assert_eq!(
                verdict.is_supported(),
                index <= best_index,
                "{fixture} on {cpu}: {verdict}"
            );
        }
    }
}

#[test]
fn a_refusal_names_what_is_missing() {
    let v3 = level(LEVELS[2].0, LEVELS[2].1);
    let verdict = host("qemu-sandybridge").assess(&v3, "x86_64-unknown-linux-gnu");
    assert_eq!(
        verdict.missing,
        ["avx2", "bmi1", "bmi2", "f16c", "fma", "lzcnt", "movbe"]
    );
    assert_eq!(
        verdict.to_string(),
        "needs avx2, bmi1, bmi2, f16c, fma, lzcnt, movbe"
    );
}

#[test]
fn every_fixture_is_listed() {
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixtures directory")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".cpuid").map(str::to_owned))
        .collect();
    on_disk.sort();
    let mut listed: Vec<&str> = EXPECTED.iter().map(|(name, _)| *name).collect();
    listed.sort_unstable();
    assert_eq!(on_disk, listed);
}
