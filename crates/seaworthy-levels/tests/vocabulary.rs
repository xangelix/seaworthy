//! Toolchain coverage: every feature name the toolchain in use can enable
//! through `-C target-cpu` must have a row, and every row must still be a
//! name that toolchain knows.
//!
//! It runs `rustc --print cfg -C target-cpu=<cpu>` (with `RUSTC_BOOTSTRAP=1`,
//! because stable rustc hides unstable target features from `--print cfg`
//! even though `-C target-cpu` still enables them) for every CPU in
//! `rustc --print target-cpus`, on both x86-64 targets the launcher supports.
//!
//! `--print cfg` is not the whole story: a CPU target can make LLVM emit
//! instructions that no reported feature covers. On rustc 1.99.1
//! `diamondrapids` and `novalake` enable APX's sub-features (NF, NDD, …)
//! but not all of APX, so `--print cfg` lists no `apxf` — yet the code
//! carries APX encodings. So the test also COMPILES a probe for every
//! 64-bit CPU and reads the assembly: a CPU that emits APX code must have
//! `apxf` in its cfg or in [`seaworthy_levels::IMPLIED_FEATURES`], every entry
//! there must still be needed, and no CPU may fold an unaligned memory
//! operand into a legacy SSE instruction (AMD's "misaligned SSE" mode,
//! which needs an MXCSR bit no record can express).
//!
//! The aarch64 table gets the same vocabulary check on `aarch64-apple-darwin`
//! (every listed CPU, plus the `apple-m1`, `apple-m2` and `apple-m3` aliases
//! rustc accepts but doesn't list), and its Apple M1 baseline rows must be
//! exactly what rustc enables for `apple-m1` — the claim
//! [`seaworthy_levels::Signal::AppleM1`] rests on. No aarch64 CPU target is
//! known to emit code its cfg doesn't report, so there's no aarch64 probe.
//!
//! This is the test a toolchain upgrade trips: a new LLVM feature fails here
//! with "add one row" — on the upgrade's own change, never in a release —
//! and a removed one with "remove the row".

// Test-only assembly parsing: every slice index comes from
// `char_indices` / `match_indices` over the same string.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGETS: [&str; 2] = ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"];

/// The target the probes compile for. Code generation depends on the CPU,
/// not the OS, and only `core` is needed; `--emit asm` needs no linker.
const PROBE_TARGET: &str = "x86_64-unknown-linux-gnu";

/// The code the probes compile: shapes that make LLVM reach for each APX
/// sub-feature when the CPU target allows it, plus unaligned SSE loads that
/// a "misaligned SSE" target would fold into arithmetic.
const PROBE_SOURCE: &str = r#"
#![no_std]
use core::arch::x86_64::{_mm_add_ps, _mm_loadu_ps, _mm_mul_ps, _mm_set1_ps, _mm_storeu_ps};

// Register pressure and three-operand arithmetic: EGPR (r16-r31), NDD, NF.
#[unsafe(no_mangle)]
pub extern "C" fn pressure(x: &[u64; 32]) -> u64 {
    let mut v = [0u64; 32];
    for i in 0..32 {
        v[i] = x[i].wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(i as u32);
    }
    let mut acc = 0u64;
    for r in 0..8 {
        for i in 0..32 {
            acc = acc.wrapping_add(v[i] ^ v[(i + r) % 32]).wrapping_sub(v[(i * 7) % 32] & acc);
        }
    }
    acc
}

// Compound conditions: CCMP / CTEST.
#[unsafe(no_mangle)]
pub extern "C" fn conditions(a: u64, b: u64, c: u64, d: u64) -> u64 {
    if (a == b && c < d) || (a > c && b != d) { a ^ d } else { b.wrapping_add(c) }
}

// A load that may not be speculated: CF (CFCMOV).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn conditional_load(p: *const u64, take: bool) -> u64 {
    if take { unsafe { *p } } else { 0 }
}

// Values live across calls: callee-saved spills (PUSH2/POP2, PPX).
unsafe extern "C" {
    fn opaque(x: u64) -> u64;
}
#[unsafe(no_mangle)]
pub extern "C" fn saves(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    unsafe {
        let x = opaque(a);
        let y = opaque(b ^ x);
        let z = opaque(c.wrapping_add(y));
        a ^ b ^ c ^ d ^ e ^ f ^ x ^ y ^ z ^ opaque(d ^ e ^ f)
    }
}

// Unaligned loads feeding SSE arithmetic.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unaligned(p: *const f32, q: *const f32, out: *mut f32) {
    unsafe {
        let sum = _mm_add_ps(_mm_loadu_ps(p), _mm_set1_ps(1.0));
        _mm_storeu_ps(out, _mm_mul_ps(sum, _mm_loadu_ps(q)));
    }
}
"#;

/// `rustc` as the test is run: the rustup proxy honours the workspace's
/// pinned `rust-toolchain.toml`.
fn rustc() -> Command {
    Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
}

fn target_cpus(target: &str) -> Vec<String> {
    let out = rustc()
        .args(["--print", "target-cpus", "--target", target])
        .output()
        .expect("rustc runs");
    assert!(
        out.status.success(),
        "rustc --print target-cpus failed for {target}"
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1) // "Available CPUs for this target:"
        .filter_map(|line| line.split_whitespace().next())
        .filter(|cpu| *cpu != "native")
        .map(str::to_owned)
        .collect()
}

fn features(target: &str, cpu: &str) -> Vec<String> {
    let out = rustc()
        .env("RUSTC_BOOTSTRAP", "1")
        .args(["--print", "cfg", "--target", target, "-C"])
        .arg(format!("target-cpu={cpu}"))
        .output()
        .expect("rustc runs");
    assert!(
        out.status.success(),
        "rustc --print cfg failed for {target} {cpu}"
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("target_feature=\""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

/// Runs `query` for every CPU, sixteen at a time.
fn per_cpu<T: Send>(cpus: &[String], query: impl Fn(&str) -> T + Sync) -> Vec<(String, T)> {
    let query = &query;
    std::thread::scope(|scope| {
        let handles: Vec<_> = cpus
            .chunks(16)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|cpu| (cpu.clone(), query(cpu)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("query thread"))
            .collect()
    })
}

/// What one CPU's probe assembly contains.
#[derive(Debug, Default)]
struct Emitted {
    /// Lines with APX encodings.
    apx: Vec<String>,
    /// Lines folding an unaligned memory operand into legacy SSE arithmetic.
    unaligned_sse: Vec<String>,
}

/// Compiles the probe for `cpu`; `None` for a 32-bit-only CPU (LLVM refuses
/// 64-bit code for it — no x86-64 core can be built for it either).
fn probe(dir: &Path, source: &Path, cpu: &str) -> Option<Emitted> {
    let asm = dir.join(format!("{cpu}.s"));
    let out = rustc()
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "lib",
            "-O",
            "--emit",
            "asm",
            "-o",
        ])
        .arg(&asm)
        .args(["--target", PROBE_TARGET, "-C"])
        .arg(format!("target-cpu={cpu}"))
        .arg(source)
        .output()
        .expect("rustc runs");
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("64-bit code requested on a subtarget that doesn't support it") {
            return None;
        }
        panic!("the probe failed to compile for {cpu}: {stderr}");
    }
    let text = std::fs::read_to_string(&asm).expect("probe assembly");
    let mut emitted = Emitted::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('.') || line.starts_with('#') || line.ends_with(':')
        {
            continue;
        }
        if is_apx(line) {
            emitted.apx.push(line.to_owned());
        }
        if is_unaligned_sse_fold(line) {
            emitted.unaligned_sse.push(line.to_owned());
        }
    }
    Some(emitted)
}

/// An instruction line's mnemonic (after `{nf}` / `{evex}` pseudo-prefixes)
/// and its operands, split at top-level commas.
fn parse(line: &str) -> (&str, Vec<&str>) {
    let mut rest = line;
    while let Some(after) = rest.strip_prefix('{') {
        rest = after
            .split_once('}')
            .map_or("", |(_, tail)| tail)
            .trim_start();
    }
    let (mnemonic, operands) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (i, c) in operands.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(operands[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if !operands.trim().is_empty() {
        parts.push(operands[start..].trim());
    }
    (mnemonic, parts)
}

/// `%r16`–`%r31` (with any size suffix): APX's extended GPRs.
fn has_egpr(line: &str) -> bool {
    line.match_indices("%r").any(|(i, _)| {
        let digits: String = line[i + 2..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse::<u32>().is_ok_and(|n| (16..=31).contains(&n))
    })
}

/// Whether `mnemonic` is `base` with an optional AT&T size suffix.
fn is_op(mnemonic: &str, base: &str) -> bool {
    mnemonic
        .strip_prefix(base)
        .is_some_and(|suffix| matches!(suffix, "" | "b" | "w" | "l" | "q"))
}

fn is_apx(line: &str) -> bool {
    if line.contains("{nf}") || line.contains("{evex}") || has_egpr(line) {
        return true;
    }
    let (mnemonic, operands) = parse(line);
    const APX_ONLY: [&str; 9] = [
        "push2", "pop2", "pushp", "popp", "ccmp", "ctest", "cfcmov", "setzu", "imulzu",
    ];
    if APX_ONLY.iter().any(|prefix| mnemonic.starts_with(prefix)) {
        return true;
    }
    // NDD: a separate destination — three operands for binary ALU ops, two
    // for unary ones (their legacy forms take one fewer).
    const BINARY: [&str; 12] = [
        "add", "sub", "and", "or", "xor", "adc", "sbb", "shl", "shr", "sar", "rol", "ror",
    ];
    const UNARY: [&str; 4] = ["neg", "not", "inc", "dec"];
    (BINARY.iter().any(|base| is_op(mnemonic, base)) && operands.len() == 3)
        || (UNARY.iter().any(|base| is_op(mnemonic, base)) && operands.len() == 2)
}

/// A legacy (non-VEX) SSE arithmetic instruction with a memory source that
/// isn't a RIP-relative (aligned) constant.
fn is_unaligned_sse_fold(line: &str) -> bool {
    let (mnemonic, operands) = parse(line);
    matches!(mnemonic, "addps" | "mulps")
        && operands
            .first()
            .is_some_and(|source| source.contains("(%") && !source.contains("(%rip)"))
}

#[test]
fn the_probe_parser_recognises_apx_and_legacy_code() {
    for apx in [
        "{nf}\timulq\t(%rdi), %rax, %rcx",
        "addq\t%rax, %rbx, %rcx",
        "movq\t%r17, %rax",
        "movl\t%r30d, %eax",
        "push2p\t%r15, %r14",
        "ccmpeq\t{dfv=}\t%rsi, %rdi",
        "cfcmovneq\t(%rdi), %rax",
        "negq\t%rax, %rcx",
    ] {
        assert!(is_apx(apx), "{apx}");
    }
    for legacy in [
        "addq\t%rax, %rbx",
        "imulq\t$7, %rax, %rcx",
        "shldq\t$3, %rax, %rbx",
        "movq\t%r15, %rax",
        "movq\t%r9, %r10",
        "negq\t%rax",
        "pushq\t%rbp",
        "movq\t-160(%rsp,%rdx,8), %rax",
    ] {
        assert!(!is_apx(legacy), "{legacy}");
    }
    assert!(is_unaligned_sse_fold("addps\t(%rdi), %xmm0"));
    assert!(!is_unaligned_sse_fold("addps\t.LCPI0_0(%rip), %xmm1"));
    assert!(!is_unaligned_sse_fold("vaddps\t(%rdi), %xmm0, %xmm0"));
    assert!(!is_unaligned_sse_fold("mulps\t%xmm1, %xmm0"));
}

#[test]
fn the_table_is_exactly_the_toolchains_x86_vocabulary() {
    let mut vocabulary = BTreeSet::new();
    let mut cpu_count = 0usize;
    for target in TARGETS {
        let cpus = target_cpus(target);
        assert!(
            cpus.len() > 100,
            "{target}: only {} CPUs listed",
            cpus.len()
        );
        cpu_count = cpus.len();
        for (cpu, found) in per_cpu(&cpus, |cpu| features(target, cpu)) {
            vocabulary.extend(found);
            vocabulary.extend(seaworthy_levels::implied_features(&cpu).map(str::to_owned));
        }
    }
    let table: BTreeSet<String> = seaworthy_levels::FEATURES
        .iter()
        .map(|f| f.name.to_owned())
        .collect();
    let missing: Vec<&String> = vocabulary.difference(&table).collect();
    let stale: Vec<&String> = table.difference(&vocabulary).collect();
    assert!(
        missing.is_empty(),
        "the toolchain can enable features the table has no row for — add one row each \
         (crates/seaworthy-levels/src/table.rs, from std_detect or LLVM): {missing:?}"
    );
    assert!(
        stale.is_empty(),
        "rows for names the toolchain no longer knows — remove them: {stale:?}"
    );
    assert_eq!(table.len(), 75, "{cpu_count} CPUs");
}

/// The aarch64 target the launcher supports (Apple Silicon macOS).
const AARCH64_TARGET: &str = "aarch64-apple-darwin";

/// CPU names rustc accepts on aarch64 without listing them.
const AARCH64_ALIASES: [&str; 3] = ["apple-m1", "apple-m2", "apple-m3"];

#[test]
fn the_table_is_exactly_the_toolchains_aarch64_vocabulary() {
    let mut cpus = target_cpus(AARCH64_TARGET);
    assert!(cpus.len() > 50, "only {} CPUs listed", cpus.len());
    cpus.extend(AARCH64_ALIASES.iter().map(|cpu| (*cpu).to_owned()));
    let mut vocabulary = BTreeSet::new();
    for (_, found) in per_cpu(&cpus, |cpu| features(AARCH64_TARGET, cpu)) {
        vocabulary.extend(found);
    }
    let table: BTreeSet<String> = seaworthy_levels::AARCH64_FEATURES
        .iter()
        .map(|f| f.name.to_owned())
        .collect();
    let missing: Vec<&String> = vocabulary.difference(&table).collect();
    let stale: Vec<&String> = table.difference(&vocabulary).collect();
    assert!(
        missing.is_empty(),
        "the toolchain can enable aarch64 features the table has no row for — add one row each \
         (crates/seaworthy-levels/src/aarch64.rs, from std_detect's darwin/aarch64.rs, or Never): {missing:?}"
    );
    assert!(
        stale.is_empty(),
        "aarch64 rows for names the toolchain no longer knows — remove them: {stale:?}"
    );
    assert_eq!(table.len(), 71, "{} CPUs", cpus.len());
}

#[test]
fn the_apple_m1_baseline_is_exactly_what_apple_m1_enables() {
    let enabled: BTreeSet<String> = features(AARCH64_TARGET, "apple-m1").into_iter().collect();
    let baseline: BTreeSet<String> = seaworthy_levels::AARCH64_FEATURES
        .iter()
        .filter(|f| matches!(f.signal, seaworthy_levels::Signal::AppleM1(_)))
        .map(|f| f.name.to_owned())
        .collect();
    assert_eq!(
        baseline, enabled,
        "the AppleM1 rows must be rustc's apple-m1 features, no more and no fewer"
    );
    // The target's own default CPU is apple-m1: a core built without
    // `-C target-cpu` gets the baseline too.
    let default: BTreeSet<String> = {
        let out = rustc()
            .env("RUSTC_BOOTSTRAP", "1")
            .args(["--print", "cfg", "--target", AARCH64_TARGET])
            .output()
            .expect("rustc runs");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix("target_feature=\""))
            .filter_map(|rest| rest.strip_suffix('"'))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(default, enabled);
    // Every later Apple chip extends the M1 (what makes it a baseline).
    for cpu in ["apple-m2", "apple-m3", "apple-m4", "apple-m5"] {
        let later: BTreeSet<String> = features(AARCH64_TARGET, cpu).into_iter().collect();
        assert!(enabled.is_subset(&later), "{cpu} lacks part of apple-m1");
    }
}

/// Whether [`PROBE_TARGET`]'s `core` is installed: the host's on Linux, a
/// cross target elsewhere (`rustup target add`).
fn probe_target_installed() -> bool {
    let out = rustc()
        .args(["--print", "target-libdir", "--target", PROBE_TARGET])
        .output()
        .expect("rustc runs");
    out.status.success() && Path::new(String::from_utf8_lossy(&out.stdout).trim()).is_dir()
}

#[test]
fn code_the_cfg_does_not_report_is_accounted_for() {
    if !probe_target_installed() {
        // Code generation depends on the CPU alone: a Linux host covers it.
        eprintln!(
            "SKIPPED: {PROBE_TARGET}'s core isn't installed (rustup target add {PROBE_TARGET})"
        );
        return;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("seaworthy-levels-probe");
    std::fs::create_dir_all(&dir).expect("probe dir");
    let source = dir.join("probe.rs");
    std::fs::write(&source, PROBE_SOURCE).expect("probe source");

    let cpus = target_cpus(PROBE_TARGET);
    let results: BTreeMap<String, (Vec<String>, Option<Emitted>)> = per_cpu(&cpus, |cpu| {
        (features(PROBE_TARGET, cpu), probe(&dir, &source, cpu))
    })
    .into_iter()
    .collect();

    let mut unaccounted = Vec::new();
    let mut folding = Vec::new();
    let mut emitting = BTreeSet::new();
    for (cpu, (cfg, emitted)) in &results {
        let Some(emitted) = emitted else { continue };
        if !emitted.unaligned_sse.is_empty() {
            folding.push(format!("{cpu}: {}", emitted.unaligned_sse.join(" | ")));
        }
        if emitted.apx.is_empty() {
            continue;
        }
        emitting.insert(cpu.as_str());
        let reported = cfg.iter().any(|f| f == "apxf");
        let implied = seaworthy_levels::implied_features(cpu).any(|f| f == "apxf");
        if !reported && !implied {
            let sample: Vec<&str> = emitted.apx.iter().take(3).map(String::as_str).collect();
            unaccounted.push(format!("{cpu} (e.g. {})", sample.join(" | ")));
        }
    }
    assert!(
        unaccounted.is_empty(),
        "these CPU targets emit APX code but neither `--print cfg` nor IMPLIED_FEATURES lists \
         `apxf` — add (\"<cpu>\", \"apxf\") to seaworthy_levels::IMPLIED_FEATURES: {unaccounted:#?}"
    );
    assert!(
        folding.is_empty(),
        "these CPU targets fold unaligned memory operands into legacy SSE instructions, which \
         faults unless the OS sets MXCSR.MM — no requirement record can express that: {folding:#?}"
    );
    for (cpu, feature) in seaworthy_levels::IMPLIED_FEATURES {
        assert_eq!(
            feature, "apxf",
            "no probe proves `{feature}` for {cpu} — add one to this test"
        );
        let (cfg, emitted) = results.get(cpu).unwrap_or_else(|| {
            panic!("IMPLIED_FEATURES names {cpu}, which this toolchain doesn't know — remove it")
        });
        assert!(
            !cfg.iter().any(|f| f == feature),
            "`--print cfg` now reports `{feature}` for {cpu} — remove it from IMPLIED_FEATURES"
        );
        assert!(
            emitted.as_ref().is_some_and(|e| !e.apx.is_empty()),
            "{cpu} no longer emits APX code — remove it from IMPLIED_FEATURES"
        );
    }
    // The probe must exercise APX at all: rustc 1.99.1 has CPU targets that
    // emit it, so finding none means the probe or its parser broke.
    assert!(
        !emitting.is_empty(),
        "no CPU target emitted APX code: the probe no longer exercises it"
    );
}
