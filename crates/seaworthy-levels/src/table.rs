//! The feature table: one row per x86 target-feature name the pinned rustc
//! (1.99.1) can enable through `-C target-cpu`, with the CPUID bit that
//! reports it and the extra conditions it needs before it may be called
//! present.
//!
//! **The vocabulary** is the 74 names `rustc --print cfg` reports, with
//! `RUSTC_BOOTSTRAP=1`, across all 136 x86 CPUs rustc 1.99.1 knows, plus the
//! features a CPU target uses without reporting them ([`IMPLIED_FEATURES`]:
//! `apxf`). `tests/vocabulary.rs` re-derives both from the toolchain in use
//! — the second by compiling a probe for every CPU — and fails on any name
//! without a row, so a toolchain upgrade that brings a new LLVM feature
//! fails with "add one row", never a release.
//!
//! **The bits** follow two references, and the stricter of the two where
//! they differ (under-reporting a feature costs speed; over-reporting it
//! crashes the program with an invalid-opcode fault):
//!
//! - [`Reference::StdDetect`] — the standard library's own detector
//!   (`library/std_detect/src/detect/os/x86.rs` in rust-src 1.99.1), which
//!   covers 71 of the 75 names, including the OS-state rules (XCR0) and its
//!   errata handling.
//! - [`Reference::Llvm`] — LLVM's X86 host detection, for the four names
//!   std does not detect (`x87`, `lahfsahf`, `prfchw`, `fma4`).
//! - [`Reference::Stricter`] — std's bit with an extra condition LLVM (or
//!   the instruction encoding) requires and std omits; each such row says
//!   which.

/// A CPUID output register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reg {
    /// EAX.
    Eax,
    /// EBX.
    Ebx,
    /// ECX.
    Ecx,
    /// EDX.
    Edx,
}

/// Where a feature's bit lives: bit [`bit`](Self::bit) of register
/// [`reg`](Self::reg) after `CPUID` with `EAX = leaf`, `ECX = subleaf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuidBit {
    /// The CPUID leaf (`EAX` input).
    pub leaf: u32,
    /// The CPUID sub-leaf (`ECX` input).
    pub subleaf: u32,
    /// The output register.
    pub reg: Reg,
    /// The bit within it (0–31).
    pub bit: u8,
}

/// The condition a feature needs beyond its CPUID bit. Every gate is a
/// further restriction: none ever makes a feature present on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Gate {
    /// The bit alone.
    None,
    /// The OS saves AVX state: `CPUID.1:ECX.OSXSAVE[27]` and
    /// `XCR0[2:1] = 11b` (SSE and AVX state). VEX-encoded instructions fault
    /// without it.
    AvxState,
    /// AVX-512 state: [`AvxState`](Self::AvxState) plus `XCR0[7:5] = 111b`
    /// (opmask, ZMM_Hi256, Hi16_ZMM), and the CPU also reports `fma` and
    /// `f16c` — std's rule: Rust's `avx512f` implies both, and Intel does
    /// not guarantee them alongside AVX-512.
    Avx512State,
    /// AMX state: `XCR0[18:17] = 11b` (XTILECFG, XTILEDATA). On Linux the
    /// launcher also requests the per-process permission
    /// (`arch_prctl(ARCH_REQ_XCOMP_PERM)`) before loading a core that lists
    /// an AMX feature, and treats a refusal as the feature being absent.
    AmxState,
    /// AMX state and AVX-512 state: AMX-AVX512 moves data between tiles and
    /// ZMM registers.
    AmxAvx512State,
    /// Only on AMD or Hygon CPUs (`AuthenticAMD`, `HygonGenuine`) — std's
    /// rule for the AMD-defined extended-leaf bits.
    AmdVendor,
    /// AMD or Hygon, with AVX state: FMA4 and XOP are AMD-only and use
    /// VEX/XOP-encoded YMM registers.
    AmdVendorAvxState,
    /// Not on an Intel CPU that lacks AVX: some Skylake parts report BMI1
    /// and BMI2 without supporting them (erratum SKL052) — std's rule.
    NotIntelWithoutAvx,
    /// Key Locker: `CPUID.7.0:ECX.KL[23]`, leaf 0x19 within the CPU's basic
    /// range, and the bit here (`AESKLE` — the OS enabled it).
    KeyLocker,
    /// Wide Key Locker: everything [`KeyLocker`](Self::KeyLocker) needs, and
    /// the bit here (`WIDE_KL`).
    KeyLockerWide,
    /// AVX10.2: the AVX10 flag with AVX-512 state, leaf 0x24's converged
    /// version ≥ 2, and `avxvnni`, `avxifma` and `avxvnniint8` — std's rule
    /// (AVX10.2 adds masked forms of those instructions).
    Avx10Version2,
    /// APX state: `XCR0[19] = 1` (the extended general-purpose registers) —
    /// std's rule for `apxf`.
    ApxState,
}

/// The reference a row follows (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reference {
    /// std_detect's bit and conditions, unchanged.
    StdDetect,
    /// LLVM's X86 host detection (std does not detect the name).
    Llvm,
    /// std's bit with a further condition std omits.
    Stricter,
}

/// One row of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Feature {
    /// The rustc/LLVM target-feature name, as `--print cfg` reports it.
    pub name: &'static str,
    /// Where the CPU reports it.
    pub bit: CpuidBit,
    /// What else it needs.
    pub gate: Gate,
    /// Which reference the row follows.
    pub reference: Reference,
}

const fn row(
    name: &'static str,
    leaf: u32,
    subleaf: u32,
    reg: Reg,
    bit: u8,
    gate: Gate,
    reference: Reference,
) -> Feature {
    Feature {
        name,
        bit: CpuidBit {
            leaf,
            subleaf,
            reg,
            bit,
        },
        gate,
        reference,
    }
}

use Gate::{
    AmdVendor, AmdVendorAvxState, AmxAvx512State, AmxState, ApxState, Avx10Version2, Avx512State,
    AvxState, KeyLocker, KeyLockerWide, NotIntelWithoutAvx,
};
use Reference::{Llvm, StdDetect, Stricter};
use Reg::{Eax, Ebx, Ecx, Edx};

/// The extended-function leaf carrying AMD-defined and LAHF/PREFETCHW bits.
pub const EXTENDED_FEATURES_LEAF: u32 = 0x8000_0001;

/// Every feature name rustc 1.99.1 can enable on x86, in CPUID order: the 74
/// names `--print cfg` reports for some CPU, plus `apxf`, which two CPU
/// targets use without `--print cfg` saying so ([`IMPLIED_FEATURES`]).
pub const FEATURES: [Feature; 75] = [
    // CPUID.1:EDX — the original feature flags.
    row("x87", 1, 0, Edx, 0, Gate::None, Llvm),
    row("fxsr", 1, 0, Edx, 24, Gate::None, StdDetect),
    row("sse", 1, 0, Edx, 25, Gate::None, StdDetect),
    row("sse2", 1, 0, Edx, 26, Gate::None, StdDetect),
    // CPUID.1:ECX.
    row("sse3", 1, 0, Ecx, 0, Gate::None, StdDetect),
    row("pclmulqdq", 1, 0, Ecx, 1, Gate::None, StdDetect),
    row("ssse3", 1, 0, Ecx, 9, Gate::None, StdDetect),
    row("fma", 1, 0, Ecx, 12, AvxState, StdDetect),
    row("cmpxchg16b", 1, 0, Ecx, 13, Gate::None, StdDetect),
    row("sse4.1", 1, 0, Ecx, 19, Gate::None, StdDetect),
    row("sse4.2", 1, 0, Ecx, 20, Gate::None, StdDetect),
    row("movbe", 1, 0, Ecx, 22, Gate::None, StdDetect),
    row("popcnt", 1, 0, Ecx, 23, Gate::None, StdDetect),
    row("aes", 1, 0, Ecx, 25, Gate::None, StdDetect),
    row("xsave", 1, 0, Ecx, 26, AvxState, StdDetect),
    row("avx", 1, 0, Ecx, 28, AvxState, StdDetect),
    // F16C is VEX-encoded: std reports the bit alone, LLVM also requires AVX
    // state.
    row("f16c", 1, 0, Ecx, 29, AvxState, Stricter),
    row("rdrand", 1, 0, Ecx, 30, Gate::None, StdDetect),
    // CPUID.7.0:EBX — structured extended features.
    row("bmi1", 7, 0, Ebx, 3, NotIntelWithoutAvx, StdDetect),
    row("avx2", 7, 0, Ebx, 5, AvxState, StdDetect),
    row("bmi2", 7, 0, Ebx, 8, NotIntelWithoutAvx, StdDetect),
    row("ermsb", 7, 0, Ebx, 9, Gate::None, StdDetect),
    row("avx512f", 7, 0, Ebx, 16, Avx512State, StdDetect),
    row("avx512dq", 7, 0, Ebx, 17, Avx512State, StdDetect),
    row("rdseed", 7, 0, Ebx, 18, Gate::None, StdDetect),
    row("adx", 7, 0, Ebx, 19, Gate::None, StdDetect),
    row("avx512ifma", 7, 0, Ebx, 21, Avx512State, StdDetect),
    row("clflushopt", 7, 0, Ebx, 23, Gate::None, StdDetect),
    row("avx512cd", 7, 0, Ebx, 28, Avx512State, StdDetect),
    row("sha", 7, 0, Ebx, 29, Gate::None, StdDetect),
    row("avx512bw", 7, 0, Ebx, 30, Avx512State, StdDetect),
    row("avx512vl", 7, 0, Ebx, 31, Avx512State, StdDetect),
    // CPUID.7.0:ECX.
    row("avx512vbmi", 7, 0, Ecx, 1, Avx512State, StdDetect),
    row("avx512vbmi2", 7, 0, Ecx, 6, Avx512State, StdDetect),
    row("gfni", 7, 0, Ecx, 8, Gate::None, StdDetect),
    // VAES and VPCLMULQDQ are VEX/EVEX-encoded (YMM and up): std reports the
    // bit alone, LLVM also requires AVX state.
    row("vaes", 7, 0, Ecx, 9, AvxState, Stricter),
    row("vpclmulqdq", 7, 0, Ecx, 10, AvxState, Stricter),
    row("avx512vnni", 7, 0, Ecx, 11, Avx512State, StdDetect),
    row("avx512bitalg", 7, 0, Ecx, 12, Avx512State, StdDetect),
    row("avx512vpopcntdq", 7, 0, Ecx, 14, Avx512State, StdDetect),
    // CPUID.7.0:EDX.
    row("avx512vp2intersect", 7, 0, Edx, 8, Avx512State, StdDetect),
    row("amx-bf16", 7, 0, Edx, 22, AmxState, StdDetect),
    row("avx512fp16", 7, 0, Edx, 23, Avx512State, StdDetect),
    row("amx-tile", 7, 0, Edx, 24, AmxState, StdDetect),
    row("amx-int8", 7, 0, Edx, 25, AmxState, StdDetect),
    // CPUID.7.1:EAX.
    row("sha512", 7, 1, Eax, 0, AvxState, StdDetect),
    row("sm3", 7, 1, Eax, 1, AvxState, StdDetect),
    row("sm4", 7, 1, Eax, 2, AvxState, StdDetect),
    row("avxvnni", 7, 1, Eax, 4, AvxState, StdDetect),
    row("avx512bf16", 7, 1, Eax, 5, Avx512State, StdDetect),
    row("amx-fp16", 7, 1, Eax, 21, AmxState, StdDetect),
    row("avxifma", 7, 1, Eax, 23, AvxState, StdDetect),
    row("movrs", 7, 1, Eax, 31, Gate::None, StdDetect),
    // CPUID.7.1:EDX.
    row("avxvnniint8", 7, 1, Edx, 4, AvxState, StdDetect),
    row("avxneconvert", 7, 1, Edx, 5, AvxState, StdDetect),
    row("amx-complex", 7, 1, Edx, 8, AmxState, StdDetect),
    row("avxvnniint16", 7, 1, Edx, 10, AvxState, StdDetect),
    // APX: one CPUID bit enumerates the whole foundation (EGPR, NDD, NF,
    // CCMP, PPX, PUSH2/POP2, CF, ZU), and the OS must enable its state.
    row("apxf", 7, 1, Edx, 21, ApxState, StdDetect),
    row("avx10.1", 7, 1, Edx, 19, Avx512State, StdDetect),
    // The AVX10 flag again: the version comes from leaf 0x24 (see the gate).
    row("avx10.2", 7, 1, Edx, 19, Avx10Version2, StdDetect),
    // CPUID.0xD.1:EAX — XSAVE extensions (std reports them only with AVX
    // state).
    row("xsaveopt", 0xD, 1, Eax, 0, AvxState, StdDetect),
    row("xsavec", 0xD, 1, Eax, 1, AvxState, StdDetect),
    row("xsaves", 0xD, 1, Eax, 3, AvxState, StdDetect),
    // CPUID.0x19:EBX — Key Locker.
    row("kl", 0x19, 0, Ebx, 0, KeyLocker, StdDetect),
    // Wide Key Locker: std reads WIDE_KL alone; this also requires AESKLE
    // (Key Locker enabled by the OS).
    row("widekl", 0x19, 0, Ebx, 2, KeyLockerWide, Stricter),
    // CPUID.0x1E.1:EAX — the AMX extensions.
    row("amx-fp8", 0x1E, 1, Eax, 4, AmxState, StdDetect),
    // AMX-AVX512 moves data between tiles and ZMM registers: std requires AMX
    // state only; this also requires AVX-512 state.
    row("amx-avx512", 0x1E, 1, Eax, 7, AmxAvx512State, Stricter),
    row("amx-movrs", 0x1E, 1, Eax, 8, AmxState, StdDetect),
    // CPUID.0x8000_0001:ECX — extended features.
    row(
        "lahfsahf",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        0,
        Gate::None,
        Llvm,
    ),
    row(
        "lzcnt",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        5,
        Gate::None,
        StdDetect,
    ),
    row(
        "sse4a",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        6,
        AmdVendor,
        StdDetect,
    ),
    row(
        "prfchw",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        8,
        Gate::None,
        Llvm,
    ),
    // XOP: std requires an AMD/Hygon vendor, LLVM requires AVX state; both.
    row(
        "xop",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        11,
        AmdVendorAvxState,
        Stricter,
    ),
    // FMA4: LLVM requires AVX state; it is also AMD-only.
    row(
        "fma4",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        16,
        AmdVendorAvxState,
        Llvm,
    ),
    row(
        "tbm",
        EXTENDED_FEATURES_LEAF,
        0,
        Ecx,
        21,
        AmdVendor,
        StdDetect,
    ),
];

/// Features a CPU target makes the compiler USE although `--print cfg`
/// does not report them — `(cpu, feature)`. rustc 1.99.1 (LLVM 23):
/// `diamondrapids` and `novalake` enable APX's sub-features (NF, NDD, …)
/// without all of them, so `--print cfg` lists no `apxf`, yet the code
/// carries APX encodings that fault without APX. `seaworthy-launcher`'s build
/// script adds these to the record; `tests/vocabulary.rs` compiles a probe
/// for every CPU and fails when a CPU emits APX code that neither its cfg
/// nor this list accounts for — the toolchain-upgrade guard for it.
pub const IMPLIED_FEATURES: [(&str, &str); 2] = [("diamondrapids", "apxf"), ("novalake", "apxf")];

/// The features `cpu` uses beyond what `--print cfg` reports (see
/// [`IMPLIED_FEATURES`]).
pub fn implied_features(cpu: &str) -> impl Iterator<Item = &'static str> + '_ {
    IMPLIED_FEATURES
        .iter()
        .filter(move |(name, _)| *name == cpu)
        .map(|(_, feature)| *feature)
}

/// The x86-64 row for `name`, or `None` for a name the table does not know.
/// An unknown name is never treated as present — see [`crate::Host::has`].
/// For a name on any architecture, see [`known`].
#[must_use]
pub fn lookup(name: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|feature| feature.name == name)
}

/// A CPU architecture seaworthy-levels has a feature table for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arch {
    /// x86-64: [`FEATURES`], detected with CPUID.
    X86_64,
    /// aarch64: [`crate::AARCH64_FEATURES`], detected through macOS's
    /// `sysctl`.
    Aarch64,
}

impl Arch {
    /// The architecture of a target triple (`x86_64-…`, `aarch64-…`), or
    /// `None` for one without a table.
    #[must_use]
    pub fn of_target(target: &str) -> Option<Self> {
        if target.starts_with("x86_64-") {
            Some(Self::X86_64)
        } else if target.starts_with("aarch64-") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    /// The architecture this crate was compiled for, if it has a table.
    #[must_use]
    pub const fn this() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    /// Whether this architecture's table has a row for `name`.
    #[must_use]
    pub fn knows(self, name: &str) -> bool {
        self.index_of(name).is_some()
    }

    /// The table's names, in table order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        match self {
            Self::X86_64 => FEATURES.iter().map(|feature| feature.name).collect(),
            Self::Aarch64 => crate::AARCH64_FEATURES
                .iter()
                .map(|feature| feature.name)
                .collect(),
        }
    }

    /// The position of `name` in this architecture's table.
    pub(crate) fn index_of(self, name: &str) -> Option<usize> {
        match self {
            Self::X86_64 => index_of(name),
            Self::Aarch64 => crate::aarch64::index_of(name),
        }
    }
}

/// Whether seaworthy-levels has a row for `name` on `target`'s architecture
/// (never, for a target without a table): what a core built for `target`
/// may list in its record.
#[must_use]
pub fn known(target: &str, name: &str) -> bool {
    Arch::of_target(target).is_some_and(|arch| arch.knows(name))
}

/// The position of `name` in [`FEATURES`].
pub(crate) fn index_of(name: &str) -> Option<usize> {
    FEATURES.iter().position(|feature| feature.name == name)
}

/// Whether `name` is a well-formed feature name (lower-case ASCII letters,
/// digits, `.` and `-`, starting with a letter, at most 32 bytes). Names in
/// a requirement record must be well-formed even when they are unknown.
#[must_use]
pub fn is_feature_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_well_formed_and_sorted_by_leaf() {
        let mut seen = std::collections::BTreeSet::new();
        for feature in &FEATURES {
            assert!(is_feature_name(feature.name), "{}", feature.name);
            assert!(seen.insert(feature.name), "duplicate row {}", feature.name);
            assert!(feature.bit.bit < 32, "{}", feature.name);
        }
        assert_eq!(seen.len(), 75);
    }

    #[test]
    fn lookup_finds_rows_and_refuses_unknown_names() {
        assert_eq!(lookup("avx2").map(|f| f.bit.bit), Some(5));
        assert!(lookup("avx9000").is_none());
        assert!(lookup("").is_none());
        assert_eq!(index_of("x87"), Some(0));
    }

    #[test]
    fn known_names_are_per_architecture() {
        assert!(known("x86_64-unknown-linux-gnu", "avx2"));
        assert!(!known("x86_64-unknown-linux-gnu", "neon"));
        assert!(known("aarch64-apple-darwin", "neon"));
        assert!(!known("aarch64-apple-darwin", "avx2"));
        // Both tables have an `aes` row (each its own instruction set).
        assert!(known("x86_64-pc-windows-msvc", "aes") && known("aarch64-apple-darwin", "aes"));
        assert!(!known("riscv64gc-unknown-linux-gnu", "aes"));
        assert_eq!(Arch::of_target("aarch64-apple-darwin"), Some(Arch::Aarch64));
        assert_eq!(Arch::of_target("x86_64-apple-darwin"), Some(Arch::X86_64));
        assert_eq!(Arch::of_target("wasm32-unknown-unknown"), None);
        assert_eq!(Arch::X86_64.names().len(), 75);
        assert_eq!(Arch::Aarch64.names().len(), 71);
    }

    #[test]
    fn feature_name_shape() {
        for good in ["sse4.1", "avx10.2", "amx-fp8", "x87"] {
            assert!(is_feature_name(good), "{good}");
        }
        for bad in [
            "",
            "AVX",
            "4avx",
            "avx 2",
            "avx,2",
            "avx\n",
            &"a".repeat(33),
        ] {
            assert!(!is_feature_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn every_avx512_row_needs_avx512_state() {
        for feature in FEATURES.iter().filter(|f| f.name.starts_with("avx512")) {
            assert_eq!(feature.gate, Gate::Avx512State, "{}", feature.name);
        }
        for feature in FEATURES.iter().filter(|f| f.name.starts_with("amx-")) {
            assert!(
                matches!(feature.gate, Gate::AmxState | Gate::AmxAvx512State),
                "{}",
                feature.name
            );
        }
    }
}
