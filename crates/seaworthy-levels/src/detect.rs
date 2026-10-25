//! Host detection: which rows of this architecture's table this CPU (and
//! its OS) supports — [`crate::FEATURES`] on x86-64,
//! [`crate::AARCH64_FEATURES`] on aarch64.
//!
//! The x86-64 evaluator reads CPUID through [`CpuidSource`], so the same
//! code runs against the live CPU ([`Native`], x86-64 only) and against a
//! recorded dump ([`crate::Snapshot`]) in tests and support reports. The
//! aarch64 one reads macOS's `sysctl` keys through [`SysctlSource`]
//! (`NativeSysctl` on Apple Silicon macOS, the only target that has it;
//! elsewhere nothing is present).
//!
//! Beyond each row's bit and [`Gate`], every read is range-checked — a leaf
//! above the CPU's maximum basic or extended leaf, or a sub-leaf above the
//! leaf's maximum sub-leaf, reads as all zeros. (Intel CPUs answer an
//! out-of-range basic leaf with the highest basic leaf's data, so an
//! unchecked read can report bits that belong to another leaf. std_detect
//! does not range-check leaves 0x19 and 0x24, or sub-leaf 7.1; this does.)

use crate::aarch64::{AARCH64_FEATURES, Signal};
use crate::table::{Arch, CpuidBit, FEATURES, Feature, Gate, Reg};

/// Where CPUID and XCR0 come from.
pub trait CpuidSource {
    /// `CPUID` with `EAX = leaf`, `ECX = subleaf`: `[eax, ebx, ecx, edx]`.
    fn cpuid(&self, leaf: u32, subleaf: u32) -> [u32; 4];

    /// `XGETBV(0)`: the OS-enabled state components. Called only when
    /// `CPUID.1:ECX` reports both XSAVE and OSXSAVE — the instruction faults
    /// otherwise.
    fn xcr0(&self) -> u64;
}

/// The live CPU.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Native;

#[cfg(target_arch = "x86_64")]
impl CpuidSource for Native {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> [u32; 4] {
        // CPUID exists on every x86-64 CPU.
        let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
        [r.eax, r.ebx, r.ecx, r.edx]
    }

    fn xcr0(&self) -> u64 {
        // XGETBV faults unless the OS set CR4.OSXSAVE: check it here, not
        // only in the trait contract, so a direct caller can't fault.
        let ecx = self.cpuid(1, 0)[2];
        if ecx & (1 << 26) == 0 || ecx & (1 << 27) == 0 {
            return 0;
        }
        // SAFETY: CPUID.1:ECX reports XSAVE and OSXSAVE (just checked): the OS
        // set CR4.OSXSAVE, which is exactly when XGETBV is enabled and cannot
        // fault.
        #[allow(unsafe_code, reason = "XGETBV(0), guarded by the OSXSAVE check above")]
        let xcr0 = unsafe { xgetbv0() };
        xcr0
    }
}

/// Where `sysctl` values come from (the aarch64 evaluator, macOS).
pub trait SysctlSource {
    /// The integer value of the `sysctl` key `name`, or `None` when the
    /// running system doesn't define it.
    fn sysctl(&self, name: &str) -> Option<i64>;
}

/// The live system's `sysctl` (Apple Silicon macOS).
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeSysctl;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
impl SysctlSource for NativeSysctl {
    fn sysctl(&self, name: &str) -> Option<i64> {
        let name = std::ffi::CString::new(name).ok()?;
        let mut value: i32 = 0;
        let mut len = core::mem::size_of::<i32>();
        // SAFETY: sysctlbyname with a NUL-terminated name, an `i32` out
        // buffer and its length (the `hw.optional.*` keys are `int`s); no
        // new value is written. std_detect reads these keys the same way.
        #[allow(unsafe_code, reason = "FFI: sysctlbyname reads one integer key")]
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&raw mut value).cast(),
                &raw mut len,
                core::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && len == core::mem::size_of::<i32>()).then_some(i64::from(value))
    }
}

/// `XGETBV(0)`.
///
/// # Safety
/// The OS must have set `CR4.OSXSAVE` (`CPUID.1:ECX` reports XSAVE and
/// OSXSAVE): XGETBV faults otherwise.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "xsave")]
#[allow(
    unsafe_code,
    reason = "the XGETBV intrinsic, callable only behind its target feature"
)]
unsafe fn xgetbv0() -> u64 {
    // SAFETY: the caller guarantees OSXSAVE (see `Native::xcr0`); this
    // function's own `target_feature` makes the intrinsic callable.
    unsafe { core::arch::x86_64::_xgetbv(0) }
}

/// `XCR0` bits 1 and 2: SSE and AVX state.
const XCR0_AVX: u64 = 0b110;
/// `XCR0` bits 5–7: opmask, ZMM_Hi256, Hi16_ZMM.
const XCR0_AVX512: u64 = 0b1110_0000;
/// `XCR0` bits 17 and 18: XTILECFG, XTILEDATA.
const XCR0_AMX: u64 = 0b110_0000_0000_0000_0000;
/// `XCR0` bit 19: APX (the extended general-purpose registers).
const XCR0_APX: u64 = 1 << 19;

/// Leaf 0x24: the AVX10 converged vector ISA leaf.
const AVX10_LEAF: u32 = 0x24;
/// Leaf 0x19: Key Locker.
const KEY_LOCKER_LEAF: u32 = 0x19;
/// Leaf 0x1E: the AMX extensions (their flags live in sub-leaf 1).
const AMX_LEAF: u32 = 0x1E;

/// The CPU state the evaluator works from: range-checked CPUID reads plus
/// the vendor and OS state, computed once.
struct Cpu<'a, S: CpuidSource> {
    source: &'a S,
    max_basic: u32,
    max_extended: u32,
    max_leaf7_subleaf: u32,
    max_amx_subleaf: u32,
    amd_vendor: bool,
    intel_vendor: bool,
    xcr0: u64,
}

impl<'a, S: CpuidSource> Cpu<'a, S> {
    fn new(source: &'a S) -> Self {
        let [max_basic, ebx, ecx, edx] = source.cpuid(0, 0);
        // The vendor string is EBX, EDX, ECX, four ASCII bytes each.
        let vendor = [ebx.to_le_bytes(), edx.to_le_bytes(), ecx.to_le_bytes()];
        let [max_extended, ..] = source.cpuid(0x8000_0000, 0);
        let mut cpu = Cpu {
            source,
            max_basic,
            // A CPU without extended leaves can answer anything here; only a
            // value inside the extended range means "this many leaves".
            max_extended: if max_extended >= 0x8000_0000 {
                max_extended
            } else {
                0
            },
            max_leaf7_subleaf: 0,
            max_amx_subleaf: 0,
            amd_vendor: vendor == [*b"Auth", *b"enti", *b"cAMD"]
                || vendor == [*b"Hygo", *b"nGen", *b"uine"],
            intel_vendor: vendor == [*b"Genu", *b"ineI", *b"ntel"],
            xcr0: 0,
        };
        if cpu.max_basic >= 7 {
            cpu.max_leaf7_subleaf = source.cpuid(7, 0)[0];
        }
        if cpu.max_basic >= AMX_LEAF {
            cpu.max_amx_subleaf = source.cpuid(AMX_LEAF, 0)[0];
        }
        let leaf1_ecx = cpu.read(1, 0)[2];
        let xsave = bit_set(leaf1_ecx, 26);
        let osxsave = bit_set(leaf1_ecx, 27);
        if xsave && osxsave {
            cpu.xcr0 = source.xcr0();
        }
        cpu
    }

    /// A range-checked CPUID read: all zeros outside the CPU's ranges.
    fn read(&self, leaf: u32, subleaf: u32) -> [u32; 4] {
        let valid = if leaf >= 0x8000_0000 {
            self.max_extended >= 0x8000_0000 && leaf <= self.max_extended && subleaf == 0
        } else if leaf > self.max_basic {
            false
        } else {
            match leaf {
                7 => subleaf <= self.max_leaf7_subleaf,
                AMX_LEAF => subleaf <= self.max_amx_subleaf,
                // Leaf 0xD's sub-leaf 1 is architecturally defined wherever
                // the leaf is; the others are read at sub-leaf 0 only.
                0xD => subleaf <= 1,
                _ => subleaf == 0,
            }
        };
        if valid {
            self.source.cpuid(leaf, subleaf)
        } else {
            [0; 4]
        }
    }

    fn bit(&self, at: CpuidBit) -> bool {
        let regs = self.read(at.leaf, at.subleaf);
        let value = match at.reg {
            Reg::Eax => regs[0],
            Reg::Ebx => regs[1],
            Reg::Ecx => regs[2],
            Reg::Edx => regs[3],
        };
        bit_set(value, u32::from(at.bit))
    }

    fn os_avx(&self) -> bool {
        self.xcr0 & XCR0_AVX == XCR0_AVX
    }

    fn os_avx512(&self) -> bool {
        self.os_avx() && self.xcr0 & XCR0_AVX512 == XCR0_AVX512
    }

    fn os_amx(&self) -> bool {
        self.xcr0 & XCR0_AMX == XCR0_AMX
    }

    fn os_apx(&self) -> bool {
        self.xcr0 & XCR0_APX == XCR0_APX
    }
}

fn bit_set(value: u32, bit: u32) -> bool {
    value
        .checked_shr(bit)
        .is_some_and(|shifted| shifted & 1 == 1)
}

/// The set of rows the host supports, in its architecture's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Host {
    arch: Option<Arch>,
    present: u128,
}

impl Host {
    /// Detects the live CPU: CPUID on x86-64, `sysctl` on Apple Silicon
    /// macOS. Anywhere else (aarch64 off macOS, an architecture without a
    /// table) every feature is absent.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self::from_source(&Native)
        }
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            Self::from_sysctl(&NativeSysctl)
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "macos")
        )))]
        {
            Self {
                arch: Arch::this(),
                present: 0,
            }
        }
    }

    /// The architecture whose table this host was evaluated against.
    #[must_use]
    pub fn arch(&self) -> Option<Arch> {
        self.arch
    }

    /// Evaluates every x86-64 row against `source`.
    #[must_use]
    pub fn from_source<S: CpuidSource>(source: &S) -> Self {
        let cpu = Cpu::new(source);
        let mut host = Self {
            arch: Some(Arch::X86_64),
            present: 0,
        };
        // Gates that depend on other rows (AVX-512 on fma and f16c, BMI on
        // avx, AVX10.2 on avxvnni and friends) only reference rows decided by
        // their bit and OS state alone, which `named` evaluates directly — so
        // the evaluation order does not matter.
        for (index, feature) in FEATURES.iter().enumerate() {
            if Self::decide(&cpu, feature) {
                host.set(index);
            }
        }
        host
    }

    fn decide<S: CpuidSource>(cpu: &Cpu<'_, S>, feature: &Feature) -> bool {
        if !cpu.bit(feature.bit) {
            return false;
        }
        match feature.gate {
            Gate::None => true,
            Gate::AvxState => cpu.os_avx(),
            Gate::Avx512State => Self::avx512_ok(cpu),
            Gate::AmxState => cpu.os_amx(),
            Gate::AmxAvx512State => cpu.os_amx() && Self::avx512_ok(cpu),
            Gate::AmdVendor => cpu.amd_vendor,
            Gate::AmdVendorAvxState => cpu.amd_vendor && cpu.os_avx(),
            Gate::NotIntelWithoutAvx => !cpu.intel_vendor || Self::named(cpu, "avx"),
            Gate::KeyLocker => cpu.bit(leaf7_bit(0, Reg::Ecx, 23)),
            Gate::KeyLockerWide => {
                cpu.bit(leaf7_bit(0, Reg::Ecx, 23))
                    && cpu.bit(CpuidBit {
                        leaf: KEY_LOCKER_LEAF,
                        subleaf: 0,
                        reg: Reg::Ebx,
                        bit: 0,
                    })
            }
            Gate::ApxState => cpu.os_apx(),
            Gate::Avx10Version2 => {
                Self::avx512_ok(cpu)
                    && cpu.read(AVX10_LEAF, 0)[1] & 0xff >= 2
                    && Self::named(cpu, "avxvnni")
                    && Self::named(cpu, "avxifma")
                    && Self::named(cpu, "avxvnniint8")
            }
        }
    }

    /// Evaluates every aarch64 row against `source` (macOS's `sysctl`; see
    /// [`crate::aarch64`] for the rules).
    #[must_use]
    pub fn from_sysctl<S: SysctlSource>(source: &S) -> Self {
        let mut host = Self {
            arch: Some(Arch::Aarch64),
            present: 0,
        };
        for (index, feature) in AARCH64_FEATURES.iter().enumerate() {
            let present = match feature.signal {
                // The M1 baseline: only a key that is defined and reads 0
                // takes it away.
                Signal::AppleM1(keys) => keys.iter().all(|key| source.sysctl(key) != Some(0)),
                Signal::Sysctl(keys) => keys
                    .iter()
                    .all(|key| source.sysctl(key).is_some_and(|value| value != 0)),
                Signal::Never => false,
            };
            if present {
                host.set(index);
            }
        }
        host
    }

    /// AVX-512 state, with `fma` and `f16c` present (std's rule).
    fn avx512_ok<S: CpuidSource>(cpu: &Cpu<'_, S>) -> bool {
        cpu.os_avx512() && Self::named(cpu, "fma") && Self::named(cpu, "f16c")
    }

    /// A row decided by its bit and OS state alone (the rows other gates
    /// depend on all have `Gate::None` or `Gate::AvxState`).
    fn named<S: CpuidSource>(cpu: &Cpu<'_, S>, name: &str) -> bool {
        crate::table::lookup(name).is_some_and(|feature| {
            cpu.bit(feature.bit)
                && match feature.gate {
                    Gate::None => true,
                    Gate::AvxState => cpu.os_avx(),
                    _ => false,
                }
        })
    }

    fn set(&mut self, index: usize) {
        if let Some(mask) = u32::try_from(index).ok().and_then(|i| 1u128.checked_shl(i)) {
            self.present |= mask;
        }
    }

    /// Whether the host supports `name`. An unknown name is never present:
    /// a core that lists a feature this table cannot check is never loaded.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.arch
            .and_then(|arch| arch.index_of(name))
            .and_then(|index| u32::try_from(index).ok())
            .and_then(|index| 1u128.checked_shl(index))
            .is_some_and(|mask| self.present & mask != 0)
    }

    /// The names the host supports, in table order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.arch
            .map(Arch::names)
            .unwrap_or_default()
            .into_iter()
            .filter(|name| self.has(name))
    }

    /// Whether this host's table has a row for `name`.
    fn knows(&self, name: &str) -> bool {
        self.arch.is_some_and(|arch| arch.knows(name))
    }

    /// How a core's requirement record fares on this host.
    #[must_use]
    pub fn assess(&self, requirement: &crate::Requirement, expected_target: &str) -> Assessment {
        let unknown: Vec<String> = requirement
            .features
            .iter()
            .filter(|name| !self.knows(name))
            .cloned()
            .collect();
        let missing: Vec<String> = requirement
            .features
            .iter()
            .filter(|name| self.knows(name) && !self.has(name))
            .cloned()
            .collect();
        Assessment {
            wrong_target: (requirement.target != expected_target)
                .then(|| requirement.target.clone()),
            unknown,
            missing,
        }
    }
}

const fn leaf7_bit(subleaf: u32, reg: Reg, bit: u8) -> CpuidBit {
    CpuidBit {
        leaf: 7,
        subleaf,
        reg,
        bit,
    }
}

/// The outcome of [`Host::assess`]: a core is usable only when all three
/// lists are empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assessment {
    /// The record names another target triple (its own value).
    pub wrong_target: Option<String>,
    /// Feature names the table does not know — never treated as present.
    pub unknown: Vec<String>,
    /// Known features the host lacks.
    pub missing: Vec<String>,
}

impl Assessment {
    /// Whether the host can run the core.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.wrong_target.is_none() && self.unknown.is_empty() && self.missing.is_empty()
    }
}

impl core::fmt::Display for Assessment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_supported() {
            return f.write_str("supported");
        }
        let mut parts = Vec::new();
        if let Some(target) = &self.wrong_target {
            parts.push(format!("built for another target ({target})"));
        }
        if !self.missing.is_empty() {
            parts.push(format!("needs {}", self.missing.join(", ")));
        }
        if !self.unknown.is_empty() {
            parts.push(format!(
                "lists features this launcher cannot check ({})",
                self.unknown.join(", ")
            ));
        }
        f.write_str(&parts.join("; "))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// A synthetic CPU: the leaves it answers, and XCR0.
    #[derive(Default)]
    struct Fake {
        leaves: HashMap<(u32, u32), [u32; 4]>,
        xcr0: u64,
    }

    const INTEL: [u32; 3] = [0x756e_6547, 0x6c65_746e, 0x4965_6e69]; // "GenuineIntel": ebx, ecx, edx
    const AMD: [u32; 3] = [0x6874_7541, 0x444d_4163, 0x6974_6e65]; // "AuthenticAMD"
    const HYGON: [u32; 3] = [0x6f67_7948, 0x656e_6975, 0x6e65_476e]; // "HygonGenuine"

    impl Fake {
        fn new(vendor: [u32; 3], max_basic: u32, max_extended: u32) -> Self {
            let mut fake = Self::default();
            fake.leaves
                .insert((0, 0), [max_basic, vendor[0], vendor[1], vendor[2]]);
            fake.leaves
                .insert((0x8000_0000, 0), [max_extended, 0, 0, 0]);
            fake
        }
        fn set(&mut self, leaf: u32, subleaf: u32, reg: usize, bit: u32) -> &mut Self {
            let regs = self.leaves.entry((leaf, subleaf)).or_insert([0; 4]);
            regs[reg] |= 1u32.checked_shl(bit).unwrap_or(0);
            self
        }
        /// XSAVE + OSXSAVE, with `xcr0` enabled.
        fn os_state(&mut self, xcr0: u64) -> &mut Self {
            self.set(1, 0, 2, 26).set(1, 0, 2, 27);
            self.xcr0 = xcr0;
            self
        }
    }

    impl CpuidSource for Fake {
        fn cpuid(&self, leaf: u32, subleaf: u32) -> [u32; 4] {
            self.leaves.get(&(leaf, subleaf)).copied().unwrap_or([0; 4])
        }
        fn xcr0(&self) -> u64 {
            self.xcr0
        }
    }

    const EAX: usize = 0;
    const EBX: usize = 1;
    const ECX: usize = 2;
    const EDX: usize = 3;

    fn with_avx_bits(fake: &mut Fake) {
        // avx, fma, f16c (leaf 1) and avx2 (leaf 7).
        fake.set(1, 0, ECX, 28)
            .set(1, 0, ECX, 12)
            .set(1, 0, ECX, 29)
            .set(7, 0, EBX, 5);
    }

    #[test]
    fn avx_needs_the_os_to_save_its_state() {
        // The CPU has AVX but no OSXSAVE: XGETBV would fault, AVX is off.
        let mut fake = Fake::new(INTEL, 7, 0);
        with_avx_bits(&mut fake);
        let host = Host::from_source(&fake);
        for name in ["avx", "avx2", "fma", "f16c", "xsave"] {
            assert!(!host.has(name), "{name} without OSXSAVE");
        }
        // OSXSAVE, but the OS enabled only x87 + SSE state.
        fake.os_state(0b011);
        let host = Host::from_source(&fake);
        assert!(!host.has("avx"), "AVX without XCR0.AVX");
        // Full AVX state.
        fake.os_state(0b111);
        let host = Host::from_source(&fake);
        for name in ["avx", "avx2", "fma", "f16c", "xsave"] {
            assert!(host.has(name), "{name} with AVX state");
        }
    }

    #[test]
    fn avx512_needs_its_state_and_fma_and_f16c() {
        let mut fake = Fake::new(AMD, 7, 0);
        with_avx_bits(&mut fake);
        fake.set(7, 0, EBX, 16).os_state(0b111);
        assert!(!Host::from_source(&fake).has("avx512f"), "no AVX-512 state");
        fake.os_state(0b1110_0111);
        assert!(Host::from_source(&fake).has("avx512f"));
        // The same CPU without F16C: std's rule refuses AVX-512.
        let mut no_f16c = Fake::new(AMD, 7, 0);
        no_f16c
            .set(1, 0, ECX, 28)
            .set(1, 0, ECX, 12)
            .set(7, 0, EBX, 5)
            .set(7, 0, EBX, 16);
        no_f16c.os_state(0b1110_0111);
        assert!(
            !Host::from_source(&no_f16c).has("avx512f"),
            "AVX-512 without F16C"
        );
    }

    #[test]
    fn bmi_on_an_intel_cpu_without_avx_is_the_skylake_erratum() {
        let mut fake = Fake::new(INTEL, 7, 0);
        fake.set(7, 0, EBX, 3).set(7, 0, EBX, 8);
        let host = Host::from_source(&fake);
        assert!(!host.has("bmi1") && !host.has("bmi2"), "SKL052");
        let mut amd = Fake::new(AMD, 7, 0);
        amd.set(7, 0, EBX, 3).set(7, 0, EBX, 8);
        let host = Host::from_source(&amd);
        assert!(
            host.has("bmi1") && host.has("bmi2"),
            "the erratum is Intel's"
        );
        with_avx_bits(&mut fake);
        fake.os_state(0b111);
        let host = Host::from_source(&fake);
        assert!(host.has("bmi1") && host.has("bmi2"), "Intel with AVX");
    }

    #[test]
    fn amd_defined_bits_need_an_amd_or_hygon_vendor() {
        for (vendor, expect) in [(INTEL, false), (AMD, true), (HYGON, true)] {
            let mut fake = Fake::new(vendor, 1, 0x8000_0001);
            fake.set(0x8000_0001, 0, ECX, 6)
                .set(0x8000_0001, 0, ECX, 21);
            let host = Host::from_source(&fake);
            assert_eq!(host.has("sse4a"), expect);
            assert_eq!(host.has("tbm"), expect);
        }
        // XOP and FMA4: AMD and AVX state.
        let mut fake = Fake::new(AMD, 7, 0x8000_0001);
        fake.set(0x8000_0001, 0, ECX, 11)
            .set(0x8000_0001, 0, ECX, 16);
        assert!(
            !Host::from_source(&fake).has("xop"),
            "XOP without AVX state"
        );
        fake.os_state(0b111);
        let host = Host::from_source(&fake);
        assert!(host.has("xop") && host.has("fma4"));
    }

    #[test]
    fn out_of_range_leaves_read_as_zero() {
        // Leaf 0x19 answered with stale data while the CPU's maximum basic
        // leaf is 0x10 (Intel repeats the highest leaf there): no Key Locker.
        let mut fake = Fake::new(INTEL, 0x10, 0);
        fake.set(7, 0, ECX, 23)
            .set(0x19, 0, EBX, 0)
            .set(0x19, 0, EBX, 2);
        assert!(
            !Host::from_source(&fake).has("kl"),
            "leaf 0x19 above the maximum"
        );
        fake.leaves
            .insert((0, 0), [0x19, INTEL[0], INTEL[1], INTEL[2]]);
        let host = Host::from_source(&fake);
        assert!(host.has("kl") && host.has("widekl"));
        // Sub-leaf 7.1 above leaf 7's maximum sub-leaf (0).
        let mut fake = Fake::new(INTEL, 7, 0);
        fake.set(7, 1, EAX, 31);
        assert!(
            !Host::from_source(&fake).has("movrs"),
            "7.1 above the maximum sub-leaf"
        );
        fake.leaves.insert((7, 0), [1, 0, 0, 0]);
        assert!(
            Host::from_source(&fake).has("movrs"),
            "7.1 within the maximum sub-leaf"
        );
        // Extended leaf 0x8000_0001 above the maximum extended leaf.
        let mut fake = Fake::new(AMD, 1, 0x8000_0000);
        fake.set(0x8000_0001, 0, ECX, 0);
        assert!(!Host::from_source(&fake).has("lahfsahf"));
        // A maximum extended leaf below the extended range means "none".
        let mut fake = Fake::new(AMD, 1, 0x0000_0042);
        fake.set(0x8000_0001, 0, ECX, 0);
        assert!(!Host::from_source(&fake).has("lahfsahf"));
    }

    #[test]
    fn widekl_needs_kl() {
        let mut fake = Fake::new(INTEL, 0x19, 0);
        fake.set(7, 0, ECX, 23).set(0x19, 0, EBX, 2);
        let host = Host::from_source(&fake);
        assert!(
            !host.has("kl") && !host.has("widekl"),
            "WIDE_KL without AESKLE"
        );
    }

    #[test]
    fn amx_needs_its_state_and_amx_avx512_also_avx512() {
        let mut fake = Fake::new(INTEL, 0x1E, 0);
        fake.set(7, 0, EDX, 24).set(7, 0, EDX, 25);
        fake.leaves.insert((0x1E, 0), [1, 0, 0, 0]);
        fake.set(0x1E, 1, EAX, 4).set(0x1E, 1, EAX, 7);
        fake.os_state(0b111);
        assert!(!Host::from_source(&fake).has("amx-tile"), "no XCR0.AMX");
        fake.os_state(0b110_0000_0000_0000_0111);
        let host = Host::from_source(&fake);
        assert!(host.has("amx-tile") && host.has("amx-int8") && host.has("amx-fp8"));
        assert!(!host.has("amx-avx512"), "AMX-AVX512 without AVX-512 state");
        with_avx_bits(&mut fake);
        fake.os_state(0b110_0000_0000_1110_0111);
        assert!(Host::from_source(&fake).has("amx-avx512"));
        // Sub-leaf 0x1E.1 above leaf 0x1E's maximum sub-leaf.
        fake.leaves.insert((0x1E, 0), [0, 0, 0, 0]);
        assert!(!Host::from_source(&fake).has("amx-fp8"));
    }

    #[test]
    fn avx10_2_needs_version_two_and_the_vnni_family() {
        let mut fake = Fake::new(INTEL, 0x24, 0);
        with_avx_bits(&mut fake);
        // Leaf 7's maximum sub-leaf is 1 (so 7.1 is read); avx2 is already set.
        fake.leaves.entry((7, 0)).or_insert([0; 4])[EAX] = 1;
        fake.set(7, 1, EDX, 19).os_state(0b1110_0111);
        fake.leaves.insert((0x24, 0), [0, 1, 0, 0]);
        let host = Host::from_source(&fake);
        assert!(host.has("avx10.1") && !host.has("avx10.2"), "version 1");
        fake.leaves.insert((0x24, 0), [0, 2, 0, 0]);
        assert!(
            !Host::from_source(&fake).has("avx10.2"),
            "version 2 without the VNNI family"
        );
        fake.set(7, 1, EAX, 4).set(7, 1, EAX, 23).set(7, 1, EDX, 4);
        assert!(Host::from_source(&fake).has("avx10.2"));
    }

    #[test]
    fn apx_needs_its_os_state() {
        let mut fake = Fake::new(INTEL, 7, 0);
        fake.leaves.insert((7, 0), [1, 0, 0, 0]);
        fake.set(7, 1, EDX, 21).os_state(0b111);
        assert!(
            !Host::from_source(&fake).has("apxf"),
            "APX without XCR0.APX"
        );
        fake.os_state(0b1000_0000_0000_0000_0111);
        assert!(Host::from_source(&fake).has("apxf"));
    }

    #[test]
    fn native_xcr0_never_faults_without_osxsave() {
        // On any host: the guarded read returns 0 or the real XCR0, never a
        // fault — and agrees with the OSXSAVE bit.
        #[cfg(target_arch = "x86_64")]
        {
            let osxsave = Native.cpuid(1, 0)[2] & (1 << 27) != 0;
            let xcr0 = Native.xcr0();
            assert_eq!(xcr0 != 0, osxsave, "XCR0 {xcr0:#x}");
        }
    }

    #[test]
    fn unknown_names_are_never_present_and_assessment_lists_them() {
        let host = Host::from_source(&Fake::new(AMD, 1, 0));
        assert!(!host.has("avx9000"));
        let record = crate::Requirement {
            target: "x86_64-unknown-linux-gnu".into(),
            cpu: "future".into(),
            features: vec!["avx9000".into(), "sse".into()],
        };
        let verdict = host.assess(&record, "x86_64-pc-windows-msvc");
        assert!(!verdict.is_supported());
        assert_eq!(verdict.unknown, ["avx9000"]);
        assert_eq!(verdict.missing, ["sse"]);
        assert_eq!(
            verdict.wrong_target.as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            verdict.to_string(),
            "built for another target (x86_64-unknown-linux-gnu); needs sse; lists features this launcher cannot check (avx9000)"
        );
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod aarch64_tests {
    use std::collections::HashMap;

    use super::*;

    /// A synthetic macOS: the keys it defines and their values.
    #[derive(Default)]
    struct Fake(HashMap<&'static str, i64>);

    impl SysctlSource for Fake {
        fn sysctl(&self, name: &str) -> Option<i64> {
            self.0.get(name).copied()
        }
    }

    /// Every key the table names, set to 1 (a macOS that defines them all).
    fn every_key() -> Fake {
        let mut fake = Fake::default();
        for feature in &AARCH64_FEATURES {
            if let Signal::AppleM1(keys) | Signal::Sysctl(keys) = feature.signal {
                for key in keys {
                    fake.0.insert(key, 1);
                }
            }
        }
        fake
    }

    fn baseline() -> Vec<&'static str> {
        AARCH64_FEATURES
            .iter()
            .filter(|f| matches!(f.signal, Signal::AppleM1(_)))
            .map(|f| f.name)
            .collect()
    }

    fn requirement(features: &[&str]) -> crate::Requirement {
        let mut features: Vec<String> = features.iter().map(|f| (*f).to_owned()).collect();
        features.sort();
        crate::Requirement {
            target: "aarch64-apple-darwin".into(),
            cpu: "apple-m1".into(),
            features,
        }
    }

    #[test]
    fn macos_11_has_the_m1_baseline_and_nothing_beyond() {
        // macOS 11 defines no hw.optional.arm.FEAT_* key at all.
        let mut fake = Fake::default();
        fake.0.insert("hw.optional.AdvSIMD", 1);
        fake.0.insert("hw.optional.floatingpoint", 1);
        fake.0.insert("hw.optional.armv8_crc32", 1);
        let host = Host::from_sysctl(&fake);
        assert_eq!(host.arch(), Some(Arch::Aarch64));
        assert_eq!(host.names().collect::<Vec<_>>(), baseline());
        assert_eq!(baseline().len(), 34);
        assert!(
            host.assess(&requirement(&baseline()), "aarch64-apple-darwin")
                .is_supported()
        );
        // A Sysctl row whose key the system doesn't define is absent.
        assert!(!host.has("i8mm") && !host.has("bf16"));
    }

    #[test]
    fn a_defined_key_reading_zero_takes_a_baseline_feature_away() {
        let mut fake = every_key();
        fake.0.insert("hw.optional.arm.FEAT_PMULL", 0);
        fake.0.insert("hw.optional.floatingpoint", 0);
        let host = Host::from_sysctl(&fake);
        assert!(!host.has("aes"), "aes needs FEAT_AES and FEAT_PMULL");
        assert!(!host.has("neon"), "neon needs AdvSIMD and floatingpoint");
        assert!(host.has("sha2") && host.has("lor") && host.has("v8.4a"));
    }

    #[test]
    fn a_virtual_mac_hiding_ssbs_and_dit_still_has_the_baseline() {
        // A Virtualization.framework guest (a macOS virtual machine)
        // reports FEAT_SSBS as 0: PSTATE controls compiled code never sets
        // must not refuse an apple-m1 core.
        let mut fake = every_key();
        fake.0.insert("hw.optional.arm.FEAT_SSBS", 0);
        fake.0.insert("hw.optional.arm.FEAT_DIT", 0);
        let host = Host::from_sysctl(&fake);
        assert!(host.has("ssbs") && host.has("dit"));
        assert!(
            host.assess(&requirement(&baseline()), "aarch64-apple-darwin")
                .is_supported()
        );
    }

    #[test]
    fn keys_beyond_the_baseline_need_every_key_and_never_rows_stay_absent() {
        let mut fake = every_key();
        fake.0.insert("hw.optional.arm.FEAT_MTE2", 0);
        let host = Host::from_sysctl(&fake);
        for name in ["bf16", "bti", "i8mm", "sme", "sme2", "wfxt"] {
            assert!(host.has(name), "{name}");
        }
        assert!(!host.has("mte"), "mte needs FEAT_MTE and FEAT_MTE2");
        for name in ["sve", "sve2", "v8.5a", "v9a", "fp8", "rand", "sm4"] {
            assert!(!host.has(name), "{name}: no signal, never present");
        }
        // An apple-m4 core (v8.7a and SME) is skipped; the m1 core runs.
        let m4 = requirement(&["sme", "sme2", "bf16", "i8mm", "v8.5a", "v8.6a", "v8.7a"]);
        let verdict = host.assess(&m4, "aarch64-apple-darwin");
        assert_eq!(verdict.missing, ["v8.5a", "v8.6a", "v8.7a"]);
        assert!(
            host.assess(&requirement(&baseline()), "aarch64-apple-darwin")
                .is_supported()
        );
    }

    #[test]
    fn x86_names_are_unknown_on_aarch64() {
        let host = Host::from_sysctl(&every_key());
        let verdict = host.assess(&requirement(&["avx2", "neon"]), "aarch64-apple-darwin");
        assert_eq!(verdict.unknown, ["avx2"]);
        assert!(!host.has("avx2"));
        assert!(!verdict.is_supported());
    }
}
