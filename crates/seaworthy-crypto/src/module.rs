//! The linked AWS-LC module: its identity and the pinned expectation, the
//! boot self-check, and the build provenance stamped into this binary.
//!
//! **The module.** Under the `fips` feature this crate links the AWS-LC
//! FIPS 4.2.0 module, built from source by `aws-lc-fips-sys` 0.14.2 behind
//! `aws-lc-rs` 1.18.1, both pinned with `=` in the workspace manifest (the
//! lockfile alone is one `cargo update` away from a module that binds a
//! different FIPS release). CMVP status: [`CMVP_STATUS`]. [`linked`] reads
//! what is actually linked, at runtime; [`ensure_expected_module`] refuses
//! anything but the pinned build; the `fips`-only
//! `the_linked_module_is_the_pinned_aws_lc_fips_4_2_0` test and
//! `scripts/check-fips-binary.sh` (an `nm` check of a release binary: the
//! `aws_lc_fips_0_14_2_*` symbols present, zero non-FIPS `aws_lc_0_*` /
//! `ring_core_*`) are the gates.
//!
//! **What [`crate::is_fips`] attests, and what it does not.** `is_fips()`
//! attests MODULE LINKAGE AND TLS FILTERING: the AWS-LC FIPS module is the
//! backend and reports FIPS mode (its power-on self-tests and integrity
//! check passed before `main`), and the canonical rustls provider carries
//! only FIPS-approved suites and groups. It does NOT attest "only approved
//! services ran": the module's per-call service indicator is not
//! consulted, and some in-module operations are non-approved by that
//! indicator (the X25519 half of the hybrid key exchange); see
//! `docs/fips.md`.
//!
//! **The boot self-check.** The 4.x module always builds CPU-jitter entropy
//! in, and its startup health tests run on the FIRST draw from the DRBG; a
//! failure is an `abort()` (observed at roughly 1 process in 100 in small
//! Hyper-V guests, and 0 in about 15,000 on bare metal). Call
//! [`startup_self_check`] first thing in `main`: it draws from the module
//! DRBG so that abort happens at boot, before the process takes traffic,
//! never mid-request; and under `fips` it asserts the pinned module. The
//! entropy caveat: whether the 4.x module's Security Policy claims an ESV
//! certificate for that source, and therefore whether the SP 800-90B "no
//! assurance of the minimum strength of generated keys" caveat that the 3.x
//! policy carries applies, is to be confirmed from the 4.x Security Policy
//! when its certificate issues; record it in your security documentation,
//! do not assume it.

use crate::CryptoError;

/// The AWS-LC FIPS module release this crate pins (what
/// `aws_lc_rs::awslc_version()` returns under `fips`).
pub const EXPECTED_FIPS_MODULE_VERSION: &str = "4.2.0";
/// The FIPS module branch (`aws_lc_rs::fips_version()`).
pub const EXPECTED_FIPS_MODULE_BRANCH: u32 = 4;
/// The `aws-lc-fips-sys` release that builds it (pinned `=` in the
/// workspace manifest).
pub const EXPECTED_FIPS_SYS_VERSION: &str = "0.14.2";
/// The `aws-lc-rs` release that binds it (pinned `=` in the workspace
/// manifest).
pub const EXPECTED_AWS_LC_RS_VERSION: &str = "1.18.1";
/// The symbol prefix the pinned sys crate gives every module symbol: what
/// `scripts/check-fips-binary.sh` requires in a release binary.
pub const FIPS_SYMBOL_PREFIX: &str = "aws_lc_fips_0_14_2_";
/// The module's CMVP status, the one wording docs and evidence use (the
/// design assumes 4.2.0 will be validated; say "validated" only once the
/// certificate issues and names 4.2.0).
pub const CMVP_STATUS: &str = "AWS-LC FIPS 4.2.0 module (CMVP: in process, Comment Resolution; its \
                               validated predecessor is AWS-LC 3, certificate #5314)";
/// How many bytes [`startup_self_check`] draws from the module DRBG.
pub const SELF_CHECK_RNG_BYTES: usize = 32;

/// What this process actually links, read at runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedModule {
    /// The AWS-LC version string's version token (`"4.2.0"` under `fips`).
    pub version: String,
    /// Whether this build enables `seaworthy-crypto/fips`.
    pub fips_build: bool,
    /// Whether the backend reports FIPS mode (`FIPS_mode()`; its power-on
    /// self-tests and integrity check ran before `main`).
    pub fips_mode: bool,
    /// The FIPS module branch the backend was built from (`None` for a
    /// non-FIPS backend).
    pub fips_branch: Option<u32>,
    /// Whether the module seeds from CPU-jitter entropy (the 4.x module
    /// always does: the first-draw health test in the module docs).
    pub cpu_jitter_entropy: bool,
}

impl LinkedModule {
    /// `"AWS-LC FIPS 4.2.0"`, or `"AWS-LC <version> (non-FIPS)"`.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.fips_build && self.fips_mode {
            format!("AWS-LC FIPS {}", self.version)
        } else {
            format!("AWS-LC {} (non-FIPS)", self.version)
        }
    }
}

/// Read the linked module (runtime queries of the backend).
#[must_use]
pub fn linked() -> LinkedModule {
    LinkedModule {
        version: aws_lc_rs::awslc_version().to_string(),
        fips_build: cfg!(feature = "fips"),
        fips_mode: aws_lc_rs::try_fips_mode().is_ok(),
        fips_branch: aws_lc_rs::fips_version(),
        cpu_jitter_entropy: aws_lc_rs::try_fips_cpu_jitter_entropy().is_ok(),
    }
}

/// The FIPS module branch the pinned sys crate was BUILT from (its
/// build-time constant; `None` without `fips`), compared against the
/// runtime [`LinkedModule::fips_branch`] by the `fips` tests.
#[must_use]
pub fn compiled_branch() -> Option<u32> {
    #[cfg(feature = "fips")]
    {
        Some(aws_lc_fips_sys::fips_version()).filter(|branch| *branch != 0)
    }
    #[cfg(not(feature = "fips"))]
    {
        None
    }
}

/// The pinned-module assertion over a [`LinkedModule`], both arms testable
/// in every profile: with `expect_fips`, only AWS-LC FIPS
/// [`EXPECTED_FIPS_MODULE_VERSION`] in FIPS mode on branch
/// [`EXPECTED_FIPS_MODULE_BRANCH`] passes; without it there is no module
/// to pin (a non-FIPS backend's version is not a compliance fact).
///
/// # Errors
/// A message naming what was linked and what was expected.
pub fn check(module: &LinkedModule, expect_fips: bool) -> Result<(), String> {
    if !expect_fips {
        return Ok(());
    }
    let ok = module.fips_mode
        && module.version == EXPECTED_FIPS_MODULE_VERSION
        && module.fips_branch == Some(EXPECTED_FIPS_MODULE_BRANCH);
    if ok {
        Ok(())
    } else {
        Err(format!(
            "linked module is {} (FIPS mode {}, branch {:?}); this build pins AWS-LC FIPS \
             {EXPECTED_FIPS_MODULE_VERSION} (branch {EXPECTED_FIPS_MODULE_BRANCH}, \
             aws-lc-fips-sys {EXPECTED_FIPS_SYS_VERSION})",
            module.describe(),
            module.fips_mode,
            module.fips_branch,
        ))
    }
}

/// Under `fips`, refuse anything but the pinned module; without it, report
/// what is linked.
///
/// # Errors
/// [`CryptoError::Config`] naming the linked and the expected module.
pub fn ensure_expected_module() -> Result<LinkedModule, CryptoError> {
    let module = linked();
    check(&module, cfg!(feature = "fips")).map_err(CryptoError::Config)?;
    Ok(module)
}

/// What [`startup_self_check`] established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfCheck {
    /// The module the process links (asserted under `fips`).
    pub module: LinkedModule,
    /// How many bytes were drawn from the module DRBG
    /// ([`SELF_CHECK_RNG_BYTES`]).
    pub rng_bytes_drawn: usize,
}

/// The boot self-check: call it first thing in `main`. Draw
/// [`SELF_CHECK_RNG_BYTES`] from the module DRBG (so the CPU-jitter
/// first-draw health test, and its `abort()` on failure, runs at boot), and
/// under `fips` assert the pinned module ([`ensure_expected_module`]).
///
/// # Errors
/// [`CryptoError::Rng`] when the DRBG fails; [`CryptoError::Config`] when a
/// FIPS build links an unexpected module.
pub fn startup_self_check() -> Result<SelfCheck, CryptoError> {
    let mut draw = zeroize::Zeroizing::new([0u8; SELF_CHECK_RNG_BYTES]);
    crate::rand::fill(draw.as_mut_slice())?;
    let module = ensure_expected_module()?;
    Ok(SelfCheck {
        module,
        rng_bytes_drawn: SELF_CHECK_RNG_BYTES,
    })
}

/// The toolchain that built this binary, stamped at compile time by this
/// crate's build script. Values are single printable lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildProvenance {
    /// `rustc -V` of the compiler that built this crate.
    pub rustc: &'static str,
    /// The target triple.
    pub target: &'static str,
    /// Cargo's `PROFILE` (`debug`/`release`).
    pub profile: &'static str,
    /// Cargo's `OPT_LEVEL`.
    pub opt_level: &'static str,
    /// Whether `seaworthy-crypto/fips` was on.
    pub fips_feature: bool,
    /// The C compiler that built the module (`<cc>: <version line>`), or
    /// `n/a (non-FIPS build…)`.
    pub c_compiler: &'static str,
    /// `cmake --version` (first line), or n/a.
    pub cmake: &'static str,
    /// `go version`, or n/a.
    pub go: &'static str,
    /// The Perl version, or n/a.
    pub perl: &'static str,
    /// The module-relevant environment present at build time (`NAME=value`
    /// pairs: compiler selection, `AWS_LC_FIPS_SYS_USE_SYSTEM`), or n/a.
    pub module_build_env: &'static str,
    /// `-C target-cpu`, or `default`.
    pub target_cpu: &'static str,
    /// Knobs the build acknowledged through `SEAWORTHY_FIPS_MODULE_BUILD_ACK`
    /// (empty in a clean build: anything here altered the module build).
    pub acknowledged_knobs: &'static str,
}

/// This binary's build provenance.
pub const BUILD: BuildProvenance = BuildProvenance {
    rustc: env!("SEAWORTHY_BUILD_RUSTC"),
    target: env!("SEAWORTHY_BUILD_TARGET"),
    profile: env!("SEAWORTHY_BUILD_PROFILE"),
    opt_level: env!("SEAWORTHY_BUILD_OPT_LEVEL"),
    fips_feature: cfg!(feature = "fips"),
    c_compiler: env!("SEAWORTHY_BUILD_CC"),
    cmake: env!("SEAWORTHY_BUILD_CMAKE"),
    go: env!("SEAWORTHY_BUILD_GO"),
    perl: env!("SEAWORTHY_BUILD_PERL"),
    module_build_env: env!("SEAWORTHY_BUILD_MODULE_ENV"),
    target_cpu: env!("SEAWORTHY_BUILD_TARGET_CPU"),
    acknowledged_knobs: env!("SEAWORTHY_BUILD_ACKNOWLEDGED"),
};

/// This binary's build provenance ([`BUILD`]).
#[must_use]
pub fn build_provenance() -> &'static BuildProvenance {
    &BUILD
}

impl BuildProvenance {
    /// The provenance as `(key, value)` pairs, in a fixed order: what boot
    /// evidence and logs stamp (`build.<key>`).
    #[must_use]
    pub fn fields(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("rustc", self.rustc),
            ("target", self.target),
            ("profile", self.profile),
            ("opt_level", self.opt_level),
            ("fips_feature", if self.fips_feature { "1" } else { "0" }),
            ("c_compiler", self.c_compiler),
            ("cmake", self.cmake),
            ("go", self.go),
            ("perl", self.perl),
            ("module_build_env", self.module_build_env),
            ("target_cpu", self.target_cpu),
            ("acknowledged_knobs", self.acknowledged_knobs),
        ]
    }
}
