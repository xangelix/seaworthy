//! `seaworthy-levels` — the CPU feature tables (x86-64 and aarch64), host
//! detection, and the requirement record every per-CPU core carries.
//!
//! A product built with seaworthy ships as a thin launcher plus one core
//! library per CPU target (`x86-64-v4`, `x86-64-v3`, `x86-64-v2`, or any CPU
//! name rustc knows). This crate is what the launcher decides with:
//!
//! - **[`FEATURES`]** — one row per target-feature name the pinned rustc can
//!   enable (75 names for rustc 1.99.1, across all 136 x86 CPUs it knows —
//!   including `apxf`, which two CPU targets use without `--print cfg`
//!   reporting it, [`IMPLIED_FEATURES`]): the CPUID leaf, sub-leaf, register
//!   and bit, plus the OS-state or vendor condition the feature also needs
//!   ([`Gate`]).
//! - **[`AARCH64_FEATURES`]** — the same for aarch64 (71 names): the macOS
//!   `sysctl` keys that report each feature on Apple Silicon, or the Apple
//!   M1 baseline every arm64 Mac has ([`aarch64`]).
//! - **[`Host`]** — the features this machine supports, read with raw CPUID
//!   on x86-64 (never std's macro, so a name std hasn't stabilised is still
//!   detectable) and `sysctl` on Apple Silicon macOS, range-checked, and
//!   conservative: a name the table doesn't know is **never** present.
//! - **[`Requirement`]** — a core's record of what its compiler enabled,
//!   written by `seaworthy-launcher`'s build script into the core's `.cpureq`
//!   section, and read back from the file without loading it
//!   ([`read_requirement`]).
//! - **[`CpuList`]** — a launcher's `.cpulist`: the core's file stem and the
//!   preference order, which a packaging tool cross-checks against the cores
//!   it packages.
//! - **[`Snapshot`]** — recorded CPUID dumps, for fixtures and support
//!   reports.
//!
//! ```
//! use seaworthy_levels::{Host, Requirement};
//!
//! let record = Requirement::parse(
//!     b"seaworthy-cpureq:1\ntarget=x86_64-unknown-linux-gnu\ncpu=x86-64\nfeatures=fxsr,sse,sse2,x87\n",
//! )?;
//! let verdict = Host::detect().assess(&record, "x86_64-unknown-linux-gnu");
//! // Every x86-64 CPU runs a baseline core.
//! # #[cfg(target_arch = "x86_64")]
//! assert!(verdict.is_supported(), "{verdict}");
//! # Ok::<(), seaworthy_levels::RecordError>(())
//! ```
//!
//! **Why a table and not the compiler's own check?** A program built with
//! `-C target-cpu=x86-64-v3` faults with an invalid opcode the first time it
//! runs an instruction the CPU lacks — often long after startup, in an
//! unrelated code path. The launcher therefore checks every feature the
//! core was compiled with, *before* loading it. The checks must cover names
//! std's `is_x86_feature_detected!` rejects on stable (`lahfsahf`, `x87`,
//! `prfchw`, `clflushopt`, `apxf`, the AMX and AVX10 families, …): skipping them
//! would make the check weaker than what the code was compiled for, which
//! is the failure mode this crate exists to remove.
//!
//! See the crate README for the rules, the platform matrix and the
//! compliance notes; `seaworthy-launcher` for the launcher and core
//! contract; `docs/cpu-levels.md` in the repository for the whole picture.

// Every parser here reads bytes from files the launcher has not loaded
// (and that an attacker may have placed): no indexing that can panic, no
// arithmetic that can overflow, no division.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod aarch64;
pub mod binary;
pub mod detect;
pub mod record;
pub mod snapshot;
pub mod table;

pub use aarch64::{AARCH64_FEATURES, Arm64Feature, Signal, lookup_aarch64};
pub use binary::{
    BinaryError, CPULIST_SECTION, MACHO_CPULIST_SECTION, MACHO_RECORD_SECTION, MACHO_SEGMENT,
    MAX_BINARY_BYTES, MAX_READ_BYTES, RECORD_SECTION, cpu_list_from_bytes, read_cpu_list,
    read_requirement, requirement_from_bytes, requirement_from_file,
};
#[cfg(target_arch = "x86_64")]
pub use detect::Native;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub use detect::NativeSysctl;
pub use detect::{Assessment, CpuidSource, Host, SysctlSource};
pub use record::{
    CPULIST_MAGIC, CpuList, MAX_RECORD_BYTES, RECORD_MAGIC, RecordError, Requirement,
};
pub use snapshot::{SNAPSHOT_MAGIC, Snapshot, SnapshotError};
pub use table::{
    Arch, CpuidBit, FEATURES, Feature, Gate, IMPLIED_FEATURES, Reference, Reg, implied_features,
    is_feature_name, known, lookup,
};
