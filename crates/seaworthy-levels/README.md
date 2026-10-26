# seaworthy-levels

*Know exactly which instructions this CPU runs, before running any.*

## What it is / how it works / where it's needed

`seaworthy-levels` is the CPU feature tables (x86-64 and aarch64), host
detection (raw CPUID; `sysctl` on Apple Silicon macOS), and the requirement
record each per-CPU core carries — what `seaworthy-launcher` selects cores
by. A product built with seaworthy ships as a thin launcher plus one core
library per CPU target (`x86-64-v4`, `x86-64-v3`, `x86-64-v2`, or any CPU
name rustc knows). A core compiled with `-C target-cpu=x86-64-v3` faults
with an invalid opcode the first time it executes an instruction the CPU
lacks — often long after startup, in an unrelated code path. So before
loading a core, the launcher checks **every** feature the compiler enabled
for it against what this machine supports.

These pieces make that check exact:

- **`FEATURES`** — one row per target-feature name the pinned rustc can
  enable (76 names for rustc 1.98.1, across all 131 x86 CPUs it knows):
  the CPUID leaf, sub-leaf, register and bit, plus the OS-state or vendor
  condition (`Gate`) the feature also needs. **`IMPLIED_FEATURES`** names
  what a CPU target uses without `--print cfg` reporting it (`apxf` for
  `diamondrapids` and `novalake`, rule 3).
- **`AARCH64_FEATURES`** — the same for aarch64 (71 names across every
  aarch64 CPU rustc 1.98.1 knows): the macOS `sysctl` keys std's own Darwin
  detector reads for each (`Signal::Sysctl`), the Apple M1 baseline every
  arm64 Mac has (`Signal::AppleM1`, rule 5), or nothing macOS reports
  (`Signal::Never`).
- **`Host`** — this machine's features, in its architecture's table: on
  x86-64 read with raw CPUID and `XGETBV`, every leaf range-checked, every
  gate applied; on Apple Silicon macOS read from `sysctl`.
- **`Requirement`** — a core's `.cpureq` record (format version, target
  triple, CPU name, the full feature list), written at build time by
  `seaworthy-launcher`'s build script and read back **from the file without
  loading it** (`read_requirement`). A launcher's `.cpulist` (`CpuList`)
  names its cores and their preference order.

The whole picture — levels, records, building one core per level, the
launcher's choice — is in [`docs/cpu-levels.md`](../../docs/cpu-levels.md).

## The rules of seaworthy-levels

1. **An unknown feature name is never present.** `Host::has` answers
   `false` for any name the table lacks, and `Host::assess` lists it under
   `unknown`; a core that names one is never loaded. The table must grow
   instead (rule 3).
2. **Under-report, never over-report.** Each row follows std's own
   detector (`std_detect`, rust-src 1.98.1) — or LLVM's for the four names
   std doesn't detect — and the *stricter* of the two where they differ
   (`Reference::Stricter`: `f16c`, `vaes`, `vpclmulqdq` also need AVX
   state; `xop` needs an AMD vendor and AVX state; `amx-avx512` also needs
   AVX-512 state; `widekl` also needs Key Locker enabled by the OS — and
   `fma4`, an LLVM row, needs an AMD vendor and AVX state). Every CPUID
   read is range-checked against the CPU's maximum basic, extended and
   sub-leaf — Intel answers an out-of-range basic leaf with another leaf's
   data, and std does not range-check leaves 0x19 and 0x24 or sub-leaf 7.1.
3. **The table is exactly the toolchain's vocabulary — what it reports and
   what it emits.** `tests/vocabulary.rs` re-derives every name
   `rustc --print cfg -C target-cpu=<cpu>` reports (with
   `RUSTC_BOOTSTRAP=1`) for every CPU on both supported x86-64 targets, and
   fails on a name without a row ("add one row") or a row the toolchain
   dropped. `--print cfg` can under-report: on rustc 1.98.1 `diamondrapids`
   and `novalake` enable APX's sub-features (NF, NDD, CCMP, PUSH2/POP2, …)
   without the `apxf` umbrella, so no `apxf` is reported, yet the code is
   full of APX encodings. So the test also compiles a probe for every
   64-bit CPU and reads its assembly: APX code must be covered by the cfg
   or by `IMPLIED_FEATURES` (which `seaworthy-launcher`'s build script adds
   to the record), every `IMPLIED_FEATURES` entry must still be needed, and
   no CPU may fold unaligned memory operands into legacy SSE instructions.
   A toolchain upgrade can therefore never silently weaken the check: it
   fails on the upgrade's own change, never in a release.
4. **Records are read, never executed.** `read_requirement` parses the
   file through a read cache — the headers, the section table, what the
   format parser needs (for ELF, the symbol tables) and the one section;
   never the whole image. A malformed file can make the parser ask for the
   same bytes again and again, so the reader refuses a file over 2 GiB
   (`MAX_BINARY_BYTES`) and takes at most 256 MiB from one file in all
   (`MAX_READ_BYTES`). It accepts ELF, PE
   and a single-architecture Mach-O only (`.cpureq`/`.cpulist`;
   `__DATA,__cpureq`/`__DATA,__cpulist` in a Mach-O; a universal binary is
   refused), and the section exactly once. The record inside may be at
   most 4 KiB; the section's raw size may exceed that by up to 4 KiB of PE
   file-alignment padding. Loading a library runs its initializers, which
   may already use instructions the CPU lacks; reading it runs nothing.
5. **On Apple Silicon, the M1 is the floor, and nothing beyond it is
   guessed.** macOS 11 defines none of the `hw.optional.arm.FEAT_*` keys
   (macOS 12 added them), and some features have no key at all; but every
   arm64 Mac is an M1 or later, and every later chip's features contain the
   M1's. So exactly what rustc enables for `apple-m1` — the default CPU of
   `aarch64-apple-darwin`, which `tests/vocabulary.rs` checks row for row —
   is present on any arm64 Mac unless a defined key reads 0 (`ssbs` and
   `dit` consult none: processor state controls compiled code never sets,
   and macOS reports `FEAT_SSBS` as 0 inside a Virtualization.framework
   guest), and anything beyond it needs its `sysctl` key (as std reads it)
   or is never present: the architecture versions `v8.5a` and later, SVE
   and FP8 have no key, so a core for a chip above `apple-m1` is skipped
   and the launcher falls back. Ship `apple-m1`.

## TL;DR — reach for this when… / not when…

- **When** you choose among per-CPU builds of a program — normally through
  `seaworthy-launcher`, which uses all of this crate.
- **When** you need to explain a selection: `Snapshot` records a machine's
  CPUID for a support report, `Assessment` says exactly what is missing.
- **When** a packaging or release tool must check, at build time, that each
  core's record names its CPU and only features the launcher can check.
- **Not when** you only need a fast runtime branch inside one binary for
  one stable feature — `is_x86_feature_detected!` is the tool for that.

## Deliberately out of scope

- **aarch64 off macOS.** The aarch64 table is detected through macOS's
  `sysctl` only; Linux (`getauxval`) and Windows
  (`IsProcessorFeaturePresent`) aren't wired. On a host without a detector
  `Host::detect()` reports nothing present, so every core is refused.
- **Choosing or loading cores.** That's `seaworthy-launcher`'s; this crate
  only decides and reads.

## Capabilities

- `FEATURES`, `lookup`, `is_feature_name` (a name's shape — `lookup` says
  whether the x86-64 table has it) — the table (`Feature`, `CpuidBit`,
  `Gate`, `Reference`).
- `AARCH64_FEATURES`, `lookup_aarch64` — the aarch64 table
  (`Arm64Feature`, `Signal`); `Arch` and `known(target, name)` — whether a
  core built for `target` may list `name`.
- `IMPLIED_FEATURES`, `implied_features` — what a CPU target uses beyond
  what `--print cfg` reports.
- `Host::detect`, `Host::from_source` (x86-64), `Host::from_sysctl`
  (aarch64), `Host::arch`, `Host::has`, `Host::names`, `Host::assess` →
  `Assessment` (`wrong_target`, `unknown`, `missing`).
- `CpuidSource` (`Native` on x86-64), `SysctlSource` (`NativeSysctl` on
  Apple Silicon macOS), `Snapshot` (record, parse, render, replay; x86-64)
  — recorded CPUs for tests and support.
- `Requirement`, `CpuList` — the two record formats (strict parsers,
  `render`).
- `read_requirement`, `read_cpu_list`, `requirement_from_bytes`,
  `cpu_list_from_bytes` — read a record from an ELF, PE or Mach-O file.
- `examples/cpuid_dump.rs` — prints this machine's dump and features.

## The formats

Every format carries a `seaworthy-<name>:<version>` first line; a parser
refuses any other.

| Format | Where | Lines |
| --- | --- | --- |
| `seaworthy-cpureq:1` | a core's `.cpureq` section (`__DATA,__cpureq` on macOS) | `target=<triple>`, `cpu=<rustc CPU>`, `features=<sorted, unique, comma-separated>` |
| `seaworthy-cpulist:1` | a launcher's `.cpulist` section (`__DATA,__cpulist`) | `core=<file stem>`, `cpus=<preference order>` |
| `seaworthy-cpuid:1` | a CPUID dump (`Snapshot`) | `# comment`, `cpuid <leaf>.<subleaf> <eax> <ebx> <ecx> <edx>`, one `xcr0 <16 hex digits>` |

The record parsers are strict: fixed line order, `\n` endings, every value
shape-checked (a core stem or CPU name can't carry `/` or `..`), at most
4 KiB, and only trailing NUL padding tolerated (a PE section's raw size is
rounded up to the file alignment).

## Architecture diagram

No diagram — no moving parts: CPUID and `XGETBV` → the table's bits and
gates → a feature set; a record is compared with it.

## Examples

Assess a core's record against this machine:

```rust
use seaworthy_levels::{Host, Requirement};

let record = Requirement::parse(
    b"seaworthy-cpureq:1\ntarget=x86_64-unknown-linux-gnu\ncpu=x86-64-v2\n\
      features=cmpxchg16b,fxsr,lahfsahf,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87\n",
)?;
let verdict = Host::detect().assess(&record, "x86_64-unknown-linux-gnu");
if !verdict.is_supported() {
    eprintln!("this CPU can't run the v2 build: {verdict}"); // "needs popcnt, sse4.1, …"
}
# Ok::<(), seaworthy_levels::RecordError>(())
```

Complete wiring — the selection a launcher makes, from files on disk (what
`seaworthy-launcher` does; shown here for callers with their own selection):

```rust,no_run
use seaworthy_levels::{read_requirement, Host};
use std::path::Path;

let host = Host::detect();
let dir = Path::new("/opt/acme/tool/lib");
let chosen = ["x86-64-v4", "x86-64-v3", "x86-64-v2"].into_iter().find(|cpu| {
    let path = dir.join(format!("libtool_core_{cpu}.so"));
    match read_requirement(&path) {
        Ok(record) => record.cpu == *cpu && host.assess(&record, "x86_64-unknown-linux-gnu").is_supported(),
        Err(e) => {
            eprintln!("{cpu}: {e}");
            false
        }
    }
});
println!("{chosen:?}");
```

A support dump: `cargo run -p seaworthy-levels --example cpuid_dump -- "host description"`
prints the snapshot (replayable with `Snapshot::parse`) and the features
detected.

## Wiring it in

- **Manifest** — `seaworthy-levels = "0.1"`. No features.
- **Server boot** — no server wiring.
- **Client** — nothing; it is a library a launcher (or packaging tool)
  calls.
- **What it injects** — nothing; you call it, it doesn't call you.
- **Configuration surface** — none: the table is code, pinned to the
  workspace toolchain (`rust-toolchain.toml`) by `tests/vocabulary.rs`.

## Proper usage by circumstance

- **Choosing a core:** compare the record's `target` with the target you
  were built for and assess the rest; treat `wrong_target`, `unknown` and
  `missing` alike — any of them means "don't load".
  **Warning:** filtering a record's feature list down to the names std's
  `is_x86_feature_detected!` accepts makes the check weaker than what the
  code was compiled for — cargo-multivers' runner dropped `clflushopt`,
  `lahfsahf`, `prfchw` and `x87` this way. Check every name; an unknown one
  must refuse.
- **Upgrading the toolchain:** run the whole suite; `tests/vocabulary.rs`
  names each new feature, and each CPU target whose code uses APX without
  reporting it. Add the row from `std_detect`'s x86 source (or LLVM's host
  detection), with the stricter gate where they differ; add an
  `IMPLIED_FEATURES` entry for a CPU the probe names.
  **Warning:** a row added with the bit alone, without its OS-state gate,
  over-reports on a system whose OS hasn't enabled the register state —
  the core then faults on its first vector instruction.
- **Testing selection under emulation:** qemu-user's TCG implements only
  part of each model (no AVX-512, AMX, GFNI or VPCLMULQDQ), and masks the
  rest — which the detector must and does respect (`tests/fixtures.rs`).
  `x86-64-v4` needs real hardware or Intel SDE.

## FAQ

**Why not just use `is_x86_feature_detected!`?** On stable it rejects names
cores are compiled with — `clflushopt`, `lahfsahf`, `prfchw` and `x87`, all
common in per-CPU builds — and every unstable one (`apxf`, the AMX and
AVX10 families, `movrs`, …). Detecting only what std accepts leaves a gap
between the check and the code; raw CPUID has none. The 57 names stable std
does accept are cross-checked against it on every run
(`tests/std_cross_check.rs`).

**Why `RUSTC_BOOTSTRAP=1`?** Stable rustc hides unstable target features
from `--print cfg` (and `CARGO_CFG_TARGET_FEATURE`) even though
`-C target-cpu` still enables them: for `znver4`, 43 names without it, 47
with it — identical to nightly. It is set only for that one print query
(the vocabulary test, `seaworthy-launcher`'s build script) and enables
nothing in compiled code.

**Why does a CPU target emit APX without `--print cfg` saying so?** rustc
maps its `apxf` feature to LLVM's extended-GPR feature (`egpr`) and reports
`apxf` only when that is on. LLVM 22's `diamondrapids` and `novalake`
definitions turn on NF, NDD, CCMP, CF, PPX, PUSH2/POP2 and ZU but not
`egpr`, so cfg stays silent while the code carries EVEX-promoted
instructions (`{nf} imulq (%rdi), %rax, %rcx`). All of them are enumerated
by one CPUID bit — `CPUID.(7,1):EDX[21]` (APX_F) — and need the OS to
enable APX state (`XCR0[19]`), which is exactly the `apxf` row.

**Couldn't the requirements come from disassembling the core instead?**
No. A baseline core linking AWS-LC contains tens of thousands of AVX-512
instructions from AWS-LC's own runtime-selected code paths — present, but
only reached on CPUs that have them. Only the compiler's record says what
the core *requires*.

## Compliance models

### HIPAA
No PHI and no HIPAA-relevant surface.

### SOC 2 Type 2
CC8.1 (change management): the toolchain-coverage test makes a toolchain
upgrade that would weaken the CPU checks fail in the pipeline, with the
missing names, before anything ships — evidence in every pipeline's test
report.

### FIPS
No cryptographic surface.

### PQ
No cryptographic surface.

## Platform notes

The x86-64 table and `Host` work on any OS (CPUID and `XGETBV` are
user-mode instructions: Linux, Windows). The aarch64 table is detected on
macOS (Apple Silicon; macOS 11 and later), and checked live on an Apple
Silicon test host (`tests/std_cross_check_aarch64.rs`). The record reader
is portable and reads ELF, PE and Mach-O files on any host (packaging runs
it on Linux for Windows and macOS cores). No wasm build.

`tests/vocabulary.rs` compiles its probes for `x86_64-unknown-linux-gnu`
(`core` only, `--emit asm`, no linker): on a Windows or macOS test host,
install that target's standard library first
(`rustup target add x86_64-unknown-linux-gnu`).

## Where it sits

Depends only on `object` (read-side: ELF, PE, Mach-O) and, on macOS,
`libc` (`sysctlbyname`). Used by `seaworthy-launcher` (selection) and by
packaging tools that verify built cores. Unsafe code is limited to the
`XGETBV` intrinsic (guarded by the OSXSAVE check) and `sysctlbyname` on
macOS, each block allowed locally with its safety argument.

## See also

[`seaworthy-launcher`](../seaworthy-launcher/README.md) ·
[`docs/cpu-levels.md`](../../docs/cpu-levels.md)
