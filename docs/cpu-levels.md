# CPU levels: one core per level, one launcher

seaworthy can ship a program built once per CPU level and pick, every time
the program starts, the best build the machine can run. Nothing is
unpacked or written to disk at run time, and a machine below the
product's floor gets a clear message instead of a crash. Two crates do
the work:

- [`seaworthy-levels`](../crates/seaworthy-levels/README.md): the CPU
  feature tables, host detection and the record each build carries.
- [`seaworthy-launcher`](../crates/seaworthy-launcher/README.md): the
  launcher, the core entry point, and the build script that writes the
  record.

## The pieces

A product is split in two:

- **The core**: the product's real code, built as a shared library
  (`cdylib`) once per CPU level with `-C target-cpu=<level>`.
- **The launcher**: a small executable built for the architecture's
  baseline (plain `x86-64`; `apple-m1` on Apple Silicon). It is the program
  people run. It holds nothing but `launcher_main!`.

At startup the launcher reads each core's **requirement record** straight
from the file, without loading it, compares it with what this CPU and OS
support, and loads the first core in the product's preference order that
passes. The core then runs in the launcher's process: arguments, signals,
the Windows service dispatcher, systemd notifications and `current_exe()`
behave as in an ordinary executable.

## Choosing levels

A level is any CPU name rustc accepts for `-C target-cpu`. The usual set
is the x86-64 microarchitecture levels:

| Level | Adds (beyond the previous level) | Hardware |
| --- | --- | --- |
| `x86-64-v2` | CMPXCHG16B, LAHF/SAHF, POPCNT, SSE3, SSSE3, SSE4.1, SSE4.2 | nearly every x86-64 CPU since about 2009 |
| `x86-64-v3` | AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE | Intel Haswell (2013) and later, AMD Excavator and Zen |
| `x86-64-v4` | AVX-512 F, BW, CD, DQ, VL | Intel Skylake-SP and later server parts (and some client parts), AMD Zen 4 and later |

- **The floor** is the last level in the list: below it nothing runs, and
  the launcher says so (exit 78). `x86-64-v2` is the usual floor.
- **Drop `x86-64-v4`** if AVX-512 doesn't help your code: one fewer build.
- **Any rustc CPU name works** (`znver4`, `sapphirerapids`, …): the record
  lists every feature the compiler enabled for it, and the launcher checks
  them all. Order the list from most to least demanding.
- **Apple Silicon:** ship `apple-m1`. Every arm64 Mac has the M1's
  features. A core for a later chip records `v8.5a` or later, which macOS
  reports no signal for, so the launcher would skip it and fall back.
- **Not per-CPU:** when the hardware is known (a server container, a
  fleet of identical machines), ship one binary built for that CPU instead.

The levels are given once, to `launcher_main!`, most preferred first:

```rust,ignore
// launcher/src/main.rs
seaworthy_launcher::launcher_main!(
    core = "acme_core",
    cpus = ["x86-64-v4", "x86-64-v3", "x86-64-v2"],
);
```

```rust,ignore
// core/src/lib.rs   (Cargo.toml: [lib] crate-type = ["cdylib"])
fn main() -> Result<(), acme::Error> {
    tracing::info!(core = seaworthy_launcher::this_core(), "starting"); // "x86-64-v3", say
    acme::run()
}
seaworthy_launcher::core_main!(main);
```

`main` may return `()`, `i32`, `u8` or `Result<(), E>`. Put everything in
the core, the GUI included; never give the launcher a CPU flag, so it runs
on any machine of its architecture and can explain when a CPU is too old.

## The records

Two small text records travel inside the binaries, in their own linker
sections:

- **The requirement record** (`.cpureq`; `__DATA,__cpureq` in a Mach-O),
  in every core: what the compiler enabled for that build.

  ```text
  seaworthy-cpureq:1
  target=x86_64-unknown-linux-gnu
  cpu=x86-64-v3
  features=avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave
  ```

- **The CPU list** (`.cpulist`; `__DATA,__cpulist`), in the launcher: the
  core's file stem and the preference order, so a packaging tool can check
  that the cores it ships are exactly the ones the launcher looks for.

  ```text
  seaworthy-cpulist:1
  core=acme_core
  cpus=x86-64-v4,x86-64-v3,x86-64-v2
  ```

`seaworthy-launcher`'s build script writes the requirement record. A core
crate depends on `seaworthy-launcher`, so cargo builds the launcher crate —
and runs its build script — with exactly the core's target and flags. The
script asks `rustc --print cfg` for the features those flags enable (with
`RUSTC_BOOTSTRAP=1` for that one query, because stable rustc hides
unstable target features from it), adds the features a CPU target uses
without reporting them (APX on `diamondrapids` and `novalake`), and
refuses to build what no record could describe:

- `-C target-feature=+name` for a name `seaworthy-levels` has no row for
  (APX's `+nf`, `+ndd`, `+egpr` reach LLVM unreported);
- any enabled feature without a row (a toolchain newer than the tables);
- flags only the core crate saw (`cargo rustc -- -C target-cpu=…`):
  `core_main!` compares the core crate's `cfg!(target_feature)` with the
  build script's view at compile time.

Both parsers are strict (fixed line order, `\n` endings, shape-checked
values, at most 4 KiB), and the readers accept ELF, PE and
single-architecture Mach-O files only, reading the headers and the one
section through a read cache. Nothing of a core runs while its record is
read: loading a library runs its initializers, which may already use
instructions the CPU lacks.

## Building one core per level

Build the launcher once, without a CPU flag, and the core once per level,
each in **its own target directory**, with `-C target-cpu=<level>` and
nothing else CPU-related, and always with `--target`:

```sh
# The launcher: plain x86-64.
cargo build --release --target x86_64-unknown-linux-gnu -p acme_launcher
# One core per level.
for cpu in x86-64-v4 x86-64-v3 x86-64-v2; do
  RUSTFLAGS="-C target-cpu=$cpu" CARGO_TARGET_DIR="target/core-$cpu" \
    cargo build --release --target x86_64-unknown-linux-gnu -p acme_core
done
```

- **`--target` matters.** Without it cargo applies `RUSTFLAGS` to build
  scripts and proc-macros too, and a build script compiled for
  `x86-64-v4` crashes on a build host without AVX-512.
- **Separate target directories.** One shared directory rebuilds each core
  over the previous one; copying files out then races the next build.
- **Set the CPU where every crate sees it:** `RUSTFLAGS`,
  `CARGO_ENCODED_RUSTFLAGS` or `[target.<triple>] rustflags`. `RUSTFLAGS`
  replaces any `rustflags` your `.cargo/config.toml` sets (cargo uses one
  source), so put the project's own flags in the same variable.
- **`-C target-cpu=native`** builds, with a warning, but its record names
  `native`, which is none of the product's levels: the launcher refuses it.
- **A dynamic TLS model** for C dependencies that offer initial-exec TLS
  (mimalloc: its `local_dynamic_tls` feature): a core is loaded at run
  time, and an initial-exec TLS core can fail to load.

Then lay the files out where the launcher looks (`core_path`):

| Platform | Launcher | Cores |
| --- | --- | --- |
| Linux | `<dir>/<program>` | `<dir>/lib/lib<core>_<cpu>.so` |
| Windows | `<dir>\<program>.exe` | `<dir>\<core>_<cpu>.dll` |
| macOS | `<App>.app/Contents/MacOS/<program>` | `<App>.app/Contents/Frameworks/lib<core>_<cpu>.dylib` |

Install into a directory only administrators can write
(`%ProgramFiles%\<vendor>\<product>`, `/opt/<vendor>/<product>`): the
launcher loads whatever file in its directory carries a matching record,
so the protected directory and the installer's signatures are the
integrity boundary.

**Trying it locally.** A plain `cargo run` of the launcher exits 74: no
core sits beside it yet. Build one core for your own machine
(`x86-64-v2` runs on nearly any x86-64 machine) and put it where the
launcher looks:

```sh
cargo build -p acme_launcher
RUSTFLAGS="-C target-cpu=x86-64-v2" CARGO_TARGET_DIR=target/core-v2 \
  cargo build -p acme_core --target x86_64-unknown-linux-gnu
mkdir -p target/debug/lib
cp target/core-v2/x86_64-unknown-linux-gnu/debug/libacme_core.so \
  target/debug/lib/libacme_core_x86-64-v2.so
target/debug/acme_launcher
```

The launcher refuses a core whose record names another CPU or target, so
keep the file name and the flag in step.

## How the launcher chooses

1. **Detect the host.** On x86-64, raw CPUID and `XGETBV`: every feature
   rustc can enable has a row with its CPUID bit and the OS-state or vendor
   condition it also needs (AVX state in XCR0, AVX-512 state, AMX and APX
   state, the AMD-only extended bits, a Skylake BMI erratum). Every read is
   range-checked, and the rules follow the standard library's detector, or
   are stricter where LLVM requires more. On Apple Silicon macOS, the
   `hw.optional.*` `sysctl` keys, on top of the Apple M1 baseline. A name
   the tables don't know is never present.
2. **Walk the cores in preference order.** For each, read its record from
   the file. Skip it when the file is missing or unreadable, when its
   record names another CPU or target (a damaged install), or when the host
   lacks any feature it lists. A core listing an AMX feature also needs
   Linux's per-process AMX permission (`arch_prctl`); a refusal skips it.
3. **Load the first core that passes**, by full path: `dlopen` with
   `RTLD_NOW | RTLD_LOCAL` on Linux and macOS; `LoadLibraryExW` with
   `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32` on
   Windows, so the core's own DLL imports come from its directory and
   System32, never the working directory or `PATH`. Then call its
   `seaworthy_core_main` entry point with the launcher ABI version.
4. **In secure-execution mode** (a set-user-ID, set-group-ID or
   file-capability launcher: Linux `AT_SECURE`, macOS `issetugid()`) the
   overrides below are ignored, and the chosen core is loaded only if root
   controls every step of its resolved path: the file and every directory
   up to `/` owned by root and not writable by group or others.

### The fallback

- **A core the CPU can't run** is skipped, and the next one is tried: an
  `x86-64-v4` core on a machine without AVX-512 falls back to `x86-64-v3`.
- **A missing or damaged core** is skipped with a note on stderr when
  another core runs: the install is incomplete.
- **Nothing loadable, every core present:** exit 78, naming what the least
  demanding core needs. Below the floor nothing the product ships can run;
  a clear message beats a crash days later in some code path.
- **Nothing loadable, some core missing or damaged:** exit 74, listing
  every core. Never "CPU too old": the missing core may be exactly the one
  this CPU needs.

On macOS, a launcher started from the Finder or the Dock has no terminal
for stderr, so its own failures also appear in an alert.

## Debugging a machine

Two environment variables, both ignored in secure-execution mode:

- `SEAWORTHY_LAUNCHER_DEBUG=1` prints the machine's CPU features and why
  each core was taken or skipped.
- `SEAWORTHY_CORE=<cpu>` forces one of the product's cores, if the machine
  supports it: an unknown name exits 64, an unsupported one 78.

The core can report which build runs with `seaworthy_launcher::this_core()`
(and its full record with `record()`).

For a support report, record the machine's CPUID with
`cargo run -p seaworthy-levels --example cpuid_dump -- "<machine description>"`:
the dump (`seaworthy-cpuid:1`) replays exactly through
`seaworthy_levels::Snapshot`, which is also how the recorded CPUs in
`crates/seaworthy-levels/tests/fixtures/` are tested.

A virtual machine on QEMU/KVM's default `qemu64` CPU model lacks the
`x86-64-v2` floor (no POPCNT or SSE4.x): the launcher exits 78 and says so.
Give the VM a newer CPU model, or `host`.

### Exit codes

| Code | Meaning |
| --- | --- |
| the core's | The product ran and exited with this code |
| 64 | `SEAWORTHY_CORE` names a CPU that isn't one of the product's builds |
| 70 | The core speaks another launcher ABI (a mixed install), has no entry point, or the launcher's own CPU list is inconsistent |
| 71 | The OS refused to load the chosen core: a missing DLL or shared library, or a TLS failure |
| 74 | Nothing loadable and a core is missing, unreadable, or carries another build's or another target's record: repair the install |
| 77 | Secure-execution mode, and root does not control the chosen core's path |
| 78 | Every core is present and this CPU runs none of them; the message names what the least demanding one needs |
| 101 | The core panicked (with `panic = "abort"` it aborts instead) |

## Linux: the glibc floor

`core_main!` and `launcher_main!` also invoke `glibc_floor!`, which binds
libm's `hypot` and `hypotf` to glibc's baseline symbol versions: glibc 2.35
versioned both anew, so without it a binary calling `f64::hypot` linked on
Debian 12 (glibc 2.36) would refuse to start on RHEL 9 (glibc 2.34). Any
other binary shipped beside them (an update helper) can invoke
`seaworthy_launcher::glibc_floor!()` at its crate root.

## Toolchain upgrades

The feature tables are pinned to the workspace toolchain. On an upgrade,
`crates/seaworthy-levels/tests/vocabulary.rs` re-derives every feature
name the new rustc can enable (and compiles a probe for every CPU target
to catch code `--print cfg` doesn't report), and fails with "add one row"
or "remove the row": a new instruction set extension fails the upgrade's
own change, never a release.

## Testing

- `cargo test -p seaworthy-levels -p seaworthy-launcher`: the tables, the
  detector against synthetic and recorded CPUs, the live CPU against the
  standard library's detector, the record readers over hand-built ELF, PE
  and Mach-O images, the selection logic and the secure-execution rule.
- `scripts/launcher-e2e.sh` (x86-64 Linux): the fixture product under
  `crates/seaworthy-launcher/e2e` built as above and run for real —
  natively, under qemu-user's CPU models, with damaged installs, the
  overrides, the build-time refusals, the glibc floor and the Windows
  records.
- `scripts/launcher-e2e-macos.sh` (Apple Silicon macOS): the same fixture
  as an app bundle.
- The `levels_records` fuzz target covers every parser of untrusted input
  in `seaworthy-levels`.
