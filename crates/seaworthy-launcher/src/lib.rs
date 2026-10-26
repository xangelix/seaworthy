//! `seaworthy-launcher` — one program, built once per CPU target, run as the
//! best build the machine supports.
//!
//! A product ships a **launcher** (a small executable built for its
//! architecture's baseline: plain x86-64, or `apple-m1` on Apple Silicon)
//! and one **core** per CPU target: the product's real code built as a
//! shared library with `-C target-cpu=<cpu>` (`x86-64-v4`, `x86-64-v3`,
//! `x86-64-v2` by default; `apple-m1` on macOS). When the program starts, the
//! launcher reads each core's requirement record **from the file, without
//! loading it** ([`seaworthy_levels`]), skips any core the host can't fully run,
//! loads the first one in the product's preference order that it can, and
//! calls it. Everything then runs in one process: `std::env::args_os()`,
//! signals, the Windows service dispatcher and systemd notifications behave
//! exactly as in a normal executable, and `current_exe()` is the launcher's
//! real installed path.
//!
//! **The launcher crate** (a `bin`, built without any target CPU):
//!
//! ```ignore
//! seaworthy_launcher::launcher_main!(
//!     core = "acme_core",
//!     cpus = ["x86-64-v4", "x86-64-v3", "x86-64-v2"],
//! );
//! ```
//!
//! **The core crate** (a `cdylib`, built once per CPU, each in its own
//! target directory):
//!
//! ```ignore
//! fn main() -> Result<(), MyError> { /* the product */ }
//! seaworthy_launcher::core_main!(main);
//! ```
//!
//! On disk (laid out by the packaging tool): Windows
//! `<dir>\<core>_<cpu>.dll` beside the launcher (with the FIPS module DLL
//! pair, resolved from the same directory); Linux `<dir>/lib/lib<core>_<cpu>.so`;
//! macOS `<App>.app/Contents/Frameworks/lib<core>_<cpu>.dylib`, the launcher
//! in `Contents/MacOS`. On macOS a launcher started from the Finder (no
//! terminal) also shows its own failures in an alert.
//!
//! See the README for the selection rules, the overrides and the exit codes,
//! and `docs/cpu-levels.md` in the repository for how levels, records and
//! the launcher fit together.

// The launcher decides from bytes it read out of files it has not loaded:
// no indexing that can panic, no arithmetic that can overflow, no division.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

mod dialog;
mod load;
// The MSI's %ProgramData% guard runs on Windows only; its rules are
// tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod programdata;
#[cfg(test)]
mod rustflags;
mod select;

use std::path::{Path, PathBuf};

use seaworthy_levels::{CpuList, Host, Requirement};

pub use seaworthy_levels;

/// The launcher-to-core calling convention version. The launcher passes it
/// to `seaworthy_core_main`; a core built for another version refuses
/// ([`EXIT_ABI_MISMATCH`]). Both halves ship in one package, so a mismatch
/// means a damaged or mixed install.
pub const ABI_VERSION: u32 = 1;

/// The target triple this crate (and therefore this launcher or core) was
/// compiled for.
pub const TARGET: &str = env!("SEAWORTHY_LAUNCHER_TARGET");

/// Exit code: every core is present and consistent, and the host can run
/// none of them (sysexits `EX_CONFIG`). The message names what the least
/// demanding core needs.
pub const EXIT_NO_COMPATIBLE_CORE: i32 = 78;
/// Exit code: nothing loadable, and the install is damaged or incomplete —
/// a core is missing, unreadable, or carries another build's or another
/// target's record (sysexits `EX_IOERR`). Never "CPU too old": the missing
/// core may be the one this CPU runs. Repair the install.
pub const EXIT_DAMAGED_INSTALL: i32 = 74;
/// Exit code: the OS refused to load the chosen core (sysexits `EX_OSERR`)
/// — on Windows typically a missing FIPS module DLL beside it.
pub const EXIT_LOAD_FAILED: i32 = 71;
/// Exit code: the core loaded but has no entry point, or speaks another
/// launcher ABI, or the launcher's own configuration is inconsistent
/// (sysexits `EX_SOFTWARE`).
pub const EXIT_ABI_MISMATCH: i32 = 70;
/// Exit code: `SEAWORTHY_CORE` names a CPU that isn't one of the product's
/// cores (sysexits `EX_USAGE`).
pub const EXIT_BAD_OVERRIDE: i32 = 64;
/// Exit code: in secure-execution mode (set-user-ID, set-group-ID, or on
/// Linux file capabilities), the chosen core — or a directory above it — is
/// not owned by root, or is writable by group or others (sysexits
/// `EX_NOPERM`). The README's rule 4 has the trust rule.
pub const EXIT_UNTRUSTED_CORE: i32 = 77;
/// Exit code: the core panicked (Rust's own panic exit code). A core built
/// with `panic = "abort"` aborts instead (`SIGABRT`; 134 from a shell on
/// Linux, `0xC0000409` on Windows) — the launcher never sees the panic.
pub const EXIT_PANIC: i32 = 101;

/// Forces one core by CPU name (support and testing). Only a core the host
/// supports is loaded; anything else fails loudly. Ignored in a privileged
/// process (see [`ENV_DEBUG`]).
pub const ENV_CORE: &str = "SEAWORTHY_CORE";
/// `1` prints every selection decision to stderr. Like [`ENV_CORE`],
/// ignored in a privileged process: in secure-execution mode (set-user-ID,
/// set-group-ID, file capabilities), as root on Linux and macOS (`sudo`, a
/// root shell, a root service), and on Windows in an elevated process (an
/// administrator's elevated token, LocalSystem and the service accounts),
/// where whoever set the environment may not be whoever runs with the
/// privileges.
pub const ENV_DEBUG: &str = "SEAWORTHY_LAUNCHER_DEBUG";

/// A product's launcher configuration ([`launcher_main!`] builds it).
#[derive(Clone, Copy, Debug)]
pub struct Launcher {
    /// The core's file stem.
    pub core: &'static str,
    /// The CPU names to try, most preferred first.
    pub cpus: &'static [&'static str],
    /// The launcher's own `.cpulist` section bytes (which a packaging tool
    /// cross-checks against the packaged cores).
    pub cpulist: &'static [u8],
    /// Windows: keep the process's legacy DLL search order. Off by default:
    /// the launcher's first act is `SetDefaultDllDirectories(
    /// LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)`, so every later `LoadLibrary` in
    /// the process — the core's own, its libraries' — searches only the
    /// launcher's directory, System32 and the directories added with
    /// `AddDllDirectory`, never the working directory or `PATH`, where
    /// anyone might plant a DLL. A core that loads libraries from `PATH`
    /// (a plugin or driver it doesn't ship) sets it with
    /// `legacy_dll_search = true` in [`launcher_main!`]. Ignored elsewhere.
    pub legacy_dll_search: bool,
}

/// Where the core for `cpu` lives, given the launcher's directory: beside
/// it on Windows, in `lib/` below it on Linux, and on macOS in the app
/// bundle's `Contents/Frameworks` (the launcher is in `Contents/MacOS`).
#[must_use]
pub fn core_path(dir: &Path, core: &str, cpu: &str) -> PathBuf {
    if cfg!(windows) {
        dir.join(format!("{core}_{cpu}.dll"))
    } else if cfg!(target_os = "macos") {
        dir.parent()
            .unwrap_or(dir)
            .join("Frameworks")
            .join(format!("lib{core}_{cpu}.dylib"))
    } else {
        dir.join("lib").join(format!("lib{core}_{cpu}.so"))
    }
}

/// Runs the launcher and exits the process with the core's exit code (or
/// one of the `EXIT_*` codes).
pub fn run(launcher: &Launcher) -> ! {
    // Windows: the MSI's custom action making the product's %ProgramData%
    // folders safe (programdata's module docs), never the core.
    if let Some(code) = programdata::intercept() {
        std::process::exit(code);
    }
    let mut out = Report::default();
    let code = launch(launcher, &mut out);
    // No terminal to read stderr on: the launcher's own failure goes into
    // an alert too (macOS, started by LaunchServices).
    if !out.core_ran && !out.lines.is_empty() && dialog::launch_services_without_terminal() {
        dialog::show(&program_name(), &out.lines.join("\n"));
    }
    std::process::exit(code)
}

/// `text` safe to print and to show: every control character (C0, DEL,
/// C1) and every invisible formatting or bidirectional control (the
/// marks, embeddings, overrides and isolates, zero-width characters, the
/// line and paragraph separators, the byte-order mark) written as
/// `\u{XXXX}`. A file name can hold any of them, and a right-to-left
/// override in a path would make a message read as something else.
fn display_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let invisible = matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        );
        if c.is_control() || invisible {
            out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// What the launcher printed, and whether the core ran (its exit code, and
/// its errors, are its own).
#[derive(Default)]
struct Report {
    lines: Vec<String>,
    core_ran: bool,
}

/// The launcher's settings from its environment.
struct Settings {
    debug: bool,
    forced: Option<String>,
}

impl Settings {
    fn from_env(name: &str) -> Self {
        // A privileged process takes no overrides (ENV_DEBUG's docs): a
        // secure-execution launcher's environment is its caller's, and
        // `sudo -E` or an elevated console carries a user's into an
        // administrator's process.
        let privileged = load::secure_execution() || load::elevated();
        if privileged {
            if !load::secure_execution()
                && (std::env::var_os(ENV_CORE).is_some() || std::env::var_os(ENV_DEBUG).is_some())
            {
                eprintln!(
                    "{name}: {ENV_CORE} and {ENV_DEBUG} are ignored in an elevated or root process"
                );
            }
            return Self {
                debug: false,
                forced: None,
            };
        }
        // The launcher runs before any product code and links nothing but
        // seaworthy-levels: its two support overrides are read straight from
        // the environment (never in secure-execution mode, above).
        // Configuration proper is the core's.
        let debug = std::env::var_os(ENV_DEBUG).is_some_and(|value| value == "1");
        let forced = std::env::var(ENV_CORE)
            .ok()
            .filter(|value| !value.is_empty());
        if forced.is_some() && debug {
            eprintln!("{name}: {ENV_CORE} is set");
        }
        Self { debug, forced }
    }
}

fn program_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|stem| display_safe(&stem.to_string_lossy()))
        })
        .unwrap_or_else(|| "launcher".to_owned())
}

/// Chooses, loads and calls a core; returns the exit code. Every line it
/// prints goes into `out` as well.
fn launch(launcher: &Launcher, out: &mut Report) -> i32 {
    let name = program_name();
    // Every line is escaped whole: paths, the override's value and what a
    // core's record said all pass through here.
    macro_rules! say {
        ($($arg:tt)*) => {{
            let line = display_safe(&format!($($arg)*));
            eprintln!("{name}: {line}");
            out.lines.push(line);
        }};
    }
    // Before anything can load a library: the process's DLL search order
    // without the working directory and PATH (Launcher::legacy_dll_search).
    if !launcher.legacy_dll_search
        && let Err(e) = load::restrict_dll_search()
    {
        say!("cannot restrict the DLL search order: {e}");
        return EXIT_LOAD_FAILED;
    }
    // The embedded list must describe this configuration (it is generated
    // from the same macro arguments; a mismatch is a build defect).
    match CpuList::parse(launcher.cpulist) {
        Ok(list)
            if list.core == launcher.core
                && list
                    .cpus
                    .iter()
                    .map(String::as_str)
                    .eq(launcher.cpus.iter().copied()) => {}
        Ok(_) | Err(_) => {
            say!(
                "the launcher's embedded CPU list does not match its configuration (build defect)"
            );
            return EXIT_ABI_MISMATCH;
        }
    }
    let settings = Settings::from_env(&name);
    // macOS reports the path the program was started by (a symlink stays a
    // symlink): the cores sit beside the real file, which Linux's
    // /proc/self/exe already names.
    let exe = std::env::current_exe().and_then(|exe| {
        if cfg!(target_os = "macos") {
            std::fs::canonicalize(exe)
        } else {
            Ok(exe)
        }
    });
    let dir = match exe {
        Ok(exe) => match exe.parent() {
            Some(dir) => dir.to_path_buf(),
            None => {
                say!("cannot tell which directory the program runs from");
                return EXIT_LOAD_FAILED;
            }
        },
        Err(e) => {
            say!("cannot locate the running program: {e}");
            return EXIT_LOAD_FAILED;
        }
    };
    let host = Host::detect();
    if settings.debug {
        say!(
            "target {TARGET}; host features: {}",
            host.names().collect::<Vec<_>>().join(",")
        );
    }

    let cpus: Vec<&str> = match &settings.forced {
        Some(forced) => {
            if !launcher.cpus.contains(&forced.as_str()) {
                say!(
                    "{ENV_CORE}={forced} is not one of this program's builds ({})",
                    launcher.cpus.join(", ")
                );
                return EXIT_BAD_OVERRIDE;
            }
            vec![forced.as_str()]
        }
        None => launcher.cpus.to_vec(),
    };
    // In secure-execution mode nothing is opened, let alone parsed, before
    // the trust rule has passed on its path: a set-user-ID launcher
    // hardlinked into a user's directory must not even read that user's
    // files with raised privileges. Each core is then opened without
    // following a symlink or blocking on a FIFO, and must be a regular file.
    let secure = load::secure_execution();
    let mut candidates: Vec<select::Candidate> = Vec::with_capacity(cpus.len());
    for cpu in &cpus {
        let path = core_path(&dir, launcher.core, cpu);
        let (path, probe) = if !path.exists() {
            (path, select::Probe::Missing)
        } else if secure {
            let opened = load::trusted_path(&path)
                .and_then(|real| load::open_regular(&real).map(|file| (real, file)));
            match opened {
                Ok((real, file)) => {
                    let probe = match seaworthy_levels::requirement_from_file(file) {
                        Ok(record) => select::Probe::Record(record),
                        Err(e) => select::Probe::Unreadable(e.to_string()),
                    };
                    (real, probe)
                }
                Err(reason) => {
                    say!(
                        "refusing {} in secure-execution mode: {reason}",
                        path.display()
                    );
                    return EXIT_UNTRUSTED_CORE;
                }
            }
        } else {
            let probe = match seaworthy_levels::read_requirement(&path) {
                Ok(record) => select::Probe::Record(record),
                Err(e) => select::Probe::Unreadable(e.to_string()),
            };
            (path, probe)
        };
        candidates.push(select::Candidate {
            cpu: (*cpu).to_owned(),
            path,
            probe,
        });
    }

    let mut report = Vec::new();
    let outcome = select::choose(
        &candidates,
        &host,
        TARGET,
        needs_amx_permission,
        &mut report,
    );
    let missing_some = candidates
        .iter()
        .any(|c| !matches!(c.probe, select::Probe::Record(_)));
    if settings.debug || (missing_some && matches!(outcome, select::Outcome::Load(_))) {
        // A missing or unreadable core is worth a line even when another one
        // runs: the install is incomplete.
        for line in &report {
            say!("skipped {line}");
        }
    }
    match outcome {
        select::Outcome::Load(index) => {
            let Some(candidate) = candidates.get(index) else {
                return EXIT_ABI_MISMATCH;
            };
            // Set-user-ID / file-capability launchers load only what root
            // controls: a hardlinked launcher in a user's directory must not
            // load that user's "core" with raised privileges. Checked before
            // the probe too; again here, right before the load.
            let path = if secure {
                match load::trusted_path(&candidate.path) {
                    Ok(path) => path,
                    Err(reason) => {
                        say!(
                            "refusing {} in secure-execution mode: {reason}",
                            candidate.path.display()
                        );
                        return EXIT_UNTRUSTED_CORE;
                    }
                }
            } else {
                candidate.path.clone()
            };
            if settings.debug {
                say!("loading {} ({})", candidate.cpu, path.display());
            }
            match load::call_core(&path, ABI_VERSION) {
                Ok(code) => {
                    out.core_ran = true;
                    code
                }
                Err(load::LoadError::Load(reason)) => {
                    say!("cannot load {}: {reason}", candidate.path.display());
                    if cfg!(windows) {
                        say!(
                            "a missing FIPS module DLL (aws_lc_fips_*.dll) beside it causes this too; repair the install"
                        );
                    } else {
                        say!("repair the install");
                    }
                    EXIT_LOAD_FAILED
                }
                Err(load::LoadError::NoEntryPoint(reason)) => {
                    say!(
                        "{} is not a seaworthy core (no `{}`: {reason}); repair the install",
                        candidate.path.display(),
                        load::ENTRY_SYMBOL
                    );
                    EXIT_ABI_MISMATCH
                }
            }
        }
        select::Outcome::NoneSupported { cpu, assessment } => {
            if settings.forced.is_some() {
                say!("{ENV_CORE}={cpu}: this CPU can't run that build ({assessment})");
                return EXIT_NO_COMPATIBLE_CORE;
            }
            say!("this CPU can't run any build of this program");
            say!("the least demanding build ({cpu}) {assessment}");
            if cfg!(target_arch = "x86_64") {
                say!(
                    "CPUs from before about 2009 lack these, and so do virtual machines using QEMU/KVM's default \
                     `qemu64` CPU model — give the VM a newer CPU model (or `host`)"
                );
            }
            EXIT_NO_COMPATIBLE_CORE
        }
        select::Outcome::Damaged => {
            say!(
                "no build of this program that this CPU can run was found ({}):",
                dir.display()
            );
            for line in &report {
                say!("  {line}");
            }
            say!("repair or reinstall it");
            EXIT_DAMAGED_INSTALL
        }
    }
}

/// A core listing an AMX feature needs the Linux AMX permission first.
fn needs_amx_permission(record: &Requirement) -> Result<(), String> {
    if record
        .features
        .iter()
        .any(|feature| feature.starts_with("amx-"))
    {
        load::request_amx()
    } else {
        Ok(())
    }
}

// --- the core side ------------------------------------------------------------

/// The requirement record of the build this crate was compiled into,
/// written by the build script. Deliberately not `#[used]`: `core_main!`'s
/// entry point references it, so the linker keeps it in every core — and
/// drops it from the launcher, which carries a `.cpulist` instead.
// SAFETY: the section holds plain read-only bytes, no code, and its name
// (`.cpureq`, `__DATA,__cpureq`) is one no toolchain or loader gives a
// meaning to: placing the static there changes only where it lives.
#[allow(unsafe_code, reason = "link_section: the record's own section")]
#[doc(hidden)]
#[cfg_attr(
    any(target_os = "linux", target_os = "windows"),
    unsafe(link_section = ".cpureq")
)]
#[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__cpureq"))]
pub static __CPUREQ: [u8; RECORD_LEN] = *include_bytes!(concat!(env!("OUT_DIR"), "/cpureq.bin"));

const RECORD_LEN: usize = include_bytes!(concat!(env!("OUT_DIR"), "/cpureq.bin")).len();

/// The requirement record of the running core (call it from the core: in
/// the launcher it describes the launcher's own baseline build).
#[must_use]
pub fn record() -> Option<Requirement> {
    Requirement::parse(&__CPUREQ).ok()
}

/// The CPU name of the running core — for startup logs and telemetry
/// (`"x86-64-v3"`). Call it from the core.
#[must_use]
pub fn this_core() -> &'static str {
    env!("SEAWORTHY_LAUNCHER_CPU")
}

/// What a core's `main` may return: `()`, an exit code (`i32` or `u8`), or
/// a `Result<(), E>` (an error prints as `Error: {e:?}` and exits 1, as a
/// Rust `main` does).
pub trait CoreExit {
    /// The process exit code.
    fn into_exit_code(self) -> i32;
}

impl CoreExit for () {
    fn into_exit_code(self) -> i32 {
        0
    }
}

impl CoreExit for i32 {
    fn into_exit_code(self) -> i32 {
        self
    }
}

impl CoreExit for u8 {
    fn into_exit_code(self) -> i32 {
        i32::from(self)
    }
}

impl<E: core::fmt::Debug> CoreExit for Result<(), E> {
    fn into_exit_code(self) -> i32 {
        match self {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("Error: {e:?}");
                1
            }
        }
    }
}

/// The body of `seaworthy_core_main` ([`core_main!`]): the ABI check and the
/// panic boundary around the core's `main`.
#[doc(hidden)]
pub fn __enter(abi: u32, main: impl FnOnce() -> i32) -> i32 {
    // Keep the record in the binary: the entry point references it.
    std::hint::black_box(&__CPUREQ);
    if abi != ABI_VERSION {
        eprintln!(
            "this core speaks launcher ABI {ABI_VERSION}, the launcher {abi}: a damaged or mixed install"
        );
        return EXIT_ABI_MISMATCH;
    }
    // A panic must not unwind across the C ABI into the launcher.
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(main)).unwrap_or(EXIT_PANIC);
    // The core links its own copy of std, whose stdout buffer the
    // launcher's exit never flushes (a final line without a newline would
    // be lost). `std::process::exit` from inside the core flushes it itself.
    let _ = std::io::Write::flush(&mut std::io::stdout());
    code
}

/// Exports a core's entry point: `seaworthy_launcher::core_main!(main);` in the
/// core crate (a `cdylib`), where `main` returns anything [`CoreExit`]
/// accepts.
///
/// It also checks, at compile time, that the core crate was compiled with
/// the same CPU flags as seaworthy-launcher — whose build script wrote the
/// record. Flags only the core crate sees (`cargo rustc -- -C target-cpu=…`)
/// would make the record describe another build: for every feature name,
/// `cfg!(target_feature)` in the core crate must agree with the build
/// script's view, or the build fails naming the feature. Set the CPU with
/// `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS` or `[target.<triple>] rustflags`,
/// which reach every crate. (`cfg!` sees the features stable rustc exposes;
/// two CPU targets that differ only in unstable ones would pass — another
/// reason to set the CPU where every crate sees it.)
///
/// A panic in `main` exits [`EXIT_PANIC`] unless the core is built with
/// `panic = "abort"`, which aborts the process instead.
///
/// On x86-64 Linux (glibc) it also invokes [`glibc_floor!`].
#[macro_export]
macro_rules! core_main {
    ($main:path) => {
        $crate::__for_each_feature!($crate::__check_feature);
        $crate::glibc_floor!();

        /// The entry point seaworthy-launcher calls (generated by
        /// `seaworthy_launcher::core_main!`).
        #[unsafe(no_mangle)]
        pub extern "C" fn seaworthy_core_main(abi: u32) -> i32 {
            $crate::__enter(abi, || $crate::CoreExit::into_exit_code($main()))
        }
    };
}

/// The names `cfg!(target_feature)` reports in seaworthy-launcher's own
/// compilation — the build script's view of the core's flags.
#[doc(hidden)]
pub const __VISIBLE_FEATURES: &[&str] = include!(concat!(env!("OUT_DIR"), "/visible.rs"));

/// Whether `name` is in [`__VISIBLE_FEATURES`] (a `const fn`: iterators and
/// `==` on `str` aren't available in const contexts).
#[doc(hidden)]
#[must_use]
// Both indexes are bounded by their loop conditions.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub const fn __visible(name: &str) -> bool {
    let name = name.as_bytes();
    let mut i = 0;
    while i < __VISIBLE_FEATURES.len() {
        let candidate = __VISIBLE_FEATURES[i].as_bytes();
        if candidate.len() == name.len() {
            let mut j = 0;
            while j < name.len() && candidate[j] == name[j] {
                j += 1;
            }
            if j == name.len() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// One compile-time check: the core crate's `cfg!(target_feature = name)`
/// must equal seaworthy-launcher's.
#[doc(hidden)]
#[macro_export]
macro_rules! __check_feature {
    ($name:tt) => {
        const _: () = if cfg!(target_feature = $name) != $crate::__visible($name) {
            panic!(concat!(
                "seaworthy-launcher: this core crate and seaworthy-launcher were compiled with different CPU \
                 flags (they disagree on `",
                $name,
                "`), so the core's requirement record would describe another build. Set the CPU \
                 through RUSTFLAGS or [target.<triple>] rustflags so every crate sees it — not \
                 `cargo rustc -- -C target-cpu=…`"
            ))
        };
    };
}

/// Calls `$callback!(name)` for every feature name in seaworthy-levels' tables
/// (as a literal token — `cfg!` needs one): the x86-64 table, then the
/// aarch64 names it doesn't already have (`aes` and `sm4` are in both). A
/// unit test keeps the list equal to [`seaworthy_levels::FEATURES`] and
/// [`seaworthy_levels::AARCH64_FEATURES`]. On one architecture the other's names
/// are simply never enabled.
#[doc(hidden)]
#[macro_export]
macro_rules! __for_each_feature {
    ($callback:path) => {
        $crate::__for_each_feature!(@each $callback;
            "x87" "fxsr" "sse" "sse2" "sse3" "pclmulqdq" "ssse3" "fma" "cmpxchg16b" "sse4.1"
            "sse4.2" "movbe" "popcnt" "aes" "xsave" "avx" "f16c" "rdrand" "bmi1" "avx2" "bmi2"
            "ermsb" "avx512f" "avx512dq" "rdseed" "adx" "avx512ifma" "clflushopt" "avx512cd" "sha"
            "avx512bw" "avx512vl" "avx512vbmi" "avx512vbmi2" "gfni" "vaes" "vpclmulqdq" "avx512vnni"
            "avx512bitalg" "avx512vpopcntdq" "avx512vp2intersect" "amx-bf16" "avx512fp16" "amx-tile"
            "amx-int8" "sha512" "sm3" "sm4" "avxvnni" "avx512bf16" "amx-fp16" "avxifma" "movrs"
            "avxvnniint8" "avxneconvert" "amx-complex" "avxvnniint16" "apxf" "avx10.1" "avx10.2"
            "xsaveopt" "xsavec" "xsaves" "kl" "widekl" "amx-fp8" "amx-avx512" "amx-movrs"
            "lahfsahf" "lzcnt" "sse4a" "prfchw" "xop" "fma4" "tbm"
            "bf16" "bti" "crc" "cssc" "dit" "dotprod" "dpb" "dpb2" "ecv" "faminmax" "fcma" "fhm"
            "flagm" "flagm2" "fp16" "fp8" "fp8dot2" "fp8dot4" "fp8fma" "frintts" "hbc" "i8mm"
            "jsconv" "lor" "lse" "lse2" "lut" "mops" "mte" "neon" "paca" "pacg" "pan" "pmuv3" "rand"
            "ras" "rcpc" "rcpc2" "rcpc3" "rdm" "sb" "sha2" "sha3" "sme" "sme-b16b16" "sme-f16f16"
            "sme-f64f64" "sme-i16i64" "sme2" "sme2p1" "spe" "ssbs" "sve" "sve-b16b16" "sve2" "v8.1a"
            "v8.2a" "v8.3a" "v8.4a" "v8.5a" "v8.6a" "v8.7a" "v8.8a" "v9.1a" "v9.2a" "v9.3a" "v9a" "vh"
            "wfxt"
        );
    };
    (@each $callback:path; $($name:tt)*) => {
        $( $callback!($name); )*
    };
}

/// Copies a string's bytes into an array (for the `.cpulist` static).
#[doc(hidden)]
#[must_use]
// A const fn can't use iterators; both indexes are bounded by the loop
// condition (`i < N && i < bytes.len()`), and `i` stays below `N`.
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
pub const fn __bytes<const N: usize>(text: &str) -> [u8; N] {
    let bytes = text.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N && i < bytes.len() {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

/// Joins string literals with commas (for the `.cpulist` static).
#[doc(hidden)]
#[macro_export]
macro_rules! __join {
    ($first:literal $(, $rest:literal)*) => {
        concat!($first $(, ",", $rest)*)
    };
}

/// Generates a product launcher's `main`: the CPU list (embedded in a
/// `.cpulist` section for a packaging tool to cross-check) and the call into
/// [`run`]. On x86-64 Linux (glibc) it also invokes [`glibc_floor!`].
///
/// ```ignore
/// seaworthy_launcher::launcher_main!(
///     core = "acme_core",
///     cpus = ["x86-64-v4", "x86-64-v3", "x86-64-v2"],
/// );
/// ```
///
/// A core that must load libraries from `PATH` on Windows keeps the legacy
/// DLL search order with `legacy_dll_search = true` after the CPU list
/// ([`Launcher::legacy_dll_search`]).
#[macro_export]
macro_rules! launcher_main {
    (core = $core:literal, cpus = [$($cpu:literal),+ $(,)?] $(,)?) => {
        $crate::launcher_main!(core = $core, cpus = [$($cpu),+], legacy_dll_search = false);
    };
    (core = $core:literal, cpus = [$($cpu:literal),+ $(,)?], legacy_dll_search = $legacy:literal $(,)?) => {
        $crate::glibc_floor!();

        const __SEAWORTHY_CPULIST_TEXT: &str =
            concat!("seaworthy-cpulist:1\ncore=", $core, "\ncpus=", $crate::__join!($($cpu),+), "\n");

        #[used]
        #[cfg_attr(any(target_os = "linux", target_os = "windows"), unsafe(link_section = ".cpulist"))]
        #[cfg_attr(target_os = "macos", unsafe(link_section = "__DATA,__cpulist"))]
        static __SEAWORTHY_CPULIST: [u8; __SEAWORTHY_CPULIST_TEXT.len()] = $crate::__bytes(__SEAWORTHY_CPULIST_TEXT);

        fn main() {
            $crate::run(&$crate::Launcher {
                core: $core,
                cpus: &[$($cpu),+],
                cpulist: &__SEAWORTHY_CPULIST,
                legacy_dll_search: $legacy,
            })
        }
    };
}

/// Keeps a Linux binary within a glibc floor of 2.34 (RHEL 9's) when its
/// builder's glibc is newer: binds libm's `hypot` and `hypotf` to glibc's
/// baseline symbol versions (`GLIBC_2.2.5` on x86-64).
///
/// glibc 2.35 gave both functions new default versions (`GLIBC_2.35`), so
/// any binary that calls `f64::hypot` or `f32::hypot` (egui does) and links
/// on glibc 2.35 or newer — Debian 12, a common builder, has 2.36 — needs
/// 2.35, and glibc 2.34's loader (RHEL 9's) refuses to start it. glibc keeps
/// the baseline versions for the binaries linked before 2.35; they are the
/// only ones on 2.34, and their results are the same (the change was the
/// removal of SVID error handling, which no Rust binary uses).
///
/// The macro defines weak, hidden `hypot` and `hypotf` in the crate that
/// invokes it, each a tail call to the baseline version: references from
/// every crate in the link resolve to them before the linker reaches libm,
/// and nothing is exported (an executable would otherwise export them and
/// interpose libm for every library in the process). [`core_main!`] and
/// [`launcher_main!`] invoke it; another binary a product ships beside them
/// (its update helper) can invoke it at its crate root. Invoked in two
/// crates of one link it is harmless (the definitions are weak); invoked
/// twice in one crate the assembler refuses it (`symbol 'hypot' is already
/// defined`) — so never beside those macros. Elsewhere (Windows, musl,
/// other architectures) it expands to nothing. It covers exactly these two
/// symbols: a release pipeline should still read every binary's symbol
/// version needs, so a symbol this misses fails the release, never a host.
#[macro_export]
macro_rules! glibc_floor {
    () => {
        #[cfg(all(target_os = "linux", target_env = "gnu", target_arch = "x86_64"))]
        ::core::arch::global_asm!(
            ".symver __seaworthy_glibc_floor_hypot, hypot@GLIBC_2.2.5",
            ".symver __seaworthy_glibc_floor_hypotf, hypotf@GLIBC_2.2.5",
            ".pushsection .text.seaworthy_glibc_floor,\"ax\",@progbits",
            ".weak hypot",
            ".hidden hypot",
            ".type hypot,@function",
            "hypot:",
            "    jmp __seaworthy_glibc_floor_hypot@PLT",
            ".size hypot, .-hypot",
            ".weak hypotf",
            ".hidden hypotf",
            ".type hypotf,@function",
            "hypotf:",
            "    jmp __seaworthy_glibc_floor_hypotf@PLT",
            ".size hypotf, .-hypotf",
            ".popsection",
        );
    };
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    /// A feature every build for this architecture has.
    const BASELINE: &str = if cfg!(target_arch = "aarch64") {
        "neon"
    } else {
        "sse2"
    };

    #[test]
    fn this_build_carries_a_valid_record() {
        let record = record().expect("the build script's record parses");
        assert_eq!(record.target, TARGET);
        assert_eq!(record.cpu, this_core());
        assert!(record.features.iter().any(|f| f == BASELINE), "{record:?}");
        assert!(
            record
                .features
                .iter()
                .all(|f| seaworthy_levels::known(TARGET, f))
        );
    }

    #[test]
    fn core_paths_follow_the_layout() {
        let dir = Path::new("/opt/acme/tool");
        let path = core_path(dir, "acme_core", "x86-64-v3");
        if cfg!(windows) {
            assert!(path.ends_with("acme_core_x86-64-v3.dll"));
        } else if cfg!(target_os = "macos") {
            let app = Path::new("/Applications/Acme Tool.app/Contents/MacOS");
            assert_eq!(
                core_path(app, "acme_core", "apple-m1"),
                Path::new(
                    "/Applications/Acme Tool.app/Contents/Frameworks/libacme_core_apple-m1.dylib"
                )
            );
        } else {
            assert_eq!(
                path,
                Path::new("/opt/acme/tool/lib/libacme_core_x86-64-v3.so")
            );
        }
    }

    #[test]
    fn the_entry_wrapper_checks_the_abi_and_contains_panics() {
        assert_eq!(__enter(ABI_VERSION, || 7), 7);
        assert_eq!(__enter(ABI_VERSION + 1, || 7), EXIT_ABI_MISMATCH);
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let code = __enter(ABI_VERSION, || panic!("boom"));
        std::panic::set_hook(previous);
        assert_eq!(code, EXIT_PANIC);
    }

    #[test]
    fn the_feature_list_macro_is_the_table() {
        let mut names: Vec<&str> = Vec::new();
        macro_rules! push {
            ($name:tt) => {
                names.push($name);
            };
        }
        __for_each_feature!(push);
        let mut tables: Vec<&str> = seaworthy_levels::FEATURES.iter().map(|f| f.name).collect();
        for feature in &seaworthy_levels::AARCH64_FEATURES {
            if !tables.contains(&feature.name) {
                tables.push(feature.name);
            }
        }
        assert_eq!(
            names, tables,
            "keep __for_each_feature! in table order: x86-64, then aarch64's own names"
        );
    }

    #[test]
    fn the_visible_list_matches_this_crates_cfg() {
        // This crate was compiled with the flags the build script saw, so
        // the check core_main! runs passes here by construction.
        let mut names: Vec<&str> = Vec::new();
        macro_rules! push_enabled {
            ($name:tt) => {
                if cfg!(target_feature = $name) {
                    names.push($name);
                }
            };
        }
        __for_each_feature!(push_enabled);
        let mut visible = __VISIBLE_FEATURES.to_vec();
        visible.sort_unstable();
        names.sort_unstable();
        assert_eq!(names, visible);
        assert!(__visible(BASELINE));
        assert!(!__visible("sse2x"));
        assert!(!__visible("ss"));
        assert!(!__visible("not-a-feature"));
        let record = record().expect("record");
        assert!(
            visible
                .iter()
                .all(|name| record.features.iter().any(|f| f == name))
        );
    }

    #[test]
    fn core_exit_conversions() {
        assert_eq!(().into_exit_code(), 0);
        assert_eq!(3i32.into_exit_code(), 3);
        assert_eq!(250u8.into_exit_code(), 250);
        assert_eq!(Ok::<(), String>(()).into_exit_code(), 0);
        assert_eq!(Err::<(), _>("bad").into_exit_code(), 1);
    }

    #[test]
    fn the_cpulist_helpers_build_a_parseable_list() {
        const TEXT: &str = concat!(
            "seaworthy-cpulist:1\ncore=",
            "demo_core",
            "\ncpus=",
            __join!("x86-64-v3", "x86-64-v2"),
            "\n"
        );
        let bytes: [u8; TEXT.len()] = __bytes(TEXT);
        let list = CpuList::parse(&bytes).expect("parses");
        assert_eq!(list.cpus, ["x86-64-v3", "x86-64-v2"]);
    }

    #[test]
    fn rustflags_find_the_effective_cpu() {
        let flags = |s: &[&str]| s.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            rustflags::target_cpu(&flags(&["-C", "target-cpu=x86-64-v3"])).as_deref(),
            Some("x86-64-v3")
        );
        assert_eq!(
            rustflags::target_cpu(&flags(&["-Ctarget-cpu=znver4"])).as_deref(),
            Some("znver4")
        );
        assert_eq!(
            rustflags::target_cpu(&flags(&[
                "--codegen",
                "target-cpu=a",
                "--codegen=target-cpu=b"
            ]))
            .as_deref(),
            Some("b")
        );
        assert_eq!(rustflags::target_cpu(&flags(&["-C", "opt-level=3"])), None);
        assert!(rustflags::sets_target_features(&flags(&[
            "-C",
            "target-feature=+avx2"
        ])));
        assert!(rustflags::sets_target_features(&flags(&[
            "-Ctarget-feature=+crt-static,+bmi2"
        ])));
        assert!(!rustflags::sets_target_features(&flags(&[
            "-C",
            "target-cpu=x86-64-v3"
        ])));
        // cargo-xwin and static-CRT Windows builds: not a CPU feature.
        assert!(!rustflags::sets_target_features(&flags(&[
            "-C",
            "target-feature=+crt-static"
        ])));
        // Enabling a name no record can describe is refused; disabling is safe.
        let known = |name: &str| seaworthy_levels::known("x86_64-unknown-linux-gnu", name);
        assert_eq!(
            rustflags::enabled_unknown_features(
                &flags(&["-C", "target-feature=+nf,+avx2,-ndd,+crt-static"]),
                known
            ),
            ["nf"]
        );
        assert!(
            rustflags::enabled_unknown_features(&flags(&["-Ctarget-feature=-egpr,+apxf"]), known)
                .is_empty()
        );
        assert_eq!(
            rustflags::resolve_native(
                "Available CPUs for this target:\n    native                  - Select the CPU of the current host (currently znver5).\n    alderlake\n"
            )
            .as_deref(),
            Some("znver5")
        );
        assert_eq!(
            rustflags::resolve_native("Available CPUs for this target:\n    alderlake\n"),
            None
        );
        assert_eq!(
            rustflags::split("-C\u{1f}target-cpu=x"),
            ["-C", "target-cpu=x"]
        );
        assert!(rustflags::split("").is_empty());
        assert_eq!(rustflags::default_cpu("x86_64-pc-windows-msvc"), "x86-64");
        assert_eq!(rustflags::default_cpu("aarch64-apple-darwin"), "apple-m1");
        assert_eq!(rustflags::default_cpu("x86_64-apple-darwin"), "penryn");
        assert_eq!(
            rustflags::enabled_unknown_features(
                &flags(&["-Ctarget-feature=+neon,+avx2"]),
                |name| { seaworthy_levels::known("aarch64-apple-darwin", name) }
            ),
            ["avx2"]
        );
        assert_eq!(
            rustflags::parse_print_cfg(
                "target_arch=\"x86_64\"\ntarget_feature=\"sse2\"\ntarget_feature=\"sse\"\ntarget_feature=\"sse\"\n"
            ),
            ["sse", "sse2"]
        );
        // `crt-static` never reaches a record: the launcher can't check it
        // against a CPU, and an unknown name would make the core unloadable.
        assert_eq!(
            rustflags::parse_print_cfg("target_feature=\"crt-static\"\ntarget_feature=\"sse\"\n"),
            ["sse"]
        );
    }

    #[test]
    fn printed_text_shows_controls_and_bidi_marks_escaped() {
        assert_eq!(
            display_safe("/opt/acme/lib/core.so"),
            "/opt/acme/lib/core.so"
        );
        assert_eq!(
            display_safe("C:\\Program Files\\Acme"),
            "C:\\Program Files\\Acme"
        );
        // A right-to-left override makes "evil\u{202E}os.exe" read as
        // "evilexe.so"; a newline would forge a second message line.
        assert_eq!(
            display_safe("lib\u{202E}os.exe\nscm: all good\u{1b}[2J"),
            "lib\\u{202E}os.exe\\u{000A}scm: all good\\u{001B}[2J"
        );
        for invisible in [
            '\u{061C}', '\u{200B}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}', '\u{202A}',
            '\u{2066}', '\u{2069}', '\u{FEFF}', '\u{0085}', '\u{007F}', '\0',
        ] {
            let shown = display_safe(&format!("a{invisible}b"));
            assert!(
                shown.is_ascii() && shown.contains("\\u{"),
                "{invisible:?}: {shown}"
            );
        }
        // Text in any script is kept as it is.
        assert_eq!(display_safe("Prüfung 試験 مرحبا"), "Prüfung 試験 مرحبا");
    }

    #[test]
    fn every_spelling_rustc_accepts_is_read() {
        let flags = |s: &[&str]| s.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        let known = |name: &str| seaworthy_levels::known("x86_64-unknown-linux-gnu", name);
        // rustc takes `_` for `-` in an option's key: APX through
        // `target_feature` must be refused like `target-feature`.
        for spelling in [
            &["-C", "target_feature=+egpr,+ndd,+nf"][..],
            &["-Ctarget_feature=+egpr,+ndd,+nf"],
            &["--codegen", "target_feature=+egpr,+ndd,+nf"],
            &["--codegen=target_feature=+egpr,+ndd,+nf"],
            &["-Ctarget-feature=+egpr,+ndd,+nf"],
        ] {
            assert_eq!(
                rustflags::enabled_unknown_features(&flags(spelling), known),
                ["egpr", "ndd", "nf"],
                "{spelling:?}"
            );
            assert!(rustflags::sets_target_features(&flags(spelling)));
        }
        assert_eq!(
            rustflags::target_cpu(&flags(&["-Ctarget_cpu=znver4"])).as_deref(),
            Some("znver4")
        );
        assert_eq!(
            rustflags::target_cpu(&flags(&[
                "-C",
                "target-cpu=x86-64-v2",
                "--codegen=target_cpu=x86-64-v4"
            ]))
            .as_deref(),
            Some("x86-64-v4"),
            "the last one wins, whatever its spelling"
        );
        // A value keeps its own spelling: only the key is normalized.
        assert_eq!(
            rustflags::target_cpu(&flags(&["-Ctarget_cpu=x86_64_v9"])).as_deref(),
            Some("x86_64_v9")
        );
    }

    #[test]
    fn argfiles_expand_as_rustc_reads_them() {
        // An absolute directory: a drive's on Windows.
        let root = if cfg!(windows) { "C:/flags" } else { "/flags" };
        let (apx, cpu) = (format!("{root}/apx"), format!("{root}/cpu"));
        let flags = |s: &[&str]| s.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
        let read = |path: &Path| -> Result<String, String> {
            if path == Path::new(&apx) {
                Ok("-C\r\ntarget_feature=+egpr\n@/flags/nested\n".to_owned())
            } else if path == Path::new(&cpu) {
                Ok("-Ctarget-cpu=x86-64-v3".to_owned())
            } else {
                Err(format!("no file {path:?}"))
            }
        };
        let (expanded, files) = rustflags::expand_argfiles(
            flags(&["--cfg", "x", &format!("@{apx}"), &format!("@{cpu}")]),
            read,
        )
        .expect("expands");
        // One argument per line, `\r\n` too, and no nesting: an `@` line is
        // an argument, as rustc reads it.
        assert_eq!(
            expanded,
            [
                "--cfg",
                "x",
                "-C",
                "target_feature=+egpr",
                "@/flags/nested",
                "-Ctarget-cpu=x86-64-v3"
            ]
        );
        assert_eq!(files, [PathBuf::from(&apx), PathBuf::from(&cpu)]);
        let known = |name: &str| seaworthy_levels::known("x86_64-unknown-linux-gnu", name);
        assert_eq!(
            rustflags::enabled_unknown_features(&expanded, known),
            ["egpr"]
        );
        assert_eq!(
            rustflags::target_cpu(&expanded).as_deref(),
            Some("x86-64-v3")
        );
        // Refused: a relative path (rustc's working directory is unknown
        // here), the unstable shell syntax, and a file that can't be read.
        for bad in [
            "@flags/apx".to_owned(),
            format!("@shell:{apx}"),
            format!("@{root}/missing"),
        ] {
            assert!(
                rustflags::expand_argfiles(flags(&[&bad]), read).is_err(),
                "{bad}"
            );
        }
    }
}
