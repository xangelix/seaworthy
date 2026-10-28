//! Step 1 of the pipeline: prove the built artifacts are what the product
//! config says, before anything is laid out, signed or packaged.
//!
//! Every check runs and every finding is reported together, so one CI run
//! names everything wrong. The checks:
//!
//! 1. **Presence and kind**: the launcher, the helper (when shipped) and one
//!    core per CPU target, on every platform the outputs need. Each must be
//!    a regular file (symlinks, FIFOs and devices are refused), at most
//!    [`MAX_ARTIFACT_BYTES`], and of the platform's format: ELF64 x86-64 on
//!    Linux (executables `ET_EXEC`, or `ET_DYN` with an interpreter; cores
//!    `ET_DYN`), PE32+ AMD64 on Windows (executables without, cores and
//!    sidecars with, the DLL flag).
//! 2. **Core records**: each core's `.cpureq` parses, names this platform's
//!    triple and this directory's CPU, lists only feature names
//!    `seaworthy_levels` has a row for (an unknown one would make the launcher
//!    refuse the core everywhere), and includes the features its CPU
//!    target uses without `--print cfg` saying so
//!    (`seaworthy_levels::IMPLIED_FEATURES`).
//! 3. **The launcher's `.cpulist`** names this product's core and exactly
//!    the configured targets, in order.
//! 4. **Windows sidecars**: each glob matches exactly one file in every core
//!    build, no file matches two globs, names are plain file names, and the
//!    copies are byte-identical. A difference means an accidental
//!    per-target FIPS build.
//! 5. **FIPS** (the product's `fips`, else `defaults.fips`): every Linux core passes
//!    `scripts/verify-fips-binary.sh`'s checks over its symbol table, read
//!    as `nm` reads it ([`fips_symbol_findings`]), for the module
//!    `defaults.fips-module` pins (default: `seaworthy-crypto`'s; its
//!    symbol prefix, [`Config::fips_symbol_prefix`]). On Windows every core
//!    imports the pinned module's crypto DLL, and the sidecars ship every
//!    DLL of the module any core imports (aws-lc-fips-sys 0.14
//!    builds one, `<prefix>crypto.dll`; older releases added a
//!    `<prefix>rust_wrapper.dll`, which the imports would then name). On
//!    macOS, where AWS-LC builds the module as a dylib too, every core
//!    loads `@rpath/lib<prefix>crypto.dylib`, the sidecars
//!    (`sidecars.macos`, shipped in `Contents/Frameworks`) ship every
//!    module dylib the cores load, and the module's own symbols pass the
//!    Linux checks. Any `@rpath/` library must be a sidecar, loaded with
//!    the search path to it (`@loader_path` for a core,
//!    `@executable_path/../Frameworks` for an executable).
//! 6. **Runtime dependencies**: Windows binaries link the C runtime
//!    statically: no `vcruntime*` or `msvcp*` import, delay-loaded or not.
//!    Linux binaries need only the base system's libraries
//!    ([`BASE_NEEDED`]), plus any the product declares in `linux.needed`,
//!    and no glibc newer than the product's floor (`linux.glibc`, default
//!    2.34): every `GLIBC_*` entry of the version-needs table, as glibc's
//!    loader checks them, ABI markers included ([`elf_glibc_needs`]).
//!    A binary past the floor would install (a package's glibc
//!    dependency says nothing about symbol versions) and fail to start on
//!    the oldest supported system. An import table, dynamic section or
//!    version table that doesn't parse, and a dynamic binary without
//!    section headers, are findings, never a pass.
//! 7. **No trust in CI test keys**, unless the build is a CI test build
//!    (`package --ci-test-signing`, [`Config::use_ci_test_keys`]): no
//!    binary may carry the CI test-key marker that a build made with
//!    `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` embeds when it trusts test keys
//!    (`seaworthy_updater::ci_test`), nor a key of
//!    `[defaults.ci-test-keys]` (a release key's last 32 bytes, raw or as
//!    hex in either case; an OpenPGP key's first armored line). Anyone can
//!    sign with a test key: a release binary that trusts one installs
//!    anyone's update. `seaworthy verify` on its own treats the artifacts
//!    as a release's.
//!
//! [`Verified`] can only come from [`verify`]. It carries the SHA-256 of
//! every file it read, and `layout` refuses a file that changed since.
//! It also carries **warnings**: a core every CPU it runs on would skip
//! for an earlier one (its features are a superset of a more preferred
//! core's) can never be chosen.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use object::read::elf::{Dyn, ElfFile64, FileHeader, ProgramHeader};
use object::read::pe::{ImageNtHeaders, PeFile64};
use object::{
    LittleEndian as LE, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind, SymbolSection,
};

use crate::config::{Config, Product, is_windows_reserved, parse_macos_version};
use crate::inputs::{Os, PlatformInputs, ProgramInputs, expected, glob_matches};

/// Where a macOS binary's linked libraries may come from: the system's
/// own (`/usr/lib`, `/System/Library`). A library outside them — a
/// Homebrew one, `@rpath/…` — isn't on a customer's Mac.
pub const MACOS_SYSTEM_PREFIXES: [&str; 2] = ["/usr/lib/", "/System/Library/"];

/// The libraries every supported distribution's base install provides.
pub const BASE_NEEDED: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
];

/// The largest artifact `verify` reads (2 GiB): a core with the FIPS
/// module is tens of megabytes.
pub const MAX_ARTIFACT_BYTES: u64 = 2 << 30;

/// What a binary must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    /// A program: the launcher, the helper.
    Executable,
    /// A shared library: a core, a Windows sidecar.
    Library,
}

/// The artifacts that passed, ready for `layout`. Only [`verify`] makes
/// one.
#[derive(Debug, Clone)]
pub struct Verified {
    product: String,
    platforms: Vec<VerifiedPlatform>,
    digests: BTreeMap<PathBuf, String>,
    warnings: Vec<String>,
}

impl Verified {
    /// The product these artifacts belong to.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// The verified platforms.
    #[must_use]
    pub fn platforms(&self) -> &[VerifiedPlatform] {
        &self.platforms
    }

    /// Findings that don't block packaging (a core that can never be
    /// chosen).
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The SHA-256 a verified file had when `verify` read it.
    pub(crate) fn digest(&self, path: &Path) -> Option<&str> {
        self.digests.get(path).map(String::as_str)
    }
}

/// One platform's verified artifacts.
#[derive(Debug, Clone)]
pub struct VerifiedPlatform {
    /// The paths that were checked.
    pub inputs: PlatformInputs,
    /// Windows: the sidecar files (one copy, from the first core build).
    pub sidecars: Vec<PathBuf>,
}

/// Runs every check for product `id`.
///
/// # Errors
/// [`crate::DistError::Verify`] with every finding.
pub fn verify(config: &Config, id: &str, artifacts: &Path) -> Result<Verified, crate::DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| crate::DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    let mut run = Run {
        test_keys: ci_test_needles(config)?,
        ..Run::default()
    };
    let mut platforms = Vec::new();
    for inputs in expected(config, product, artifacts) {
        let sidecars = run.platform(config, product, &inputs);
        platforms.push(VerifiedPlatform { inputs, sidecars });
    }
    if run.findings.is_empty() {
        Ok(Verified {
            product: id.to_owned(),
            platforms,
            digests: run.digests,
            warnings: run.warnings,
        })
    } else {
        Err(crate::DistError::Verify(run.findings))
    }
}

#[derive(Default)]
struct Run {
    findings: Vec<String>,
    warnings: Vec<String>,
    digests: BTreeMap<PathBuf, String>,
    /// What no binary of a release may carry ([`ci_test_needles`]).
    test_keys: Vec<Needle>,
}

/// A byte string a binary must not carry, and what it means.
struct Needle {
    what: String,
    bytes: Vec<u8>,
}

/// What marks a binary that trusts CI test keys: the marker every build
/// made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` embeds when it trusts one,
/// and `[defaults.ci-test-keys]`'s keys themselves. Nothing for a CI test
/// build ([`Config::ci_test`]), which trusts them on purpose.
fn ci_test_needles(config: &Config) -> Result<Vec<Needle>, crate::DistError> {
    if config.ci_test {
        return Ok(Vec::new());
    }
    let mut needles = vec![Needle {
        what: format!(
            "the CI test-key marker: it was built with {}=1 and trusts public CI test keys",
            seaworthy_updater::ci_test::CI_TEST_KEYS_VAR
        ),
        bytes: seaworthy_updater::ci_test::ci_test_keys_marker(),
    }];
    let Some(test) = &config.defaults.ci_test_keys else {
        return Ok(needles);
    };
    for key in config.clone().use_ci_test_keys()?.release_keys()? {
        // The last 32 bytes: the end of an ML-DSA-87 key's t1, the whole
        // Ed25519 key, a P-256 point's y.
        let public_key = key.public_key();
        let tail = public_key
            .get(public_key.len().saturating_sub(32)..)
            .unwrap_or(public_key)
            .to_vec();
        let id = hex::encode(key.key_id());
        for (form, bytes) in [
            ("raw", tail.clone()),
            ("hex", hex::encode(&tail).into_bytes()),
            ("hex", hex::encode_upper(&tail).into_bytes()),
        ] {
            needles.push(Needle {
                what: format!("CI test release key {id} ({form}; [defaults.ci-test-keys])"),
                bytes,
            });
        }
    }
    for file in &test.openpgp_keys {
        let path = config.dir.join(file);
        let text = std::fs::read_to_string(&path).map_err(|e| crate::DistError::io(&path, e))?;
        // The armor's first body line: after the header block's blank line.
        let first = text
            .lines()
            .skip_while(|line| !line.trim().is_empty())
            .map(str::trim)
            .find(|line| !line.is_empty());
        if let Some(line) = first.filter(|line| line.len() >= 32) {
            needles.push(Needle {
                what: format!(
                    "CI test OpenPGP key {} ([defaults.ci-test-keys])",
                    file.display()
                ),
                bytes: line.as_bytes().to_vec(),
            });
        }
    }
    Ok(needles)
}

/// The needles `haystack` contains, in one pass.
fn found_needles<'a>(haystack: &[u8], needles: &'a [Needle]) -> Vec<&'a Needle> {
    let mut starts = [false; 256];
    for needle in needles {
        if let Some(&byte) = needle.bytes.first() {
            starts[usize::from(byte)] = true;
        }
    }
    let mut found = vec![false; needles.len()];
    for (at, &byte) in haystack.iter().enumerate() {
        if !starts[usize::from(byte)] {
            continue;
        }
        let rest = haystack.get(at..).unwrap_or_default();
        for (hit, needle) in found.iter_mut().zip(needles) {
            if !*hit && !needle.bytes.is_empty() && rest.starts_with(&needle.bytes) {
                *hit = true;
            }
        }
    }
    needles
        .iter()
        .zip(found)
        .filter_map(|(needle, hit)| hit.then_some(needle))
        .collect()
}

impl Run {
    fn finding(&mut self, path: &Path, what: impl std::fmt::Display) {
        self.findings.push(format!("{}: {what}", path.display()));
    }

    /// Reads a regular file of bounded size, recording its digest.
    fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
        match std::fs::symlink_metadata(path) {
            Err(e) => {
                self.finding(path, e);
                return None;
            }
            Ok(meta) if !meta.file_type().is_file() => {
                self.finding(
                    path,
                    "not a regular file (symlinks, FIFOs and devices are refused)",
                );
                return None;
            }
            Ok(meta) if meta.len() > MAX_ARTIFACT_BYTES => {
                self.finding(
                    path,
                    format!(
                        "{} bytes exceeds the {MAX_ARTIFACT_BYTES}-byte limit",
                        meta.len()
                    ),
                );
                return None;
            }
            Ok(_) => {}
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                self.digests.insert(
                    path.to_path_buf(),
                    seaworthy_crypto::digest::sha256_hex(&bytes),
                );
                let carried: Vec<String> = found_needles(&bytes, &self.test_keys)
                    .into_iter()
                    .map(|needle| needle.what.clone())
                    .collect();
                for what in carried {
                    self.finding(
                        path,
                        format!(
                            "carries {what}; only a CI test build (package --ci-test-signing) may ship a binary that trusts CI test keys"
                        ),
                    );
                }
                Some(bytes)
            }
            Err(e) => {
                self.finding(path, e);
                None
            }
        }
    }

    /// Format, then runtime dependencies.
    fn binary(
        &mut self,
        path: &Path,
        bytes: &[u8],
        os: Os,
        kind: BinaryKind,
        config: &Config,
        product: &Product,
    ) -> bool {
        let format = binary_format_findings(bytes, os, kind);
        let ok = format.is_empty();
        for finding in format {
            self.finding(path, finding);
        }
        if !ok {
            return false;
        }
        if os == Os::Macos {
            self.macos_binary(path, bytes, kind, config, product);
        } else if os == Os::Windows {
            match pe_imports(bytes) {
                Ok(imports) => {
                    let crt: Vec<String> = imports
                        .into_iter()
                        .filter(|lib| lib.starts_with("vcruntime") || lib.starts_with("msvcp"))
                        .collect();
                    if !crt.is_empty() {
                        self.finding(
                            path,
                            format!(
                                "imports the dynamic C runtime ({}) — Windows binaries must link it statically (+crt-static)",
                                crt.join(", ")
                            ),
                        );
                    }
                }
                Err(e) => self.finding(path, format!("its import tables don't parse: {e}")),
            }
        } else {
            match elf_needed(bytes) {
                Ok(needed) => {
                    let extra: Vec<String> = needed
                        .into_iter()
                        .filter(|lib| {
                            !BASE_NEEDED.contains(&lib.as_str())
                                && !product.linux.needed.contains(lib)
                        })
                        .collect();
                    if !extra.is_empty() {
                        self.finding(
                            path,
                            format!(
                                "needs {} beyond the base system — declare it in linux.needed (and its package in linux.depends)",
                                extra.join(", ")
                            ),
                        );
                    }
                }
                Err(e) => self.finding(path, format!("its dynamic section doesn't parse: {e}")),
            }
            // A core the launcher dlopen()s can't rely on glibc's
            // static TLS block.
            if kind == BinaryKind::Library {
                match elf_static_tls(bytes) {
                    Ok(false) => {}
                    Ok(true) => self.finding(
                        path,
                        "uses initial-exec TLS (DF_STATIC_TLS): glibc places a library loaded at run time that needs it in the static TLS block's small surplus, and the launcher's dlopen fails (\"cannot allocate memory in static TLS block\") when it doesn't fit; build the C dependency that uses it with -ftls-model=global-dynamic or local-dynamic (mimalloc: its local_dynamic_tls feature)".to_owned(),
                    ),
                    Err(e) => self.finding(path, format!("its dynamic section doesn't parse: {e}")),
                }
            }
            // glibc versions past the product's floor.
            let floor = product.linux.glibc_floor();
            match elf_glibc_needs(bytes) {
                Ok(needs) => {
                    let beyond: Vec<String> = needs
                        .iter()
                        .filter(|need| need.since.is_none_or(|since| since > floor))
                        .map(|need| {
                            let since = need.since.map_or_else(
                                || "unknown to this check".to_owned(),
                                |(major, minor)| format!("glibc {major}.{minor}"),
                            );
                            if need.symbols.is_empty() {
                                format!("{} ({since})", need.name)
                            } else {
                                let users: Vec<&str> =
                                    need.symbols.iter().map(String::as_str).collect();
                                format!("{} ({since}: {})", need.name, users.join(", "))
                            }
                        })
                        .collect();
                    if !beyond.is_empty() {
                        // libm's hypot and hypotf, versioned anew in
                        // glibc 2.35, have a fix that keeps the builder.
                        let libm = needs
                            .iter()
                            .filter(|need| need.since.is_none_or(|since| since > floor))
                            .flat_map(|need| &need.symbols)
                            .any(|symbol| {
                                let name = symbol.strip_suffix(" (weak)").unwrap_or(symbol);
                                name == "hypot" || name == "hypotf"
                            });
                        let hint = if libm {
                            "; for hypot and hypotf, invoke seaworthy_launcher::glibc_floor!() at the binary's crate root (core_main! and launcher_main! do), which binds them to glibc's baseline versions"
                        } else {
                            ""
                        };
                        self.finding(
                            path,
                            format!(
                                "needs {}, past the product's glibc floor {}.{} (linux.glibc): glibc's loader refuses to start it on an older glibc, even when only weak references use a version; build on a system whose glibc is {}.{} or older, or raise the floor and the packages' glibc dependency together{hint}",
                                beyond.join("; "),
                                floor.0,
                                floor.1,
                                floor.0,
                                floor.1
                            ),
                        );
                    }
                }
                Err(e) => self.finding(path, format!("its symbol versions don't parse: {e}")),
            }
        }
        true
    }

    /// A macOS binary's runtime dependencies (the system's libraries, and
    /// the product's sidecars through `@rpath` with the search path to
    /// them) and the macOS it needs (at most `defaults.macos-minimum`).
    fn macos_binary(
        &mut self,
        path: &Path,
        bytes: &[u8],
        kind: BinaryKind,
        config: &Config,
        product: &Product,
    ) {
        match macho_facts(bytes) {
            Ok(facts) => {
                let sidecar = |lib: &str| {
                    lib.strip_prefix("@rpath/").is_some_and(|name| {
                        product
                            .sidecars
                            .macos
                            .iter()
                            .any(|glob| glob_matches(glob, name))
                    })
                };
                let foreign: Vec<&str> = facts
                    .dylibs
                    .iter()
                    .map(String::as_str)
                    .filter(|lib| {
                        !MACOS_SYSTEM_PREFIXES.iter().any(|p| lib.starts_with(p)) && !sidecar(lib)
                    })
                    .collect();
                if !foreign.is_empty() {
                    self.finding(
                        path,
                        format!(
                            "links {} outside the system's libraries (/usr/lib, /System/Library) and the product's sidecars.macos (as @rpath/<name>): a customer's Mac doesn't have them",
                            foreign.join(", ")
                        ),
                    );
                }
                // A sidecar loads from the bundle's Contents/Frameworks:
                // a core (or sidecar) sits there itself, an executable in
                // Contents/MacOS.
                let search = match kind {
                    BinaryKind::Library => "@loader_path",
                    BinaryKind::Executable => "@executable_path/../Frameworks",
                };
                if facts.dylibs.iter().any(|lib| sidecar(lib))
                    && !facts
                        .rpaths
                        .iter()
                        .any(|p| p.trim_end_matches('/') == search)
                {
                    self.finding(
                        path,
                        format!(
                            "loads a sidecar through @rpath but has no {search} search path (LC_RPATH; the build plan links it with -Wl,-rpath,{search})"
                        ),
                    );
                }
                let minimum =
                    parse_macos_version(&config.defaults.macos_minimum).unwrap_or((11, 0, 0));
                match facts.minimum {
                    None => self.finding(
                        path,
                        "no LC_BUILD_VERSION (or LC_VERSION_MIN_MACOSX): which macOS it needs is unknown".to_owned(),
                    ),
                    Some(needs) if needs > minimum => self.finding(
                        path,
                        format!(
                            "needs macOS {}.{}.{}, newer than defaults.macos-minimum {} — build with MACOSX_DEPLOYMENT_TARGET={} (the build plan sets it)",
                            needs.0, needs.1, needs.2, config.defaults.macos_minimum, config.defaults.macos_minimum
                        ),
                    ),
                    Some(_) => {}
                }
            }
            Err(e) => self.finding(path, format!("its load commands don't parse: {e}")),
        }
    }

    fn platform(
        &mut self,
        config: &Config,
        product: &Product,
        inputs: &PlatformInputs,
    ) -> Vec<PathBuf> {
        let os = inputs.os();
        let targets = if os == Os::Macos {
            &config.defaults.macos_targets
        } else {
            &config.defaults.targets
        };

        // Each program's launcher and its CPU list.
        for program in &inputs.programs {
            let launcher = &program.launcher;
            let Some(bytes) = self.read(launcher) else {
                continue;
            };
            if !self.binary(
                launcher,
                &bytes,
                os,
                BinaryKind::Executable,
                config,
                product,
            ) {
                continue;
            }
            match seaworthy_levels::cpu_list_from_bytes(&bytes) {
                Ok(list) => {
                    if list.core != program.program.core {
                        self.finding(
                            launcher,
                            format!(
                                "its .cpulist names core {:?}, seaworthy.toml says {:?}",
                                list.core, program.program.core
                            ),
                        );
                    }
                    if &list.cpus != targets {
                        self.finding(
                            launcher,
                            format!(
                                "its .cpulist lists {:?}, seaworthy.toml's {} are {:?} (same CPUs, same order)",
                                list.cpus,
                                if os == Os::Macos { "macos-targets" } else { "targets" },
                                targets
                            ),
                        );
                    }
                }
                Err(e) => self.finding(launcher, format!("not a seaworthy launcher: {e}")),
            }
        }
        if let Some(helper) = &inputs.helper
            && let Some(bytes) = self.read(helper)
        {
            self.binary(helper, &bytes, os, BinaryKind::Executable, config, product);
        }

        // Each program's cores and their records.
        // Windows FIPS: the module's DLLs the cores import, which the
        // sidecars must ship.
        let mut module_imports: BTreeSet<String> = BTreeSet::new();
        for program in &inputs.programs {
            self.cores(config, product, inputs, program, &mut module_imports);
        }

        if os == Os::Linux {
            Vec::new()
        } else {
            self.sidecars(config, product, inputs, &module_imports)
        }
    }

    /// One program's cores: each one's format, runtime dependencies,
    /// record and FIPS module, and which can never be chosen.
    fn cores(
        &mut self,
        config: &Config,
        product: &Product,
        inputs: &PlatformInputs,
        program: &ProgramInputs,
        module_imports: &mut BTreeSet<String>,
    ) {
        let triple = inputs.triple;
        let os = inputs.os();
        let windows = os == Os::Windows;
        // The module the product's cores must carry (defaults.fips-module).
        let prefix = config.fips_symbol_prefix();
        let mut records: Vec<(String, BTreeSet<String>)> = Vec::new();
        for (cpu, core, _) in &program.cores {
            let Some(bytes) = self.read(core) else {
                continue;
            };
            if !self.binary(core, &bytes, os, BinaryKind::Library, config, product) {
                continue;
            }
            match seaworthy_levels::requirement_from_bytes(&bytes) {
                Ok(record) => {
                    if record.target != triple {
                        self.finding(
                            core,
                            format!("built for {}, expected {triple}", record.target),
                        );
                    }
                    if &record.cpu != cpu {
                        self.finding(
                            core,
                            format!("built for CPU {}, but sits in the {cpu} build", record.cpu),
                        );
                    }
                    let unknown: Vec<&str> = record
                        .features
                        .iter()
                        .map(String::as_str)
                        .filter(|f| !seaworthy_levels::known(&record.target, f))
                        .collect();
                    if !unknown.is_empty() {
                        self.finding(
                            core,
                            format!(
                                "features seaworthy_levels has no row for ({}) — the launcher would refuse this core on every machine",
                                unknown.join(", ")
                            ),
                        );
                    }
                    let missing: Vec<&str> = seaworthy_levels::implied_features(&record.cpu)
                        .filter(|f| !record.features.iter().any(|have| have == f))
                        .collect();
                    if !missing.is_empty() {
                        self.finding(
                            core,
                            format!(
                                "its record lacks {} — features the {} target uses without --print cfg reporting them; rebuild with the current seaworthy_launcher",
                                missing.join(", "),
                                record.cpu
                            ),
                        );
                    }
                    records.push((cpu.clone(), record.features.iter().cloned().collect()));
                }
                Err(e) => self.finding(core, format!("no valid requirement record: {e}")),
            }
            if config.fips(product) && os == Os::Linux {
                for finding in fips_symbol_findings(&bytes, &prefix) {
                    self.finding(core, finding);
                }
            }
            if config.fips(product) && windows {
                let crypto = format!("{prefix}crypto.dll");
                let imports = pe_imports(&bytes).unwrap_or_default();
                if !imports.contains(&crypto) {
                    self.finding(
                        core,
                        format!("does not import {crypto} — not a FIPS build of the pinned module (defaults.fips-module)"),
                    );
                }
                module_imports.extend(
                    imports
                        .into_iter()
                        .filter(|name| name.starts_with(prefix.as_str())),
                );
            }
            if config.fips(product) && os == Os::Macos {
                let module = format!("lib{prefix}");
                let crypto = format!("{module}crypto.dylib");
                let loads: Vec<String> = macho_facts(&bytes)
                    .map(|facts| {
                        facts
                            .dylibs
                            .into_iter()
                            .filter_map(|lib| lib.strip_prefix("@rpath/").map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                if !loads.contains(&crypto) {
                    self.finding(
                        core,
                        format!(
                            "does not load @rpath/{crypto} — not a FIPS build of the pinned module (defaults.fips-module)"
                        ),
                    );
                }
                module_imports.extend(loads.into_iter().filter(|name| name.starts_with(&module)));
            }
        }
        // A core whose features include every feature of an earlier core
        // can never be chosen: whenever it would run, the earlier one runs.
        for (j, (later, later_features)) in records.iter().enumerate() {
            if let Some((earlier, _)) = records[..j]
                .iter()
                .find(|(_, f)| f.is_subset(later_features))
            {
                // A product of several programs names whose core it is.
                let whose = if inputs.programs.len() > 1 {
                    format!(" ({})", program.program.core)
                } else {
                    String::new()
                };
                self.warnings.push(format!(
                    "{triple}: the {later} core can never be chosen — every CPU that runs it also runs the {earlier} core, which comes first in targets{whose}"
                ));
            }
        }
    }

    fn sidecars(
        &mut self,
        config: &Config,
        product: &Product,
        inputs: &PlatformInputs,
        module_imports: &BTreeSet<String>,
    ) -> Vec<PathBuf> {
        let triple = inputs.triple;
        let os = inputs.os();
        let key_name = if os == Os::Macos {
            "sidecars.macos"
        } else {
            "sidecars.windows"
        };
        let mut sidecars = Vec::new();
        let mut claimed: BTreeMap<String, &str> = BTreeMap::new();
        for glob in product.sidecars.for_os(os) {
            let mut first: Option<(PathBuf, String)> = None;
            for (cpu, _, dir) in inputs.cores() {
                let matches: Vec<PathBuf> = std::fs::read_dir(dir)
                    .map(|entries| {
                        entries
                            .filter_map(Result::ok)
                            .filter(|e| glob_matches(glob, &e.file_name().to_string_lossy()))
                            .map(|e| e.path())
                            .collect()
                    })
                    .unwrap_or_default();
                if matches.len() != 1 {
                    self.finding(
                        dir,
                        format!("sidecar {glob:?} matches {} files in the {cpu} build (exactly one expected)", matches.len()),
                    );
                    continue;
                }
                let path = matches[0].clone();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_owned();
                if !crate::config::is_file_name(&name)
                    || (os == Os::Windows && is_windows_reserved(&name))
                {
                    self.finding(&path, "a sidecar's name must be a plain file name ([A-Za-z0-9][A-Za-z0-9._-]*, not a Windows device name)");
                    continue;
                }
                let key = name.to_ascii_lowercase();
                if let Some(other) = claimed.get(&key)
                    && *other != glob.as_str()
                {
                    self.finding(
                        &path,
                        format!("matched by two sidecar globs ({other:?} and {glob:?})"),
                    );
                    continue;
                }
                claimed.insert(key, glob);
                let Some(bytes) = self.read(&path) else {
                    continue;
                };
                let digest = seaworthy_crypto::digest::sha256_hex(&bytes);
                match &first {
                    None => {
                        if self.binary(&path, &bytes, os, BinaryKind::Library, config, product)
                            && os == Os::Macos
                            && config.fips(product)
                            && name.starts_with(&format!("lib{}", config.fips_symbol_prefix()))
                        {
                            // The module itself: its symbols pass the
                            // Linux cores' checks (scripts/verify-fips-binary.sh).
                            for finding in
                                fips_symbol_findings(&bytes, &config.fips_symbol_prefix())
                            {
                                self.finding(&path, finding);
                            }
                        }
                        first = Some((path.clone(), digest));
                        sidecars.push(path);
                    }
                    Some((first_path, first_digest)) if *first_digest != digest => self.finding(
                        &path,
                        format!(
                            "differs from {} — sidecars must be identical across target builds (an accidental per-target FIPS build?)",
                            first_path.display()
                        ),
                    ),
                    Some(_) => {}
                }
            }
        }
        if config.fips(product) {
            let names: Vec<String> = sidecars
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
                .collect();
            for want in module_imports {
                if !names.contains(want) {
                    self.findings.push(format!(
                        "{triple}: the cores import the pinned FIPS module's {want}, but no sidecar ships it (add it to {key_name})"
                    ));
                }
            }
        }
        sidecars
    }
}

/// What is wrong with a binary's format for `os` and `kind`: empty when it
/// is ELF64 x86-64 (Linux), PE32+ AMD64 (Windows) or a thin 64-bit arm64
/// Mach-O (macOS) of the right kind.
#[must_use]
pub fn binary_format_findings(image: &[u8], os: Os, kind: BinaryKind) -> Vec<String> {
    if os == Os::Macos {
        return macho_format_findings(image, kind);
    }
    if os == Os::Windows {
        let file = match PeFile64::parse(image) {
            Ok(file) => file,
            Err(e) => return vec![format!("not a 64-bit PE image: {e}")],
        };
        let header = file.nt_headers().file_header();
        let mut findings = Vec::new();
        if header.machine.get(LE) != object::pe::IMAGE_FILE_MACHINE_AMD64 {
            findings.push(format!(
                "not an AMD64 image (machine {:#06x})",
                header.machine.get(LE)
            ));
        }
        let dll = header
            .characteristics
            .get(LE)
            .contains(object::pe::IMAGE_FILE_DLL);
        match (kind, dll) {
            (BinaryKind::Executable, true) => {
                findings.push("a DLL where an executable belongs".to_owned())
            }
            (BinaryKind::Library, false) => {
                findings.push("an executable where a DLL belongs".to_owned())
            }
            _ => {}
        }
        findings
    } else {
        let file = match ElfFile64::<object::Endianness>::parse(image) {
            Ok(file) => file,
            Err(e) => return vec![format!("not a 64-bit ELF file: {e}")],
        };
        let endian = file.endian();
        let header = file.elf_header();
        let mut findings = Vec::new();
        if header.e_machine(endian) != object::elf::EM_X86_64 {
            findings.push(format!(
                "not an x86-64 binary (machine {})",
                header.e_machine(endian)
            ));
        }
        let interpreter = file
            .elf_program_headers()
            .iter()
            .any(|ph| ph.p_type(endian) == object::elf::PT_INTERP);
        match (kind, header.e_type(endian)) {
            (BinaryKind::Executable, object::elf::ET_EXEC)
            | (BinaryKind::Library, object::elf::ET_DYN) => {}
            (BinaryKind::Executable, object::elf::ET_DYN) if interpreter => {}
            (BinaryKind::Executable, _) => findings
                .push("not an executable (ET_EXEC, or ET_DYN with an interpreter)".to_owned()),
            (BinaryKind::Library, _) => findings.push("not a shared library (ET_DYN)".to_owned()),
        }
        findings
    }
}

/// [`binary_format_findings`] for macOS: a thin 64-bit Mach-O for arm64,
/// an executable (`MH_EXECUTE`) or a dylib (`MH_DYLIB`).
fn macho_format_findings(image: &[u8], kind: BinaryKind) -> Vec<String> {
    use object::read::macho::MachHeader as _;
    if matches!(
        object::FileKind::parse(image),
        Ok(object::FileKind::MachOFat32 | object::FileKind::MachOFat64)
    ) {
        return vec![
            "a universal (multi-architecture) Mach-O: ship the arm64 slice alone".to_owned(),
        ];
    }
    let header = match object::macho::MachHeader64::<object::Endianness>::parse(image, 0) {
        Ok(header) => header,
        Err(e) => return vec![format!("not a 64-bit Mach-O file: {e}")],
    };
    let Ok(endian) = header.endian() else {
        return vec!["a Mach-O header of unknown byte order".to_owned()];
    };
    let mut findings = Vec::new();
    if header.cputype(endian) != object::macho::CPU_TYPE_ARM64 {
        findings.push(format!(
            "not an arm64 binary (CPU type {:#x})",
            header.cputype(endian)
        ));
    }
    match (kind, header.filetype(endian)) {
        (BinaryKind::Executable, object::macho::MH_EXECUTE)
        | (BinaryKind::Library, object::macho::MH_DYLIB) => {}
        (BinaryKind::Executable, _) => findings.push("not an executable (MH_EXECUTE)".to_owned()),
        (BinaryKind::Library, _) => findings.push("not a dynamic library (MH_DYLIB)".to_owned()),
    }
    findings
}

/// What a Mach-O's load commands say: the libraries it links and the macOS
/// it needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachoFacts {
    /// Every linked library's install name (`LC_LOAD_DYLIB` and its weak,
    /// re-exported, lazy and upward forms).
    pub dylibs: Vec<String>,
    /// The minimum macOS (`LC_BUILD_VERSION`'s `minos`, or
    /// `LC_VERSION_MIN_MACOSX`), as `(major, minor, patch)`.
    pub minimum: Option<(u32, u32, u32)>,
    /// The search paths `@rpath/…` libraries resolve against (`LC_RPATH`).
    pub rpaths: Vec<String>,
}

/// Reads [`MachoFacts`] from a thin 64-bit Mach-O.
///
/// # Errors
/// The parse error, or a build version for another platform than macOS.
pub fn macho_facts(image: &[u8]) -> Result<MachoFacts, String> {
    use object::read::macho::MachHeader as _;
    let header = object::macho::MachHeader64::<object::Endianness>::parse(image, 0)
        .map_err(|e| e.to_string())?;
    let endian = header.endian().map_err(|e| e.to_string())?;
    let mut commands = header
        .load_commands(endian, image, 0)
        .map_err(|e| e.to_string())?;
    // X.Y.Z, encoded in nibbles xxxx.yy.zz.
    let decode = |v: u32| (v >> 16, (v >> 8) & 0xff, v & 0xff);
    let mut facts = MachoFacts {
        dylibs: Vec::new(),
        minimum: None,
        rpaths: Vec::new(),
    };
    while let Some(command) = commands.next().map_err(|e| e.to_string())? {
        if let Some(dylib) = command.dylib().map_err(|e| e.to_string())? {
            let name = command
                .string(endian, dylib.dylib.name)
                .map_err(|e| e.to_string())?;
            facts
                .dylibs
                .push(String::from_utf8_lossy(name).into_owned());
        } else if let Some((build, _tools)) =
            command.build_version(endian).map_err(|e| e.to_string())?
        {
            if build.platform.get(endian) != object::macho::PLATFORM_MACOS {
                return Err(format!(
                    "built for another platform than macOS (LC_BUILD_VERSION platform {})",
                    build.platform.get(endian).0
                ));
            }
            facts.minimum = Some(decode(build.minos.get(endian).0));
        } else if command.cmd() == object::macho::LC_RPATH {
            let rpath = command
                .data::<object::macho::RpathCommand<object::Endianness>>()
                .map_err(|e| e.to_string())?;
            let path = command
                .string(endian, rpath.path)
                .map_err(|e| e.to_string())?;
            facts
                .rpaths
                .push(String::from_utf8_lossy(path).into_owned());
        } else if command.cmd() == object::macho::LC_VERSION_MIN_MACOSX {
            let version = command
                .data::<object::macho::VersionMinCommand<object::Endianness>>()
                .map_err(|e| e.to_string())?;
            facts.minimum = Some(decode(version.version.get(endian).0));
        }
    }
    Ok(facts)
}

/// `scripts/verify-fips-binary.sh`'s checks over an ELF image's symbol
/// table, read as `nm` reads it: empty means pass.
///
/// - `nm` prints every `.symtab` entry except `STT_FILE` and
///   `STT_SECTION` ones (rustc names its file symbols after the codegen
///   unit, `aws_lc_fips_sys.<hash>-cgu.0`).
/// - The script strips one leading `_` (Mach-O) and compares the rest.
/// - Its "defined in text" means `nm` type `T`/`t`: a defined, non-weak
///   symbol in an executable section.
#[must_use]
pub fn fips_symbol_findings(image: &[u8], prefix: &str) -> Vec<String> {
    let file = match object::File::parse(image) {
        Ok(file) => file,
        Err(e) => return vec![format!("not an object file: {e}")],
    };
    let prefix = prefix.as_bytes();
    let names: Vec<(Vec<u8>, bool)> = file
        .symbols()
        .filter(|s| !matches!(s.kind(), SymbolKind::File | SymbolKind::Section))
        .filter_map(|s| {
            let raw = s.name_bytes().ok()?;
            let name = raw.strip_prefix(b"_").unwrap_or(raw).to_vec();
            let in_code = match s.section() {
                SymbolSection::Section(index) => file
                    .section_by_index(index)
                    .is_ok_and(|section| section.kind() == SectionKind::Text),
                _ => false,
            };
            let text = s.is_definition() && !s.is_weak() && in_code;
            Some((name, text))
        })
        .filter(|(name, _)| !name.is_empty())
        .collect();
    if names.is_empty() {
        return vec!["no symbol table — build the binaries with strip = false; layout strips the shipped copies".to_owned()];
    }
    let shown = |name: &[u8]| String::from_utf8_lossy(name).into_owned();
    let pinned = String::from_utf8_lossy(prefix).into_owned();
    let mut findings = Vec::new();
    if !names.iter().any(|(n, _)| n.starts_with(prefix)) {
        findings.push(format!(
            "no {pinned}* symbols — the pinned AWS-LC FIPS module is not linked"
        ));
    }
    let version = [prefix, b"awslc_version_string"].concat();
    if !names.iter().any(|(n, text)| *n == version && *text) {
        findings.push(format!(
            "{} is not a defined text symbol (the Security Policy's static-link check)",
            shown(&version)
        ));
    }
    let non_fips: Vec<&Vec<u8>> = names
        .iter()
        .map(|(n, _)| n)
        .filter(|n| {
            n.strip_prefix(b"aws_lc_").is_some_and(|rest| {
                let mut parts = rest.splitn(4, |b| *b == b'_');
                let mut numeric = || {
                    parts
                        .next()
                        .is_some_and(|p| !p.is_empty() && p.iter().all(u8::is_ascii_digit))
                };
                numeric() && numeric() && numeric()
            })
        })
        .collect();
    if let Some(first) = non_fips.first() {
        findings.push(format!(
            "{} non-FIPS AWS-LC (aws-lc-sys) symbols, e.g. {}",
            non_fips.len(),
            shown(first)
        ));
    }
    if let Some((ring, _)) = names.iter().find(|(n, _)| n.starts_with(b"ring_core_")) {
        findings.push(format!("ring symbols, e.g. {}", shown(ring)));
    }
    if let Some((other, _)) = names
        .iter()
        .find(|(n, _)| n.starts_with(b"aws_lc_fips_") && !n.starts_with(prefix))
    {
        findings.push(format!(
            "AWS-LC FIPS symbols of a version other than {pinned}, e.g. {}",
            shown(other)
        ));
    }
    findings
}

/// The DLL names a PE image imports, lowercased: every import descriptor,
/// by name or by ordinal, and every delay-load descriptor.
///
/// # Errors
/// The parse error, for an image or import table `object` can't read.
pub fn pe_imports(image: &[u8]) -> Result<Vec<String>, String> {
    let file = PeFile64::parse(image).map_err(|e| e.to_string())?;
    let mut libraries = Vec::new();
    if let Some(table) = file.import_table().map_err(|e| e.to_string())? {
        let mut descriptors = table.descriptors().map_err(|e| e.to_string())?;
        while let Some(descriptor) = descriptors.next().map_err(|e| e.to_string())? {
            let name = table
                .name(descriptor.name.get(LE))
                .map_err(|e| e.to_string())?;
            libraries.push(String::from_utf8_lossy(name).to_lowercase());
        }
    }
    let sections = file.section_table();
    if let Some(table) = file
        .data_directories()
        .delay_load_import_table(file.data(), &sections)
        .map_err(|e| e.to_string())?
    {
        let mut descriptors = table.descriptors().map_err(|e| e.to_string())?;
        while let Some(descriptor) = descriptors.next().map_err(|e| e.to_string())? {
            let name = table
                .name(descriptor.dll_name_rva.get(LE))
                .map_err(|e| e.to_string())?;
            libraries.push(String::from_utf8_lossy(name).to_lowercase());
        }
    }
    libraries.sort();
    libraries.dedup();
    Ok(libraries)
}

/// One glibc version an ELF image needs: an entry of its version-needs
/// table (`.gnu.version_r`) naming a `GLIBC_*` version, which glibc's
/// loader checks at startup whatever uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlibcNeed {
    /// The version name (`GLIBC_2.39`, `GLIBC_ABI_DT_RELR`).
    pub name: String,
    /// The glibc release that introduced it; `None` for a name this check
    /// doesn't know (refused: it can't be shown to be old enough).
    pub since: Option<(u32, u32)>,
    /// The dynamic symbols bound to it (`name (weak)` for a weak
    /// reference); empty for an ABI marker, which no symbol uses.
    pub symbols: BTreeSet<String>,
}

/// glibc's ABI markers (versions no symbol uses: a binary needs one for an
/// ELF feature the loader must support) and the release that added each.
pub const GLIBC_ABI_MARKERS: &[(&str, (u32, u32))] = &[
    // Packed relative relocations (`-z pack-relative-relocs`).
    ("GLIBC_ABI_DT_RELR", (2, 36)),
    // The x86-64 `DT_X86_64_PLT` lazy-binding table.
    ("GLIBC_ABI_DT_X86_64_PLT", (2, 41)),
    // The fixed x86-64 TLS descriptor calling convention.
    ("GLIBC_ABI_GNU2_TLS", (2, 42)),
];

/// The release of a numbered glibc version (`2.39`, `2.2.5`).
fn glibc_release(number: &str) -> Option<(u32, u32)> {
    let mut parts = number.split('.');
    let digits = |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
    let (major, minor) = (parts.next()?, parts.next()?);
    let patch_ok = parts.next().is_none_or(digits) && parts.next().is_none();
    if !digits(major) || !digits(minor) || !patch_ok {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// The glibc versions an ELF image needs, read as glibc's loader reads
/// them: every entry of the version-needs table whose name starts
/// `GLIBC_`, from whichever of glibc's libraries. The loader refuses to
/// start the binary when any is missing, unless that entry itself carries
/// `VER_FLG_WEAK`; a weak SYMBOL bound to a version doesn't make the
/// version optional (linkers don't flag such entries weak: a host-built
/// binary that only weakly references std's `pidfd_spawnp` still needs
/// `GLIBC_2.39` to start). Weak-flagged entries and `GLIBC_PRIVATE` are
/// skipped. The dynamic symbol table only names each version's users. An
/// image with no version-needs table needs nothing (a static binary).
///
/// # Errors
/// The parse error, for an image or a version table `object` can't read.
pub fn elf_glibc_needs(image: &[u8]) -> Result<Vec<GlibcNeed>, String> {
    use object::read::elf::Sym as _;
    let file = ElfFile64::<object::Endianness>::parse(image).map_err(|e| e.to_string())?;
    let endian = file.endian();
    let sections = file.elf_section_table();
    let Some((mut verneeds, link)) = sections
        .gnu_verneed(endian, image)
        .map_err(|e| e.to_string())?
    else {
        return Ok(Vec::new());
    };
    let strings = sections
        .strings(endian, image, link)
        .map_err(|e| e.to_string())?;
    // By version index, so the symbols can be attached.
    let mut needs: BTreeMap<object::elf::VersionIndex, GlibcNeed> = BTreeMap::new();
    while let Some((_, mut auxiliaries)) = verneeds.next().map_err(|e| e.to_string())? {
        while let Some(aux) = auxiliaries.next().map_err(|e| e.to_string())? {
            if aux
                .vna_flags
                .get(endian)
                .contains(object::elf::VER_FLG_WEAK)
            {
                continue;
            }
            let name =
                String::from_utf8_lossy(aux.name(endian, strings).map_err(|e| e.to_string())?)
                    .into_owned();
            let Some(rest) = name.strip_prefix("GLIBC_") else {
                continue;
            };
            if rest == "PRIVATE" {
                continue;
            }
            let since = GLIBC_ABI_MARKERS
                .iter()
                .find(|(marker, _)| *marker == name)
                .map(|(_, release)| *release)
                .or_else(|| glibc_release(rest));
            needs.insert(
                aux.vna_other.get(endian),
                GlibcNeed {
                    name,
                    since,
                    symbols: BTreeSet::new(),
                },
            );
        }
    }
    if let Some(versions) = sections
        .versions(endian, image)
        .map_err(|e| e.to_string())?
    {
        let symbols = sections
            .symbols(endian, image, object::elf::SHT_DYNSYM)
            .map_err(|e| e.to_string())?;
        for (index, symbol) in symbols.enumerate() {
            if !symbol.is_undefined(endian) {
                continue;
            }
            let Some(need) = needs.get_mut(&versions.version_index(endian, index).index()) else {
                continue;
            };
            let name = String::from_utf8_lossy(
                symbol
                    .name(endian, symbols.strings())
                    .map_err(|e| e.to_string())?,
            )
            .into_owned();
            need.symbols
                .insert(if symbol.st_bind() == object::elf::STB_WEAK {
                    format!("{name} (weak)")
                } else {
                    name
                });
        }
    }
    Ok(needs.into_values().collect())
}

/// Whether an ELF image's `DT_FLAGS` carries `DF_STATIC_TLS`: some code in
/// it uses the initial-exec TLS model, which glibc can't always satisfy for
/// a library loaded with `dlopen`. No dynamic section: false (what
/// [`elf_needed`] says about that is its finding).
///
/// # Errors
/// The parse error, for an image or dynamic section `object` can't read.
pub fn elf_static_tls(image: &[u8]) -> Result<bool, String> {
    let file = ElfFile64::<object::Endianness>::parse(image).map_err(|e| e.to_string())?;
    let endian = file.endian();
    let Some((entries, _)) = file
        .elf_section_table()
        .dynamic(endian, image)
        .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    Ok(entries.iter().any(|d| {
        d.tag(endian) == object::elf::DT_FLAGS
            && object::elf::DynamicFlags(d.val(endian)).contains(object::elf::DF_STATIC_TLS)
    }))
}

/// An ELF image's `DT_NEEDED` entries (none for a static binary).
///
/// # Errors
/// The parse error, for an image or dynamic section `object` can't read.
pub fn elf_needed(image: &[u8]) -> Result<Vec<String>, String> {
    let file = ElfFile64::<object::Endianness>::parse(image).map_err(|e| e.to_string())?;
    let endian = file.endian();
    let sections = file.elf_section_table();
    let Some((entries, link)) = sections.dynamic(endian, image).map_err(|e| e.to_string())? else {
        // No dynamic section. A static binary has no dynamic segment
        // either; one that does was stripped of its section headers (the
        // loader reads program headers, so it still runs), and its
        // libraries and glibc versions can't be read from sections.
        use object::read::elf::ProgramHeader as _;
        if file
            .elf_program_headers()
            .iter()
            .any(|header| header.p_type(endian) == object::elf::PT_DYNAMIC)
        {
            return Err(
                "it has a dynamic segment but no dynamic section (stripped section headers): its dependencies can't be checked"
                    .to_owned(),
            );
        }
        return Ok(Vec::new());
    };
    let strings = sections
        .strings(endian, image, link)
        .map_err(|e| e.to_string())?;
    entries
        .iter()
        .filter(|d| d.tag(endian) == object::elf::DT_NEEDED)
        .map(|d| {
            d.string(endian, strings)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .map_err(|e| e.to_string())
        })
        .collect()
}
