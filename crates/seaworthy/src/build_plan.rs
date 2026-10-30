//! The build plan: what the CI templates'
//! build jobs run to leave every binary of every product `seaworthy.toml`
//! defines in the artifact directory ([`crate::inputs`]), for one target
//! triple.
//!
//! `seaworthy` never compiles: the plan is data, which
//! `scripts/ci/seaworthy.sh build` (Linux) and
//! `scripts/ci/seaworthy-build.ps1` (Windows) carry out. Per product whose
//! outputs need the triple, for each of its programs
//! ([`crate::config::Product::programs`]: `[[programs]]`, or the
//! single-program keys):
//!
//! - **the launcher**, once, built for plain x86-64 (`--bin <executable>`,
//!   or `--bin <launcher-bin>` when its cargo binary is named apart, shipped
//!   as the executable; from `launcher`'s manifest when `seaworthy.toml`
//!   names it) in the target directory `base`;
//! - **the update helper**, when it ships, the same way (from
//!   `helper-crate`'s manifest when `seaworthy.toml` names it: built from the
//!   workspace root, a binary gets the features every workspace member
//!   enables);
//!
//! `seaworthy.toml`'s crate paths (`launcher`, `helper-crate`) are relative to the
//! workspace root, the directory of the workspace manifest (`--manifest`,
//! the CI template's `manifest` input). The plan names each crate's manifest
//! through that directory ([`plan_for`]), because the builds run where the
//! workspace manifest is named from. A product whose workspace is in a
//! subdirectory (a template built from its repository's root) builds the
//! crates its `seaworthy.toml` names, not
//! paths beside the repository root.
//! - **the core**, once per CPU target (`-p <core>`, with the program's
//!   `--no-default-features` and `--features`), each in its own target
//!   directory named for the build ([`crate::config::Program::build_dir`]:
//!   the CPU, or `<cpu>.f<8 hex>` for a core built with features of its
//!   own, so builds of one crate with other features never share one),
//!   with `-C target-cpu=<cpu>` (given as `target.<triple>.rustflags`,
//!   which joins the product's own), copied to that build's directory
//!   under `<triple>/cores/`;
//! - on Windows and macOS, **each sidecar** (`sidecars.windows` /
//!   `sidecars.macos`, the FIPS module's DLL or dylib) from the product's
//!   FIRST program's FIRST CPU target's core build, beside every core of
//!   every program of the product. Each
//!   CPU's build compiles the module (its core links against it), but MSVC
//!   output isn't byte-reproducible across target directories (timestamps,
//!   PDB paths), and a release ships one module binary: the cores import it
//!   by name, it is the same module version and configuration in every
//!   build (`-C target-cpu` reaches only Rust codegen, never the module's
//!   C build), and `verify` holds the copies to one set of bytes;
//! - on Windows, every build with `-C target-feature=+crt-static`: `verify`
//!   refuses a Windows binary importing the dynamic C runtime, and the FIPS
//!   module's CMake build follows the flag (`/MT`); and the launcher and
//!   helper linked with `/DEPENDENTLOADFLAG:0xA00`
//!   (`LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`):
//!   their own imports resolve from their directory and System32, never the
//!   working directory or `PATH`. (A link argument from seaworthy-launcher's
//!   build script would reach only that crate's own targets, never the
//!   product's launcher; the helper needs its directory for the FIPS
//!   module's DLL it imports.)
//! - on macOS ([`MACOS`]), the cores for `defaults.macos-targets`
//!   (`lib<core>.dylib`), the launcher and helper for the target's default
//!   CPU (`apple-m1`), and every build with `--config
//!   env.MACOSX_DEPLOYMENT_TARGET.value="<macos-minimum>" --config
//!   env.MACOSX_DEPLOYMENT_TARGET.force=true` (dotted keys: cargo refuses an
//!   inline table on the command line): cargo hands it to rustc, the linker
//!   and build scripts alike, whatever the job's environment says, and
//!   `verify` holds each binary's minimum to it. A product with macOS
//!   sidecars links each core with the search path `@loader_path` (its
//!   own directory, the bundle's `Contents/Frameworks`) and the launcher
//!   and helper with `@executable_path/../Frameworks`, so each finds the
//!   module's dylib the bundle ships there.
//!
//! Every build is `--release` with `strip = false` (`verify` reads the
//! symbol tables of Linux binaries and of macOS FIPS cores; `layout` strips
//! the shipped Linux copies), and steps two products share are listed once (two products building one artifact
//! path differently are refused). A product's own flags belong in
//! `target.<triple>.rustflags`, which joins the per-CPU flags: cargo
//! ignores `build.rustflags` once any target flags are set, so
//! [`check_cargo_config`] refuses it.
//!
//! The launchers' and helper's build steps use the target directory
//! `base`; each core's, its build's name. The scripts that carry the plan
//! out rely on it: they add the caller's `SEAWORTHY_RUSTFLAGS` to every
//! build and `SEAWORTHY_CORE_RUSTFLAGS` to each step whose target
//! directory isn't `base` (`docs/packaging.md`, "Extra build flags").
//!
//! The text form ([`render`]) is one step per line, tab-separated:
//!
//! ```text
//! build     <target dir>  <rustflags>  <cargo args>      under the target root
//! copy      <built file>  <artifact path>                target root → artifacts
//! sidecars  <directory>   <pattern>    <artifact dir>    every match, beside the core
//! ```
//!
//! Fields never hold a tab, a newline or (but the cargo arguments and
//! flags, space-separated) a space.

use std::collections::BTreeMap;
use std::path::Path;

use crate::DistError;
use crate::config::{Config, Output};
use crate::inputs::{LINUX, MACOS, Os, WINDOWS, core_file};

/// One step of the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `cargo build --release --target <triple> --target-dir <root>/<target_dir>`
    /// with `rustflags` (as `target.<triple>.rustflags`) and `args`.
    Build {
        /// The target directory's name under the target root.
        target_dir: String,
        /// The flags for this build (`-C target-cpu=<cpu>`; empty for the
        /// launcher and helper).
        rustflags: Vec<String>,
        /// The cargo arguments selecting what's built.
        args: Vec<String>,
    },
    /// A built file (relative to the target root) to its place in the
    /// artifact directory.
    Copy {
        /// The built file, under the target root.
        from: String,
        /// Its path in the artifact directory.
        to: String,
    },
    /// Every file matching `pattern` under `directory` (relative to the
    /// target root) into `to` (relative to the artifact directory); at
    /// least one, and one set of bytes per name.
    Sidecars {
        /// Where the build left them (the core build's `build/` directory).
        directory: String,
        /// The `seaworthy.toml` glob (`aws_lc_fips_*_crypto.dll`).
        pattern: String,
        /// The core's directory in the artifact directory.
        to: String,
    },
}

/// The steps that build every product needing `triple` (or only product
/// `only`); none when no product needs it. The workspace is the current
/// directory's: [`plan_for`] with `Cargo.toml`.
///
/// # Errors
/// As [`plan_for`].
pub fn plan(config: &Config, triple: &str, only: Option<&str>) -> Result<Vec<Step>, DistError> {
    plan_for(config, triple, only, Path::new("Cargo.toml"))
}

/// [`plan`] for the workspace whose manifest is `manifest`, as the builds
/// will name it (build-plan's `--manifest`). `seaworthy.toml`'s crate paths are
/// relative to the workspace root, so a crate's `--manifest-path` is
/// `<manifest's directory>/<crate>/Cargo.toml`: `crates/x/Cargo.toml` for
/// `Cargo.toml`, `templates/t/crates/x/Cargo.toml` for
/// `templates/t/Cargo.toml`.
///
/// # Errors
/// [`DistError::Config`] for a triple seaworthy doesn't package, an unknown
/// product, a `launcher` or `helper-crate` path that isn't a plain relative
/// path, a crate path under a workspace directory the plan's text form
/// can't carry (anything but letters, digits, `.`, `_`, `-` and `/`), or
/// (with `only`) a product that doesn't need the triple.
pub fn plan_for(
    config: &Config,
    triple: &str,
    only: Option<&str>,
    manifest: &Path,
) -> Result<Vec<Step>, DistError> {
    let Some(os) = Os::of_triple(triple) else {
        return Err(DistError::Config(format!(
            "no build plan for {triple:?}: seaworthy packages {LINUX}, {WINDOWS} and {MACOS}"
        )));
    };
    let windows = os == Os::Windows;
    if let Some(id) = only
        && !config.products.contains_key(id)
    {
        return Err(DistError::Config(format!(
            "no product {id:?} in seaworthy.toml"
        )));
    }
    // The workspace root as the builds name it, with its trailing `/` (empty
    // for the current directory). Checked only when a crate path needs it.
    let root: Result<String, String> = {
        let dir = manifest.parent().unwrap_or(Path::new(""));
        match dir.to_str() {
            Some("" | ".") => Ok(String::new()),
            Some(text) if plain_path(text) => Ok(format!("{}/", text.trim_end_matches('/'))),
            _ => Err(format!(
                "the workspace manifest {:?} is in a directory the build plan can't name \
                 (letters, digits, `.`, `_`, `-` and `/` only): seaworthy.toml's crate paths are \
                 relative to it",
                manifest.display()
            )),
        }
    };
    let exe = if windows { ".exe" } else { "" };
    // Windows binaries link the C runtime statically (verify refuses
    // vcruntime imports); joined to each build's own flags.
    let crt: Vec<String> = if windows {
        vec!["-C".to_owned(), "target-feature=+crt-static".to_owned()]
    } else {
        Vec::new()
    };
    // The launcher's and helper's own imports: their directory and System32
    // only (the module docs), never the working directory or PATH.
    let dependent_load: Vec<String> = if windows {
        vec![
            "-C".to_owned(),
            "link-arg=/DEPENDENTLOADFLAG:0xA00".to_owned(),
        ]
    } else {
        Vec::new()
    };
    // macOS builds take the deployment target from seaworthy.toml, forced over
    // any the environment sets (cargo's [env]: rustc, the linker and build
    // scripts all see it). Dotted keys, one per --config: cargo refuses an
    // inline table there.
    let deployment: Vec<String> = if os == Os::Macos {
        vec![
            "--config".to_owned(),
            format!(
                "env.MACOSX_DEPLOYMENT_TARGET.value=\"{}\"",
                config.defaults.macos_minimum
            ),
            "--config".to_owned(),
            "env.MACOSX_DEPLOYMENT_TARGET.force=true".to_owned(),
        ]
    } else {
        Vec::new()
    };
    let cpus = if os == Os::Macos {
        &config.defaults.macos_targets
    } else {
        &config.defaults.targets
    };
    // The CPU whose build's FIPS module library ships beside every core.
    let module_cpu = cpus.first().cloned();
    let mut plan = Plan::default();
    let mut any = false;
    let mut sidecars: Vec<Step> = Vec::new();
    for (id, product) in &config.products {
        if only.is_some_and(|o| o != id)
            || !product
                .outputs
                .iter()
                .any(|o: &Output| o.platform() == os.platform())
        {
            continue;
        }
        any = true;
        // A crate path named in seaworthy.toml: its manifest, so the build
        // enables that crate's features alone.
        let manifest = |key: &str,
                        path: &Option<std::path::PathBuf>|
         -> Result<Vec<String>, DistError> {
            let Some(path) = path else {
                return Ok(Vec::new());
            };
            let text = path.to_str().unwrap_or_default();
            if !plain_relative(text) {
                return Err(DistError::Config(format!(
                    "product.{id}.{key} {:?} must be a relative path of plain segments (no spaces)",
                    path.display()
                )));
            }
            let root = root.clone().map_err(DistError::Config)?;
            Ok(vec![
                "--manifest-path".to_owned(),
                format!("{root}{}/Cargo.toml", text.trim_end_matches('/')),
            ])
        };
        // macOS sidecars: each binary's search path to the bundle's
        // Contents/Frameworks (the module's dylib is loaded as @rpath/…).
        let mac_sidecars = os == Os::Macos && !product.sidecars.macos.is_empty();
        let rpath = |path: &str| -> Vec<String> {
            if mac_sidecars {
                vec!["-C".to_owned(), format!("link-arg=-Wl,-rpath,{path}")]
            } else {
                Vec::new()
            }
        };
        let executable_flags = [
            crt.clone(),
            dependent_load.clone(),
            rpath("@executable_path/../Frameworks"),
        ]
        .concat();
        let core_flags = rpath("@loader_path");
        let programs = product.programs();
        for program in &programs {
            let mut launcher_args = vec!["--bin".to_owned(), program.launcher_bin.clone()];
            launcher_args.extend(manifest("launcher", &program.launcher)?);
            launcher_args.extend(deployment.iter().cloned());
            plan.built(
                Step::Build {
                    target_dir: "base".to_owned(),
                    rustflags: executable_flags.clone(),
                    args: launcher_args,
                },
                format!("base/{triple}/release/{}{exe}", program.launcher_bin),
                format!("{triple}/launcher/{}{exe}", program.executable),
            )?;
        }
        if let Some(helper) = product
            .helper
            .as_ref()
            .filter(|_| product.ships_helper_on(os))
        {
            let mut helper_args = vec!["--bin".to_owned(), helper.clone()];
            helper_args.extend(manifest("helper-crate", &product.helper_crate)?);
            helper_args.extend(deployment.iter().cloned());
            plan.built(
                Step::Build {
                    target_dir: "base".to_owned(),
                    rustflags: executable_flags.clone(),
                    args: helper_args,
                },
                format!("base/{triple}/release/{helper}{exe}"),
                format!("{triple}/helper/{helper}{exe}"),
            )?;
        }
        // The core build whose FIPS module library ships beside every core
        // of the product: its first program's, for the first CPU.
        let module_dir = programs
            .first()
            .zip(module_cpu.as_ref())
            .map(|(program, cpu)| program.build_dir(cpu));
        for program in &programs {
            let core_file = core_file(os, &program.core);
            for cpu in cpus {
                let dir = program.build_dir(cpu);
                plan.built(
                    Step::Build {
                        target_dir: dir.clone(),
                        rustflags: [
                            vec!["-C".to_owned(), format!("target-cpu={cpu}")],
                            crt.clone(),
                            core_flags.clone(),
                        ]
                        .concat(),
                        args: [
                            vec!["-p".to_owned(), program.core.clone()],
                            program.feature_args(),
                            deployment.clone(),
                        ]
                        .concat(),
                    },
                    format!("{dir}/{triple}/release/{core_file}"),
                    format!("{triple}/cores/{dir}/{core_file}"),
                )?;
                if !product.sidecars.for_os(os).is_empty() {
                    let from = module_dir.as_ref().unwrap_or(&dir);
                    for pattern in product.sidecars.for_os(os) {
                        let step = Step::Sidecars {
                            directory: format!("{from}/{triple}/release/build"),
                            pattern: pattern.clone(),
                            to: format!("{triple}/cores/{dir}"),
                        };
                        if !sidecars.contains(&step) {
                            sidecars.push(step);
                        }
                    }
                }
            }
        }
    }
    // The module's library is copied into every CPU directory after EVERY
    // product's cores built: products share the per-CPU target directories
    // (and the artifacts' cores/<cpu>), so a copy made after the first
    // product's core would never see a second product's build, and the
    // copy's one-set-of-bytes-per-name check (scripts/ci/seaworthy-build.ps1)
    // must see them all.
    for step in sidecars {
        plan.add(step);
    }
    let steps = plan.steps;
    if !any && let Some(id) = only {
        return Err(DistError::Config(format!(
            "product {id:?} has no {triple} output"
        )));
    }
    for step in &steps {
        let fields: Vec<&str> = match step {
            Step::Build {
                target_dir,
                rustflags,
                args,
            } => std::iter::once(target_dir.as_str())
                .chain(rustflags.iter().map(String::as_str))
                .chain(args.iter().map(String::as_str))
                .collect(),
            Step::Copy { from, to } => vec![from, to],
            Step::Sidecars {
                directory,
                pattern,
                to,
            } => vec![directory, pattern, to],
        };
        if let Some(bad) = fields
            .iter()
            .find(|f| f.is_empty() || f.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(DistError::Config(format!(
                "a build step's field {bad:?} is empty or holds whitespace"
            )));
        }
    }
    Ok(steps)
}

/// The steps so far, each once, and which build leaves each built file.
#[derive(Default)]
struct Plan {
    steps: Vec<Step>,
    produced: BTreeMap<String, Step>,
}

impl Plan {
    fn add(&mut self, step: Step) {
        if !self.steps.contains(&step) {
            self.steps.push(step);
        }
    }

    /// `build`, then its file `from` copied to `to`. Two products shipping
    /// one artifact path must build it the same way: otherwise the
    /// second's build would overwrite the first's after its copy, and the
    /// shared copy (listed once) would ship the first's.
    fn built(&mut self, build: Step, from: String, to: String) -> Result<(), DistError> {
        match self.produced.get(&from) {
            Some(earlier) if *earlier != build => {
                return Err(DistError::Config(format!(
                    "two products build {from} differently ({earlier:?} and {build:?}): give their binaries different names"
                )));
            }
            Some(_) => {}
            None => {
                self.produced.insert(from.clone(), build.clone());
            }
        }
        self.add(build);
        self.add(Step::Copy { from, to });
        Ok(())
    }
}

/// A relative path of plain segments: no `.`/`..`, no leading `/`, nothing
/// but `[A-Za-z0-9._-]` and `/`.
/// A directory the plan's space-separated text form carries as one word:
/// absolute or relative, `.` and `..` allowed.
fn plain_path(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

fn plain_relative(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('/')
        && text
            .split('/')
            .filter(|s| !s.is_empty())
            .all(|s| s != "." && s != "..")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
}

/// Refuses a product whose cargo configuration sets `build.rustflags`
/// (in `.cargo/config.toml` or `.cargo/config`, beside `manifest` or in a
/// directory above it up to the repository's root, the one holding
/// `.git`; configuration beyond it, and `CARGO_HOME`'s, is the build
/// image's, which must keep `build.rustflags` out — without a `.git` (a
/// source tarball) the walk goes up to `/`, `CARGO_HOME`'s included, which
/// cargo reads too): the per-CPU flags go in as
/// `target.<triple>.rustflags`, and cargo ignores `build.rustflags` once any
/// `target` rustflags are set — the cores would build without the
/// product's flags while the launcher builds with them. Product flags
/// belong in `target.<triple>.rustflags` (or `target.'cfg(…)'.rustflags`),
/// which join the per-CPU flags.
///
/// # Errors
/// [`DistError::Config`] naming the file; [`DistError::Io`] for an
/// unreadable one.
pub fn check_cargo_config(manifest: &Path) -> Result<(), DistError> {
    let absolute = std::path::absolute(manifest).map_err(|e| DistError::io(manifest, e))?;
    let mut dir = absolute.parent();
    while let Some(here) = dir {
        for name in ["config.toml", "config"] {
            let path = here.join(".cargo").join(name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let value: toml::Table = toml::from_str(&text)
                .map_err(|e| DistError::Config(format!("{}: {e}", path.display())))?;
            let sets = value
                .get("build")
                .and_then(|b| b.as_table())
                .is_some_and(|b| b.contains_key("rustflags"));
            if sets {
                return Err(DistError::Config(format!(
                    "{} sets build.rustflags, which cargo ignores for the per-CPU core builds (their flags are target.<triple>.rustflags): move them to target.<triple>.rustflags or target.'cfg(…)'.rustflags, which join the per-CPU flags",
                    path.display()
                )));
            }
        }
        if here.join(".git").exists() {
            break;
        }
        dir = here.parent();
    }
    Ok(())
}

/// The version a crate's `Cargo.toml` declares: its `[package] version`,
/// or, for `version.workspace = true`, the `[workspace.package] version` of
/// the workspace root (the manifest itself when it holds `[workspace]`,
/// else the nearest parent directory's `Cargo.toml` that does). Read as
/// TOML, so comments, multi-line strings and table order can't mislead it
/// (the CI template's `version-file`).
///
/// # Errors
/// [`DistError::Io`] for an unreadable manifest; [`DistError::Config`] for
/// one that isn't TOML, declares no version, or inherits one no workspace
/// root above it provides.
pub fn manifest_version(manifest: &Path) -> Result<String, DistError> {
    let read = |path: &Path| -> Result<toml::Table, DistError> {
        let text = std::fs::read_to_string(path).map_err(|e| DistError::io(path, e))?;
        toml::from_str(&text).map_err(|e| DistError::Config(format!("{}: {e}", path.display())))
    };
    let table = read(manifest)?;
    let declared = table
        .get("package")
        .and_then(|package| package.get("version"))
        .ok_or_else(|| {
            DistError::Config(format!(
                "{} declares no [package] version",
                manifest.display()
            ))
        })?;
    if let Some(version) = declared.as_str() {
        return Ok(version.to_owned());
    }
    let inherited = declared
        .as_table()
        .and_then(|t| t.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    if !inherited {
        return Err(DistError::Config(format!(
            "{}: [package] version is neither a string nor `version.workspace = true`",
            manifest.display()
        )));
    }
    let workspace_version = |root: &toml::Table| {
        root.get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get("version"))
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
    };
    if table.contains_key("workspace") {
        return workspace_version(&table).ok_or_else(|| {
            DistError::Config(format!(
                "{} inherits its version but its [workspace.package] has none",
                manifest.display()
            ))
        });
    }
    let start = manifest
        .canonicalize()
        .map_err(|e| DistError::io(manifest, e))?;
    for dir in start.parent().into_iter().flat_map(Path::ancestors).skip(1) {
        let candidate = dir.join("Cargo.toml");
        if !candidate.is_file() {
            continue;
        }
        let root = read(&candidate)?;
        if root.contains_key("workspace") {
            return workspace_version(&root).ok_or_else(|| {
                DistError::Config(format!(
                    "{} inherits its version but {}'s [workspace.package] has none",
                    manifest.display(),
                    candidate.display()
                ))
            });
        }
    }
    Err(DistError::Config(format!(
        "{} inherits its version but no workspace root above it",
        manifest.display()
    )))
}

/// The plan's text form (the module docs), one step per line.
#[must_use]
pub fn render(steps: &[Step]) -> String {
    let mut out = String::new();
    for step in steps {
        let line = match step {
            Step::Build {
                target_dir,
                rustflags,
                args,
            } => format!(
                "build\t{target_dir}\t{}\t{}",
                if rustflags.is_empty() {
                    "-".to_owned()
                } else {
                    rustflags.join(" ")
                },
                args.join(" ")
            ),
            Step::Copy { from, to } => format!("copy\t{from}\t{to}"),
            Step::Sidecars {
                directory,
                pattern,
                to,
            } => format!("sidecars\t{directory}\t{pattern}\t{to}"),
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::plain_relative;

    #[test]
    fn launcher_paths_are_plain_and_relative() {
        for good in ["crates/launcher", "a/b/c/", "launcher"] {
            assert!(plain_relative(good), "{good}");
        }
        for bad in [
            "", "/abs", "../up", "a/../b", "./a", "a b", "a\tb", "a$b", "a\\b",
        ] {
            assert!(!plain_relative(bad), "{bad:?}");
        }
    }
}
