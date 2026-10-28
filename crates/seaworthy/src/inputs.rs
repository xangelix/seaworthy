//! The built artifacts `seaworthy` packages, and where it finds them.
//!
//! `seaworthy` never compiles. The CI templates (or a developer's build)
//! leave every binary in one **artifact directory**, laid out by target
//! triple:
//!
//! ```text
//! <artifacts>/<triple>/launcher/<executable>[.exe]   each program's launcher (the baseline build)
//! <artifacts>/<triple>/helper/<helper>[.exe]         the update helper, when shipped
//! <artifacts>/<triple>/cores/<build>/<core file>     each program's core, one per CPU target:
//!                                                    lib<core>.so / <core>.dll / lib<core>.dylib
//! <artifacts>/<triple>/cores/<build>/<sidecar>       Windows, macOS: the FIPS module DLL(s) / dylib
//! ```
//!
//! `<build>` is the core build's name ([`crate::config::Program::build_dir`]):
//! the CPU, or `<cpu>.f<8 hex>` for a program whose core builds with its
//! own cargo features.
//!
//! The triples: [`LINUX`], [`WINDOWS`] and, for macOS outputs, [`MACOS`]
//! (Apple Silicon, with `defaults.macos-targets`' CPUs).
//!
//! Linux binaries must keep their symbol tables (build with
//! `strip = false`): `verify` reads them for the FIPS checks, and `layout`
//! strips the shipped copies.

use std::path::{Path, PathBuf};

use crate::config::{Config, Output, Product, Program};

/// The Linux target triple.
pub const LINUX: &str = "x86_64-unknown-linux-gnu";
/// The Windows target triple.
pub const WINDOWS: &str = "x86_64-pc-windows-msvc";
/// The macOS target triple (Apple Silicon).
pub const MACOS: &str = "aarch64-apple-darwin";

/// The operating system a target triple is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// [`LINUX`].
    Linux,
    /// [`WINDOWS`].
    Windows,
    /// [`MACOS`].
    Macos,
}

impl Os {
    /// The target triple.
    #[must_use]
    pub fn triple(self) -> &'static str {
        match self {
            Self::Linux => LINUX,
            Self::Windows => WINDOWS,
            Self::Macos => MACOS,
        }
    }

    /// The OS of a triple seaworthy packages, or `None`.
    #[must_use]
    pub fn of_triple(triple: &str) -> Option<Self> {
        [Self::Linux, Self::Windows, Self::Macos]
            .into_iter()
            .find(|os| os.triple() == triple)
    }

    /// `seaworthy.toml`'s name for the platform.
    #[must_use]
    pub fn platform(self) -> crate::config::Platform {
        match self {
            Self::Linux => crate::config::Platform::Linux,
            Self::Windows => crate::config::Platform::Windows,
            Self::Macos => crate::config::Platform::Macos,
        }
    }
}

/// One program's expected artifacts on one platform.
#[derive(Debug, Clone)]
pub struct ProgramInputs {
    /// The program.
    pub program: Program,
    /// Its launcher.
    pub launcher: PathBuf,
    /// `(cpu, core file, the build's directory)`, in preference order.
    pub cores: Vec<(String, PathBuf, PathBuf)>,
}

/// One platform's expected artifacts for one product.
#[derive(Debug, Clone)]
pub struct PlatformInputs {
    /// The target triple.
    pub triple: &'static str,
    /// Each program's launcher and cores, in `seaworthy.toml`'s order.
    pub programs: Vec<ProgramInputs>,
    /// The update helper, when shipped.
    pub helper: Option<PathBuf>,
}

impl PlatformInputs {
    /// Whether this is the Windows platform.
    #[must_use]
    pub fn is_windows(&self) -> bool {
        self.triple == WINDOWS
    }

    /// The platform's OS.
    #[must_use]
    pub fn os(&self) -> Os {
        Os::of_triple(self.triple).unwrap_or(Os::Linux)
    }

    /// Every program's cores, `(cpu, core file, the build's directory)`,
    /// program by program.
    pub fn cores(&self) -> impl Iterator<Item = &(String, PathBuf, PathBuf)> {
        self.programs.iter().flat_map(|p| p.cores.iter())
    }
}

/// The platforms `product`'s outputs need, with every expected path.
#[must_use]
pub fn expected(config: &Config, product: &Product, artifacts: &Path) -> Vec<PlatformInputs> {
    let mut platforms = Vec::new();
    for os in [Os::Linux, Os::Windows, Os::Macos] {
        if !product
            .outputs
            .iter()
            .any(|o: &Output| o.platform() == os.platform())
        {
            continue;
        }
        let triple = os.triple();
        let windows = os == Os::Windows;
        let root = artifacts.join(triple);
        let exe = |stem: &str| {
            if windows {
                format!("{stem}.exe")
            } else {
                stem.to_owned()
            }
        };
        let cpus = if os == Os::Macos {
            &config.defaults.macos_targets
        } else {
            &config.defaults.targets
        };
        let programs = product
            .programs()
            .into_iter()
            .map(|program| {
                let core_file = core_file(os, &program.core);
                ProgramInputs {
                    launcher: root.join("launcher").join(exe(&program.executable)),
                    cores: cpus
                        .iter()
                        .map(|cpu| {
                            let dir = root.join("cores").join(program.build_dir(cpu));
                            (cpu.clone(), dir.join(&core_file), dir)
                        })
                        .collect(),
                    program,
                }
            })
            .collect();
        platforms.push(PlatformInputs {
            triple,
            programs,
            helper: product
                .ships_helper_on(os)
                .then(|| {
                    product
                        .helper
                        .as_deref()
                        .map(|h| root.join("helper").join(exe(h)))
                })
                .flatten(),
        });
    }
    platforms
}

/// A core's file name as cargo builds it: `lib<core>.so`, `<core>.dll` or
/// `lib<core>.dylib` (`core` is a crate name with no `-`, so the library's
/// name is the crate's as is).
#[must_use]
pub fn core_file(os: Os, core: &str) -> String {
    match os {
        Os::Windows => format!("{core}.dll"),
        Os::Linux => format!("lib{core}.so"),
        Os::Macos => format!("lib{core}.dylib"),
    }
}

/// Matches a file name against a glob whose only wildcard is `*`.
#[must_use]
pub fn glob_matches(glob: &str, name: &str) -> bool {
    let parts: Vec<&str> = glob.split('*').collect();
    let (Some(first), Some(last)) = (parts.first(), parts.last()) else {
        return false;
    };
    if parts.len() == 1 {
        return glob == name;
    }
    if !name.starts_with(first) || name.len() < first.len() + last.len() || !name.ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_star_only() {
        assert!(glob_matches(
            "aws_lc_fips_*_crypto.dll",
            "aws_lc_fips_0_14_3_crypto.dll"
        ));
        assert!(!glob_matches(
            "aws_lc_fips_*_crypto.dll",
            "aws_lc_fips_0_14_3_rust_wrapper.dll"
        ));
        assert!(glob_matches("*.dll", "x.dll"));
        assert!(!glob_matches("*.dll", "x.dl"));
        assert!(glob_matches("exact.dll", "exact.dll"));
        assert!(!glob_matches("exact.dll", "exact.dlll"));
        assert!(glob_matches("a*b*c", "aXXbYYc"));
        assert!(!glob_matches("a*b*c", "aXXcYYb"));
        assert!(!glob_matches("ab*ba", "aba"));
    }
}
