//! pacman's effective configuration, as pacman itself reads it.
//!
//! `pacman.conf` has `Include` directives (often globs), accumulates
//! repeated `SigLevel` lines token by token, and has a compiled-in default
//! signature level that changed between releases. Reimplementing that is a
//! way to disagree with pacman, so the helper and the policy ask
//! `pacman-conf`, which ships with pacman, for the resolved values.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::process;

/// How long `pacman-conf` may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The settings the helper and the policy read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PacmanConf {
    /// `SigLevel`, resolved (pacman-conf prints every flag, defaults
    /// included: `PackageRequired`, `DatabaseOptional`, …).
    pub(crate) sig_level: Vec<String>,
    /// `LocalFileSigLevel`: only the flags set explicitly, which override
    /// `SigLevel`'s for `pacman -U`.
    pub(crate) local_file_sig_level: Vec<String>,
    /// `IgnorePkg` patterns (fnmatch globs), every line and include.
    pub(crate) ignore_pkg: Vec<String>,
    /// `IgnoreGroup` names. The seaworthy CLI's packages belong to no
    /// group, so an ignored group never holds them.
    pub(crate) ignore_group: Vec<String>,
}

impl PacmanConf {
    /// Parses `pacman-conf --verbose` output (`Key = value`, one value per
    /// line).
    pub(crate) fn parse(output: &str) -> Self {
        let mut conf = Self::default();
        for line in output.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim().to_owned();
            match key.trim() {
                "SigLevel" => conf.sig_level.push(value),
                "LocalFileSigLevel" => conf.local_file_sig_level.push(value),
                "IgnorePkg" => conf.ignore_pkg.push(value),
                "IgnoreGroup" => conf.ignore_group.push(value),
                _ => {}
            }
        }
        conf
    }

    /// Whether `pacman -U` requires a signature: the package flag of
    /// `SigLevel`, overridden by `LocalFileSigLevel`'s. Only the Linux
    /// installer asks; the policy reader (every unix) doesn't.
    #[cfg_attr(
        not(all(target_os = "linux", feature = "installers")),
        allow(dead_code, reason = "only the Linux installers ask")
    )]
    pub(crate) fn local_file_signature_required(&self) -> bool {
        let package_level = |flags: &[String]| {
            flags.iter().rev().find_map(|flag| match flag.as_str() {
                "PackageRequired" => Some(true),
                "PackageOptional" | "PackageNever" => Some(false),
                _ => None,
            })
        };
        package_level(&self.local_file_sig_level)
            .or_else(|| package_level(&self.sig_level))
            // pacman-conf always prints SigLevel's package flag; if it
            // somehow didn't, pacman 7's default is Required.
            .unwrap_or(true)
    }

    /// Whether `IgnorePkg` holds `package`.
    pub(crate) fn ignores(&self, package: &str) -> bool {
        self.ignore_pkg
            .iter()
            .any(|pattern| crate::policy::glob_matches(pattern, package))
    }
}

/// Runs `tool` (`pacman-conf`) on `config` (`/etc/pacman.conf`).
///
/// # Errors
/// What went wrong: `pacman-conf` missing, failing (a configuration pacman
/// itself refuses), or not finishing.
pub(crate) fn read(tool: &Path, config: &Path) -> Result<PacmanConf, String> {
    let mut command = Command::new(tool);
    command.arg("--config").arg(config).args([
        "--verbose",
        "SigLevel",
        "LocalFileSigLevel",
        "IgnorePkg",
        "IgnoreGroup",
    ]);
    let finished = process::run(&mut command, "pacman configuration", None, TIMEOUT, 1 << 20)
        .map_err(|e| e.to_string())?;
    if !finished.status.success() {
        return Err(format!(
            "pacman-conf refused {} ({}): {}",
            config.display(),
            finished.status,
            finished.shown()
        ));
    }
    Ok(PacmanConf::parse(&String::from_utf8_lossy(
        &finished.stdout,
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn conf(output: &str) -> PacmanConf {
        PacmanConf::parse(output)
    }

    #[test]
    fn signature_levels_resolve_as_pacman_conf_reports_them() {
        // Arch's shipped configuration, as pacman-conf prints it.
        let arch = conf(
            "SigLevel = PackageRequired\nSigLevel = PackageTrustedOnly\nSigLevel = DatabaseOptional\n\
             SigLevel = DatabaseTrustedOnly\nLocalFileSigLevel = PackageOptional\nLocalFileSigLevel = PackageTrustedOnly\n",
        );
        assert!(!arch.local_file_signature_required());
        // No LocalFileSigLevel: SigLevel's package flag applies.
        let global = conf("SigLevel = PackageRequired\nSigLevel = DatabaseOptional\n");
        assert!(global.local_file_signature_required());
        let optional = conf("SigLevel = PackageOptional\nSigLevel = DatabaseOptional\n");
        assert!(!optional.local_file_signature_required());
        // LocalFileSigLevel overrides in either direction.
        assert!(
            conf("SigLevel = PackageOptional\nLocalFileSigLevel = PackageRequired\n")
                .local_file_signature_required()
        );
        assert!(
            !conf("SigLevel = PackageRequired\nLocalFileSigLevel = PackageNever\n")
                .local_file_signature_required()
        );
        // The last package flag of a list wins (pacman-conf prints the
        // resolved flags; a list naming two keeps the later).
        assert!(
            !conf("SigLevel = PackageRequired\nLocalFileSigLevel = PackageRequired\nLocalFileSigLevel = PackageOptional\n")
                .local_file_signature_required()
        );
        // Nothing printed at all: pacman 7's compiled-in default, Required.
        assert!(conf("").local_file_signature_required());
        // Database flags alone say nothing about packages.
        assert!(
            !conf("SigLevel = PackageOptional\nLocalFileSigLevel = DatabaseRequired\n")
                .local_file_signature_required()
        );
    }

    #[test]
    fn ignored_packages_match_as_globs() {
        let c = conf(
            "SigLevel = PackageRequired\nIgnorePkg = foo\nIgnorePkg = acme-*\nIgnoreGroup = acme-agent\n",
        );
        assert!(c.ignores("acme-agent"));
        assert!(!c.ignores("other"));
        assert!(!conf("IgnoreGroup = acme-agent\n").ignores("acme-agent"));
        assert_eq!(c.ignore_group, ["acme-agent"]);
    }

    /// The real pacman-conf, when installed: includes resolve and repeated
    /// SigLevel lines accumulate.
    #[test]
    fn the_real_pacman_conf_resolves_includes() {
        let tool = Path::new("/usr/bin/pacman-conf");
        if !tool.is_file() {
            assert!(
                !crate::tests_support::tools_required(),
                "/usr/bin/pacman-conf is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1)"
            );
            eprintln!("SKIPPED: /usr/bin/pacman-conf is not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let drop_ins = dir.path().join("pacman.d");
        std::fs::create_dir(&drop_ins).unwrap();
        let included = drop_ins.join("hold.conf");
        std::fs::write(
            &included,
            "IgnorePkg = acme-*\nSigLevel = PackageRequired\n",
        )
        .unwrap();
        let config = dir.path().join("pacman.conf");
        std::fs::write(
            &config,
            format!(
                "[options]\nSigLevel = PackageOptional\nSigLevel = DatabaseOptional\nInclude = {}/*.conf\n",
                drop_ins.display()
            ),
        )
        .unwrap();
        let resolved = read(tool, &config).unwrap();
        assert!(resolved.ignores("acme-agent"), "{resolved:?}");
        assert!(resolved.local_file_signature_required(), "{resolved:?}");
        std::fs::write(&config, "[options]\nSigLevel = Bogus\n").unwrap();
        assert!(read(tool, &config).is_err());
        assert!(read(tool, &dir.path().join("missing.conf")).is_err());
    }
}
