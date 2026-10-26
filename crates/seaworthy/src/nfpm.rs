//! The deb, rpm and pacman packages: one nFPM configuration per format,
//! generated from a [`LinuxPackage`], and nFPM run on each. The tool is
//! `$NFPM`, else `nfpm` on `PATH`. CI installs the pinned release with
//! `scripts/ci/install-nfpm.sh`; the build is reproducible only with that
//! release.
//!
//! One configuration per format, because each spells the release version
//! its own way: deb `1.4.0~rc.2-812`, rpm `1.4.0~rc.2` with
//! release `812`, pacman `1.4.0rc.2` with pkgrel `812`. pacman has no `~`.
//! The configurations are JSON, which nFPM reads as YAML, and they set
//! `version_schema: none`, so nFPM takes each version as given.
//!
//! What every package carries is [`crate::linux`]'s: the install tree
//! (root-owned, mode 0755), the units, the `sysusers.d` file and the
//! preset, plus [`crate::scripts`]' scripts. Reproducibility: every file,
//! directory and generated control file carries one timestamp (the
//! caller's `SOURCE_DATE_EPOCH`), the rpm build host is fixed
//! (`seaworthy`), and the inputs are sorted. With the pinned nFPM the same
//! inputs give the same package, byte for byte (`tests/package.rs`).
//!
//! Compression: xz for deb and rpm, which every supported dpkg and rpm
//! reads (zstd needs dpkg 1.21.18 and rpm 4.14); pacman packages are zstd,
//! as nFPM writes them.
//!
//! A package with systemd units depends on `systemd` (rpm also with
//! `Requires(post)`), so a one-transaction image build installs systemd
//! before the package's scripts look for `systemctl`. A package shipping
//! the update helper depends on `ca-certificates` (the package's name on
//! every supported family): the helper's TLS client loads the system's CA
//! store before any request, so on a minimal host without one every
//! update run would fail. A desktop app shipping its helper's unit depends
//! on `systemd` too, and on polkit (`polkitd | policykit-1` for deb,
//! `polkit` for rpm and pacman), which reads the rule letting the session
//! start it.
//!
//! nFPM expands `$VAR` and `${VAR}` in several metadata fields (description,
//! maintainer, vendor, homepage, dependencies) with no escape, so
//! `seaworthy.toml` refuses `$` in every text that reaches it
//! (`config::is_plain_text`): a build's environment can neither leak into
//! nor change a package.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::DistError;
use crate::archive::rfc3339;
use crate::config::{Config, Output};
use crate::linux::{LinuxPackage, Source};
use crate::version::PackageVersions;

/// The nFPM release CI pins (`scripts/ci/install-nfpm.sh`).
pub const PINNED_VERSION: &str = "2.47.0";

/// The rpm build host every package records, instead of the machine's
/// name.
pub const BUILD_HOST: &str = "seaworthy";

/// nFPM's name for a format (`--packager`).
fn packager(format: Output) -> Option<&'static str> {
    match format {
        Output::Deb => Some("deb"),
        Output::Rpm => Some("rpm"),
        Output::Pacman => Some("archlinux"),
        Output::Msi | Output::Zip | Output::Tar | Output::Dmg | Output::Pkg => None,
    }
}

/// What a package's contents run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86-64: deb `amd64`, rpm and pacman `x86_64` (every product).
    X86_64,
    /// Nothing architecture-specific: deb `all`, rpm `noarch`, pacman
    /// `any` (the repository package).
    Independent,
}

impl Arch {
    /// nFPM's name for it (`arch:`), which it translates per format.
    fn nfpm(self) -> &'static str {
        match self {
            Self::X86_64 => "amd64",
            Self::Independent => "all",
        }
    }

    /// Its name in `format`'s file names and metadata.
    #[must_use]
    pub fn name(self, format: Output) -> &'static str {
        match (self, format) {
            (Self::X86_64, Output::Deb) => "amd64",
            (Self::X86_64, _) => "x86_64",
            (Self::Independent, Output::Deb) => "all",
            (Self::Independent, Output::Rpm) => "noarch",
            (Self::Independent, _) => "any",
        }
    }
}

/// The package file name, by each ecosystem's convention:
/// `<name>_<version>_<arch>.deb`, `<name>-<version>-<release>.<arch>.rpm`,
/// `<name>-<pkgver>-<pkgrel>-<arch>.pkg.tar.zst` (`amd64`/`x86_64` for a
/// product, `all`/`noarch`/`any` for an [`Arch::Independent`] package).
///
/// # Errors
/// [`DistError::Config`] for a format that isn't a Linux package.
pub fn file_name(
    name: &str,
    format: Output,
    v: &PackageVersions,
    arch: Arch,
) -> Result<String, DistError> {
    let a = arch.name(format);
    match format {
        Output::Deb => Ok(format!("{name}_{}_{a}.deb", v.deb)),
        Output::Rpm => Ok(format!(
            "{name}-{}-{}.{a}.rpm",
            v.rpm_version, v.rpm_release
        )),
        Output::Pacman => Ok(format!(
            "{name}-{}-{}-{a}.pkg.tar.zst",
            v.pacman_pkgver, v.pacman_pkgrel
        )),
        Output::Msi | Output::Zip | Output::Tar | Output::Dmg | Output::Pkg => Err(
            DistError::Config(format!("{format:?} is not a Linux package format")),
        ),
    }
}

/// The version fields of `format`: (`version`, `release`).
fn version_fields(format: Output, v: &PackageVersions) -> (&str, &str) {
    match format {
        // nFPM writes a deb's Version as `<version>-<release>`; the
        // upstream part is rpm's (the semver, `-` → `~`).
        Output::Deb | Output::Rpm => (&v.rpm_version, &v.rpm_release),
        _ => (&v.pacman_pkgver, &v.pacman_pkgrel),
    }
}

/// Writes `format`'s nFPM configuration for product `id` under `work`
/// (generated files and scripts beside it) and returns its path.
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Config`] for an unknown product or a
/// format that isn't a Linux package.
pub fn write_config(
    config: &Config,
    id: &str,
    package: &LinuxPackage,
    format: Output,
    versions: &PackageVersions,
    mtime: u64,
    work: &Path,
) -> Result<PathBuf, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    let name = packager(format)
        .ok_or_else(|| DistError::Config(format!("{format:?} is not a Linux package format")))?;
    let dir = work.join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| DistError::io(&dir, e))?;
    }
    let files_dir = dir.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| DistError::io(&files_dir, e))?;
    let write =
        |path: &Path, text: &str| std::fs::write(path, text).map_err(|e| DistError::io(path, e));
    let time = rfc3339(mtime);
    let info = |mode: u32| json!({"mode": mode, "owner": "root", "group": "root", "mtime": time});

    let mut contents = Vec::new();
    for directory in &package.directories {
        contents.push(json!({"dst": directory, "type": "dir", "file_info": info(0o755)}));
    }
    for (n, file) in package.files.iter().enumerate() {
        let src = match &file.source {
            Source::Staged(path) => path.clone(),
            Source::Generated(text) => {
                let base = Path::new(&file.dst)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned());
                let path = files_dir.join(format!("{n:03}-{}", base.unwrap_or_default()));
                write(&path, text)?;
                path
            }
        };
        let src = src
            .to_str()
            .ok_or_else(|| DistError::Layout(format!("{} is not valid UTF-8", src.display())))?
            .to_owned();
        contents.push(json!({"src": src, "dst": file.dst, "file_info": info(file.mode)}));
    }
    for link in &package.links {
        contents.push(json!({"src": link.target, "dst": link.dst, "type": "symlink"}));
    }

    let (version, release) = version_fields(format, versions);
    let d = &config.defaults;
    let mut depends = match format {
        Output::Deb => product.linux.depends.deb.clone(),
        Output::Rpm => product.linux.depends.rpm.clone(),
        _ => product.linux.depends.pacman.clone(),
    };
    // A package with units needs systemd, and its scripts need `systemctl`
    // when they run: in a one-transaction image build the dependency
    // orders systemd first (rpm: `Requires(post)` as well).
    let has_units = !package.units.enabled().is_empty() || package.units.update_service.is_some();
    if has_units && !depends.iter().any(|d| d == "systemd") {
        depends.push("systemd".to_owned());
    }
    // A desktop app's helper is started through its polkit rule: without
    // polkit nothing may start it. Debian's and Ubuntu's daemon is
    // `polkitd` (`policykit-1` before Debian 12).
    if package
        .files
        .iter()
        .any(|f| f.dst.starts_with(crate::linux::POLKIT_RULES_DIR))
    {
        let polkit = match format {
            Output::Deb => "polkitd | policykit-1",
            _ => "polkit",
        };
        if !depends.iter().any(|d| d.starts_with("polkit")) {
            depends.push(polkit.to_owned());
        }
    }
    // The helper's TLS client needs the system's CA store.
    if package.units.update_service.is_some()
        && !depends.iter().any(|d| d.starts_with("ca-certificates"))
    {
        depends.push("ca-certificates".to_owned());
    }
    // A desktop product's icons belong under the hicolor theme's
    // directories, which its package owns: deb and rpm recommend it (a weak
    // dependency: installed when the host's repositories carry it, never
    // failing an install from a mirror without it).
    let recommends: Vec<&str> = if format != Output::Pacman
        && package
            .files
            .iter()
            .any(|f| f.dst.starts_with("/usr/share/icons/hicolor/"))
    {
        vec!["hicolor-icon-theme"]
    } else {
        Vec::new()
    };
    let mut archlinux = json!({"packager": d.maintainer});
    let mut scripts_json = None;
    if let Some(scripts) = crate::scripts::scripts(format, &package.name, &package.units) {
        let scripts_dir = dir.join("scripts");
        std::fs::create_dir_all(&scripts_dir).map_err(|e| DistError::io(&scripts_dir, e))?;
        let path_of = |phase: &str, text: &str| -> Result<String, DistError> {
            let path = scripts_dir.join(format!("{phase}.sh"));
            write(&path, text)?;
            set_executable(&path)?;
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| DistError::Layout(format!("{} is not valid UTF-8", path.display())))
        };
        scripts_json = Some(json!({
            "preinstall": path_of("preinstall", &scripts.pre_install)?,
            "postinstall": path_of("postinstall", &scripts.post_install)?,
            "preremove": path_of("preremove", &scripts.pre_remove)?,
            "postremove": path_of("postremove", &scripts.post_remove)?,
        }));
        if let (Some(pre), Some(post)) = (&scripts.pre_upgrade, &scripts.post_upgrade) {
            archlinux = json!({
                "packager": d.maintainer,
                "scripts": {
                    "preupgrade": path_of("preupgrade", pre)?,
                    "postupgrade": path_of("postupgrade", post)?,
                },
            });
        }
    }
    let mut nfpm = json!({
        "name": package.name,
        "arch": Arch::X86_64.nfpm(),
        "platform": "linux",
        "version": version,
        "version_schema": "none",
        "release": release,
        "section": "misc",
        "priority": "optional",
        "maintainer": d.maintainer,
        "description": product.description,
        "vendor": d.vendor,
        "license": d.license,
        "mtime": time,
        "umask": 0o022,
        "disable_globbing": true,
        "depends": depends,
        "contents": contents,
        "deb": {"compression": "xz"},
        "rpm": {
            "requires": {"post": if has_units { vec!["systemd"] } else { vec![] }},
            "compression": "xz",
            "buildhost": BUILD_HOST,
            "summary": product.description,
            "packager": d.maintainer,
        },
        "archlinux": archlinux,
    });
    if !recommends.is_empty() {
        nfpm["recommends"] = json!(recommends);
    }
    // The packages this product supersedes (`linux.replaces`): nFPM's
    // `conflicts` and `replaces` (rpm: `Obsoletes:`), so the package
    // manager removes them on install rather than refusing the files both
    // own.
    if !product.linux.replaces.is_empty() {
        nfpm["conflicts"] = json!(product.linux.replaces);
        nfpm["replaces"] = json!(product.linux.replaces);
    }
    if let Some(object) = nfpm.as_object_mut() {
        if let Some(homepage) = &d.homepage {
            object.insert("homepage".to_owned(), Value::String(homepage.clone()));
        }
        if let Some(scripts) = scripts_json {
            object.insert("scripts".to_owned(), scripts);
        }
    }
    let path = dir.join("nfpm.json");
    let text = serde_json::to_string_pretty(&canonical(nfpm))
        .map_err(|e| DistError::Layout(e.to_string()))?;
    write(&path, &format!("{text}\n"))?;
    Ok(path)
}

/// Writes `format`'s nFPM configuration for the repository package
/// ([`crate::repository_package`]) under `work` and returns its path:
/// architecture-independent, no dependencies, no scripts, its definition a
/// configuration file (deb conffile, rpm `%config(noreplace)`).
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Config`] for a format that isn't a
/// Linux package.
pub fn write_repository_config(
    config: &Config,
    contents: &crate::repository_package::Contents,
    format: Output,
    versions: &PackageVersions,
    mtime: u64,
    work: &Path,
) -> Result<PathBuf, DistError> {
    let name = packager(format)
        .ok_or_else(|| DistError::Config(format!("{format:?} is not a Linux package format")))?;
    let dir = work.join(name);
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| DistError::io(&dir, e))?;
    }
    let files_dir = dir.join("files");
    std::fs::create_dir_all(&files_dir).map_err(|e| DistError::io(&files_dir, e))?;
    let write =
        |path: &Path, text: &str| std::fs::write(path, text).map_err(|e| DistError::io(path, e));
    let time = rfc3339(mtime);
    let mut entries = Vec::new();
    for (n, file) in contents.package.files.iter().enumerate() {
        let Source::Generated(text) = &file.source else {
            return Err(DistError::Layout(format!(
                "the repository package's {} isn't generated",
                file.dst
            )));
        };
        let base = Path::new(&file.dst)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let path = files_dir.join(format!("{n:03}-{base}"));
        write(&path, text)?;
        let src = path
            .to_str()
            .ok_or_else(|| DistError::Layout(format!("{} is not valid UTF-8", path.display())))?
            .to_owned();
        let mut entry = json!({
            "src": src,
            "dst": file.dst,
            "file_info": {"mode": file.mode, "owner": "root", "group": "root", "mtime": time},
        });
        if contents.config_files.contains(&file.dst)
            && let Some(object) = entry.as_object_mut()
        {
            object.insert(
                "type".to_owned(),
                Value::String("config|noreplace".to_owned()),
            );
        }
        entries.push(entry);
    }
    let (version, release) = version_fields(format, versions);
    let d = &config.defaults;
    let mut nfpm = json!({
        "name": contents.package.name,
        "arch": Arch::Independent.nfpm(),
        "platform": "linux",
        "version": version,
        "version_schema": "none",
        "release": release,
        "section": "misc",
        "priority": "optional",
        "maintainer": d.maintainer,
        "description": contents.description,
        "vendor": d.vendor,
        "license": d.license,
        "mtime": time,
        "umask": 0o022,
        "disable_globbing": true,
        "contents": entries,
        "deb": {"compression": "xz"},
        "rpm": {
            "compression": "xz",
            "buildhost": BUILD_HOST,
            "summary": contents.description,
            "packager": d.maintainer,
        },
    });
    if let (Some(object), Some(homepage)) = (nfpm.as_object_mut(), &d.homepage) {
        object.insert("homepage".to_owned(), Value::String(homepage.clone()));
    }
    let path = dir.join("nfpm.json");
    let text = serde_json::to_string_pretty(&canonical(nfpm))
        .map_err(|e| DistError::Layout(e.to_string()))?;
    write(&path, &format!("{text}\n"))?;
    Ok(path)
}

/// `value` with every object's keys sorted. `serde_json` keeps insertion
/// order when any crate in the build enables its `preserve_order` feature
/// (Cargo unifies features across a workspace), so without this the
/// configuration's bytes would depend on what else was compiled.
fn canonical(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k, canonical(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
        other => other,
    }
}

fn set_executable(path: &Path) -> Result<(), DistError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| DistError::io(path, e))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// The version `tool` reports (`GitVersion:` in `nfpm --version`).
///
/// # Errors
/// [`DistError::Tool`] when it can't run or reports no version.
pub fn tool_version(tool: &Path) -> Result<String, DistError> {
    let output = Command::new(tool).arg("--version").output().map_err(|e| {
        DistError::Tool(format!(
            "cannot run {} (nFPM {PINNED_VERSION}: scripts/ci/install-nfpm.sh installs it; set NFPM to its path): {e}",
            tool.display()
        ))
    })?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("GitVersion:"))
        .map(|v| v.trim().to_owned())
        .ok_or_else(|| {
            DistError::Tool(format!(
                "{} --version reports no GitVersion",
                tool.display()
            ))
        })
}

/// Runs nFPM on `config` for `format`, writing `target`.
///
/// # Errors
/// [`DistError::Tool`] when nFPM can't run, fails, or writes no file.
pub fn run(tool: &Path, config: &Path, format: Output, target: &Path) -> Result<(), DistError> {
    let packager = packager(format)
        .ok_or_else(|| DistError::Config(format!("{format:?} is not a Linux package format")))?;
    if target.exists() {
        std::fs::remove_file(target).map_err(|e| DistError::io(target, e))?;
    }
    let output = Command::new(tool)
        .arg("package")
        .arg("--config")
        .arg(config)
        .arg("--packager")
        .arg(packager)
        .arg("--target")
        .arg(target)
        .env("NO_COLOR", "1")
        .output()
        .map_err(|e| DistError::Tool(format!("cannot run {}: {e}", tool.display())))?;
    if !output.status.success() || !target.is_file() {
        return Err(DistError::Tool(format!(
            "nfpm package --packager {packager} failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
