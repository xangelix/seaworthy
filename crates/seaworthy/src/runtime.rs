//! Bundled runtimes (`[[product.<id>.runtime]]`): third-party native code and
//! its data, shipped beside a product's own binaries and pinned file by file.
//!
//! A runtime's files arrive in `<artifacts>/<triple>/runtime/<name>/`, laid
//! out as they install under the runtime's `destination`. Its pin list
//! (`pins`, `sha256sum`'s format) names every file with its SHA-256: `verify`
//! refuses a runtime directory holding anything else, missing anything, or
//! holding other bytes ([`read_pins`] parses the list).

use std::path::Path;

use crate::DistError;

/// The most files one runtime may hold.
pub const MAX_RUNTIME_FILES: usize = 20_000;

/// The largest pin list read (2 MiB).
pub const MAX_PINS_BYTES: u64 = 2 * 1024 * 1024;

/// One pinned file: its path in the runtime and its SHA-256 (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Its path, relative to the runtime directory, `/`-separated.
    pub path: String,
    /// Its SHA-256, 64 lowercase hex characters.
    pub sha256: String,
}

/// A path inside a runtime: relative, `/`-separated segments of printable
/// ASCII (no `\\`, no control characters, no `$`), none of them empty, `.`
/// or `..`, at most 255 bytes.
#[must_use]
pub fn is_runtime_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 255
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|b| (0x20..0x7F).contains(&b) && b != b'\\' && b != b'$')
        })
}

/// Parses a pin list: `<64 lowercase hex>  <path>` per line (`sha256sum`'s
/// text form; ` *<path>`, its binary form, too), blank lines and `#` comments
/// skipped. Every path once, each a [`is_runtime_path`], at most
/// [`MAX_RUNTIME_FILES`] of them, at least one.
///
/// # Errors
/// A message naming the first refused line.
pub fn parse_pins(text: &str) -> Result<Vec<Pin>, String> {
    let mut pins: Vec<Pin> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line_no = n.saturating_add(1);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |why: &str| format!("line {line_no}: {why}");
        let (digest, rest) = line
            .split_at_checked(64)
            .ok_or_else(|| bad("not `<sha256>  <path>`"))?;
        if !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(bad("the digest isn't 64 lowercase hex characters"));
        }
        let path = rest
            .strip_prefix("  ")
            .or_else(|| rest.strip_prefix(" *"))
            .ok_or_else(|| bad("not `<sha256>  <path>` (two spaces, or ` *`)"))?;
        if !is_runtime_path(path) {
            return Err(bad(&format!(
                "{path:?} isn't a path in the runtime (relative, `/`-separated, plain segments of printable ASCII)"
            )));
        }
        if !seen.insert(path.to_owned()) {
            return Err(bad(&format!("{path:?} is pinned twice")));
        }
        if pins.len() >= MAX_RUNTIME_FILES {
            return Err(bad(&format!("more than {MAX_RUNTIME_FILES} files")));
        }
        pins.push(Pin {
            path: path.to_owned(),
            sha256: digest.to_owned(),
        });
    }
    if pins.is_empty() {
        return Err("it pins no file".to_owned());
    }
    // A path can't be both a file and a directory.
    for pin in &pins {
        let mut prefix = String::new();
        for segment in pin.path.split('/') {
            if !prefix.is_empty() && seen.contains(&prefix) {
                return Err(format!(
                    "{prefix:?} is pinned as a file and is the directory of {:?}",
                    pin.path
                ));
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
        }
    }
    Ok(pins)
}

/// Reads `runtime`'s pin list from `dir` (`seaworthy.toml`'s directory): a
/// regular file inside it, at most [`MAX_PINS_BYTES`], that [`parse_pins`]
/// accepts, naming every per-file setting's path.
///
/// # Errors
/// [`DistError::Io`], or [`DistError::Config`] naming the runtime and why.
pub fn read_pins(
    dir: &Path,
    id: &str,
    runtime: &crate::config::Runtime,
) -> Result<Vec<Pin>, DistError> {
    let at = |why: String| {
        DistError::Config(format!(
            "product.{id}.runtime {:?} ({}): pins {}: {why}",
            runtime.name,
            runtime.platform.name(),
            runtime.pins.display()
        ))
    };
    let bytes = crate::layout::read_project_file_limited(dir, &runtime.pins, MAX_PINS_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| at("not UTF-8 text".to_owned()))?;
    let pins = parse_pins(text).map_err(at)?;
    for file in &runtime.files {
        if !pins.iter().any(|pin| pin.path == file.path) {
            return Err(at(format!(
                "pins no {:?}, which runtime.files names",
                file.path
            )));
        }
    }
    Ok(pins)
}

/// The deepest directory a runtime's tree may nest.
pub const MAX_RUNTIME_DEPTH: usize = 16;

/// Every file below a runtime's directory, sorted by path: `(path relative
/// to it, /-separated; the file)`. Nothing is followed: a link, a special
/// file, a name that isn't a [`is_runtime_path`] segment, more than
/// [`MAX_RUNTIME_FILES`] files or [`MAX_RUNTIME_DEPTH`] levels is refused.
///
/// # Errors
/// Why the directory is refused.
pub fn walk(dir: &Path) -> Result<Vec<(String, std::path::PathBuf)>, String> {
    let meta =
        std::fs::symlink_metadata(dir).map_err(|e| format!("the runtime's directory: {e}"))?;
    if !meta.is_dir() {
        return Err("the runtime's directory isn't a directory (a link or a file?)".to_owned());
    }
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), String::new(), 0_usize)];
    while let Some((path, prefix, depth)) = stack.pop() {
        let entries = std::fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .filter(|n| is_runtime_path(n))
                .ok_or_else(|| {
                    format!(
                        "{}: a name a runtime can't hold (plain printable ASCII)",
                        entry.path().display()
                    )
                })?
                .to_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|e| format!("{}: {e}", entry.path().display()))?;
            if kind.is_dir() {
                if depth.saturating_add(1) >= MAX_RUNTIME_DEPTH {
                    return Err(format!(
                        "{}: deeper than {MAX_RUNTIME_DEPTH} levels",
                        entry.path().display()
                    ));
                }
                stack.push((entry.path(), relative, depth.saturating_add(1)));
            } else if kind.is_file() {
                if out.len() >= MAX_RUNTIME_FILES {
                    return Err(format!("more than {MAX_RUNTIME_FILES} files"));
                }
                out.push((relative, entry.path()));
            } else {
                return Err(format!(
                    "{}: a link or a special file (a runtime holds regular files and directories)",
                    entry.path().display()
                ));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// What a runtime file is, by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Image {
    /// An ELF image (`\x7fELF`).
    Elf,
    /// A PE image (`MZ`).
    Pe,
    /// A Mach-O image (thin or universal).
    MachO,
    /// Anything else: data.
    Data,
}

impl Image {
    /// What `bytes` start as.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        match bytes.get(..4) {
            Some([0x7f, b'E', b'L', b'F']) => Self::Elf,
            Some([b'M', b'Z', ..]) => Self::Pe,
            Some([0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe]) => Self::MachO,
            _ => Self::Data,
        }
    }

    /// Whether it is native code (the default mode is then 0755).
    #[must_use]
    pub fn is_code(self) -> bool {
        self != Self::Data
    }
}

/// Resolves one `DT_RUNPATH` entry of a binary that installs in `place`
/// (its directory relative to the install root, `/`-separated, `""` for the
/// root) to a directory relative to the install root: the entry must be
/// `$ORIGIN` (or `${ORIGIN}`), optionally followed by `/` and plain segments,
/// `.` and `..`, never leaving the install root. Anything else (an absolute
/// path, another token, an empty entry) is refused: a bundled library is
/// found only beside the binary that needs it, never wherever the machine's
/// own libraries are.
///
/// # Errors
/// Why the entry is refused.
pub fn resolve_origin(place: &str, entry: &str) -> Result<String, String> {
    let rest = ["$ORIGIN", "${ORIGIN}"]
        .iter()
        .find_map(|origin| {
            let rest = entry.strip_prefix(origin)?;
            (rest.is_empty() || rest.starts_with('/')).then_some(rest)
        })
        .ok_or_else(|| format!("{entry:?} isn't $ORIGIN-relative"))?;
    let mut dirs: Vec<&str> = place.split('/').filter(|s| !s.is_empty()).collect();
    for segment in rest.split('/').filter(|s| !s.is_empty()) {
        match segment {
            "." => {}
            ".." => {
                if dirs.pop().is_none() {
                    return Err(format!("{entry:?} leaves the install root"));
                }
            }
            _ if segment.contains('$') => {
                return Err(format!("{entry:?} names another token ({segment})"));
            }
            _ => dirs.push(segment),
        }
    }
    Ok(dirs.join("/"))
}

/// The directory part of an install path (`lib/libcef.so` → `lib`, a file
/// at the root → `""`).
#[must_use]
pub fn parent_of(install: &str) -> &str {
    install.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The file name part of an install path.
#[must_use]
pub fn name_of(install: &str) -> &str {
    install.rsplit_once('/').map_or(install, |(_, name)| name)
}

/// The runtime `runtime-stage` stages: product `id`'s runtime `name` for
/// the platform of `triple` (Linux or Windows).
///
/// # Errors
/// [`DistError::Config`] for an unknown product, a triple that isn't
/// Linux's or Windows', or a runtime the product doesn't have there.
pub fn find<'a>(
    config: &'a crate::config::Config,
    id: &str,
    name: &str,
    triple: &str,
) -> Result<
    (
        &'a crate::config::Product,
        &'a crate::config::Runtime,
        crate::inputs::Os,
    ),
    DistError,
> {
    use crate::inputs::Os;
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    let os = match Os::of_triple(triple) {
        Some(os @ (Os::Linux | Os::Windows)) => os,
        _ => {
            return Err(DistError::Config(format!(
                "{triple:?}: a bundled runtime ships for {} or {}",
                crate::inputs::LINUX,
                crate::inputs::WINDOWS
            )));
        }
    };
    let runtime = product
        .runtime
        .iter()
        .find(|r| r.name == name && r.platform == os.platform())
        .ok_or_else(|| {
            DistError::Config(format!(
                "product {id} has no runtime {name:?} for {} ([[product.{id}.runtime]])",
                os.platform().name()
            ))
        })?;
    Ok((product, runtime, os))
}

/// What [`stage`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// `<artifacts>/<triple>/runtime/<name>`.
    pub dir: std::path::PathBuf,
    /// How many files it holds.
    pub files: usize,
    /// How many bytes they hold.
    pub bytes: u64,
    /// The core build directories the files were also copied into
    /// (`--beside-cores`).
    pub beside_cores: Vec<std::path::PathBuf>,
}

/// Where a pinned path is in one root.
enum Located {
    /// Not in this root (a later root may hold it).
    Missing,
    /// A regular file, reached through real directories.
    Found(std::path::PathBuf),
    /// Something this root holds at the path that may not be staged (a
    /// link, a special file): refused, never looked past.
    Refused(String),
}

/// Finds `path` (a [`is_runtime_path`]) under `root` without following a
/// link: every directory on the way a real directory, the file a regular
/// one.
fn locate(root: &Path, path: &str) -> Located {
    let mut at = root.to_path_buf();
    let segments: Vec<&str> = path.split('/').collect();
    for (i, segment) in segments.iter().enumerate() {
        at.push(segment);
        let last = i.saturating_add(1) == segments.len();
        match std::fs::symlink_metadata(&at) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Located::Missing,
            Err(e) => return Located::Refused(format!("{}: {e}", at.display())),
            Ok(meta) if meta.file_type().is_symlink() => {
                return Located::Refused(format!(
                    "{}: a link (a runtime is staged from regular files, never through a link)",
                    at.display()
                ));
            }
            Ok(meta) if last && !meta.is_file() => {
                return Located::Refused(format!("{}: not a regular file", at.display()));
            }
            Ok(meta) if !last && !meta.is_dir() => {
                return Located::Refused(format!("{}: not a directory", at.display()));
            }
            Ok(_) => {}
        }
    }
    Located::Found(at)
}

/// Copies `from` (opened without following a link) to the new file `to`,
/// at most `cap` bytes, returning its SHA-256 (hex) and size. The mode is
/// 0755 when the source is executable by its owner, else 0644.
fn copy_hashed(from: &Path, to: &Path, cap: u64) -> Result<(String, u64), String> {
    use std::io::{Read as _, Write as _};
    let mut source =
        crate::layout::open_no_follow(from).map_err(|e| format!("{}: {e}", from.display()))?;
    let meta = source
        .metadata()
        .map_err(|e| format!("{}: {e}", from.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", from.display()));
    }
    if meta.len() > cap {
        return Err(format!(
            "{}: {} bytes, past the runtime's max-file-mib ({} MiB)",
            from.display(),
            meta.len(),
            cap / (1024 * 1024)
        ));
    }
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt as _;
        meta.permissions().mode() & 0o100 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if executable { 0o755 } else { 0o644 });
    }
    let mut out = options
        .open(to)
        .map_err(|e| format!("{}: {e}", to.display()))?;
    let mut hasher = seaworthy_crypto::digest::Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut total: u64 = 0;
    loop {
        let n = source
            .read(&mut buffer)
            .map_err(|e| format!("{}: {e}", from.display()))?;
        if n == 0 {
            break;
        }
        let chunk = buffer.get(..n).unwrap_or_default();
        total = total.saturating_add(n as u64);
        if total > cap {
            return Err(format!(
                "{}: grew past the runtime's max-file-mib while it was copied",
                from.display()
            ));
        }
        hasher.update(chunk);
        out.write_all(chunk)
            .map_err(|e| format!("{}: {e}", to.display()))?;
    }
    out.sync_all()
        .map_err(|e| format!("{}: {e}", to.display()))?;
    Ok((hex::encode(hasher.finish()), total))
}

/// The SHA-256 of a file already in place (a core build directory's), read
/// without following a link; `None` when nothing is there.
fn existing_digest(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read as _;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
        Ok(meta) if !meta.is_file() => {
            return Err(format!(
                "{}: holds something other than a regular file",
                path.display()
            ));
        }
        Ok(_) => {}
    }
    let mut file =
        crate::layout::open_no_follow(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = seaworthy_crypto::digest::Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(buffer.get(..n).unwrap_or_default());
    }
    Ok(Some(hex::encode(hasher.finish())))
}

/// Stages product `id`'s runtime `name` for `triple` from an unpacked
/// distribution (`seaworthy runtime-stage`): each pinned path is taken from
/// the first of `roots` holding it (a regular file reached through real
/// directories; a link there is refused, never followed, and a file no root
/// holds is named), checked against its pinned SHA-256 as it is copied, and
/// lands in `<artifacts>/<triple>/runtime/<name>/<path>`. Files the pins
/// don't name are left behind (a distribution carries more than ships).
/// With `beside_cores` (Windows) every file is also copied into each core
/// build directory the product's build plan fills for the triple
/// (`<artifacts>/<triple>/cores/<build>/`), at its install path relative
/// to the install root, where a core finds it as the installed product's
/// does; a different file already there is refused.
///
/// Every refusal is reported together, and nothing is staged unless all of
/// it can be: the files are copied into a sibling directory renamed into
/// place at the end (an earlier staging of the runtime is replaced).
///
/// # Errors
/// [`DistError::Config`] as [`find`] and [`read_pins`];
/// [`DistError::Verify`] with every refusal; [`DistError::Io`].
pub fn stage(
    config: &crate::config::Config,
    id: &str,
    name: &str,
    triple: &str,
    roots: &[std::path::PathBuf],
    artifacts: &Path,
    beside_cores: bool,
) -> Result<Staged, DistError> {
    use crate::inputs::Os;
    let (product, runtime, os) = find(config, id, name, triple)?;
    if beside_cores && os != Os::Windows {
        return Err(DistError::Config(format!(
            "--beside-cores: a {triple} core finds the runtime's libraries through its search path, not its directory; only a Windows core loads them from beside it"
        )));
    }
    if roots.is_empty() {
        return Err(DistError::Config(
            "no root to stage the runtime from".to_owned(),
        ));
    }
    let pins = read_pins(&config.dir, id, runtime)?;
    let mut findings = Vec::new();
    for root in roots {
        match std::fs::symlink_metadata(root) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => findings.push(format!(
                "{}: a root to stage from is a directory, not a link or a file",
                root.display()
            )),
            Err(e) => findings.push(format!("{}: {e}", root.display())),
        }
    }
    if !findings.is_empty() {
        return Err(DistError::Verify(findings));
    }
    // The core build directories the files also go into.
    let cores = artifacts.join(triple).join("cores");
    let mut core_dirs = Vec::new();
    if beside_cores {
        for program in product.programs() {
            for cpu in config.targets(product, os) {
                let dir = cores.join(program.build_dir(cpu));
                if !core_dirs.contains(&dir) {
                    core_dirs.push(dir);
                }
            }
        }
        for dir in &core_dirs {
            if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
                findings.push(format!(
                    "{}: no core build directory (--beside-cores runs after the build)",
                    dir.display()
                ));
            }
        }
    }
    let runtime_dir = artifacts.join(triple).join("runtime");
    std::fs::create_dir_all(&runtime_dir).map_err(|e| DistError::io(&runtime_dir, e))?;
    let pid = std::process::id();
    let staging = runtime_dir.join(format!(".{name}.staging-{pid}"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| DistError::io(&staging, e))?;
    }
    std::fs::create_dir(&staging).map_err(|e| DistError::io(&staging, e))?;
    let cap = runtime.max_file_bytes();
    let (mut files, mut bytes) = (0_usize, 0_u64);
    for pin in &pins {
        let mut found = None;
        for root in roots {
            match locate(root, &pin.path) {
                Located::Missing => continue,
                Located::Refused(why) => {
                    findings.push(why);
                    found = Some(None);
                    break;
                }
                Located::Found(path) => {
                    found = Some(Some(path));
                    break;
                }
            }
        }
        let source = match found {
            Some(Some(source)) => source,
            Some(None) => continue,
            None => {
                findings.push(format!(
                    "{}: pinned in runtime {name:?}, but in no root ({})",
                    pin.path,
                    roots
                        .iter()
                        .map(|r| r.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
                continue;
            }
        };
        let target = staging.join(&pin.path);
        match copy_hashed(&source, &target, cap) {
            Ok((digest, size)) if digest == pin.sha256 => {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(size);
            }
            Ok((digest, _)) => findings.push(format!(
                "{}: SHA-256 {digest}, but runtime {name:?} pins {} for {} ({})",
                source.display(),
                pin.sha256,
                pin.path,
                runtime.distribution
            )),
            Err(why) => findings.push(why),
        }
        for dir in &core_dirs {
            let beside = dir.join(runtime.install_path(&pin.path));
            match existing_digest(&beside) {
                Ok(Some(digest)) if digest != pin.sha256 => findings.push(format!(
                    "{}: a different file is there already; --beside-cores never overwrites one",
                    beside.display()
                )),
                Ok(_) => {}
                Err(why) => findings.push(why),
            }
        }
    }
    if !findings.is_empty() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(DistError::Verify(findings));
    }
    // Into place: an earlier staging moved aside, then removed.
    let dir = runtime_dir.join(name);
    if std::fs::symlink_metadata(&dir).is_ok() {
        let old = runtime_dir.join(format!(".{name}.old-{pid}"));
        std::fs::rename(&dir, &old).map_err(|e| DistError::io(&dir, e))?;
        std::fs::rename(&staging, &dir).map_err(|e| DistError::io(&staging, e))?;
        std::fs::remove_dir_all(&old).map_err(|e| DistError::io(&old, e))?;
    } else {
        std::fs::rename(&staging, &dir).map_err(|e| DistError::io(&staging, e))?;
    }
    for core_dir in &core_dirs {
        for pin in &pins {
            let beside = core_dir.join(runtime.install_path(&pin.path));
            if existing_digest(&beside)
                .map_err(DistError::Layout)?
                .is_some()
            {
                continue;
            }
            copy_hashed(&dir.join(&pin.path), &beside, cap).map_err(DistError::Layout)?;
        }
    }
    Ok(Staged {
        dir,
        files,
        bytes,
        beside_cores: core_dirs,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const D: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn sha256sum_output_parses() {
        let text = format!("# CEF 154\n\n{D}  libcef.so\n{D} *locales/en-US.pak\n");
        let pins = parse_pins(&text).unwrap();
        assert_eq!(
            pins,
            [
                Pin {
                    path: "libcef.so".into(),
                    sha256: D.into()
                },
                Pin {
                    path: "locales/en-US.pak".into(),
                    sha256: D.into()
                }
            ]
        );
    }

    #[test]
    fn every_bad_line_is_refused_by_number() {
        for (text, mentions) in [
            (String::new(), "pins no file"),
            ("# only a comment\n".to_owned(), "pins no file"),
            (format!("{}  libcef.so\n", &D[1..]), "line 1"),
            (
                format!("{}  libcef.so\n", D.to_uppercase()),
                "lowercase hex",
            ),
            (format!("{D} libcef.so\n"), "two spaces"),
            (format!("{D}\tlibcef.so\n"), "two spaces"),
            (format!("{D}  ../libcef.so\n"), "isn't a path"),
            (format!("{D}  /libcef.so\n"), "isn't a path"),
            (format!("{D}  a//b\n"), "isn't a path"),
            (format!("{D}  a\\b\n"), "isn't a path"),
            (format!("{D}  $HOME\n"), "isn't a path"),
            (format!("{D}  \n"), "isn't a path"),
            (format!("{D}  a\n{D}  a\n"), "line 2: \"a\" is pinned twice"),
            (
                format!("{D}  a\n{D}  a/b\n"),
                "pinned as a file and is the directory",
            ),
            (format!("{D}  é\n"), "isn't a path"),
        ] {
            let err = parse_pins(&text).expect_err(&text);
            assert!(err.contains(mentions), "{text:?}: {err}");
        }
    }

    #[test]
    fn origin_entries_resolve_inside_the_install_root_only() {
        assert_eq!(resolve_origin("lib", "$ORIGIN").unwrap(), "lib");
        assert_eq!(resolve_origin("lib", "${ORIGIN}").unwrap(), "lib");
        assert_eq!(resolve_origin("lib", "$ORIGIN/").unwrap(), "lib");
        assert_eq!(resolve_origin("", "$ORIGIN/lib").unwrap(), "lib");
        assert_eq!(
            resolve_origin("lib", "$ORIGIN/../lib/./cef").unwrap(),
            "lib/cef"
        );
        assert_eq!(resolve_origin("libexec", "$ORIGIN/..").unwrap(), "");
        for (place, bad) in [
            ("lib", "/usr/lib"),
            ("lib", "/opt/acme/lib"),
            ("lib", ""),
            ("lib", "$ORIGINAL"),
            ("lib", "$LIB"),
            ("lib", "$ORIGIN/$PLATFORM"),
            ("lib", "$ORIGIN/../.."),
            ("", "$ORIGIN/.."),
            ("lib", "lib"),
            ("lib", "./lib"),
        ] {
            assert!(resolve_origin(place, bad).is_err(), "{place:?} {bad:?}");
        }
    }

    #[test]
    fn images_are_told_by_their_magic() {
        assert_eq!(Image::of(b"\x7fELF\x02"), Image::Elf);
        assert_eq!(Image::of(b"MZ\x90\x00"), Image::Pe);
        assert_eq!(Image::of(&[0xcf, 0xfa, 0xed, 0xfe]), Image::MachO);
        assert_eq!(Image::of(&[0xca, 0xfe, 0xba, 0xbe]), Image::MachO);
        assert_eq!(Image::of(b"{\"file_format_version\""), Image::Data);
        assert_eq!(Image::of(b""), Image::Data);
        assert_eq!(parent_of("lib/locales/en-US.pak"), "lib/locales");
        assert_eq!(parent_of("chrome-sandbox"), "");
        assert_eq!(name_of("lib/libcef.so"), "libcef.so");
    }

    #[test]
    fn runtime_paths_are_plain() {
        assert!(is_runtime_path("locales/en-US.pak"));
        assert!(is_runtime_path("chrome-sandbox"));
        for bad in [
            "",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "/a",
            "a/",
            "a\\b",
            "a\u{7f}",
            &"x".repeat(256),
        ] {
            assert!(!is_runtime_path(bad), "{bad:?}");
        }
    }
}
