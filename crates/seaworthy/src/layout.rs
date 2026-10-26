//! Step 3 of the pipeline: lay out each platform's install tree from
//! verified artifacts.
//!
//! | | Linux | Windows | macOS |
//! | --- | --- | --- | --- |
//! | Root | `/opt/<vendor>/<product>` (lowercase) | `%ProgramFiles%\<Vendor>\<Directory>` | `/Applications/<Display Name>.app` |
//! | Launcher | `<executable>` | `<executable>.exe` | `Contents/MacOS/<executable>` |
//! | Cores | `lib/lib<core>_<cpu>.so` | `<core>_<cpu>.dll` | `Contents/Frameworks/lib<core>_<cpu>.dylib` |
//! | Sidecars | — | beside the cores, one copy | — |
//! | Helper | `libexec/<vendor>-<product>-update` | `<helper>.exe` | — |
//! | Data files (`[[files]]`) | `<destination>`, mode 0644 | `<destination>` | `Contents/Resources/<destination>` |
//! | Icons | `[desktop]`: `/usr/share/icons/hicolor/<size>/apps/<app-id>.<ext>` | `[desktop]`: `tree/<Vendor>/<Directory>.ico`, for the MSI only | `[macos] icon`: `Contents/Resources/<file>.icns` |
//!
//! On macOS a bundle keeps executable code in `Contents/MacOS` and
//! `Contents/Frameworks`, and everything else in `Contents/Resources` (code
//! signing seals them so; a data file beside the executable breaks the
//! signature). `package` writes the bundle's `Info.plist`, with the
//! release's version, and signs the bundle (`crate::macos`).
//!
//! Each tree is staged under `<out>/<product>/<triple>/tree/` exactly as
//! it installs (Linux: `tree/opt/<vendor>/<product>/…`; Windows:
//! `tree/<Vendor>/<Directory>/…`; macOS: `tree/<Display Name>.app/…`), every
//! file mode 0755. Linux binaries are
//! stripped with `strip --strip-all` (`$STRIP` overrides the tool), and
//! each stripped copy's record is read back, so stripping can never cost a
//! core its `.cpureq`. `layout.json` beside the tree lists every file with
//! its install path, role, mode and SHA-256: the input to packaging, and an
//! audit record.
//!
//! Data files and icons are read once, from `seaworthy.toml`'s directory:
//! a regular file (not a link, nothing outside that directory), at most
//! [`MAX_DATA_FILE`] bytes, and never executable code (ELF, PE, Mach-O):
//! code ships as the launcher, a core, a sidecar or the helper, the files
//! `verify` checks. A Linux icon must be a square PNG of a hicolor size, or
//! an SVG; the Windows icon an ICO. They install outside the install root,
//! so they're listed apart from [`Layout::files`] (the tarball and the zip
//! carry only those).
//!
//! An existing staging directory is replaced only if it carries the
//! marker file `layout` writes. `seaworthy` never deletes a directory it
//! didn't create.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::DistError;
use crate::config::{Config, ExtraFiles, HICOLOR_SIZES, Platform};
use crate::inputs::Os;
use crate::verify::Verified;

/// The marker file in every staging directory `layout` owns.
pub const MARKER: &str = ".seaworthy-layout";

/// The largest data file or icon: 256 MiB.
pub const MAX_DATA_FILE: u64 = 256 * 1024 * 1024;

/// The most files one `[[files]]` directory may hold.
pub const MAX_DATA_FILES: usize = 10_000;

/// The most data files a product's tree may hold, all `[[files]]` entries
/// together (the archives are built in memory; a zip holds 65,535 entries).
pub const MAX_PRODUCT_DATA_FILES: usize = 20_000;

/// The most data bytes a product's tree may hold (an MSI's embedded cabinet
/// stops at 2 GB).
pub const MAX_PRODUCT_DATA_BYTES: u64 = 2 * 1024 * 1024 * 1024 - 64 * 1024 * 1024;

/// Windows' path limit (`MAX_PATH`, 260 with the terminator), which Windows
/// Installer and Explorer's zip extraction keep to: an install path past it
/// fails on the customer's machine.
const MAX_WINDOWS_PATH: usize = 259;

/// The install root's parent on a default Windows install.
const PROGRAM_FILES: &str = "C:\\Program Files\\";

/// File types Windows runs or interprets when opened, or that change how a
/// program beside them loads: refused among a product's data files on
/// Windows (they'd ship unsigned beside the signed binaries, past script
/// rules like AppLocker's). Web assets (`.js`, `.html`) stay allowed.
const WINDOWS_ACTIVE_EXTENSIONS: [&str; 25] = [
    "exe", "dll", "sys", "ocx", "cpl", "scr", "com", "pif", "msi", "msp", "mst", "msix", "appx",
    "ps1", "psm1", "psd1", "bat", "cmd", "vbs", "vbe", "wsf", "wsh", "hta", "lnk", "url",
];

/// More names Windows acts on: Explorer's folder settings and autorun, an
/// application's side-by-side manifest or redirection beside its `.exe`
/// or `.dll`.
const WINDOWS_ACTIVE_NAMES: [&str; 2] = ["desktop.ini", "autorun.inf"];
const WINDOWS_ACTIVE_SUFFIXES: [&str; 8] = [
    ".exe.manifest",
    ".exe.local",
    ".exe.config",
    ".dll.manifest",
    ".dll.config",
    ".scf",
    ".reg",
    ".jar",
];

/// What a file is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Role {
    /// The launcher.
    Launcher,
    /// The core for one CPU target.
    Core {
        /// The CPU name.
        cpu: String,
    },
    /// A sidecar shipped beside the cores.
    Sidecar,
    /// The update helper.
    Helper,
    /// A data file (`[[product.<id>.files]]`): mode 0644, never stripped,
    /// stamped or signed.
    Asset,
    /// An icon (`[product.<id>.desktop]`): a Linux hicolor icon, or the
    /// Windows icon the MSI's Icon table holds; on macOS the bundle's
    /// `.icns` (`[product.<id>.macos]`).
    Icon,
    /// A macOS bundle's `Contents/Info.plist` (`package` writes it).
    BundleInfo,
    /// A macOS bundle's signature seal,
    /// `Contents/_CodeSignature/CodeResources` (`codesign` writes it).
    CodeSignature,
    /// A macOS service's uninstaller, `Contents/Resources/uninstall`
    /// (`package` writes it for a pkg).
    Uninstaller,
}

/// One file in a laid-out tree.
#[derive(Debug, Clone, Serialize)]
pub struct File {
    /// Where it installs: an absolute path on Linux, a path relative to
    /// `%ProgramFiles%` on Windows (backslash-separated).
    pub install_path: String,
    /// Its staged copy.
    pub staged: PathBuf,
    /// What it is.
    pub role: Role,
    /// Its Unix mode.
    pub mode: u32,
    /// SHA-256 of the staged (shipped) bytes, hex.
    pub sha256: String,
}

/// One platform's laid-out tree.
#[derive(Debug, Clone, Serialize)]
pub struct Layout {
    /// The product id.
    pub product: String,
    /// The target triple.
    pub triple: String,
    /// The install root (`/opt/acme/collector`, or
    /// `Acme\Collector` under `%ProgramFiles%`).
    pub install_root: String,
    /// The staging tree (`<out>/<product>/<triple>/tree`).
    pub tree: PathBuf,
    /// Every file under the install root, launcher first, data files last.
    pub files: Vec<File>,
    /// Files a Linux package installs outside the install root for the
    /// desktop (the hicolor icons), staged in the tree at their install
    /// path.
    pub desktop_files: Vec<File>,
    /// Windows: the application icon, staged as `tree/<Vendor>/<Directory>.ico`
    /// (its `install_path`, the MSI's `!(bindpath.tree)` reference) for the
    /// MSI's Icon table; never installed as a file.
    pub icon: Option<File>,
}

impl Layout {
    /// The launcher's install path.
    #[must_use]
    pub fn launcher(&self) -> Option<&File> {
        self.files.iter().find(|f| f.role == Role::Launcher)
    }

    /// The helper's install path, when shipped.
    #[must_use]
    pub fn helper(&self) -> Option<&File> {
        self.files.iter().find(|f| f.role == Role::Helper)
    }
}

/// Layout options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Strip Linux binaries (the shipped default). Off only for debugging.
    pub strip: bool,
    /// The strip tool (default `strip`, from binutils; the CLI honours
    /// `$STRIP`). It is run as `<tool> --strip-all <file>`.
    pub strip_tool: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            strip: true,
            strip_tool: PathBuf::from("strip"),
        }
    }
}

/// One file in `layout.json`: paths relative to the manifest's own
/// directory, so the manifest stays valid when the output directory moves.
#[derive(Serialize)]
struct ManifestFile<'a> {
    install_path: &'a str,
    path: String,
    role: &'a Role,
    mode: u32,
    sha256: &'a str,
}

/// `layout.json`.
#[derive(Serialize)]
struct Manifest<'a> {
    product: &'a str,
    triple: &'a str,
    install_root: &'a str,
    tree: &'static str,
    files: Vec<ManifestFile<'a>>,
}

/// Lays out product `id`'s verified artifacts under `out`.
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Layout`] for artifacts verified for
/// another product, an existing directory without the marker, two files
/// landing on one install path (case-insensitively on Windows), a file
/// that changed since `verify` read it, or a stripped binary whose record
/// no longer reads; [`DistError::Tool`] when the strip tool is missing or
/// fails.
pub fn layout(
    config: &Config,
    id: &str,
    verified: &Verified,
    out: &Path,
    options: Options,
) -> Result<Vec<Layout>, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    if verified.product() != id {
        return Err(DistError::Layout(format!(
            "these artifacts were verified for product {:?}, not {id:?}",
            verified.product()
        )));
    }
    let vendor_lower = config.defaults.vendor.to_ascii_lowercase();
    let mut layouts = Vec::new();
    for platform in verified.platforms() {
        let triple = platform.inputs.triple;
        let os = platform.inputs.os();
        let windows = os == Os::Windows;
        let macos = os == Os::Macos;
        let base = out.join(id).join(triple);
        prepare(&base)?;
        let tree = base.join("tree");
        let (install_root, staged_root) = if macos {
            let bundle = crate::macos::bundle_name(product);
            (format!("/Applications/{bundle}"), tree.join(&bundle))
        } else if windows {
            let root = format!(
                "{}\\{}",
                config.defaults.vendor,
                product.windows_directory()
            );
            let staged = tree
                .join(&config.defaults.vendor)
                .join(product.windows_directory());
            (root, staged)
        } else {
            let root = format!("/opt/{vendor_lower}/{id}");
            let staged = tree.join("opt").join(&vendor_lower).join(id);
            (root, staged)
        };
        let join_install = |relative: &str| {
            if windows {
                format!("{install_root}\\{}", relative.replace('/', "\\"))
            } else {
                format!("{install_root}/{relative}")
            }
        };
        let mut files = Vec::new();
        // Every install path taken, by a file or as a directory (case-folded
        // on Windows and macOS, whose file systems are case-insensitive by
        // default): a file and a directory of one name can't coexist.
        let mut claimed: BTreeSet<String> = BTreeSet::new();
        let mut claimed_dirs: BTreeSet<String> = BTreeSet::new();
        let fold = |path: &str| {
            if windows || macos {
                path.to_ascii_lowercase()
            } else {
                path.to_owned()
            }
        };
        let (mut data_files, mut data_bytes) = (0_usize, 0_u64);
        let mut place = |source: &Path, relative: &str, role: Role| -> Result<(), DistError> {
            let install_path = join_install(relative);
            if windows && PROGRAM_FILES.len() + install_path.len() > MAX_WINDOWS_PATH {
                return Err(DistError::Layout(format!(
                    "{install_path} (from {}): {} characters under {PROGRAM_FILES}, past Windows' {MAX_WINDOWS_PATH}-character path limit, where Windows Installer and Explorer fail",
                    source.display(),
                    PROGRAM_FILES.len() + install_path.len()
                )));
            }
            let key = fold(&install_path);
            if claimed_dirs.contains(&key) {
                return Err(DistError::Layout(format!(
                    "{install_path} (from {}) would install as both a file and a directory",
                    source.display()
                )));
            }
            if !claimed.insert(key) {
                return Err(DistError::Layout(format!(
                    "two files would install as {install_path} (from {})",
                    source.display()
                )));
            }
            let parts: Vec<&str> = relative.split('/').collect();
            for depth in 1..parts.len() {
                let directory = fold(&join_install(&parts[..depth].join("/")));
                if claimed.contains(&directory) {
                    return Err(DistError::Layout(format!(
                        "{} (from {}) would install as both a file and a directory",
                        join_install(&parts[..depth].join("/")),
                        source.display()
                    )));
                }
                claimed_dirs.insert(directory);
            }
            let staged = staged_root.join(relative);
            if let Some(parent) = staged.parent() {
                std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
            }
            if role == Role::Asset {
                if windows {
                    refuse_windows_active(source, relative)?;
                }
                // Read once, checked as data, written as read.
                let bytes = read_data(source)?;
                data_files += 1;
                data_bytes += bytes.len() as u64;
                if data_files > MAX_PRODUCT_DATA_FILES || data_bytes > MAX_PRODUCT_DATA_BYTES {
                    return Err(DistError::Layout(format!(
                        "{}: past what a product's data files may add up to ({MAX_PRODUCT_DATA_FILES} files, {MAX_PRODUCT_DATA_BYTES} bytes)",
                        source.display()
                    )));
                }
                write_data(&staged, &bytes)?;
                files.push(File {
                    install_path,
                    staged,
                    role,
                    mode: 0o644,
                    sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
                });
                return Ok(());
            }
            std::fs::copy(source, &staged).map_err(|e| DistError::io(source, e))?;
            set_mode(&staged, 0o755)?;
            // The copy must be the file verify read, byte for byte.
            let copied = std::fs::read(&staged).map_err(|e| DistError::io(&staged, e))?;
            if verified.digest(source)
                != Some(seaworthy_crypto::digest::sha256_hex(&copied).as_str())
            {
                return Err(DistError::Layout(format!(
                    "{} changed since verify read it; run verify again",
                    source.display()
                )));
            }
            let is_elf = os == Os::Linux && role != Role::Sidecar;
            if is_elf && options.strip {
                strip(&options.strip_tool, &staged)?;
                recheck_record(&staged, &role, "stripped")?;
            }
            let bytes = std::fs::read(&staged).map_err(|e| DistError::io(&staged, e))?;
            files.push(File {
                install_path,
                staged,
                role,
                mode: 0o755,
                sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
            });
            Ok(())
        };
        let exe = |stem: &str| {
            if windows {
                format!("{stem}.exe")
            } else {
                stem.to_owned()
            }
        };
        let launcher = if macos {
            format!("Contents/MacOS/{}", product.executable)
        } else {
            exe(&product.executable)
        };
        place(&platform.inputs.launcher, &launcher, Role::Launcher)?;
        for (cpu, core, _) in &platform.inputs.cores {
            let relative = match os {
                Os::Windows => format!("{}_{cpu}.dll", product.core),
                Os::Linux => format!("lib/lib{}_{cpu}.so", product.core),
                Os::Macos => format!("Contents/Frameworks/lib{}_{cpu}.dylib", product.core),
            };
            place(core, &relative, Role::Core { cpu: cpu.clone() })?;
        }
        for sidecar in &platform.sidecars {
            let name = sidecar
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    DistError::Layout(format!("{} has no file name", sidecar.display()))
                })?;
            let relative = if macos {
                format!("Contents/Frameworks/{name}")
            } else {
                name
            };
            place(sidecar, &relative, Role::Sidecar)?;
        }
        if let Some(helper) = &platform.inputs.helper {
            let relative = match os {
                Os::Windows => exe(product.helper.as_deref().unwrap_or("update")),
                Os::Linux => format!("libexec/{vendor_lower}-{id}-update"),
                Os::Macos => format!(
                    "Contents/MacOS/{}",
                    product.helper.as_deref().unwrap_or("update")
                ),
            };
            place(helper, &relative, Role::Helper)?;
        }
        let platform_kind: Platform = os.platform();
        for extra in product
            .files
            .iter()
            .filter(|f| f.platforms.contains(&platform_kind))
        {
            for (source, relative) in data_sources(&config.dir, extra)? {
                let relative = if macos {
                    format!("Contents/Resources/{relative}")
                } else {
                    relative
                };
                place(&source, &relative, Role::Asset)?;
            }
        }
        if macos && let Some(path) = product.macos.as_ref().and_then(|m| m.icon.as_ref()) {
            let source = inside(&config.dir, path)?;
            let bytes = read_data(&source)?;
            if bytes.get(..4) != Some(b"icns".as_slice()) {
                return Err(DistError::Layout(format!(
                    "{}: not an ICNS file (macos.icon)",
                    source.display()
                )));
            }
            let relative = format!("Contents/Resources/{}", crate::macos::ICON_FILE);
            let install_path = join_install(&relative);
            if files
                .iter()
                .any(|f: &File| fold(&f.install_path) == fold(&install_path))
            {
                return Err(DistError::Layout(format!(
                    "a data file would install as {install_path}, the bundle's icon (macos.icon)"
                )));
            }
            let staged = staged_root.join(&relative);
            write_data(&staged, &bytes)?;
            files.push(File {
                install_path,
                staged,
                role: Role::Icon,
                mode: 0o644,
                sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
            });
        }
        let mut desktop_files = Vec::new();
        let mut icon = None;
        if let Some(desktop) = product.desktop.as_ref().filter(|_| !macos) {
            if windows {
                if let Some(path) = &desktop.windows_icon {
                    let source = inside(&config.dir, path)?;
                    let bytes = read_data(&source)?;
                    if !is_ico(&bytes) {
                        return Err(DistError::Layout(format!(
                            "{}: not an ICO file (desktop.windows-icon)",
                            source.display()
                        )));
                    }
                    let name = format!("{}.ico", product.windows_directory());
                    let staged = tree.join(&config.defaults.vendor).join(&name);
                    write_data(&staged, &bytes)?;
                    icon = Some(File {
                        install_path: format!("{}\\{name}", config.defaults.vendor),
                        staged,
                        role: Role::Icon,
                        mode: 0o644,
                        sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
                    });
                }
            } else {
                let app_id = desktop.app_id(config, id);
                let mut sizes = BTreeSet::new();
                for path in &desktop.linux_icons {
                    let source = inside(&config.dir, path)?;
                    let bytes = read_data(&source)?;
                    let extension = crate::config::extension_of(path);
                    let size_dir = if extension == "svg" {
                        if !is_svg(&bytes) {
                            return Err(DistError::Layout(format!(
                                "{}: not an SVG image (desktop.linux-icons)",
                                source.display()
                            )));
                        }
                        "scalable".to_owned()
                    } else {
                        let size = png_size(&bytes)
                            .filter(|(w, h)| w == h && HICOLOR_SIZES.contains(w))
                            .map(|(w, _)| w)
                            .ok_or_else(|| {
                                DistError::Layout(format!(
                                    "{}: a Linux icon is a square PNG of a hicolor size ({})",
                                    source.display(),
                                    HICOLOR_SIZES.map(|s| s.to_string()).join(", ")
                                ))
                            })?;
                        if !sizes.insert(size) {
                            return Err(DistError::Layout(format!(
                                "{}: a second {size}x{size} icon (desktop.linux-icons: one per size)",
                                source.display()
                            )));
                        }
                        format!("{size}x{size}")
                    };
                    let install_path =
                        format!("/usr/share/icons/hicolor/{size_dir}/apps/{app_id}.{extension}");
                    let staged = tree.join(install_path.trim_start_matches('/'));
                    write_data(&staged, &bytes)?;
                    desktop_files.push(File {
                        install_path,
                        staged,
                        role: Role::Icon,
                        mode: 0o644,
                        sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
                    });
                }
            }
        }
        let layout = Layout {
            product: id.to_owned(),
            triple: triple.to_owned(),
            install_root,
            tree,
            files,
            desktop_files,
            icon,
        };
        write_manifest(&layout)?;
        layouts.push(layout);
    }
    Ok(layouts)
}

/// Writes `layout.json` beside the layout's tree: every file with its
/// install path, path relative to the manifest, role, mode and SHA-256. The
/// packaging step rewrites it after stamping and signing change the files,
/// so it always describes the shipped bytes.
///
/// # Errors
/// [`DistError::Io`], or [`DistError::Layout`] when the tree has no parent.
pub(crate) fn write_manifest(layout: &Layout) -> Result<(), DistError> {
    let base = layout
        .tree
        .parent()
        .ok_or_else(|| DistError::Layout(format!("{} has no parent", layout.tree.display())))?;
    let manifest = Manifest {
        product: &layout.product,
        triple: &layout.triple,
        install_root: &layout.install_root,
        tree: "tree",
        files: layout
            .files
            .iter()
            .chain(&layout.desktop_files)
            .chain(&layout.icon)
            .map(|f| ManifestFile {
                install_path: &f.install_path,
                path: f
                    .staged
                    .strip_prefix(&layout.tree)
                    .unwrap_or(&f.staged)
                    .to_string_lossy()
                    .replace('\\', "/"),
                role: &f.role,
                mode: f.mode,
                sha256: &f.sha256,
            })
            .collect(),
    };
    let text =
        serde_json::to_string_pretty(&manifest).map_err(|e| DistError::Layout(e.to_string()))?;
    let path = base.join("layout.json");
    std::fs::write(&path, text).map_err(|e| DistError::io(&path, e))
}

/// Makes `base` an empty staging directory owned by `layout`.
pub(crate) fn prepare(base: &Path) -> Result<(), DistError> {
    if base.exists() {
        if !base.join(MARKER).is_file() {
            return Err(DistError::Layout(format!(
                "{} exists and was not created by seaworthy layout (no {MARKER}); remove it or choose another --out",
                base.display()
            )));
        }
        std::fs::remove_dir_all(base).map_err(|e| DistError::io(base, e))?;
    }
    std::fs::create_dir_all(base).map_err(|e| DistError::io(base, e))?;
    let marker = base.join(MARKER);
    std::fs::write(
        &marker,
        "seaworthy layout staging directory; safe to delete\n",
    )
    .map_err(|e| DistError::io(&marker, e))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), DistError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| DistError::io(path, e))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// `<tool> --strip-all` on a staged copy.
fn strip(tool: &Path, path: &Path) -> Result<(), DistError> {
    let output = crate::process::tool(tool)
        .arg("--strip-all")
        .arg(path)
        .output()
        .map_err(|e| {
            DistError::Tool(format!(
                "cannot run {} (binutils; set STRIP to override): {e}",
                tool.display()
            ))
        })?;
    if !output.status.success() {
        return Err(DistError::Tool(format!(
            "{} --strip-all {} failed: {}",
            tool.display(),
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// After stripping, stamping or signing (`when`): the launcher's
/// `.cpulist` and a core's `.cpureq` must still read.
pub(crate) fn recheck_record(path: &Path, role: &Role, when: &str) -> Result<(), DistError> {
    let result = match role {
        Role::Launcher => seaworthy_levels::read_cpu_list(path).map(|_| ()),
        Role::Core { .. } => seaworthy_levels::read_requirement(path).map(|_| ()),
        Role::Sidecar
        | Role::Helper
        | Role::Asset
        | Role::Icon
        | Role::BundleInfo
        | Role::CodeSignature
        | Role::Uninstaller => Ok(()),
    };
    result.map_err(|e| {
        DistError::Layout(format!(
            "{} lost its record when {when}: {e}",
            path.display()
        ))
    })
}

/// `relative` under `seaworthy.toml`'s directory, as its canonical path (no
/// link left on the way, so every later open names the file checked here):
/// refused when it resolves outside that directory (a link on the way;
/// `config` already refused `..`) or is itself a link.
fn inside(dir: &Path, relative: &Path) -> Result<PathBuf, DistError> {
    let base = base_dir(dir);
    let path = base.join(relative);
    let root = std::fs::canonicalize(base).map_err(|e| DistError::io(base, e))?;
    let resolved = std::fs::canonicalize(&path).map_err(|e| DistError::io(&path, e))?;
    if !resolved.starts_with(&root) {
        return Err(DistError::Layout(format!(
            "{}: resolves outside seaworthy.toml's directory ({})",
            path.display(),
            root.display()
        )));
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|e| DistError::io(&path, e))?;
    if meta.file_type().is_symlink() {
        return Err(DistError::Layout(format!(
            "{}: a link (data files and icons are regular files and directories)",
            path.display()
        )));
    }
    Ok(resolved)
}

/// A file `seaworthy.toml` names (`relative`, already checked for `..`):
/// read once, a regular file inside `seaworthy.toml`'s directory and no
/// link, as data files and icons are read.
///
/// # Errors
/// As data files: [`DistError::Layout`] for a link, a file outside the
/// directory, a special file, a file past the size limit or one carrying
/// executable code; [`DistError::Io`].
pub(crate) fn read_project_file(dir: &Path, relative: &Path) -> Result<Vec<u8>, DistError> {
    read_data(&inside(dir, relative)?)
}

/// `seaworthy.toml`'s directory (`.` for a config parsed from text).
fn base_dir(dir: &Path) -> &Path {
    if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }
}

/// Every file one `[[files]]` entry installs, with its path relative to the
/// install root: the file itself, or every regular file below the
/// directory, sorted (deterministic packages). The source must resolve
/// inside `seaworthy.toml`'s directory and hold no links or special files.
fn data_sources(dir: &Path, extra: &ExtraFiles) -> Result<Vec<(PathBuf, String)>, DistError> {
    let source = inside(dir, &extra.source)?;
    let meta = std::fs::symlink_metadata(&source).map_err(|e| DistError::io(&source, e))?;
    let destination = extra.destination();
    let mut out = Vec::new();
    if meta.is_file() {
        out.push((source, destination));
    } else if meta.is_dir() {
        walk_data(&source, &destination, extra.hidden, &mut out)?;
        if out.is_empty() {
            return Err(DistError::Layout(format!(
                "{}: an empty directory ([[files]] source)",
                source.display()
            )));
        }
    } else {
        return Err(DistError::Layout(format!(
            "{}: not a regular file or a directory (a link or a special file)",
            source.display()
        )));
    }
    Ok(out)
}

fn walk_data(
    dir: &Path,
    relative: &str,
    hidden: bool,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), DistError> {
    let mut entries = std::fs::read_dir(dir)
        .map_err(|e| DistError::io(dir, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DistError::io(dir, e))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            DistError::Layout(format!("{}: a file name that isn't UTF-8", path.display()))
        })?;
        if crate::config::VCS_DIRECTORIES.contains(&name) {
            return Err(DistError::Layout(format!(
                "{}: version control data never ships (a .git/config can hold a CI token)",
                path.display()
            )));
        }
        if name.starts_with('.') && !hidden {
            return Err(DistError::Layout(format!(
                "{}: a hidden file; set `hidden = true` on its [[files]] entry to ship hidden files",
                path.display()
            )));
        }
        let below = format!("{relative}/{name}");
        if !crate::config::is_install_relative(&below) {
            return Err(DistError::Layout(format!(
                "{}: installs as {below:?}, a name both platforms don't accept (printable ASCII; no `$`, `!(`, `\\`, `<>:\"|?*`, device names, short-name aliases like `X~1`, or names starting with a space or ending in a space or a dot; at most 200 bytes)",
                path.display()
            )));
        }
        let kind = entry.file_type().map_err(|e| DistError::io(&path, e))?;
        if kind.is_dir() {
            walk_data(&path, &below, hidden, out)?;
        } else if kind.is_file() {
            out.push((path, below));
            if out.len() > MAX_DATA_FILES {
                return Err(DistError::Layout(format!(
                    "{}: more than {MAX_DATA_FILES} files under one [[files]] source",
                    dir.display()
                )));
            }
        } else {
            return Err(DistError::Layout(format!(
                "{}: a link or a special file ([[files]] ship regular files only)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// A data file's or icon's bytes: a regular file (not a link), at most
/// [`MAX_DATA_FILE`] bytes, carrying no executable code. Opened without
/// following a link at its last component and without blocking (a FIFO
/// swapped in is refused, not waited on); its type and size come from the
/// open file, and the read stops past the limit.
fn read_data(path: &Path) -> Result<Vec<u8>, DistError> {
    use std::io::Read as _;
    let not_regular = || {
        DistError::Layout(format!(
            "{}: not a regular file (a link or a special file)",
            path.display()
        ))
    };
    let file = match open_no_follow(path) {
        Ok(file) => file,
        Err(e) => {
            let link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
            return Err(if link {
                not_regular()
            } else {
                DistError::io(path, e)
            });
        }
    };
    let meta = file.metadata().map_err(|e| DistError::io(path, e))?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    let too_big = |len: u64| {
        DistError::Layout(format!(
            "{}: {len} bytes or more, past what a data file may have ({MAX_DATA_FILE})",
            path.display()
        ))
    };
    if meta.len() > MAX_DATA_FILE {
        return Err(too_big(meta.len()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_DATA_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| DistError::io(path, e))?;
    if bytes.len() as u64 > MAX_DATA_FILE {
        return Err(too_big(bytes.len() as u64));
    }
    if let Some(kind) = code_kind(&bytes) {
        return Err(DistError::Layout(format!(
            "{}: executable code ({kind}); data files carry none — ship code as the launcher, a core, a sidecar or the helper, the files `verify` checks",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("a link"));
    }
    std::fs::File::open(path)
}

/// A data file Windows would act on (an active extension, `desktop.ini`,
/// an application manifest or redirection beside a binary): refused on
/// Windows.
fn refuse_windows_active(source: &Path, relative: &str) -> Result<(), DistError> {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or(relative)
        .to_ascii_lowercase();
    let extension = name.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    if WINDOWS_ACTIVE_EXTENSIONS.contains(&extension)
        || WINDOWS_ACTIVE_NAMES.contains(&name.as_str())
        || WINDOWS_ACTIVE_SUFFIXES.iter().any(|s| name.ends_with(s))
    {
        return Err(DistError::Layout(format!(
            "{} (installing as {relative}): a file Windows runs or acts on when it's opened or beside a program; data files on Windows carry none (a script, a shortcut, an installer, a manifest or redirection beside a binary, desktop.ini)",
            source.display()
        )));
    }
    Ok(())
}

fn write_data(path: &Path, bytes: &[u8]) -> Result<(), DistError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
    }
    std::fs::write(path, bytes).map_err(|e| DistError::io(path, e))?;
    set_mode(path, 0o644)
}

/// What kind of executable code `bytes` is, if any: an ELF or PE image
/// (parsed), or a Mach-O image or universal binary (by its magic number;
/// a Java class file shares the universal one's, and is code too).
fn code_kind(bytes: &[u8]) -> Option<&'static str> {
    match object::FileKind::parse(bytes) {
        Ok(object::FileKind::Elf32 | object::FileKind::Elf64) => return Some("an ELF image"),
        Ok(object::FileKind::Pe32 | object::FileKind::Pe64) => return Some("a PE image"),
        _ => {}
    }
    let magic = bytes.get(..4)?;
    match magic {
        [0xFE, 0xED, 0xFA, 0xCE | 0xCF] | [0xCE | 0xCF, 0xFA, 0xED, 0xFE] => Some("a Mach-O image"),
        [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => {
            Some("a Mach-O universal binary or a Java class file")
        }
        _ => None,
    }
}

/// A PNG's width and height, from its IHDR chunk.
fn png_size(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.get(..8)? != SIGNATURE || bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    let field = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    Some((field(16)?, field(20)?))
}

/// An SVG: UTF-8 text with an `<svg` element.
fn is_svg(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| text.contains("<svg"))
}

/// An ICO: the icon-resource header (reserved 0, type 1) and its image
/// directory.
fn is_ico(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..6) else {
        return false;
    };
    let count = usize::from(u16::from_le_bytes([header[4], header[5]]));
    header[..4] == [0, 0, 1, 0] && count > 0 && bytes.len() >= 6 + 16 * count
}
