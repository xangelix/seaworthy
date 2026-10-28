//! What a Linux package carries: the laid-out install tree plus the files
//! the OS needs to run it, rendered by `seaworthy_service::render` from the
//! product's service:
//!
//! - `/usr/lib/systemd/system/<service>.service`: the service unit;
//! - `/usr/lib/systemd/system/<service>-update.path` and `.service`: the
//!   update helper's trigger and oneshot, when the helper ships (the
//!   request file lives in the service's `state-directory`; the helper
//!   stages under `/var/cache/<vendor>/<product>`);
//! - `/usr/lib/sysusers.d/<service>.conf`: the sandbox user, when there
//!   is one;
//! - `/usr/lib/systemd/system-preset/80-<package>.preset`: the vendor
//!   preset enabling those units (`crate::scripts` explains the policy).
//!
//! Units go to `/usr/lib` (the vendor location), leaving `/etc` to
//! administrators.
//!
//! A desktop product whose helper ships carries instead:
//!
//! - `/usr/lib/systemd/system/<package>-update.service`: the helper's root
//!   oneshot, the same unit and hardening as a service's helper, with no path
//!   unit, no `[Install]` section and no preset: nothing starts it but the
//!   logged-in user's session;
//! - `/usr/share/polkit-1/rules.d/60-<package>-update.rules`: the rule
//!   letting an active, local session start exactly that unit and nothing
//!   else (the Windows interactive-users grant's twin; the app asks with
//!   `systemctl start`, `seaworthy_updater::request_update`).
//!
//! Its package scripts only reload systemd after an install or upgrade and
//! stop the helper before removal; they never start it. A tool's helper
//! ships as a binary only: no unit, no start right.
//!
//! A desktop product with `[product.<id>.desktop]` also carries its
//! menu entry, `/usr/share/applications/<app-id>.desktop` ([`desktop_entry`],
//! Desktop Entry Specification 1.5, starting the `gui` program), and its
//! hicolor icons; each program's command (`linux.command`, or a
//! `[[programs]]` entry's) adds `/usr/bin/<command>`, a link to its
//! launcher. Its file types (`[[product.<id>.file-types]]`) add the
//! menu entry's `MimeType` and `Exec` (the default verb), the owned types'
//! shared-mime-info package ([`mime_info`]) and document icons, and a KDE
//! service menu for each other verb ([`service_menus`]). Those directories
//! belong to the system (the icon theme, the menu, the MIME database), so
//! the package owns only its files there; the distributions' triggers
//! refresh the menu, the MIME database and the icon cache.
//!
//! The package owns `/opt/<vendor>` and every directory below it that
//! holds its files, so removal leaves nothing behind (rpm removes only
//! directories a package owns; another product of the same vendor shares
//! `/opt/<vendor>`, which every format allows).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use seaworthy_service::render::systemd::{self, Scope};

use crate::DistError;
use crate::config::{Config, Desktop, Kind, Product};
use crate::layout::Layout;
use crate::scripts::Units;

/// Where a packaged file's bytes come from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A staged file from the layout.
    Staged(PathBuf),
    /// Text generated here (a unit, a `sysusers.d` entry).
    Generated(String),
}

/// One file in a Linux package.
#[derive(Debug, Clone)]
pub struct PackagedFile {
    /// Its absolute install path.
    pub dst: String,
    /// Its mode.
    pub mode: u32,
    /// Its bytes.
    pub source: Source,
}

/// A symbolic link in a Linux package.
#[derive(Debug, Clone)]
pub struct PackagedLink {
    /// Where the link is (absolute).
    pub dst: String,
    /// What it points to (absolute).
    pub target: String,
}

/// Everything a Linux package of one product carries.
#[derive(Debug, Clone)]
pub struct LinuxPackage {
    /// The package name (`<vendor>-<product>`, lowercase).
    pub name: String,
    /// The directories the package owns, parents first.
    pub directories: Vec<String>,
    /// Every file, the tree first.
    pub files: Vec<PackagedFile>,
    /// Its symbolic links (`/usr/bin/<command>`, one per program put on
    /// `PATH`).
    pub links: Vec<PackagedLink>,
    /// What the package scripts manage.
    pub units: Units,
}

/// Where vendor polkit rules live: polkit reads them beside
/// administrators' (`/etc/polkit-1/rules.d`), all in file-name order.
pub const POLKIT_RULES_DIR: &str = "/usr/share/polkit-1/rules.d";

/// A desktop product's polkit rule, `60-<helper>.rules`: after an
/// administrator's usual low-numbered overrides (the first rule to answer
/// wins), so a site rule can always refuse what this one allows.
#[must_use]
pub fn polkit_rule_path(helper: &str) -> String {
    format!("{POLKIT_RULES_DIR}/60-{helper}.rules")
}

/// The package name every Linux format uses: `<vendor>-<product>`,
/// lowercase (`acme-collector`).
#[must_use]
pub fn package_name(config: &Config, id: &str) -> String {
    format!("{}-{id}", config.defaults.vendor.to_ascii_lowercase())
}

/// The Linux package contents for product `id`, from its laid-out tree.
///
/// # Errors
/// [`DistError::Config`] for a service the renderers refuse (validation
/// already ran at load, so this is defense in depth), or a layout without
/// a launcher.
pub fn linux_package(
    config: &Config,
    id: &str,
    layout: &Layout,
) -> Result<LinuxPackage, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    let mut files: Vec<PackagedFile> = layout
        .files
        .iter()
        .map(|f| PackagedFile {
            dst: f.install_path.clone(),
            mode: f.mode,
            source: Source::Staged(f.staged.clone()),
        })
        .collect();
    files.extend(layout.desktop_files.iter().map(|f| PackagedFile {
        dst: f.install_path.clone(),
        mode: f.mode,
        source: Source::Staged(f.staged.clone()),
    }));
    let launcher_path = |executable: &str| {
        layout
            .launcher_of(executable)
            .map(|l| l.install_path.clone())
            .ok_or_else(|| {
                DistError::Layout(format!(
                    "product {id}'s Linux tree has no launcher {executable}"
                ))
            })
    };
    if let (Some(desktop), Some(gui)) = (&product.desktop, product.gui_program()) {
        let app_id = desktop.app_id(config, id);
        let icon = layout
            .desktop_files
            .iter()
            .any(|f| f.role == crate::layout::Role::Icon)
            .then_some(app_id.as_str());
        let launcher = launcher_path(&gui.executable)?;
        files.push(PackagedFile {
            dst: format!("/usr/share/applications/{app_id}.desktop"),
            mode: 0o644,
            source: Source::Generated(desktop_entry(product, desktop, &launcher, icon)),
        });
        if let Some(xml) = mime_info(product) {
            files.push(PackagedFile {
                dst: format!("{MIME_PACKAGES_DIR}/{app_id}.xml"),
                mode: 0o644,
                source: Source::Generated(xml),
            });
        }
        for (verb, text) in service_menus(product, &launcher, icon) {
            files.push(PackagedFile {
                dst: format!("{SERVICE_MENUS_DIR}/{app_id}-{verb}.desktop"),
                mode: 0o644,
                source: Source::Generated(text),
            });
        }
    }
    let mut links = Vec::new();
    for program in product.programs() {
        if let Some(command) = &program.linux_command {
            links.push(PackagedLink {
                dst: format!("/usr/bin/{command}"),
                target: launcher_path(&program.executable)?,
            });
        }
    }
    let mut units = Units::default();
    if product.service.is_some() {
        let launcher = layout.launcher().ok_or_else(|| {
            DistError::Layout(format!("product {id}'s Linux tree has no launcher"))
        })?;
        let spec = config.service_spec(id, product, Path::new(&launcher.install_path))?;
        let render = |e: seaworthy_service::ServiceError| {
            DistError::Config(format!("product.{id}.service: {e}"))
        };
        let unit = systemd::unit(&spec, Scope::System).map_err(render)?;
        let name = systemd::unit_file_name(&spec).map_err(render)?;
        files.push(PackagedFile {
            dst: format!("/usr/lib/systemd/system/{name}"),
            mode: 0o644,
            source: Source::Generated(unit),
        });
        units.service = Some(name);
        if let Some(helper) = layout.helper() {
            let cache = config.update_product(id, product)?.cache_directory();
            let path_unit = systemd::update_path_unit(&spec).map_err(render)?;
            let service_unit =
                systemd::update_service_unit(&spec, Path::new(&helper.install_path), &cache)
                    .map_err(render)?;
            let path_name = format!("{}-update.path", spec.name);
            files.push(PackagedFile {
                dst: format!("/usr/lib/systemd/system/{path_name}"),
                mode: 0o644,
                source: Source::Generated(path_unit),
            });
            let service_name = format!("{}-update.service", spec.name);
            files.push(PackagedFile {
                dst: format!("/usr/lib/systemd/system/{service_name}"),
                mode: 0o644,
                source: Source::Generated(service_unit),
            });
            units.update_path = Some(path_name);
            units.update_service = Some(service_name);
        } else {
            // An earlier version may have shipped the helper: stop and
            // disable its trigger when upgrading to (or downgrading to) one
            // without it.
            units.retired.push(format!("{}-update.path", spec.name));
        }
        if let Some(text) = systemd::sysusers(&spec).map_err(render)? {
            let dst = format!("/usr/lib/sysusers.d/{}.conf", spec.name);
            files.push(PackagedFile {
                dst: dst.clone(),
                mode: 0o644,
                source: Source::Generated(text),
            });
            units.sysusers = Some(dst);
        }
    }
    if product.kind == Kind::Desktop
        && let Some(helper) = layout.helper()
    {
        // The helper's unit, started by the logged-in session through the
        // polkit rule beside it: no path unit, no preset, never started by
        // the package scripts.
        let render =
            |e: seaworthy_service::ServiceError| DistError::Config(format!("product.{id}: {e}"));
        let names = config.update_product(id, product)?;
        let unit_name = systemd::desktop_update_unit_name(&names.helper_name()).map_err(render)?;
        let unit = systemd::desktop_update_service_unit(
            &product.display_name,
            Path::new(&helper.install_path),
            &names.cache_directory(),
        )
        .map_err(render)?;
        files.push(PackagedFile {
            dst: format!("/usr/lib/systemd/system/{unit_name}"),
            mode: 0o644,
            source: Source::Generated(unit),
        });
        let rule =
            systemd::desktop_update_polkit_rule(&names.package(), &unit_name).map_err(render)?;
        files.push(PackagedFile {
            dst: polkit_rule_path(&names.helper_name()),
            mode: 0o644,
            source: Source::Generated(rule),
        });
        units.update_service = Some(unit_name);
    }
    let name = package_name(config, id);
    if let Some(text) = crate::scripts::preset(&units) {
        files.push(PackagedFile {
            dst: crate::scripts::preset_path(&name),
            mode: 0o644,
            source: Source::Generated(text),
        });
    }
    let vendor_dir = format!("/opt/{}", config.defaults.vendor.to_ascii_lowercase());
    let mut directories = BTreeSet::from([vendor_dir.clone(), layout.install_root.clone()]);
    for file in &layout.files {
        let mut dir = Path::new(&file.install_path).parent();
        while let Some(d) = dir.and_then(Path::to_str) {
            if !d.starts_with(&layout.install_root) || !directories.insert(d.to_owned()) {
                break;
            }
            dir = Path::new(d).parent();
        }
    }
    // Sorted, a parent comes before its children.
    let directories = directories.into_iter().collect();
    Ok(LinuxPackage {
        name,
        directories,
        files,
        links,
        units,
    })
}

/// Where shared-mime-info reads packages' type definitions:
/// `update-mime-database`, which each distribution's shared-mime-info runs
/// from its package manager's trigger or hook when a package changes this
/// directory, compiles them into the database.
pub const MIME_PACKAGES_DIR: &str = "/usr/share/mime/packages";

/// Where KDE's file manager (KF 5.85 and later, KF 6) reads the service
/// menus packages install.
pub const SERVICE_MENUS_DIR: &str = "/usr/share/kio/servicemenus";

/// Every media type the menu entry opens: `desktop.mime-types`, then each
/// file type's.
fn mime_types(product: &Product, desktop: &Desktop) -> Vec<String> {
    desktop
        .mime_types
        .iter()
        .cloned()
        .chain(product.file_types.iter().map(|ft| ft.mime_type.clone()))
        .collect()
}

/// A verb's arguments as a desktop entry's `Exec` takes them after the
/// program: the file placeholder as `%f` (one file per launch). `config`
/// keeps every other argument to characters no `Exec` quoting rule
/// touches, and puts `--` before the file.
fn exec_arguments(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|a| {
            if a == crate::config::PATH_PLACEHOLDER {
                "%f"
            } else {
                a.as_str()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A desktop product's menu entry (Desktop Entry Specification 1.5):
/// `exec`, the launcher's absolute install path (its characters need no
/// quoting: `config` limits the vendor, product id and executable to
/// `[A-Za-z0-9._-]`), and, when the entry opens media types (its
/// `MimeType`: `desktop.mime-types` and every file type's), the default
/// verb's arguments with the file it's opened with (`-- %f`: one file per
/// launch, after `--` so it's never read as an option); the icon name when
/// the package ships icons.
#[must_use]
pub fn desktop_entry(
    product: &Product,
    desktop: &Desktop,
    exec: &str,
    icon: Option<&str>,
) -> String {
    let mut text = String::from("[Desktop Entry]\nType=Application\nVersion=1.5\n");
    text.push_str(&format!("Name={}\n", entry_string(&product.display_name)));
    text.push_str(&format!("Comment={}\n", entry_string(&product.description)));
    let mime_types = mime_types(product, desktop);
    let files = if mime_types.is_empty() {
        String::new()
    } else {
        // Every file type's default verb takes the same arguments
        // (`config`); without one, the file after `--`.
        let arguments = product.file_types.first().map_or_else(
            || crate::config::default_verbs().remove(0).arguments,
            |ft| ft.default_verb().arguments,
        );
        format!(" {}", exec_arguments(&arguments))
    };
    text.push_str(&format!("Exec={exec}{files}\nTryExec={exec}\n"));
    if let Some(icon) = icon {
        text.push_str(&format!("Icon={icon}\n"));
    }
    text.push_str("Terminal=false\n");
    text.push_str(&format!("Categories={};\n", desktop.categories.join(";")));
    if !desktop.keywords.is_empty() {
        let keywords: Vec<String> = desktop.keywords.iter().map(|k| entry_string(k)).collect();
        text.push_str(&format!("Keywords={};\n", keywords.join(";")));
    }
    if !mime_types.is_empty() {
        text.push_str(&format!("MimeType={};\n", mime_types.join(";")));
    }
    if let Some(class) = &desktop.wm_class {
        text.push_str(&format!("StartupWMClass={class}\n"));
    }
    text
}

/// The product's shared-mime-info package (`<app-id>.xml` in
/// [`MIME_PACKAGES_DIR`]): each type it owns, with its name, a glob per
/// extension and its magic; `None` when it owns none (an editor's or a
/// viewer's types are defined by their owners). Each type's icon is
/// shared-mime-info's default for it (the type with `/` as `-`), which the
/// package installs in the hicolor theme's `mimetypes` context.
#[must_use]
pub fn mime_info(product: &Product) -> Option<String> {
    let owned: Vec<&crate::config::FileType> = product
        .file_types
        .iter()
        .filter(|ft| ft.role == crate::config::FileTypeRole::Owner)
        .collect();
    if owned.is_empty() {
        return None;
    }
    let mut text = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n",
    );
    for ft in owned {
        text.push_str(&format!(
            "  <mime-type type=\"{}\">\n",
            xml_text(&ft.mime_type)
        ));
        text.push_str(&format!("    <comment>{}</comment>\n", xml_text(&ft.name)));
        for extension in &ft.extensions {
            text.push_str(&format!(
                "    <glob pattern=\"*.{}\"/>\n",
                xml_text(extension)
            ));
        }
        if !ft.magic.is_empty() {
            text.push_str("    <magic priority=\"50\">\n");
            for magic in &ft.magic {
                // A string as itself; bytes as shared-mime-info's \xHH
                // escapes (config keeps `\` out of a string).
                let value = match (&magic.string, &magic.bytes) {
                    (Some(text), _) => xml_text(text),
                    (None, Some(hex)) => hex
                        .as_bytes()
                        .chunks(2)
                        .map(|pair| {
                            format!("\\x{}", String::from_utf8_lossy(pair).to_ascii_lowercase())
                        })
                        .collect(),
                    (None, None) => continue,
                };
                text.push_str(&format!(
                    "      <match type=\"string\" offset=\"{}\" value=\"{value}\"/>\n",
                    magic.offset
                ));
            }
            text.push_str("    </magic>\n");
        }
        text.push_str("  </mime-type>\n");
    }
    text.push_str("</mime-info>\n");
    Some(text)
}

/// KDE service menus for the file types' verbs other than the default
/// (the menu entry's): `(verb id, file)`, one per verb id (`config` makes
/// one id mean one action), each for every type that has it. A service
/// menu's `Exec` follows the desktop entry's rules (the launcher, the
/// verb's arguments, `%f` after `--`). desktop-file-validate doesn't read
/// `Type=Service` files, so they're generated from validated parts only.
/// Nemo's actions aren't written: Nemo substitutes the file into a command
/// line it then splits as a shell would, and documents no quoting of it.
#[must_use]
pub fn service_menus(product: &Product, exec: &str, icon: Option<&str>) -> Vec<(String, String)> {
    let mut verbs: std::collections::BTreeMap<String, (crate::config::Verb, Vec<String>)> =
        std::collections::BTreeMap::new();
    for ft in &product.file_types {
        for verb in ft.verbs().into_iter().filter(|v| !v.default) {
            verbs
                .entry(verb.id.clone())
                .or_insert_with(|| (verb, Vec::new()))
                .1
                .push(ft.mime_type.clone());
        }
    }
    verbs
        .into_iter()
        .map(|(id, (verb, mime_types))| {
            let mut text = String::from("[Desktop Entry]\nType=Service\n");
            text.push_str(&format!("MimeType={};\n", mime_types.join(";")));
            text.push_str(&format!("Actions={id};\n"));
            text.push_str("X-KDE-ServiceTypes=KonqPopupMenu/Plugin\n\n");
            text.push_str(&format!("[Desktop Action {id}]\n"));
            text.push_str(&format!("Name={}\n", entry_string(&verb.label)));
            if let Some(icon) = icon {
                text.push_str(&format!("Icon={icon}\n"));
            }
            text.push_str(&format!(
                "Exec={exec} {}\n",
                exec_arguments(&verb.arguments)
            ));
            (id, text)
        })
        .collect()
}

/// `text` escaped for XML (an element's text or an attribute's value).
fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Runs `desktop-file-validate` (desktop-file-utils) over the package's
/// menu entries, when it's on `PATH` (`$DESKTOP_FILE_VALIDATE` names
/// another; the CI templates install it): an entry it refuses fails the
/// build, not the menu. Without the tool the entries ship as `config`
/// checked them.
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Layout`] naming what the validator
/// printed.
pub fn validate_desktop_entries(package: &LinuxPackage, work: &Path) -> Result<(), DistError> {
    let entries: Vec<(&str, &str)> = package
        .files
        .iter()
        .filter(|f| f.dst.starts_with("/usr/share/applications/"))
        .filter_map(|f| match &f.source {
            Source::Generated(text) => Some((f.dst.as_str(), text.as_str())),
            Source::Staged(_) => None,
        })
        .collect();
    if entries.is_empty() {
        return Ok(());
    }
    // allow-std-env: an override for the validator's path, like $NFPM.
    let tool = std::env::var_os("DESKTOP_FILE_VALIDATE")
        .map_or_else(|| PathBuf::from("desktop-file-validate"), PathBuf::from);
    if crate::process::tool(&tool).arg("--help").output().is_err() {
        return Ok(());
    }
    let dir = work.join("desktop-entries");
    std::fs::create_dir_all(&dir).map_err(|e| DistError::io(&dir, e))?;
    for (dst, text) in entries {
        let name = Path::new(dst).file_name().unwrap_or_default();
        let path = dir.join(name);
        std::fs::write(&path, text).map_err(|e| DistError::io(&path, e))?;
        crate::process::run_ok(
            crate::process::tool(&tool).arg(&path),
            "desktop-file-validate",
            std::time::Duration::from_secs(60),
        )
        .map_err(|e| DistError::Layout(format!("{dst}: desktop-file-validate refuses it: {e}")))?;
    }
    Ok(())
}

/// A `.desktop` string value: a backslash doubled, a leading space written
/// `\s` (the specification's escapes; `config` refuses control characters).
fn entry_string(text: &str) -> String {
    let escaped = text.replace('\\', "\\\\");
    match escaped.strip_prefix(' ') {
        Some(rest) => format!("\\s{rest}"),
        None => escaped,
    }
}
