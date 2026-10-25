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
//!   oneshot, the same unit and sandbox as a service's helper, with no path
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
//! Desktop Entry Specification 1.5), and its hicolor icons; `linux.command`
//! adds `/usr/bin/<command>`, a link to the launcher. Those directories
//! belong to the system (the icon theme, the menu), so the package owns
//! only its files there; the distributions' triggers refresh the menu and
//! the icon cache.
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
    /// Its symbolic links (`/usr/bin/<command>`).
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
    let launcher_path = || {
        layout
            .launcher()
            .map(|l| l.install_path.clone())
            .ok_or_else(|| DistError::Layout(format!("product {id}'s Linux tree has no launcher")))
    };
    if let Some(desktop) = &product.desktop {
        let app_id = desktop.app_id(config, id);
        let icon = (!layout.desktop_files.is_empty()).then_some(app_id.as_str());
        files.push(PackagedFile {
            dst: format!("/usr/share/applications/{app_id}.desktop"),
            mode: 0o644,
            source: Source::Generated(desktop_entry(product, desktop, &launcher_path()?, icon)),
        });
    }
    let mut links = Vec::new();
    if let Some(command) = &product.linux.command {
        links.push(PackagedLink {
            dst: format!("/usr/bin/{command}"),
            target: launcher_path()?,
        });
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

/// A desktop product's menu entry (Desktop Entry Specification 1.5):
/// `exec`, the launcher's absolute install path (its characters need no
/// quoting: `config` limits the vendor, product id and executable to
/// `[A-Za-z0-9._-]`), and the icon name when the package ships icons.
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
    text.push_str(&format!("Exec={exec}\nTryExec={exec}\n"));
    if let Some(icon) = icon {
        text.push_str(&format!("Icon={icon}\n"));
    }
    text.push_str("Terminal=false\n");
    text.push_str(&format!("Categories={};\n", desktop.categories.join(";")));
    if !desktop.keywords.is_empty() {
        let keywords: Vec<String> = desktop.keywords.iter().map(|k| entry_string(k)).collect();
        text.push_str(&format!("Keywords={};\n", keywords.join(";")));
    }
    if let Some(class) = &desktop.wm_class {
        text.push_str(&format!("StartupWMClass={class}\n"));
    }
    text
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
    if std::process::Command::new(&tool)
        .arg("--help")
        .output()
        .is_err()
    {
        return Ok(());
    }
    let dir = work.join("desktop-entries");
    std::fs::create_dir_all(&dir).map_err(|e| DistError::io(&dir, e))?;
    for (dst, text) in entries {
        let name = Path::new(dst).file_name().unwrap_or_default();
        let path = dir.join(name);
        std::fs::write(&path, text).map_err(|e| DistError::io(&path, e))?;
        crate::process::run_ok(
            std::process::Command::new(&tool).arg(&path),
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
