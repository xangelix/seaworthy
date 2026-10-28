//! macOS outputs: the app bundle's `Info.plist`,
//! its ad hoc signature, and the disk image.
//!
//! `layout` stages `<Display Name>.app` ([`bundle_name`]); `package`
//! completes it: [`info_plist`] (with the release's version) goes in
//! `Contents/Info.plist`, then [`sign_bundle`] signs from the inside out
//! with `codesign` — every core in `Contents/Frameworks`, the helper, then
//! the bundle itself, which signs the main executable and seals
//! `Contents/Resources` in `Contents/_CodeSignature/CodeResources` — and
//! [`build_dmg`] wraps it in a disk image with `hdiutil`: the app beside a
//! link to `/Applications` (the drag-to-install window), the image signed
//! too. Both tools are macOS's own, so `package` builds a dmg on a Mac
//! only ([`Tools::find`]).
//!
//! Without a signer the signature is **ad hoc** (`codesign --sign -`):
//! Apple Silicon runs only signed code, and an ad hoc signature runs
//! anywhere the copy wasn't quarantined. Gatekeeper refuses a downloaded
//! one; testers clear the quarantine (`xattr -dr com.apple.quarantine
//! <App>.app`). No hardened runtime then: its library validation would
//! refuse the ad hoc cores the launcher loads.
//!
//! With a **Developer ID** ([`DeveloperId`], `signing.toml`'s `[apple]`),
//! every Mach-O in the bundle and then the bundle itself are signed with
//! the identity, the hardened runtime (`--options runtime`; library
//! validation accepts the cores, which carry the same team's signature)
//! and a secure timestamp, the product's `macos.entitlements` on the main
//! executable (and each launcher of the tool directory) alone; each
//! signature must satisfy the Developer ID
//! requirement for `seaworthy.toml`'s `defaults.apple.team-id`
//! ([`developer_id_requirement`]). The disk image is signed the same way,
//! submitted to Apple's notary service (`xcrun notarytool submit --wait`
//! with the `[apple]` keychain profile), its ticket stapled (`xcrun stapler`)
//! and the result assessed as Gatekeeper will (`spctl --assess`). A
//! pkg is signed by the Developer ID Installer identity
//! (`productbuild --sign`), notarized, stapled and assessed likewise.
//!
//! A disk image isn't byte-reproducible (`hdiutil` writes timestamps and a
//! UUID). The files inside it are, and the listing names the image by its
//! digest like every artifact.
//!
//! A service, a tool, or a product with `cli` programs ships as a **pkg**
//! instead: the signed bundle (when the product has a bundled program) in
//! `/Applications`, the tool directory ([`tool_directory`]: the other
//! programs, each binary signed on its own, [`sign_tool`]) with a link in
//! `/usr/local/bin` to each program a `[[programs]]` entry puts on `PATH`,
//! a [`preinstall`] that refuses to install while a product it conflicts
//! with is installed by its pkg, and for a service its LaunchDaemons in
//! `/Library/LaunchDaemons` ([`launch_daemons`]: the service's, and with
//! the update helper the helper's on-demand one), a [`preinstall`] that
//! stops the service and a [`postinstall`] that makes its directories
//! (`/Library/Application Support/<Vendor>/<Directory>/{state,updates}`,
//! `/Library/Logs/<Vendor>/<Directory>`) and loads the daemons. Neither
//! script ever touches the helper's daemon while it's loaded: it may be the
//! one running the install (the Linux packages' rule). macOS has no
//! uninstall for a package, so the bundle (or, without one, the tool
//! directory) carries [`uninstaller`] (`Contents/Resources/uninstall`, or
//! `uninstall`; run with `sudo`). [`build_pkg`] runs
//! `pkgbuild` (the bundle never relocated or version-checked:
//! [`component_plist`]) and `productbuild` ([`distribution`]: Apple Silicon,
//! `macos-minimum` or later, the startup volume only). Unsigned until
//! Developer ID Installer signing; `sudo installer -pkg` installs it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::DistError;
use crate::config::{Config, Product};
use crate::version::Release;

/// Where system daemons' property lists live.
pub const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";

/// The uninstaller's place in the bundle.
pub const UNINSTALLER: &str = "Contents/Resources/uninstall";

/// The uninstaller's place in a product's tool directory, when it has no
/// bundle.
pub const TOOL_UNINSTALLER: &str = "uninstall";

/// Where a pkg links its programs onto `PATH`.
pub const PATH_LINKS: &str = "/usr/local/bin";

/// A product's tool directory on macOS, `/usr/local/<vendor>/<id>`
/// (lowercase, as Linux's `/opt/<vendor>/<id>`): the programs that aren't
/// in the app bundle (`cli` programs, a tool's), laid out like a bundle's
/// `Contents` (`bin/`, `Frameworks/`, `Resources/`), so a launcher finds
/// its cores in `../Frameworks` wherever it is. A pkg installs it and
/// links each program's command into `/usr/local/bin`.
#[must_use]
pub fn tool_directory(config: &Config, id: &str) -> String {
    format!(
        "/usr/local/{}/{id}",
        config.defaults.vendor.to_ascii_lowercase()
    )
}

/// The bundle's icon in `Contents/Resources` (`CFBundleIconFile`).
pub const ICON_FILE: &str = "AppIcon.icns";

/// How long one `codesign` or `hdiutil` run may take.
const TOOL_TIMEOUT: Duration = Duration::from_secs(600);

/// How long Apple's notary service may take by default (`[apple]`
/// `timeout-seconds`): 30 minutes.
pub const DEFAULT_NOTARY_TIMEOUT: Duration = Duration::from_secs(1800);

/// The longest notarization wait `[apple]` may set: the process runner's
/// limit, less ten minutes for the upload.
pub const MAX_NOTARY_TIMEOUT: Duration = Duration::from_secs(3000);

/// The time `notarytool submit` gets beyond its own wait: the upload.
const NOTARY_UPLOAD: Duration = Duration::from_secs(600);

/// A Developer ID signer (`signing.toml`'s `[apple]`): the identities in
/// the keychain that sign, and the notary service's credentials, which
/// `xcrun notarytool store-credentials` keeps in a keychain profile
/// (never in a file or on a command line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeveloperId {
    /// The Developer ID Application identity: its common name
    /// (`Developer ID Application: Acme Inc (ABCDE12345)`) or its
    /// certificate's SHA-1 (40 hex characters).
    pub identity: String,
    /// The Developer ID Installer identity, which signs a pkg.
    pub installer_identity: Option<String>,
    /// The keychain holding the identities and the profile (default: the
    /// user's search list).
    pub keychain: Option<PathBuf>,
    /// The `notarytool` keychain profile.
    pub notary_profile: String,
    /// How long notarization may take.
    pub notary_timeout: Duration,
}

/// What signs a bundle and its container on a Mac: ad hoc, or a
/// Developer ID with the team its signatures must carry and the product's
/// entitlements.
#[derive(Debug, Clone, Copy)]
pub enum MacSigner<'a> {
    /// `codesign --sign -`: no identity, no hardened runtime, no
    /// notarization.
    AdHoc,
    /// A Developer ID.
    DeveloperId {
        /// The signer.
        id: &'a DeveloperId,
        /// `seaworthy.toml`'s `defaults.apple.team-id`.
        team_id: &'a str,
        /// The main executable's entitlements (a staged copy of
        /// `macos.entitlements`).
        entitlements: Option<&'a Path>,
    },
}

/// The code requirement every Developer ID Application signature must
/// satisfy (Apple's own for notarized Developer ID code): Apple's anchor,
/// the Developer ID intermediate (OID 1.2.840.113635.100.6.2.6), a
/// Developer ID Application leaf (1.2.840.113635.100.6.1.13), issued to
/// `team_id`.
#[must_use]
pub fn developer_id_requirement(team_id: &str) -> String {
    format!(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{team_id}\""
    )
}

/// Whether `text` names a codesign identity `[apple]` accepts: `prefix`
/// and a plain name (`Developer ID Application: Acme Inc (ABCDE12345)`),
/// or a certificate's SHA-1 (40 hex characters).
#[must_use]
pub fn is_identity(text: &str, prefix: &str) -> bool {
    let sha1 = text.len() == 40 && text.bytes().all(|b| b.is_ascii_hexdigit());
    let named = text.len() <= 256
        && text
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.trim().is_empty())
        && !text.chars().any(char::is_control);
    sha1 || named
}

/// The app bundle's directory name: `<Display Name>.app`.
#[must_use]
pub fn bundle_name(product: &Product) -> String {
    format!("{}.app", product.display_name)
}

/// The tools that sign and wrap a bundle.
#[derive(Debug, Clone)]
pub struct Tools {
    /// `codesign`.
    pub codesign: PathBuf,
    /// `hdiutil`.
    pub hdiutil: PathBuf,
    /// `pkgbuild`.
    pub pkgbuild: PathBuf,
    /// `productbuild`.
    pub productbuild: PathBuf,
    /// `xcrun` (`notarytool`, `stapler`; a Developer ID only).
    pub xcrun: PathBuf,
    /// `spctl` (Gatekeeper's assessment; a Developer ID only).
    pub spctl: PathBuf,
    /// `pkgutil` (a signed pkg's check; a Developer ID only).
    pub pkgutil: PathBuf,
}

impl Tools {
    /// macOS's own `codesign`, `hdiutil`, `pkgbuild`, `productbuild` and
    /// `xcrun` (`/usr/bin`), `spctl` and `pkgutil` (`/usr/sbin`); `None` on
    /// any other system.
    #[must_use]
    pub fn find() -> Option<Self> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let tools = Self {
            codesign: PathBuf::from("/usr/bin/codesign"),
            hdiutil: PathBuf::from("/usr/bin/hdiutil"),
            pkgbuild: PathBuf::from("/usr/bin/pkgbuild"),
            productbuild: PathBuf::from("/usr/bin/productbuild"),
            xcrun: PathBuf::from("/usr/bin/xcrun"),
            spctl: PathBuf::from("/usr/sbin/spctl"),
            pkgutil: PathBuf::from("/usr/sbin/pkgutil"),
        };
        [
            &tools.codesign,
            &tools.hdiutil,
            &tools.pkgbuild,
            &tools.productbuild,
            &tools.xcrun,
            &tools.spctl,
            &tools.pkgutil,
        ]
        .iter()
        .all(|tool| tool.is_file())
        .then_some(tools)
    }
}

/// A product a pkg can't be installed beside (`conflicts`), as its own
/// pkg names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PkgConflict {
    /// Its package identifier (its bundle id): `pkgutil`'s receipt.
    pub identifier: String,
    /// Its display name.
    pub display_name: String,
    /// Its uninstaller's install path.
    pub uninstaller: String,
}

/// The names a product's package uses: every script and daemon derives
/// its paths from here, and the update helper reads the same directories
/// through `seaworthy_updater::Product`.
#[derive(Debug, Clone)]
pub struct PkgNames {
    /// The display name (the installer's title).
    pub display_name: String,
    /// The package's identifier: the bundle id (`pkgutil`'s receipt).
    pub identifier: String,
    /// The bundle's install path, `/Applications/<Display Name>.app`, when
    /// the product has a bundled program.
    pub bundle: Option<String>,
    /// The tool directory ([`tool_directory`]), when a program installs
    /// there.
    pub tool: Option<String>,
    /// The `PATH` links, `(/usr/local/bin/<command>, the launcher's install
    /// path)`.
    pub links: Vec<(String, String)>,
    /// The products this one can't be installed beside that ship a pkg.
    pub conflicts: Vec<PkgConflict>,
    /// The service's launchd label (the service name), for a service.
    pub service: Option<String>,
    /// The update helper's label (`<service>-update`) when it ships with a
    /// service (a tool's helper is a file only).
    pub helper: Option<String>,
    /// `/Library/Application Support/<Vendor>/<Directory>`.
    pub support: PathBuf,
    /// `/Library/Logs/<Vendor>/<Directory>`.
    pub logs: PathBuf,
}

impl PkgNames {
    /// A label's daemon plist, `/Library/LaunchDaemons/<label>.plist`.
    #[must_use]
    pub fn daemon_path(label: &str) -> String {
        format!("{LAUNCH_DAEMONS}/{label}.plist")
    }

    /// Every label, the helper's first (the order the uninstaller stops
    /// them in).
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.helper
            .iter()
            .chain(&self.service)
            .map(String::as_str)
            .collect()
    }

    /// The uninstaller's install path: in the bundle
    /// (`Contents/Resources/uninstall`, sealed by its signature), else in
    /// the tool directory.
    #[must_use]
    pub fn uninstaller(&self) -> String {
        match (&self.bundle, &self.tool) {
            (Some(bundle), _) => format!("{bundle}/{UNINSTALLER}"),
            (None, Some(tool)) => format!("{tool}/{TOOL_UNINSTALLER}"),
            (None, None) => String::new(),
        }
    }
}

/// Program `executable`'s launcher's install path on macOS: in the bundle
/// (`Contents/MacOS`) when it's bundled, else in the tool directory
/// (`bin`).
fn launcher_path(config: &Config, id: &str, product: &Product, executable: &str) -> String {
    let bundled = product
        .programs()
        .iter()
        .find(|p| p.executable == executable)
        .is_some_and(|p| p.bundled);
    if bundled {
        format!(
            "/Applications/{}/Contents/MacOS/{executable}",
            bundle_name(product)
        )
    } else {
        format!("{}/bin/{executable}", tool_directory(config, id))
    }
}

/// The names product `id`'s package uses.
///
/// # Errors
/// [`DistError::Config`] for a product without a `[macos]` section.
pub fn pkg_names(config: &Config, id: &str, product: &Product) -> Result<PkgNames, DistError> {
    let missing = |what: &str| DistError::Config(format!("product {id}'s pkg needs {what}"));
    let macos = product
        .macos
        .as_ref()
        .ok_or_else(|| missing("[product.<id>.macos]"))?;
    let names = config.update_product(id, product)?;
    let programs = product.programs();
    let bundle = programs
        .iter()
        .any(|p| p.bundled)
        .then(|| format!("/Applications/{}", bundle_name(product)));
    let tool = programs
        .iter()
        .any(|p| !p.bundled)
        .then(|| tool_directory(config, id));
    let links = programs
        .iter()
        .filter_map(|p| {
            p.macos_command.as_ref().map(|command| {
                (
                    format!("{PATH_LINKS}/{command}"),
                    launcher_path(config, id, product, &p.executable),
                )
            })
        })
        .collect();
    let conflicts = config
        .conflicting_products(id)
        .into_iter()
        .filter_map(|other| {
            let product = config.products.get(&other)?;
            let macos = product.macos.as_ref()?;
            product
                .outputs
                .contains(&crate::config::Output::Pkg)
                .then(|| PkgConflict {
                    identifier: macos.bundle_id.clone(),
                    display_name: product.display_name.clone(),
                    uninstaller: if product.programs().iter().any(|p| p.bundled) {
                        format!("/Applications/{}/{UNINSTALLER}", bundle_name(product))
                    } else {
                        format!("{}/{TOOL_UNINSTALLER}", tool_directory(config, &other))
                    },
                })
        })
        .collect();
    let service = product.service.as_ref().map(|s| s.name.clone());
    Ok(PkgNames {
        display_name: product.display_name.clone(),
        identifier: macos.bundle_id.clone(),
        bundle,
        tool,
        links,
        conflicts,
        helper: service
            .as_ref()
            .filter(|_| product.ships_helper())
            .map(|service| format!("{service}-update")),
        service,
        support: names.macos_support_directory(),
        logs: names.macos_log_directory(),
    })
}

/// The package's LaunchDaemons, `(label, plist)`: the service's
/// (`seaworthy_service`'s `daemon_plist`, its output in
/// `<logs>/<service>.log`), then with the update helper the helper's
/// (`update_helper_plist`: the helper in `Contents/MacOS`, watching
/// `<support>/state/update-request`).
///
/// # Errors
/// [`DistError::Config`] for what `seaworthy_service` refuses, or a product
/// [`pkg_names`] refuses.
pub fn launch_daemons(
    config: &Config,
    id: &str,
    product: &Product,
) -> Result<Vec<(String, String)>, DistError> {
    use seaworthy_service::render::launchd;
    let names = pkg_names(config, id, product)?;
    let refused = |e: seaworthy_service::ServiceError| DistError::Config(e.to_string());
    let service = names
        .service
        .clone()
        .ok_or_else(|| DistError::Config(format!("product {id} runs no service")))?;
    let executable = product
        .service_program()
        .map(|p| p.executable)
        .unwrap_or_default();
    let program = launcher_path(config, id, product, &executable);
    let spec = config.macos_service_spec(id, product, Path::new(&program))?;
    let log = |label: &str| mac_join(&names.logs, &format!("{label}.log"));
    let mut daemons = vec![(
        service.clone(),
        launchd::daemon_plist(&spec, &log(&service)).map_err(refused)?,
    )];
    if let Some(label) = &names.helper {
        // Beside the bundle's launcher, else the tool's (layout's rule).
        let helper_name = product.helper.as_deref().unwrap_or("update");
        let helper = match (&names.bundle, &names.tool) {
            (Some(bundle), _) => format!("{bundle}/Contents/MacOS/{helper_name}"),
            (None, Some(tool)) => format!("{tool}/bin/{helper_name}"),
            (None, None) => String::new(),
        };
        let request = config
            .update_product(id, product)?
            .macos_request_file()
            .ok_or_else(|| {
                DistError::Config(format!(
                    "product {id} ships the update helper without a service state-directory"
                ))
            })?;
        daemons.push((
            label.clone(),
            launchd::update_helper_plist(&spec, Path::new(&helper), &request, &log(label))
                .map_err(refused)?,
        ));
    }
    Ok(daemons)
}

/// `text` as one single-quoted shell word.
fn sh(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// A path as one single-quoted shell word.
fn sh_path(path: &Path) -> String {
    sh(&path.to_string_lossy())
}

/// `name` under the macOS directory `dir`, joined with `/` whatever the
/// host's separator (a package is written from any host).
fn mac_join(dir: &Path, name: &str) -> PathBuf {
    PathBuf::from(format!("{}/{name}", dir.to_string_lossy()))
}

/// Text for a double-quoted `echo` in a script: no quote, newline, `$`,
/// backquote or backslash.
fn echo_text(text: &str) -> String {
    text.replace(['"', '\n', '$', '`', '\\'], "")
}

/// The package's `preinstall`: refuses any volume but the startup one,
/// refuses to install while a product it conflicts with is installed (its
/// pkg's receipt), and stops the service (`launchctl bootout`) so its files
/// change under no running process. Never the update helper's daemon: it
/// may be the one running this install.
#[must_use]
pub fn preinstall(names: &PkgNames) -> String {
    let mut text = format!(
        "#!/bin/sh
         # {title} preinstall (generated by seaworthy): stops the service
         # before its files change; never the update helper's daemon, which may
         # be running this install.
         [ \"$3\" = / ] || {{ echo \"installs on the startup volume only\" >&2; exit 1; }}
",
        title = names.display_name.replace('\n', " "),
    );
    for conflict in &names.conflicts {
        text.push_str(&format!(
            "if /usr/sbin/pkgutil --pkg-info {identifier} >/dev/null 2>&1; then
                 echo \"{title_text} can't be installed while {other} is installed: uninstall it first (sudo {uninstaller})\" >&2
                 exit 1
             fi
",
            identifier = sh(&conflict.identifier),
            title_text = echo_text(&names.display_name),
            other = echo_text(&conflict.display_name),
            uninstaller = echo_text(&conflict.uninstaller),
        ));
    }
    if let Some(service) = &names.service {
        text.push_str(&format!(
            "if /bin/launchctl print system/{service} >/dev/null 2>&1; then
             /bin/launchctl bootout system/{service} || echo \"could not stop {service_text}; installing over it\" >&2
         fi
",
            service = sh(service),
            service_text = service,
        ));
    }
    text.push_str("exit 0\n");
    text
}

/// The package's `postinstall`: the support (`state`, `updates`: root's,
/// private) and log directories, then the daemons: the service's loaded
/// (`launchctl bootstrap`, which starts it: `RunAtLoad`) unless an
/// administrator disabled it, and the helper's loaded only when it isn't
/// already (a loaded helper may be running this install; its plist names
/// the same paths). The daemons start from an `EXIT` trap, so however the
/// script ends (a directory it can't make, say) the service the preinstall
/// stopped runs again: a failed install never leaves it stopped, and the
/// script's status is still the failure.
/// A package without a service has nothing to start: its postinstall
/// checks the volume alone.
#[must_use]
pub fn postinstall(names: &PkgNames) -> String {
    let Some(service) = &names.service else {
        return format!(
            "#!/bin/sh
         # {title} postinstall (generated by seaworthy): no service to start.
         [ \"$3\" = / ] || exit 1
         exit 0
",
            title = names.display_name.replace('\n', " "),
        );
    };
    let state = mac_join(&names.support, "state");
    let updates = mac_join(&names.support, "updates");
    let mut text = format!(
        "#!/bin/sh
         # {title} postinstall (generated by seaworthy). However it ends, it
         # starts the service the preinstall stopped (start_daemons, on EXIT).
         # shellcheck disable=SC2317,SC2329 # the functions run from the trap
         [ \"$3\" = / ] || exit 1
         disabled() {{ /bin/launchctl print-disabled system 2>/dev/null | /usr/bin/grep -Eq \"\\\"$1\\\" => (disabled|true)\"; }}
         loaded() {{ /bin/launchctl print \"system/$1\" >/dev/null 2>&1; }}
         start_daemons() {{
             status=$?
             trap - EXIT
",
        title = names.display_name.replace('\n', " "),
    );
    text.push_str(&format!(
        "if disabled {service}; then
             echo \"{service_text} is disabled (launchctl disable): not starting it\" >&2
         elif loaded {service}; then
             /bin/launchctl kickstart -k system/{service} || status=1
         else
             /bin/launchctl bootstrap system {plist} || status=1
         fi
",
        service = sh(service),
        service_text = service,
        plist = sh(&PkgNames::daemon_path(service)),
    ));
    if let Some(helper) = &names.helper {
        text.push_str(&format!(
            "if ! disabled {helper} && ! loaded {helper}; then
                 /bin/launchctl bootstrap system {plist} || status=1
             fi
",
            helper = sh(helper),
            plist = sh(&PkgNames::daemon_path(helper)),
        ));
    }
    text.push_str(&format!(
        "exit \"$status\"
         }}
         trap start_daemons EXIT
         umask 022
         /bin/mkdir -p {state} {updates} {logs} || exit 1
         /usr/sbin/chown root:wheel {support} {state} {updates} {logs} || exit 1
         /bin/chmod 0755 {support} {logs} || exit 1
         /bin/chmod 0700 {state} {updates} || exit 1
         exit 0
",
        support = sh_path(&names.support),
        state = sh_path(&state),
        updates = sh_path(&updates),
        logs = sh_path(&names.logs),
    ));
    text
}

/// The uninstaller the package carries ([`PkgNames::uninstaller`]: in the
/// bundle, `Contents/Resources/uninstall`, else the tool directory's
/// `uninstall`): run as root, it stops and removes the daemons, the app,
/// the tool directory, the `PATH` links that still point into it and the
/// package's receipt; `--purge` removes the state and logs too. The
/// administrator's policy file (`/etc/<vendor>/<id>/policy.toml`) stays,
/// as on Linux.
///
/// The daemons stop first, and nothing is removed unless they did: the
/// update helper (so no run of it starts the service again), then any
/// package install a helper run left in flight (`installer` hands the
/// package to the system's install daemon, whose postinstall loads the
/// service), then the service, which must stay unloaded for a few seconds.
/// A `launchctl bootout` can fail while a daemon is mid-transition (just
/// restarted by an update), so each is retried until launchd no longer
/// knows the label; a daemon that won't go stops the uninstall with exit 1
/// before anything is removed, so running it again finishes the job.
#[must_use]
pub fn uninstaller(names: &PkgNames) -> String {
    let mut text = format!(
        "#!/bin/sh
         # Uninstalls {title} (generated by seaworthy). As root:
         #   sudo {self_path} [--purge]
         # --purge also removes its state and logs.
         set -u
         [ \"$(/usr/bin/id -u)\" = 0 ] || {{ echo \"run it as root (sudo)\" >&2; exit 1; }}
         purge=0
         case \"${{1:-}}\" in --purge) purge=1 ;; '') ;; *) echo \"usage: $0 [--purge]\" >&2; exit 2 ;; esac
",
        title = names.display_name.replace('\n', " "),
        self_path = sh(&names.uninstaller()),
    );
    // The daemons' functions, with daemons to stop.
    if !names.labels().is_empty() {
        text.push_str(
            "         loaded() { /bin/launchctl print \"system/$1\" >/dev/null 2>&1; }
         # Unload a daemon, retrying a bootout that fails mid-transition.
         unload() {
             tries=0
             while loaded \"$1\"; do
                 if [ \"$tries\" -ge 10 ]; then
                     echo \"could not stop $1; nothing was removed: run the uninstaller again\" >&2
                     exit 1
                 fi
                 /bin/launchctl bootout \"system/$1\" 2>/dev/null
                 tries=$((tries + 1))
                 /bin/sleep 1
             done
         }
",
        );
    }
    let mut labels = names.labels();
    let service = names.service.as_ref().and_then(|_| labels.pop());
    for label in labels {
        text.push_str(&format!("unload {label}\n", label = sh(label)));
    }
    let updates = mac_join(&names.support, "updates");
    // An update a helper run left in flight: only a service's helper runs.
    if names.service.is_some() {
        text.push_str(&format!(
        "waited=0
         while /usr/bin/pgrep -f {pattern} >/dev/null 2>&1; do
             if [ \"$waited\" -ge 600 ]; then
                 echo \"an update is still installing; nothing was removed: run the uninstaller again\" >&2
                 exit 1
             fi
             /bin/sleep 2
             waited=$((waited + 2))
         done
",
        pattern = sh(&format!("^/usr/sbin/installer -pkg {}/", updates.display())),
    ));
    }
    if let Some(service) = service {
        text.push_str(&format!(
            "stable=0
             tries=0
             while [ \"$stable\" -lt 5 ]; do
                 if loaded {label}; then
                     if [ \"$tries\" -ge 5 ]; then
                         echo \"{label_text} keeps coming back; nothing was removed: run the uninstaller again\" >&2
                         exit 1
                     fi
                     unload {label}
                     tries=$((tries + 1))
                     stable=0
                 else
                     stable=$((stable + 1))
                 fi
                 /bin/sleep 1
             done
",
            label = sh(service),
            label_text = service.replace(['"', '\n', '$', '`', '\\'], ""),
        ));
    }
    for label in names.labels() {
        text.push_str(&format!(
            "/bin/rm -f {plist}\n",
            plist = sh(&PkgNames::daemon_path(label)),
        ));
    }
    // A link another product took over since stays.
    for (link, target) in &names.links {
        text.push_str(&format!(
            "if [ \"$(/usr/bin/readlink {link})\" = {target} ]; then /bin/rm -f {link}; fi\n",
            link = sh(link),
            target = sh(target),
        ));
    }
    for directory in names.bundle.iter().chain(&names.tool) {
        text.push_str(&format!("/bin/rm -rf {}\n", sh(directory)));
    }
    text.push_str(&format!(
        "/usr/sbin/pkgutil --forget {identifier} >/dev/null 2>&1
         if [ \"$purge\" = 1 ]; then /bin/rm -rf {support} {logs}; fi
         echo \"{title_text} is uninstalled\"
",
        identifier = sh(&names.identifier),
        support = sh_path(&names.support),
        logs = sh_path(&names.logs),
        title_text = echo_text(&names.display_name),
    ));
    text
}

/// `pkgbuild`'s component property list for the bundle: never relocated
/// (an installer would otherwise update a copy found elsewhere), never
/// version-checked (the update helper's floor decides downgrades), its
/// identifier strict, an upgrade replacing it.
///
/// `None` without a bundle: a tool directory is plain files.
#[must_use]
pub fn component_plist(names: &PkgNames) -> Option<String> {
    let relative = names.bundle.as_deref()?.trim_start_matches('/');
    Some(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<array>\n\t<dict>\n\
         \t\t<key>BundleHasStrictIdentifier</key>\n\t\t<true/>\n\
         \t\t<key>BundleIsRelocatable</key>\n\t\t<false/>\n\
         \t\t<key>BundleIsVersionChecked</key>\n\t\t<false/>\n\
         \t\t<key>BundleOverwriteAction</key>\n\t\t<string>upgrade</string>\n\
         \t\t<key>RootRelativeBundlePath</key>\n\t\t<string>{}</string>\n\
         \t</dict>\n</array>\n</plist>\n",
        xml_text(relative)
    ))
}

/// `productbuild`'s distribution: one hidden choice holding the component
/// package, Apple Silicon only, `minimum` or later, the startup volume
/// only, nothing to customize.
#[must_use]
pub fn distribution(names: &PkgNames, version: &str, minimum: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <installer-gui-script minSpecVersion=\"2\">\n\
         \t<title>{title}</title>\n\
         \t<options customize=\"never\" hostArchitectures=\"arm64\"/>\n\
         \t<domains enable_anywhere=\"false\" enable_currentUserHome=\"false\" enable_localSystem=\"true\"/>\n\
         \t<volume-check>\n\
         \t\t<allowed-os-versions>\n\
         \t\t\t<os-version min=\"{minimum}\"/>\n\
         \t\t</allowed-os-versions>\n\
         \t</volume-check>\n\
         \t<choices-outline>\n\
         \t\t<line choice=\"default\">\n\
         \t\t\t<line choice=\"{id}\"/>\n\
         \t\t</line>\n\
         \t</choices-outline>\n\
         \t<choice id=\"default\"/>\n\
         \t<choice id=\"{id}\" visible=\"false\">\n\
         \t\t<pkg-ref id=\"{id}\"/>\n\
         \t</choice>\n\
         \t<pkg-ref id=\"{id}\" version=\"{version}\" onConclusion=\"none\">component.pkg</pkg-ref>\n\
         </installer-gui-script>\n",
        title = xml_text(&names.display_name),
        minimum = xml_text(minimum),
        id = xml_text(&names.identifier),
        version = xml_text(version),
    )
}

/// Writes `text` to `path` with `mode`.
fn write_mode(path: &Path, text: &str, mode: u32) -> Result<(), DistError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
    }
    std::fs::write(path, text).map_err(|e| DistError::io(path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| DistError::io(path, e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

/// Builds `pkg` from the signed macOS `tree` (layout's: the bundle as
/// `<Display Name>.app`, the tool directory at its install path): the
/// payload (the bundle and the tool directory at their install paths, the
/// `PATH` links in `/usr/local/bin`, the `daemons` in
/// `/Library/LaunchDaemons`, 0644), the scripts, `pkgbuild` into a
/// component package (identifier and `version`; the bundle never
/// relocated, [`component_plist`]), then `productbuild` with
/// [`distribution`]. Staged in
/// `work`. With a Developer ID, `productbuild` signs it with the Developer
/// ID Installer identity, and it's notarized, stapled and assessed as
/// Gatekeeper will install it; without one it stays unsigned.
///
/// # Errors
/// [`DistError::Io`] staging; [`DistError::Tool`] when `pkgbuild`,
/// `productbuild` or a notarization tool fails; [`DistError::Sign`] for a
/// Developer ID without an installer identity, a pkg signed by another
/// team, or one Gatekeeper wouldn't install.
#[allow(clippy::too_many_arguments)]
pub fn build_pkg(
    tools: &Tools,
    names: &PkgNames,
    tree: &Path,
    daemons: &[(String, String)],
    version: &str,
    minimum: &str,
    pkg: &Path,
    work: &Path,
    signer: &MacSigner<'_>,
) -> Result<(), DistError> {
    let installer = match signer {
        MacSigner::AdHoc => None,
        MacSigner::DeveloperId { id, team_id, .. } => Some((
            id,
            *team_id,
            id.installer_identity.as_deref().ok_or_else(|| {
                DistError::Sign(
                    "a Developer ID-signed pkg needs [apple]'s installer-identity (a Developer ID Installer identity)"
                        .to_owned(),
                )
            })?,
        )),
    };
    let staging = work.join("pkg");
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| DistError::io(&staging, e))?;
    }
    let root = staging.join("root");
    if let Some(bundle) = &names.bundle {
        let name = Path::new(bundle)
            .file_name()
            .ok_or_else(|| DistError::Layout(format!("{bundle} has no name")))?;
        copy_tree(&tree.join(name), &root.join(bundle.trim_start_matches('/')))?;
    }
    if let Some(tool) = &names.tool {
        let relative = tool.trim_start_matches('/');
        copy_tree(&tree.join(relative), &root.join(relative))?;
    }
    for (link, target) in &names.links {
        let path = root.join(link.trim_start_matches('/'));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &path).map_err(|e| DistError::io(&path, e))?;
        #[cfg(not(unix))]
        let _ = target;
    }
    for (label, plist) in daemons {
        let path = root.join(PkgNames::daemon_path(label).trim_start_matches('/'));
        write_mode(&path, plist, 0o644)?;
    }
    let scripts = staging.join("scripts");
    write_mode(&scripts.join("preinstall"), &preinstall(names), 0o755)?;
    write_mode(&scripts.join("postinstall"), &postinstall(names), 0o755)?;
    let component_list = staging.join("component.plist");
    let mut component_args: Vec<&std::ffi::OsStr> = Vec::new();
    if let Some(text) = component_plist(names) {
        write_mode(&component_list, &text, 0o644)?;
        component_args.extend([OsStr::new("--component-plist"), component_list.as_os_str()]);
    }
    let packages = staging.join("packages");
    std::fs::create_dir_all(&packages).map_err(|e| DistError::io(&packages, e))?;
    let component = packages.join("component.pkg");
    let mut pkgbuild: Vec<&std::ffi::OsStr> = vec!["--root".as_ref(), root.as_os_str()];
    pkgbuild.extend(component_args);
    pkgbuild.extend([
        OsStr::new("--identifier"),
        OsStr::new(&names.identifier),
        OsStr::new("--version"),
        OsStr::new(version),
        OsStr::new("--scripts"),
        scripts.as_os_str(),
        OsStr::new("--install-location"),
        OsStr::new("/"),
        OsStr::new("--ownership"),
        OsStr::new("recommended"),
        component.as_os_str(),
    ]);
    run(&tools.pkgbuild, &pkgbuild, "pkgbuild")?;
    let distribution_xml = staging.join("distribution.xml");
    write_mode(
        &distribution_xml,
        &distribution(names, version, minimum),
        0o644,
    )?;
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "--distribution".as_ref(),
        distribution_xml.as_os_str(),
        "--package-path".as_ref(),
        packages.as_os_str(),
    ];
    if let Some((id, _, identity)) = &installer {
        args.extend([
            OsStr::new("--sign"),
            OsStr::new(identity),
            OsStr::new("--timestamp"),
        ]);
        if let Some(keychain) = &id.keychain {
            args.extend([OsStr::new("--keychain"), keychain.as_os_str()]);
        }
    }
    args.push(pkg.as_os_str());
    run(&tools.productbuild, &args, "productbuild")?;
    std::fs::remove_dir_all(&staging).map_err(|e| DistError::io(&staging, e))?;
    if let Some((id, team_id, _)) = installer {
        check_installer_signature(tools, pkg, team_id)?;
        notarize(tools, id, pkg)?;
        assess(tools, pkg, &["--type", "install"])?;
    }
    Ok(())
}

/// A pkg's signature (`pkgutil --check-signature`): a Developer ID
/// Installer certificate of `team_id` must lead its chain.
fn check_installer_signature(tools: &Tools, pkg: &Path, team_id: &str) -> Result<(), DistError> {
    let shown = run(
        &tools.pkgutil,
        &["--check-signature".as_ref(), pkg.as_os_str()],
        "pkgutil --check-signature",
    )?;
    let leaf = shown
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("1. "))
        .unwrap_or_default();
    if !(leaf.starts_with("Developer ID Installer:") && leaf.ends_with(&format!("({team_id})"))) {
        return Err(DistError::Sign(format!(
            "{}: not signed by a Developer ID Installer identity of team {team_id} (defaults.apple.team-id); pkgutil shows {leaf:?}",
            pkg.display()
        )));
    }
    Ok(())
}

/// `text` escaped for an XML plist string.
fn xml_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The bundle's `Info.plist`: its identity (`[product.<id>.macos]`), the
/// launcher as its executable, the release as its version
/// (`CFBundleShortVersionString` is `MAJOR.MINOR.PATCH`, the three integers
/// Apple allows; `CFBundleVersion` the release sequence, which only grows),
/// `defaults.macos-minimum` as `LSMinimumSystemVersion`, and the app's
/// languages as `CFBundleLocalizations`.
///
/// # Errors
/// [`DistError::Config`] when the product has no `[macos]` section.
pub fn info_plist(
    product: &Product,
    release: &Release,
    minimum: &str,
    icon: bool,
) -> Result<String, DistError> {
    let macos = product
        .macos
        .as_ref()
        .ok_or_else(|| DistError::Config("a macOS bundle needs [product.<id>.macos]".to_owned()))?;
    let mut entries: Vec<(&str, String)> = vec![
        ("CFBundleDevelopmentRegion", "en".to_owned()),
        ("CFBundleDisplayName", product.display_name.clone()),
        (
            "CFBundleExecutable",
            product
                .bundled_program()
                .map(|p| p.executable)
                .unwrap_or_default(),
        ),
    ];
    if icon {
        entries.push(("CFBundleIconFile", ICON_FILE.to_owned()));
    }
    entries.extend([
        ("CFBundleIdentifier", macos.bundle_id.clone()),
        ("CFBundleInfoDictionaryVersion", "6.0".to_owned()),
        ("CFBundleName", product.display_name.clone()),
        ("CFBundlePackageType", "APPL".to_owned()),
        (
            "CFBundleShortVersionString",
            format!(
                "{}.{}.{}",
                release.version.major, release.version.minor, release.version.patch
            ),
        ),
        ("CFBundleVersion", release.sequence.to_string()),
    ]);
    if let Some(category) = &macos.category {
        entries.push(("LSApplicationCategoryType", category.clone()));
    }
    entries.push(("LSMinimumSystemVersion", minimum.to_owned()));
    let mut text = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n",
    );
    for (key, value) in entries {
        text.push_str(&format!(
            "\t<key>{key}</key>\n\t<string>{}</string>\n",
            xml_text(&value)
        ));
    }
    if !macos.localizations.is_empty() {
        text.push_str("\t<key>CFBundleLocalizations</key>\n\t<array>\n");
        for language in &macos.localizations {
            text.push_str(&format!("\t\t<string>{}</string>\n", xml_text(language)));
        }
        text.push_str("\t</array>\n");
    }
    text.push_str("\t<key>NSHighResolutionCapable</key>\n\t<true/>\n</dict>\n</plist>\n");
    Ok(text)
}

fn run(tool: &Path, args: &[&std::ffi::OsStr], what: &str) -> Result<String, DistError> {
    let mut command = crate::process::tool(tool);
    command.args(args);
    crate::process::run_ok(&mut command, what, TOOL_TIMEOUT)
}

/// `codesign --sign` of `target` by `signer`: ad hoc without a timestamp,
/// or a Developer ID with a secure timestamp, the hardened runtime when
/// `runtime` (code, never a disk image), and `entitlements` when given.
fn codesign(
    tools: &Tools,
    signer: &MacSigner<'_>,
    target: &Path,
    runtime: bool,
    entitlements: Option<&Path>,
) -> Result<(), DistError> {
    let mut args: Vec<&std::ffi::OsStr> = vec!["--force".as_ref(), "--sign".as_ref()];
    match signer {
        MacSigner::AdHoc => args.extend([OsStr::new("-"), OsStr::new("--timestamp=none")]),
        MacSigner::DeveloperId { id, .. } => {
            args.extend([OsStr::new(&id.identity), OsStr::new("--timestamp")]);
            if runtime {
                args.extend([OsStr::new("--options"), OsStr::new("runtime")]);
            }
            if let Some(keychain) = &id.keychain {
                args.extend([OsStr::new("--keychain"), keychain.as_os_str()]);
            }
            if let Some(entitlements) = entitlements {
                args.extend([OsStr::new("--entitlements"), entitlements.as_os_str()]);
            }
        }
    }
    args.push(target.as_os_str());
    run(&tools.codesign, &args, "codesign").map(drop)
}

/// `codesign --verify --strict` of `target` (`--deep` for a bundle) and,
/// for a Developer ID, its signature against the Developer ID requirement
/// for the pinned team.
fn verify_signature(
    tools: &Tools,
    signer: &MacSigner<'_>,
    target: &Path,
    deep: bool,
) -> Result<(), DistError> {
    let requirement = match signer {
        MacSigner::AdHoc => None,
        MacSigner::DeveloperId { team_id, .. } => Some(developer_id_requirement(team_id)),
    };
    let mut args: Vec<&std::ffi::OsStr> = vec!["--verify".as_ref(), "--strict".as_ref()];
    if deep {
        args.push("--deep".as_ref());
    }
    if let Some(requirement) = &requirement {
        args.extend([OsStr::new("--test-requirement"), OsStr::new(requirement)]);
    }
    args.push(target.as_os_str());
    run(&tools.codesign, &args, "codesign --verify").map_err(|e| match signer {
        MacSigner::AdHoc => e,
        MacSigner::DeveloperId { team_id, .. } => DistError::Sign(format!(
            "{}: not signed by a Developer ID Application identity of team {team_id} (defaults.apple.team-id): {e}",
            target.display()
        )),
    })?;
    Ok(())
}

/// Signs a staged bundle from the inside out: each of `nested` (the cores,
/// the helper, the sidecars), then the bundle, which signs its main
/// executable and seals everything else; then checks the result
/// (`codesign --verify --deep --strict`, and for a Developer ID every
/// signature against the Developer ID requirement for the pinned team).
///
/// # Errors
/// [`DistError::Tool`] when `codesign` fails, or the signed bundle doesn't
/// verify; [`DistError::Sign`] for a signature by another team or another
/// kind of identity.
pub fn sign_bundle(
    tools: &Tools,
    bundle: &Path,
    nested: &[PathBuf],
    signer: &MacSigner<'_>,
) -> Result<(), DistError> {
    for code in nested {
        codesign(tools, signer, code, true, None)?;
    }
    let entitlements = match signer {
        MacSigner::AdHoc => None,
        MacSigner::DeveloperId { entitlements, .. } => *entitlements,
    };
    codesign(tools, signer, bundle, true, entitlements)?;
    if matches!(signer, MacSigner::DeveloperId { .. }) {
        for code in nested {
            verify_signature(tools, signer, code, false)?;
        }
    }
    verify_signature(tools, signer, bundle, true)
}

/// Signs the code in a product's tool directory, which no bundle seals:
/// each of `nested` (the cores, the sidecars, the helper), then each of
/// `launchers` (with the product's entitlements, as a bundle's main
/// executable carries them: each launcher is a program's process), each
/// with the hardened runtime and a secure timestamp under a Developer ID;
/// then checks every signature (`codesign --verify --strict`, and for a
/// Developer ID against its requirement for the pinned team).
///
/// # Errors
/// [`DistError::Tool`] when `codesign` fails or a signature doesn't
/// verify; [`DistError::Sign`] for a signature by another team or kind of
/// identity.
pub fn sign_tool(
    tools: &Tools,
    launchers: &[PathBuf],
    nested: &[PathBuf],
    signer: &MacSigner<'_>,
) -> Result<(), DistError> {
    for code in nested {
        codesign(tools, signer, code, true, None)?;
    }
    let entitlements = match signer {
        MacSigner::AdHoc => None,
        MacSigner::DeveloperId { entitlements, .. } => *entitlements,
    };
    for launcher in launchers {
        codesign(tools, signer, launcher, true, entitlements)?;
    }
    for code in nested.iter().chain(launchers) {
        verify_signature(tools, signer, code, false)?;
    }
    Ok(())
}

/// Submits `file` (a signed disk image or pkg) to Apple's notary service
/// and waits for its verdict, then staples the ticket to it and checks the
/// staple. A rejection names the service's log.
///
/// # Errors
/// [`DistError::Sign`] when the service doesn't accept it (with its log),
/// [`DistError::Tool`] when `notarytool` or `stapler` fails or answers
/// something unreadable.
pub fn notarize(tools: &Tools, id: &DeveloperId, file: &Path) -> Result<(), DistError> {
    let timeout = format!("{}s", id.notary_timeout.as_secs());
    let mut credentials: Vec<&std::ffi::OsStr> =
        vec!["--keychain-profile".as_ref(), id.notary_profile.as_ref()];
    if let Some(keychain) = &id.keychain {
        credentials.extend([OsStr::new("--keychain"), keychain.as_os_str()]);
    }
    let mut args: Vec<&std::ffi::OsStr> = vec!["notarytool".as_ref(), "submit".as_ref()];
    args.push(file.as_os_str());
    args.extend(credentials.iter().copied());
    args.extend([
        OsStr::new("--wait"),
        OsStr::new("--timeout"),
        OsStr::new(&timeout),
        OsStr::new("--output-format"),
        OsStr::new("json"),
    ]);
    let deadline = id.notary_timeout.saturating_add(NOTARY_UPLOAD);
    let mut command = crate::process::tool(&tools.xcrun);
    command.args(&args);
    let finished = crate::process::run(&mut command, "notarytool submit", None, deadline, 1 << 20)?;
    let answer: serde_json::Value = serde_json::from_slice(&finished.stdout).map_err(|_| {
        DistError::Tool(format!(
            "notarytool submit {}: no JSON answer (exit {}): {}",
            file.display(),
            finished.status,
            finished.shown()
        ))
    })?;
    let status = answer.get("status").and_then(serde_json::Value::as_str);
    let submission = answer.get("id").and_then(serde_json::Value::as_str);
    if status != Some("Accepted") || !finished.status.success() {
        // The service's own account of the rejection, when it got that far.
        let log = submission
            .filter(|s| s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            .map(|submission| {
                let mut args: Vec<&std::ffi::OsStr> =
                    vec!["notarytool".as_ref(), "log".as_ref(), submission.as_ref()];
                args.extend(credentials.iter().copied());
                let mut command = crate::process::tool(&tools.xcrun);
                command.args(&args);
                crate::process::run(&mut command, "notarytool log", None, TOOL_TIMEOUT, 64 << 10)
                    .map(|log| {
                        String::from_utf8_lossy(&log.stdout)
                            .chars()
                            .filter(|c| !c.is_control() || *c == '\n')
                            .take(4000)
                            .collect::<String>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        return Err(DistError::Sign(format!(
            "Apple's notary service didn't accept {} (status {}, submission {}): {}",
            file.display(),
            status.unwrap_or("none"),
            submission.unwrap_or("none"),
            if log.is_empty() {
                finished.shown()
            } else {
                log
            }
        )));
    }
    run(
        &tools.xcrun,
        &["stapler".as_ref(), "staple".as_ref(), file.as_os_str()],
        "stapler staple",
    )?;
    run(
        &tools.xcrun,
        &["stapler".as_ref(), "validate".as_ref(), file.as_os_str()],
        "stapler validate",
    )?;
    Ok(())
}

/// Copies directory `from` to `to` (files and directories; a bundle holds
/// nothing else), keeping each file's mode.
fn copy_tree(from: &Path, to: &Path) -> Result<(), DistError> {
    std::fs::create_dir_all(to).map_err(|e| DistError::io(to, e))?;
    for entry in std::fs::read_dir(from).map_err(|e| DistError::io(from, e))? {
        let entry = entry.map_err(|e| DistError::io(from, e))?;
        let kind = entry
            .file_type()
            .map_err(|e| DistError::io(&entry.path(), e))?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).map_err(|e| DistError::io(&entry.path(), e))?;
        } else {
            return Err(DistError::Layout(format!(
                "{}: a bundle holds files and directories only",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Builds `dmg` from the signed `bundle`: a compressed (UDZO) HFS+ image
/// named `volume`, holding the app and a link to `/Applications`, staged
/// in `work`; then signs the image (ad hoc, or with the Developer ID,
/// then notarized, stapled and assessed as Gatekeeper will open it).
///
/// # Errors
/// [`DistError::Io`] staging; [`DistError::Tool`] when `hdiutil`,
/// `codesign` or a notarization tool fails; [`DistError::Sign`] when the
/// image's signature or notarization isn't the Developer ID's, or
/// Gatekeeper wouldn't open it.
pub fn build_dmg(
    tools: &Tools,
    bundle: &Path,
    volume: &str,
    dmg: &Path,
    work: &Path,
    signer: &MacSigner<'_>,
) -> Result<(), DistError> {
    let staging = work.join("dmg");
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|e| DistError::io(&staging, e))?;
    }
    let name = bundle
        .file_name()
        .ok_or_else(|| DistError::Layout(format!("{} has no name", bundle.display())))?;
    copy_tree(bundle, &staging.join(name))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("/Applications", staging.join("Applications"))
        .map_err(|e| DistError::io(&staging, e))?;
    run(
        &tools.hdiutil,
        &[
            "create".as_ref(),
            "-volname".as_ref(),
            volume.as_ref(),
            "-srcfolder".as_ref(),
            staging.as_os_str(),
            "-fs".as_ref(),
            "HFS+".as_ref(),
            "-format".as_ref(),
            "UDZO".as_ref(),
            "-ov".as_ref(),
            dmg.as_os_str(),
        ],
        "hdiutil create",
    )?;
    std::fs::remove_dir_all(&staging).map_err(|e| DistError::io(&staging, e))?;
    codesign(tools, signer, dmg, false, None)?;
    if let MacSigner::DeveloperId { id, .. } = signer {
        verify_signature(tools, signer, dmg, false)?;
        notarize(tools, id, dmg)?;
        assess(
            tools,
            dmg,
            &["--type", "open", "--context", "context:primary-signature"],
        )?;
    }
    Ok(())
}

/// Gatekeeper's verdict on `file` (`spctl --assess`): accepted, or an error.
fn assess(tools: &Tools, file: &Path, kind: &[&str]) -> Result<(), DistError> {
    let mut args: Vec<&std::ffi::OsStr> = vec!["--assess".as_ref()];
    args.extend(kind.iter().map(std::ffi::OsStr::new));
    args.extend([OsStr::new("--verbose"), file.as_os_str()]);
    run(&tools.spctl, &args, "spctl --assess").map_err(|e| {
        DistError::Sign(format!(
            "Gatekeeper refuses {} (notarized and stapled, still refused): {e}",
            file.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn plist_strings_are_escaped() {
        assert_eq!(
            xml_text("A & B <\"x\">'"),
            "A &amp; B &lt;&quot;x&quot;&gt;&apos;"
        );
    }
}
