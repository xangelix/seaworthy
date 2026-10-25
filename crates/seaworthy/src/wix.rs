//! The Windows Installer package: a WiX `.wxs` generated from a laid-out
//! Windows tree and the product's service, built with the pinned WiX
//! on the Windows runner:
//!
//! ```text
//! wix build -arch x64 -bindpath tree=<tree> -o <name>.msi <name>.wxs
//! ```
//!
//! `<tree>` is the layout's staging tree (`<out>/<product>/<triple>/tree`).
//! Every `File/@Source` names it through the bind path
//! (`!(bindpath.tree)\<Vendor>\<Directory>\<file>`), so the `.wxs` builds
//! wherever the tree is copied, and a plain relative path can't pick up a
//! same-named file from the working directory instead (WiX tries the
//! working directory before unnamed bind paths). It uses the WiX v4 schema,
//! which WiX v5, v6 and v7 all read.
//!
//! What the package does, following the shapes the distribution spike
//! checks on the Windows runner (`tools/windows-spike`):
//!
//! - **Files:** the tree under `%ProgramFiles%\<Vendor>\<Directory>`, one
//!   component per file (Rust binaries carry no version resource until
//!   [`crate::pe_version`] stamps one, and WiX derives a stable component
//!   GUID only for a single-file component). The directories have mixed-case ids, so they
//!   are private properties: the install location can't be moved from the
//!   command line.
//! - **Program directory DACL** (service products): `MsiLockPermissionsEx`
//!   with `render::windows::program_dir_sddl`: protected, SYSTEM and
//!   Administrators full control, the service account read and execute.
//! - **The service** (`render::windows::service_record`): `ServiceInstall`
//!   (auto-start, its account, arguments in their own column) and two
//!   `ServiceControl` rows. One stops it on upgrade and removal, waiting
//!   until it has stopped so no file is replaced under it, and removes it
//!   on removal. The other starts it on install without waiting for it to
//!   stay running (`Wait="no"`): a service may retire at once with
//!   exit 0 (an agent not yet enrolled), which isn't a failed install,
//!   yet with `Wait="yes"` Windows Installer waits 30 s for `Running`,
//!   retries, and fails the install with error 1920. A start the service
//!   manager refuses (an image Windows can't load) still fails it.
//! - **Recovery** (the failure actions, also on non-crash exits): two
//!   deferred custom actions running the system's `sc.exe failure` and
//!   `sc.exe failureflag` as LocalSystem, right after `InstallServices`,
//!   on a first install or an upgrade only (`NOT Installed`). A
//!   repair, which a standard user can start, never runs them: a console
//!   program running as SYSTEM during a user-started repair is a known
//!   escalation path, and a repair leaves the recovery settings in place. Not `MsiServiceConfigFailureActions`: Microsoft documents
//!   that table as not working (a restart action fails the install with
//!   error 1939, `MsiConfigureServices` opening the service without
//!   `SERVICE_START`), and recommends `sc.exe` in a custom action. WiX's
//!   `util:ServiceConfig` holds only three actions with one delay. The
//!   commands sit in the `CustomAction` table, readable like any other.
//! - **A rolled-back removal:** an upgrade removes the old version first
//!   (below), so a failed upgrade, like a failed uninstall, has Windows
//!   Installer recreate the removed version's services from its own
//!   record, which holds neither the recovery settings nor the helper's
//!   DACL. The removal sequence carries rollback custom actions that put
//!   them back (`sc.exe failure`, `failureflag`, `sdset`), scheduled just
//!   before `DeleteServices` so a rollback runs them once the services are
//!   back, on a removal only (`REMOVE="ALL"`, which an upgrade's removal of
//!   the old version is). So the version being removed restores its own
//!   values. Not in the upgrading package's sequence: Windows Installer
//!   allows nothing that writes to the script between `InstallInitialize`
//!   and `RemoveExistingProducts` (error 1603).
//! - **State and staging**: `%ProgramData%\<Vendor>\<Directory>\
//!   state`, protected, the service account Modify
//!   (`render::windows::state_dir_sddl`); `…\updates`, protected, SYSTEM
//!   and Administrators only (`updates_dir_sddl`), when the helper ships.
//!   The two directories above them are locked too (`data_dir_sddl`): any
//!   user may create directories in `%ProgramData%`, so each of these
//!   descriptors names SYSTEM the owner (`O:SY`: the installer takes a
//!   pre-creating user's ownership back, since the update helper
//!   and the service refuse an untrusted owner) and carries an OWNER
//!   RIGHTS entry that strips an owner's implicit `WRITE_DAC`. All of them
//!   stay on removal when they hold files.
//! - **Logs** (a service product or a shipped helper):
//!   `%ProgramData%\<Vendor>\<Directory>\logs`, locked like `state` (the
//!   service's account may modify; a desktop product's, SYSTEM and
//!   Administrators alone): where the service writes its log and the update
//!   helper its own (`seaworthy_updater::helper::log_file`), never readable by
//!   every user. Like `state` it stays on removal while it holds files: an
//!   upgrade removes the old product first, and deleting the logs then
//!   would empty them on every update.
//! - **The update helper** (service products, when it ships): a second
//!   `ServiceInstall`, `<service>-update`, LocalSystem, demand-start, whose
//!   DACL lets the main service's account start it and query it, nothing
//!   more (`render::windows::helper_service_sddl`). A desktop product's
//!   helper is the same service under the product's
//!   `<package>-update` (`Product::helper_name`), whose DACL lets
//!   interactive users (`IU`) start it and query it, nothing more: the
//!   helper takes no input, so the most a local user can do is make the
//!   machine install the release the server names. A tool product's helper
//!   ships as a file only (an administrator runs it).
//! - **Update policy default:** `UPDATES=auto|notify|off` (default from
//!   `updates.default`) written to `HKLM\SOFTWARE\<Vendor>\<Directory>`
//!   `UpdatePolicy`. A first install or an upgrade takes `UPDATES=` from
//!   the command line, else the value already installed, else the default;
//!   a command-line value other than the three fails the install (never a
//!   removal). A repair or other maintenance run ignores a command-line
//!   `UPDATES=`, since a standard user can start one, and keeps the
//!   installed value. An installed value that isn't one of the three is
//!   ignored, so a hand edit can't block upgrades. Group Policy's key under
//!   `SOFTWARE\Policies` (the ADMX template, [`crate::admx`]) wins over it.
//! - **The installed release** (when the helper ships): the same key's
//!   `Release`, deb's spelling (`1.4.0~rc.2-812`, `PackageVersions::
//!   msi_release`). ProductVersion holds neither a pre-release nor the
//!   sequence, and the helper's version floor compares both.
//! - **The machine's update server** (when the helper ships): the
//!   optional `SERVER=https://…`, written to the same key's `Server` only
//!   when set (a conditioned component), and kept like `UPDATES=`: a first
//!   install or an upgrade takes the command line, else the installed
//!   value; a repair keeps the installed value. A value not starting with
//!   `https://` fails the install (never a removal); the helper checks the
//!   whole URL (`seaworthy_updater::read_admin_server`). Group Policy's
//!   `Server` wins over it.
//! - **A desktop app** (`[product.<id>.desktop]`): the icon
//!   (`desktop.windows-icon`, staged as `tree/<Vendor>/<Directory>.ico`) in
//!   the Icon table, as Programs and Features' icon (`ARPPRODUCTICON`) and
//!   the shortcuts'; a Start-menu shortcut (`ProgramMenuFolder\<display
//!   name>.lnk`, unless `start-menu = false`) and a desktop one
//!   (`desktop-shortcut = true`, every user's desktop) to the launcher,
//!   started in the install directory. Each shortcut's component keys on an
//!   HKCU value under the product's key, as Windows Installer's validation
//!   requires of a component in the Start-menu or desktop folder: ICE38 and
//!   ICE43 want an HKCU key path there, and ICE57 counts the shortcut as
//!   per-user data even in a per-machine package, refusing an HKLM key path
//!   beside it (the Windows runner). The shortcuts still go to the
//!   all-users folders (`ALLUSERS=1`); the value lands in the installing
//!   user's hive. Non-advertised, they never start a repair for another
//!   user; another administrator's removal leaves that one value behind.
//! - **Data files** (`[[product.<id>.files]]`) in their subdirectories of
//!   the install directory, one component each like every file.
//! - **Programs and Features:** the entry can't be modified
//!   (`ARPNOMODIFY`), names the maintainer and the homepage, and records the
//!   install directory (`ARPINSTALLLOCATION`, set after `CostFinalize`).
//!   The database's code page is UTF-8 (`Codepage="65001"`, WiX's default
//!   pinned): a display name outside one Windows code page still reaches
//!   the entry whole (the Windows update lane's product has one).
//! - **Upgrades:** `MajorUpgrade` removes the installed version first
//!   (`afterInstallInitialize`), allows two builds of one version (the
//!   sequence orders them) and refuses downgrades. The UpgradeCode is
//!   `upgrade-code` from `seaworthy.toml`, else derived from the vendor and the
//!   product id ([`upgrade_code`]).
//!
//! Every value written into the `.wxs` was validated (`config`,
//! `render::windows`) and goes through [`wix_text`]: XML-escaped, and with
//! WiX's own expansions (`$(env.X)`, `$(var.X)`, `$(sys.X)`, `!(bind.X)`,
//! `!(wix.X)`) doubled into literals, so a `seaworthy.toml` value can't pull a
//! CI secret or a build path into the package, or break the build. Several
//! WiX columns are MSI *Formatted* strings, where `[PROPERTY]` expands: the
//! service record refuses brackets, and vendor and directory names can't
//! contain them. No free text goes into XML comments.
//! The `.wxs` is deterministic; the MSI is not byte-reproducible, since
//! WiX gives every build a fresh package code.

use std::collections::{BTreeMap, BTreeSet};

use crate::DistError;
use crate::config::{Config, UpdatePolicy};
use crate::layout::{Layout, Role};
use crate::version::Release;
use seaworthy_service::render::windows::{self as win, HelperGrantee};

/// A deterministic GUID (an RFC 9562 version 8 UUID) from SHA-256 of
/// `parts`, NUL-joined, in registry form (`{…}`, uppercase).
#[must_use]
pub fn derived_guid(parts: &[&str]) -> String {
    let hash = seaworthy_crypto::digest::sha256(parts.join("\0").as_bytes());
    let mut hex = String::with_capacity(38);
    hex.push('{');
    for (i, byte) in hash.iter().take(16).enumerate() {
        let byte = match i {
            6 => (byte & 0x0F) | 0x80, // version 8
            8 => (byte & 0x3F) | 0x80, // the RFC 9562 variant
            _ => *byte,
        };
        if matches!(i, 4 | 6 | 8 | 10) {
            hex.push('-');
        }
        hex.push_str(&format!("{byte:02X}"));
    }
    hex.push('}');
    hex
}

/// The product's UpgradeCode: `upgrade-code` from `seaworthy.toml`, uppercase,
/// else derived from the vendor and product id. Renaming either changes
/// the derived code, and an MSI with another UpgradeCode installs beside
/// the old product instead of upgrading it, so pin `upgrade-code` before
/// renaming.
///
/// # Errors
/// [`DistError::Config`] for an unknown product.
pub fn upgrade_code(config: &Config, id: &str) -> Result<String, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    Ok(product.upgrade_code.as_ref().map_or_else(
        || derived_guid(&["seaworthy upgrade code", &config.defaults.vendor, id]),
        |code| code.to_ascii_uppercase(),
    ))
}

/// A value for a `.wxs` attribute: XML-escaped, with WiX's preprocessor
/// (`$(…)`) and bind-time (`!(…)`) variable syntax doubled so WiX writes it
/// literally (`$$(` and `!!(` are WiX's escapes).
#[must_use]
pub fn wix_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
        .replace("$(", "$$(")
        .replace("!(", "!!(")
}

fn xml(text: &str) -> String {
    wix_text(text)
}

/// A WiX identifier from a file name: `[A-Za-z0-9_.]`, starting with a
/// letter or underscore, at most 72 characters.
fn identifier(prefix: &str, name: &str, n: usize) -> String {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut id = format!("{prefix}{n:03}_{clean}");
    id.truncate(72);
    id
}

fn policy_value(policy: UpdatePolicy) -> &'static str {
    match policy {
        UpdatePolicy::Auto => "auto",
        UpdatePolicy::Notify => "notify",
        UpdatePolicy::Off => "off",
    }
}

/// The `.wxs` for product `id`'s Windows layout, for `release`
/// (ProductVersion `PackageVersions::msi`).
///
/// # Errors
/// [`DistError::Config`] for an unknown product, a non-Windows layout, a
/// file outside the install root, or a service the renderers refuse.
pub fn wxs(
    config: &Config,
    id: &str,
    layout: &Layout,
    release: &Release,
) -> Result<String, DistError> {
    let versions = release.package_versions()?;
    let msi_version = versions.msi.as_str();
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    if layout.triple != crate::inputs::WINDOWS {
        return Err(DistError::Config(format!(
            "an MSI is built from the Windows layout, not {}",
            layout.triple
        )));
    }
    let d = &config.defaults;
    let vendor = &d.vendor;
    let directory = product.windows_directory();
    // The key the app and the helper read the MSI's policy default from.
    let registry_key = config.update_product(id, product)?.install_key();
    let upgrade = upgrade_code(config, id)?;
    let component_guid = |what: &str| derived_guid(&["seaworthy component", &upgrade, what]);
    let render = |e: seaworthy_service::ServiceError| {
        DistError::Config(format!("product.{id}.service: {e}"))
    };
    let helper_ships = layout.helper().is_some();
    // A desktop product's helper service: its name and the DACL that
    // lets interactive users start it.
    let desktop_helper = if helper_ships && product.kind == crate::config::Kind::Desktop {
        let sddl = win::helper_service_sddl(&HelperGrantee::InteractiveUsers).map_err(render)?;
        Some((config.update_product(id, product)?.helper_name(), sddl))
    } else {
        None
    };

    // The service, rendered once for every table it feeds.
    let service = match (&product.service, layout.launcher()) {
        (Some(_), Some(launcher)) => {
            let spec = config.service_spec(
                id,
                product,
                std::path::Path::new(&format!("C:\\Program Files\\{}", launcher.install_path)),
            )?;
            let record = win::service_record(&spec).map_err(render)?;
            let program_sddl = win::program_dir_sddl(&spec).map_err(render)?;
            let state_sddl = win::state_dir_sddl(&spec).map_err(render)?;
            let grantee = record.account_sid.clone().ok_or_else(|| {
                DistError::Config(format!(
                    "product.{id}.service: the account has no SID to grant the helper"
                ))
            })?;
            let helper_sddl =
                win::helper_service_sddl(&HelperGrantee::Service(grantee)).map_err(render)?;
            Some((record, program_sddl, state_sddl, helper_sddl))
        }
        (Some(_), None) => {
            return Err(DistError::Config(format!(
                "product {id}'s Windows layout has no launcher"
            )));
        }
        (None, _) => None,
    };

    let mut w = String::new();
    let mut line = |indent: usize, text: &str| {
        if !text.is_empty() {
            w.push_str(&" ".repeat(indent));
            w.push_str(text);
        }
        w.push('\n');
    };
    line(0, "<?xml version=\"1.0\" encoding=\"utf-8\"?>");
    line(0, "<!--");
    line(
        2,
        &format!(
            "Generated by seaworthy from seaworthy.toml: product {id}, ProductVersion {msi_version}."
        ),
    );
    line(2, "Build it with the pinned WiX:");
    line(
        4,
        "wix build -arch x64 -bindpath tree=<tree> -o <name>.msi <name>.wxs",
    );
    line(
        2,
        "where <tree> is the Windows layout's staging tree. Don't edit: regenerate.",
    );
    line(0, "-->");
    line(0, "<Wix xmlns=\"http://wixtoolset.org/schemas/v4/wxs\">");
    line(
        2,
        &format!(
            "<Package Name=\"{}\" Manufacturer=\"{}\" Version=\"{}\" UpgradeCode=\"{upgrade}\" Scope=\"perMachine\" Language=\"1033\" Codepage=\"65001\" Compressed=\"yes\" InstallerVersion=\"500\">",
            xml(&product.display_name),
            xml(vendor),
            xml(msi_version)
        ),
    );
    line(
        4,
        &format!(
            "<SummaryInformation Description=\"{}\" Manufacturer=\"{}\" />",
            xml(&product.description),
            xml(vendor)
        ),
    );
    line(
        4,
        "<MajorUpgrade AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallInitialize\" DowngradeErrorMessage=\"A newer version of [ProductName] is already installed.\" />",
    );
    line(
        4,
        "<MediaTemplate EmbedCab=\"yes\" CompressionLevel=\"high\" />",
    );
    line(
        4,
        "<Launch Condition=\"VersionNT64\" Message=\"[ProductName] requires 64-bit Windows.\" />",
    );
    line(4, "<Property Id=\"ARPNOMODIFY\" Value=\"1\" />");
    // Programs and Features' install location (the Uninstall key's
    // `InstallLocation`), which inventory tools read; an MSI leaves it
    // empty unless the package sets it.
    line(
        4,
        "<SetProperty Id=\"ARPINSTALLLOCATION\" Value=\"[InstallDir]\" After=\"CostFinalize\" Sequence=\"execute\" />",
    );
    if let Some(icon) = &layout.icon {
        line(
            4,
            &format!(
                "<Icon Id=\"ProductIcon.ico\" SourceFile=\"!(bindpath.tree)\\{}\" />",
                xml(&icon.install_path)
            ),
        );
        line(
            4,
            "<Property Id=\"ARPPRODUCTICON\" Value=\"ProductIcon.ico\" />",
        );
    }
    line(
        4,
        &format!(
            "<Property Id=\"ARPCONTACT\" Value=\"{}\" />",
            xml(&d.maintainer)
        ),
    );
    if let Some(homepage) = &d.homepage {
        line(
            4,
            &format!(
                "<Property Id=\"ARPURLINFOABOUT\" Value=\"{}\" />",
                xml(homepage)
            ),
        );
    }
    if helper_ships {
        let default = policy_value(product.updates.default);
        // The installed value counts only when it's one of the three: a
        // hand edit must never block every later upgrade.
        let saved_ok = "(SAVEDUPDATES = &quot;auto&quot; OR SAVEDUPDATES = &quot;notify&quot; OR SAVEDUPDATES = &quot;off&quot;)";
        line(4, "");
        line(
            4,
            "<!-- The update policy default. First install or upgrade: UPDATES= from the command line, else the",
        );
        line(
            4,
            "     installed value, else seaworthy.toml's. Maintenance (repair), which a standard user can start: the",
        );
        line(
            4,
            "     installed value, else seaworthy.toml's; a command-line UPDATES= is ignored. Group Policy wins. -->",
        );
        line(4, "<Property Id=\"SAVEDUPDATES\">");
        line(
            6,
            &format!(
                "<RegistrySearch Id=\"SavedUpdatePolicy\" Root=\"HKLM\" Key=\"{}\" Name=\"UpdatePolicy\" Type=\"raw\" Bitness=\"always64\" />",
                xml(&registry_key)
            ),
        );
        line(4, "</Property>");
        line(4, "<Property Id=\"UPDATES\" Secure=\"yes\" />");
        line(
            4,
            &format!(
                "<SetProperty Id=\"UPDATES\" Action=\"SetUpdatesForMaintenance\" Value=\"[SAVEDUPDATES]\" After=\"AppSearch\" Condition=\"Installed AND {saved_ok}\" Sequence=\"both\" />"
            ),
        );
        line(
            4,
            &format!(
                "<SetProperty Id=\"UPDATES\" Action=\"SetUpdatesDefaultForMaintenance\" Value=\"{default}\" After=\"SetUpdatesForMaintenance\" Condition=\"Installed AND NOT {saved_ok}\" Sequence=\"both\" />"
            ),
        );
        line(
            4,
            &format!(
                "<SetProperty Id=\"UPDATES\" Action=\"SetUpdatesFromInstalled\" Value=\"[SAVEDUPDATES]\" After=\"SetUpdatesDefaultForMaintenance\" Condition=\"NOT Installed AND NOT UPDATES AND {saved_ok}\" Sequence=\"both\" />"
            ),
        );
        line(
            4,
            &format!(
                "<SetProperty Id=\"UPDATES\" Action=\"SetUpdatesDefault\" Value=\"{default}\" After=\"SetUpdatesFromInstalled\" Condition=\"NOT UPDATES\" Sequence=\"both\" />"
            ),
        );
        // Never on removal: nothing about the policy may block an uninstall.
        line(
            4,
            "<Launch Condition=\"REMOVE = &quot;ALL&quot; OR UPDATES = &quot;auto&quot; OR UPDATES = &quot;notify&quot; OR UPDATES = &quot;off&quot;\" Message=\"UPDATES must be auto, notify or off.\" />",
        );
        line(4, "");
        line(
            4,
            "<!-- The machine's update server, optional. First install or upgrade: SERVER= from the command",
        );
        line(
            4,
            "     line, else the installed value. Maintenance (repair): the installed value; a command-line SERVER= is",
        );
        line(
            4,
            "     ignored. Written only when set; Group Policy's Server wins. The helper checks the URL itself. -->",
        );
        line(4, "<Property Id=\"SAVEDSERVER\">");
        line(
            6,
            &format!(
                "<RegistrySearch Id=\"SavedServer\" Root=\"HKLM\" Key=\"{}\" Name=\"Server\" Type=\"raw\" Bitness=\"always64\" />",
                xml(&registry_key)
            ),
        );
        line(4, "</Property>");
        line(4, "<Property Id=\"SERVER\" Secure=\"yes\" />");
        line(
            4,
            "<SetProperty Id=\"SERVER\" Action=\"SetServerForMaintenance\" Value=\"[SAVEDSERVER]\" After=\"SetUpdatesDefault\" Condition=\"Installed\" Sequence=\"both\" />",
        );
        line(
            4,
            "<SetProperty Id=\"SERVER\" Action=\"SetServerFromInstalled\" Value=\"[SAVEDSERVER]\" After=\"SetServerForMaintenance\" Condition=\"NOT Installed AND NOT SERVER AND SAVEDSERVER\" Sequence=\"both\" />",
        );
        // Never on removal, like UPDATES.
        line(
            4,
            "<Launch Condition=\"REMOVE = &quot;ALL&quot; OR NOT SERVER OR SERVER ~&lt;&lt; &quot;https://&quot;\" Message=\"SERVER must be an https:// URL.\" />",
        );
    }
    // The helper service the package installs, if any: its name and DACL.
    let helper_service = match (&service, &desktop_helper) {
        (Some((record, _, _, sddl)), _) if helper_ships => {
            Some((format!("{}-update", record.name), sddl.as_str()))
        }
        (None, Some((name, sddl))) => Some((name.clone(), sddl.as_str())),
        _ => None,
    };
    let sc = |arguments: &str| xml(&format!("\"[System64Folder]sc.exe\" {arguments}"));
    // `deferred` runs on a first install or an upgrade; `rollback`, when a
    // removal (an upgrade's of this version, or an uninstall) fails, once
    // Windows Installer has put this version's services back (their
    // scheduling below).
    let custom_action = |id: &str, execute: &str, command: &str| {
        let ret = if execute == "rollback" {
            "ignore"
        } else {
            "check"
        };
        format!(
            "<CustomAction Id=\"{id}\" Directory=\"System64Folder\" ExeCommand=\"{}\" Execute=\"{execute}\" Impersonate=\"no\" Return=\"{ret}\" />",
            sc(command)
        )
    };
    let mut sequence: Vec<String> = Vec::new();
    let mut rollbacks: Vec<&str> = Vec::new();
    if service.is_some() || helper_service.is_some() {
        line(4, "");
        line(4, "<StandardDirectory Id=\"System64Folder\" />");
    }
    if let Some((record, _, _, _)) = &service {
        let actions = &record.failure_actions;
        let restarts: Vec<String> = actions
            .restart_delays_ms
            .iter()
            .map(|delay| format!("restart/{delay}"))
            .collect();
        let failure = format!(
            "failure {} reset= {} actions= {}",
            record.name,
            actions.reset_period_secs,
            restarts.join("/")
        );
        let flag = format!(
            "failureflag {} {}",
            record.name,
            u8::from(actions.on_non_crash_failures)
        );
        line(
            4,
            "<!-- Recovery: sc.exe, as MsiServiceConfigFailureActions is documented broken.",
        );
        line(
            4,
            "     First install and upgrade only: never in a repair a standard user can start.",
        );
        line(
            4,
            "     Again when this version's removal rolls back: the service comes back without them. -->",
        );
        line(4, &custom_action("ServiceRecovery", "deferred", &failure));
        line(
            4,
            &custom_action("ServiceRecoveryOnErrorExit", "deferred", &flag),
        );
        line(
            4,
            &custom_action("ServiceRecoveryRollback", "rollback", &failure),
        );
        line(
            4,
            &custom_action("ServiceRecoveryOnErrorExitRollback", "rollback", &flag),
        );
        sequence.push(
            "<Custom Action=\"ServiceRecovery\" After=\"InstallServices\" Condition=\"NOT Installed AND NOT REMOVE=&quot;ALL&quot;\" />".to_owned(),
        );
        sequence.push(
            "<Custom Action=\"ServiceRecoveryOnErrorExit\" After=\"ServiceRecovery\" Condition=\"NOT Installed AND NOT REMOVE=&quot;ALL&quot;\" />".to_owned(),
        );
        rollbacks.extend([
            "ServiceRecoveryRollback",
            "ServiceRecoveryOnErrorExitRollback",
        ]);
    }
    if let Some((name, sddl)) = &helper_service {
        line(
            4,
            "<!-- When this version's removal rolls back, the helper service comes back without its DACL. -->",
        );
        line(
            4,
            &custom_action(
                "HelperServiceDaclRollback",
                "rollback",
                &format!("sdset {name} {sddl}"),
            ),
        );
        rollbacks.push("HelperServiceDaclRollback");
    }
    // A rollback action runs when the rollback reaches its place in the
    // script, so these go before DeleteServices: its deletions are undone
    // first, then they run.
    for action in &rollbacks {
        sequence.push(format!(
            "<Custom Action=\"{action}\" Before=\"DeleteServices\" Condition=\"Installed AND REMOVE=&quot;ALL&quot;\" />"
        ));
    }
    if !sequence.is_empty() {
        line(4, "<InstallExecuteSequence>");
        for custom in &sequence {
            line(6, custom);
        }
        line(4, "</InstallExecuteSequence>");
    }
    // Every file's path below the install directory, and the directories
    // they need, each with its id (sorted by component: a depth-first walk).
    let prefix = format!("{}\\", layout.install_root);
    let relatives = layout
        .files
        .iter()
        .map(|file| {
            file.install_path
                .strip_prefix(&prefix)
                .filter(|relative| {
                    !relative.is_empty() && relative.split('\\').all(|part| !part.is_empty())
                })
                .ok_or_else(|| {
                    DistError::Config(format!(
                        "{} is not a file under {}",
                        file.install_path, layout.install_root
                    ))
                })
        })
        .collect::<Result<Vec<&str>, DistError>>()?;
    let mut directories: BTreeSet<Vec<&str>> = BTreeSet::new();
    for relative in &relatives {
        let parts: Vec<&str> = relative.split('\\').collect();
        for depth in 1..parts.len() {
            directories.insert(parts[..depth].to_vec());
        }
    }
    let directory_ids: BTreeMap<Vec<&str>, String> = directories
        .iter()
        .enumerate()
        .map(|(n, parts)| (parts.clone(), identifier("d", &parts.join("_"), n)))
        .collect();
    let directory_of = |relative: &str| -> String {
        let mut parts: Vec<&str> = relative.split('\\').collect();
        parts.pop();
        directory_ids
            .get(&parts)
            .cloned()
            .unwrap_or_else(|| "InstallDir".to_owned())
    };
    line(4, "");
    line(4, "<StandardDirectory Id=\"ProgramFiles64Folder\">");
    line(
        6,
        &format!("<Directory Id=\"VendorDir\" Name=\"{}\">", xml(vendor)),
    );
    if directories.is_empty() {
        line(
            8,
            &format!(
                "<Directory Id=\"InstallDir\" Name=\"{}\" />",
                xml(&directory)
            ),
        );
    } else {
        line(
            8,
            &format!("<Directory Id=\"InstallDir\" Name=\"{}\">", xml(&directory)),
        );
        let mut open: Vec<&str> = Vec::new();
        for parts in &directories {
            while !(open.len() < parts.len() && parts[..open.len()] == open[..]) {
                open.pop();
                line(10 + 2 * open.len(), "</Directory>");
            }
            let name = parts.last().copied().unwrap_or_default();
            line(
                10 + 2 * open.len(),
                &format!(
                    "<Directory Id=\"{}\" Name=\"{}\">",
                    directory_ids[parts],
                    xml(name)
                ),
            );
            open.push(name);
        }
        while !open.is_empty() {
            open.pop();
            line(10 + 2 * open.len(), "</Directory>");
        }
        line(8, "</Directory>");
    }
    line(6, "</Directory>");
    line(4, "</StandardDirectory>");
    let shortcuts: Vec<(&str, &str)> = product
        .desktop
        .as_ref()
        .map(|desktop| {
            let mut wanted = Vec::new();
            if desktop.start_menu {
                wanted.push(("StartMenuShortcut", "ProgramMenuFolder"));
            }
            if desktop.desktop_shortcut {
                wanted.push(("DesktopShortcut", "DesktopFolder"));
            }
            wanted
        })
        .unwrap_or_default();
    for (_, folder) in &shortcuts {
        line(4, &format!("<StandardDirectory Id=\"{folder}\" />"));
    }
    if service.is_some() || helper_ships {
        line(4, "<StandardDirectory Id=\"CommonAppDataFolder\">");
        line(
            6,
            &format!("<Directory Id=\"DataVendorDir\" Name=\"{}\">", xml(vendor)),
        );
        line(
            8,
            &format!("<Directory Id=\"DataDir\" Name=\"{}\">", xml(&directory)),
        );
        if service.is_some() {
            line(10, "<Directory Id=\"StateDir\" Name=\"state\" />");
        }
        if helper_ships {
            line(10, "<Directory Id=\"UpdatesDir\" Name=\"updates\" />");
        }
        line(10, "<Directory Id=\"LogsDir\" Name=\"logs\" />");
        line(8, "</Directory>");
        line(6, "</Directory>");
        line(4, "</StandardDirectory>");
    }
    line(4, "");
    line(
        4,
        &format!(
            "<Feature Id=\"Main\" Title=\"{}\" AllowAbsent=\"no\">",
            xml(&product.display_name)
        ),
    );

    let mut launcher_id = None;
    for (n, (file, relative)) in layout.files.iter().zip(&relatives).enumerate() {
        let file_id = identifier("f", relative, n);
        let component_id = identifier("c", relative, n);
        if file.role == Role::Launcher {
            launcher_id = Some(file_id.clone());
        }
        line(
            6,
            &format!(
                "<Component Id=\"{component_id}\" Directory=\"{}\" Bitness=\"always64\">",
                directory_of(relative)
            ),
        );
        line(
            8,
            &format!(
                "<File Id=\"{file_id}\" Source=\"!(bindpath.tree)\\{}\" KeyPath=\"yes\" />",
                xml(&file.install_path)
            ),
        );
        match (&file.role, &service) {
            (Role::Launcher, Some((record, _, _, _))) => {
                let mut install = format!(
                    "<ServiceInstall Id=\"Service\" Name=\"{}\" DisplayName=\"{}\" Description=\"{}\" Type=\"ownProcess\" Start=\"auto\" ErrorControl=\"normal\" Vital=\"yes\" Account=\"{}\"",
                    xml(&record.name),
                    xml(&record.display_name),
                    xml(&record.description),
                    xml(&record.account)
                );
                if !record.arguments.is_empty() {
                    install.push_str(&format!(" Arguments=\"{}\"", xml(&record.arguments)));
                }
                install.push_str(" />");
                line(8, &install);
                line(
                    8,
                    &format!(
                        "<ServiceControl Id=\"ServiceControl\" Name=\"{}\" Stop=\"both\" Remove=\"uninstall\" Wait=\"yes\" />",
                        xml(&record.name)
                    ),
                );
                line(
                    8,
                    &format!(
                        "<ServiceControl Id=\"ServiceStart\" Name=\"{}\" Start=\"install\" Wait=\"no\" />",
                        xml(&record.name)
                    ),
                );
            }
            (Role::Helper, Some((record, _, _, helper_sddl))) => {
                let name = format!("{}-update", record.name);
                line(
                    8,
                    &format!(
                        "<ServiceInstall Id=\"HelperService\" Name=\"{}\" DisplayName=\"{} updater\" Description=\"Installs signed releases of {}.\" Type=\"ownProcess\" Start=\"demand\" ErrorControl=\"normal\" Vital=\"yes\" Account=\"LocalSystem\">",
                        xml(&name),
                        xml(&record.display_name),
                        xml(&record.display_name)
                    ),
                );
                line(
                    10,
                    &format!("<PermissionEx Sddl=\"{}\" />", xml(helper_sddl)),
                );
                line(8, "</ServiceInstall>");
                line(
                    8,
                    &format!(
                        "<ServiceControl Id=\"HelperServiceControl\" Name=\"{}\" Stop=\"both\" Remove=\"uninstall\" Wait=\"yes\" />",
                        xml(&name)
                    ),
                );
            }
            (Role::Helper, None) => {
                if let Some((name, helper_sddl)) = &desktop_helper {
                    line(
                        8,
                        &format!(
                            "<ServiceInstall Id=\"HelperService\" Name=\"{}\" DisplayName=\"{} updater\" Description=\"Installs signed releases of {}.\" Type=\"ownProcess\" Start=\"demand\" ErrorControl=\"normal\" Vital=\"yes\" Account=\"LocalSystem\">",
                            xml(name),
                            xml(&product.display_name),
                            xml(&product.display_name)
                        ),
                    );
                    line(
                        10,
                        &format!("<PermissionEx Sddl=\"{}\" />", xml(helper_sddl)),
                    );
                    line(8, "</ServiceInstall>");
                    line(
                        8,
                        &format!(
                            "<ServiceControl Id=\"HelperServiceControl\" Name=\"{}\" Stop=\"both\" Remove=\"uninstall\" Wait=\"yes\" />",
                            xml(name)
                        ),
                    );
                }
            }
            _ => {}
        }
        line(6, "</Component>");
    }
    if let Some((_, program_sddl, state_sddl, _)) = &service {
        line(
            6,
            &format!(
                "<Component Id=\"InstallDirAcl\" Directory=\"InstallDir\" Guid=\"{}\" Bitness=\"always64\">",
                component_guid("InstallDirAcl")
            ),
        );
        line(8, "<CreateFolder>");
        line(
            10,
            &format!("<PermissionEx Sddl=\"{}\" />", xml(program_sddl)),
        );
        line(8, "</CreateFolder>");
        line(6, "</Component>");
        line(
            6,
            &format!(
                "<Component Id=\"StateDir\" Directory=\"StateDir\" Guid=\"{}\" Bitness=\"always64\">",
                component_guid("StateDir")
            ),
        );
        line(8, "<CreateFolder>");
        line(
            10,
            &format!("<PermissionEx Sddl=\"{}\" />", xml(state_sddl)),
        );
        line(8, "</CreateFolder>");
        line(6, "</Component>");
    }
    if service.is_some() || helper_ships {
        // The logs: the service's and the helper's, locked like
        // `state` (the service's account writes; for a desktop product's
        // helper, SYSTEM and Administrators alone), never readable by
        // every user as an inherited Program Files folder was.
        let logs_sddl = match &service {
            Some((_, _, state_sddl, _)) => state_sddl.clone(),
            None => win::updates_dir_sddl(),
        };
        line(
            6,
            &format!(
                "<Component Id=\"LogsDir\" Directory=\"LogsDir\" Guid=\"{}\" Bitness=\"always64\">",
                component_guid("LogsDir")
            ),
        );
        line(8, "<CreateFolder>");
        line(
            10,
            &format!("<PermissionEx Sddl=\"{}\" />", xml(&logs_sddl)),
        );
        line(8, "</CreateFolder>");
        line(6, "</Component>");
        for (component, dir) in [
            ("DataVendorDirAcl", "DataVendorDir"),
            ("DataDirAcl", "DataDir"),
        ] {
            line(
                6,
                &format!(
                    "<Component Id=\"{component}\" Directory=\"{dir}\" Guid=\"{}\" Bitness=\"always64\">",
                    component_guid(component)
                ),
            );
            line(8, "<CreateFolder>");
            line(
                10,
                &format!("<PermissionEx Sddl=\"{}\" />", xml(&win::data_dir_sddl())),
            );
            line(8, "</CreateFolder>");
            line(6, "</Component>");
        }
    }
    if helper_ships {
        line(
            6,
            &format!(
                "<Component Id=\"UpdatesDir\" Directory=\"UpdatesDir\" Guid=\"{}\" Bitness=\"always64\">",
                component_guid("UpdatesDir")
            ),
        );
        line(8, "<CreateFolder>");
        line(
            10,
            &format!(
                "<PermissionEx Sddl=\"{}\" />",
                xml(&win::updates_dir_sddl())
            ),
        );
        line(8, "</CreateFolder>");
        line(6, "</Component>");
        line(
            6,
            &format!(
                "<Component Id=\"UpdatePolicyDefault\" Directory=\"InstallDir\" Guid=\"{}\" Bitness=\"always64\">",
                component_guid("UpdatePolicyDefault")
            ),
        );
        line(
            8,
            &format!(
                "<RegistryValue Root=\"HKLM\" Key=\"{}\" Name=\"UpdatePolicy\" Type=\"string\" Value=\"[UPDATES]\" KeyPath=\"yes\" />",
                xml(&registry_key)
            ),
        );
        line(
            8,
            &format!(
                "<RegistryValue Root=\"HKLM\" Key=\"{}\" Name=\"{}\" Type=\"string\" Value=\"{}\" />",
                xml(&registry_key),
                seaworthy_updater::MSI_RELEASE_VALUE,
                xml(&versions.msi_release)
            ),
        );
        line(6, "</Component>");
        // Only when SERVER is set: no empty value stands in for "unset".
        line(
            6,
            &format!(
                "<Component Id=\"UpdateServer\" Directory=\"InstallDir\" Guid=\"{}\" Bitness=\"always64\" Condition=\"SERVER\">",
                component_guid("UpdateServer")
            ),
        );
        line(
            8,
            &format!(
                "<RegistryValue Root=\"HKLM\" Key=\"{}\" Name=\"Server\" Type=\"string\" Value=\"[SERVER]\" KeyPath=\"yes\" />",
                xml(&registry_key)
            ),
        );
        line(6, "</Component>");
    }
    if !shortcuts.is_empty() {
        let target = launcher_id.ok_or_else(|| {
            DistError::Config(format!(
                "product {id}'s Windows layout has no launcher for its shortcuts"
            ))
        })?;
        let icon = if layout.icon.is_some() {
            " Icon=\"ProductIcon.ico\""
        } else {
            ""
        };
        // `Shortcut.Description` holds 255 characters (ASCII dots: one
        // byte in the package's UTF-8 code page).
        let description = if product.description.chars().count() > 255 {
            let mut cut: String = product.description.chars().take(252).collect();
            cut.push_str("...");
            cut
        } else {
            product.description.clone()
        };
        for (shortcut, folder) in &shortcuts {
            line(
                6,
                &format!(
                    "<Component Id=\"{shortcut}\" Directory=\"{folder}\" Guid=\"{}\" Bitness=\"always64\">",
                    component_guid(shortcut)
                ),
            );
            line(
                8,
                &format!(
                    "<Shortcut Id=\"{shortcut}\" Name=\"{}\" Description=\"{}\" Target=\"[#{target}]\" WorkingDirectory=\"InstallDir\"{icon} />",
                    xml(&product.display_name),
                    xml(&description)
                ),
            );
            line(
                8,
                &format!(
                    "<RegistryValue Root=\"HKCU\" Key=\"{}\" Name=\"{shortcut}\" Type=\"integer\" Value=\"1\" KeyPath=\"yes\" />",
                    xml(&registry_key)
                ),
            );
            line(6, "</Component>");
        }
    }
    line(4, "</Feature>");
    line(2, "</Package>");
    line(0, "</Wix>");
    Ok(w)
}
