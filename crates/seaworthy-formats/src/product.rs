//! A product's names: everything the app side, the update helper and the
//! seaworthy CLI must agree on, derived in one place.
//!
//! The seaworthy CLI names the package, the release manifests' product and
//! channel, the helper's staging directory, the update request file, the
//! update-policy registry keys and the `/etc` policy file from
//! `seaworthy.toml`. The helper and the app must use exactly the same
//! names, or every update fails in the field (a manifest for another
//! product, a request file nobody watches). So the helper reads them from
//! the same `seaworthy.toml`, compiled in:
//!
//! ```
//! # fn main() -> Result<(), seaworthy_formats::ProductError> {
//! // A helper's main reads its product's seaworthy.toml, compiled in:
//! // `include_str!("../../seaworthy.toml")`.
//! let config = r#"
//! [defaults]
//! vendor = "Acme"
//! channel = "stable"
//!
//! [product.agent]
//! display-name = "Acme Agent"
//! executable = "AcmeAgent"
//!
//! [product.agent.service]
//! name = "AcmeAgent"
//! state-directory = "acme/agent"
//! "#;
//! let product = seaworthy_formats::Product::from_config(config, "agent")?;
//! assert_eq!(product.package(), "acme-agent");
//! assert_eq!(product.helper_service().as_deref(), Some("AcmeAgent-update"));
//! # Ok(())
//! # }
//! ```
//!
//! and the seaworthy CLI builds the same [`Product`] from its validated
//! configuration (its tests check the two readings agree).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::manifest::ReleaseTrust;
use crate::policy::UpdatePolicy;

/// Why a product's names were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("product names: {0}")]
pub struct ProductError(String);

/// The service a product runs, if it is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceNames {
    /// The service's name: the systemd unit stem, the launchd label and
    /// the Windows service name (`AcmeAgent`).
    pub name: String,
    /// Its state directory under `/var/lib` (`acme/agent`), which holds
    /// the update request file. Required when the helper ships.
    pub state_directory: Option<String>,
}

/// A product's names (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    vendor: String,
    id: String,
    windows_directory: String,
    channel: String,
    service: Option<ServiceNames>,
    default_policy: UpdatePolicy,
    macos_bundle_id: Option<String>,
    release_trust: ReleaseTrust,
}

/// A reverse-DNS bundle identifier: at least two dot-separated labels of
/// `[A-Za-z0-9-]`, at most 155 bytes (the seaworthy CLI's rule for
/// `[product.<id>.macos] bundle-id`).
fn is_bundle_id(text: &str) -> bool {
    text.len() <= 155
        && text.split('.').count() >= 2
        && text.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 64 bytes: a directory name on
/// both platforms and a registry key segment (the seaworthy CLI's rule).
fn is_directory_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[a-z0-9][a-z0-9-]*`, at most 64 bytes: product ids and channels.
fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Relative segments over `[A-Za-z0-9._@+-]`, none `.` or `..`: a systemd
/// `StateDirectory=`.
fn is_state_directory(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && text.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-')
                })
        })
}

impl Product {
    /// A product's names: `vendor` (`Acme`) and the Windows directory
    /// (`Agent`) as directory names, `id` (`agent`) and `channel`
    /// (`stable`) as `[a-z0-9-]` identifiers. No service, and the default
    /// update policy `auto`, until set.
    ///
    /// # Errors
    /// [`ProductError`] for a name outside its grammar.
    pub fn new(
        vendor: &str,
        id: &str,
        windows_directory: &str,
        channel: &str,
    ) -> Result<Self, ProductError> {
        if !is_directory_name(vendor) {
            return Err(ProductError(format!(
                "vendor {vendor:?} must be [A-Za-z0-9][A-Za-z0-9._-]*, at most 64 bytes"
            )));
        }
        if !is_directory_name(windows_directory) {
            return Err(ProductError(format!(
                "windows directory {windows_directory:?} must be [A-Za-z0-9][A-Za-z0-9._-]*, at most 64 bytes"
            )));
        }
        if !is_identifier(id) {
            return Err(ProductError(format!(
                "product id {id:?} must be [a-z0-9][a-z0-9-]*, at most 64 bytes"
            )));
        }
        if !is_identifier(channel) {
            return Err(ProductError(format!(
                "channel {channel:?} must be [a-z0-9][a-z0-9-]*, at most 64 bytes"
            )));
        }
        Ok(Self {
            vendor: vendor.to_owned(),
            id: id.to_owned(),
            windows_directory: windows_directory.to_owned(),
            channel: channel.to_owned(),
            service: None,
            default_policy: UpdatePolicy::Auto,
            macos_bundle_id: None,
            release_trust: ReleaseTrust::AnyKey,
        })
    }

    /// The service the product runs.
    ///
    /// # Errors
    /// [`ProductError`] for a service name outside
    /// `[A-Za-z0-9][A-Za-z0-9._-]*` (at most 64 bytes) or a state directory
    /// outside systemd's `StateDirectory=` grammar.
    pub fn with_service(mut self, service: ServiceNames) -> Result<Self, ProductError> {
        if !is_directory_name(&service.name) {
            return Err(ProductError(format!(
                "service name {:?} must be [A-Za-z0-9][A-Za-z0-9._-]*, at most 64 bytes",
                service.name
            )));
        }
        if let Some(state) = &service.state_directory
            && !is_state_directory(state)
        {
            return Err(ProductError(format!(
                "state directory {state:?} must be relative segments over [A-Za-z0-9._@+-]"
            )));
        }
        self.service = Some(service);
        Ok(self)
    }

    /// The update policy when nothing on the machine sets one
    /// (`seaworthy.toml`'s `updates.default`).
    #[must_use]
    pub fn with_default_policy(mut self, policy: UpdatePolicy) -> Self {
        self.default_policy = policy;
        self
    }

    /// Which signatures the product's helper requires of a release
    /// manifest (`seaworthy.toml`'s `[defaults] release-trust`; default
    /// [`ReleaseTrust::AnyKey`]). [`ManifestTrust::for_product`](crate::ManifestTrust::for_product)
    /// applies it.
    #[must_use]
    pub fn with_release_trust(mut self, release_trust: ReleaseTrust) -> Self {
        self.release_trust = release_trust;
        self
    }

    /// Which signatures the product's helper requires of a release
    /// manifest.
    #[must_use]
    pub fn release_trust(&self) -> ReleaseTrust {
        self.release_trust
    }

    /// Reads product `id`'s names from a `seaworthy.toml` (see the module
    /// docs). Only the settings that name things are read, and anything
    /// else in the file is ignored; the seaworthy CLI validates the whole
    /// file when it packages. The keys read:
    ///
    /// - `[defaults]` `vendor` and `channel` (both required), and
    ///   `release-trust` (`any-key` or `every-algorithm`; else `any-key`);
    /// - `[product.<id>]` `display-name` and `executable` (required), and
    ///   `windows-directory` (else the display name's last word, else the
    ///   executable);
    /// - `[product.<id>]` `updates.default` (`auto`, `notify` or `off`;
    ///   else `auto`);
    /// - `[product.<id>.service]` `name` (required in the table) and
    ///   `state-directory`;
    /// - `[product.<id>.macos]` `bundle-id` (required in the table).
    ///
    /// # Errors
    /// [`ProductError`] for text that isn't TOML, a missing product or
    /// setting, or a name outside its grammar.
    pub fn from_config(text: &str, id: &str) -> Result<Self, ProductError> {
        let file: ConfigFile =
            toml::from_str(text).map_err(|e| ProductError(format!("seaworthy.toml: {e}")))?;
        let entry = file
            .product
            .get(id)
            .ok_or_else(|| ProductError(format!("seaworthy.toml has no [product.{id}]")))?;
        let windows_directory = entry.windows_directory.clone().unwrap_or_else(|| {
            entry
                .display_name
                .split_whitespace()
                .last()
                .unwrap_or(&entry.executable)
                .to_owned()
        });
        let mut product = Self::new(
            &file.defaults.vendor,
            id,
            &windows_directory,
            &file.defaults.channel,
        )?
        .with_default_policy(entry.updates.default)
        .with_release_trust(file.defaults.release_trust);
        if let Some(service) = &entry.service {
            product = product.with_service(ServiceNames {
                name: service.name.clone(),
                state_directory: service.state_directory.clone(),
            })?;
        }
        if let Some(macos) = &entry.macos {
            product = product.with_macos_bundle_id(&macos.bundle_id)?;
        }
        Ok(product)
    }

    /// The product's macOS bundle identifier (`[product.<id>.macos]
    /// bundle-id`): its app bundle's, and its package's (`pkgbuild
    /// --identifier`, the receipt `pkgutil` reads).
    ///
    /// # Errors
    /// [`ProductError`] for an identifier outside the reverse-DNS grammar.
    pub fn with_macos_bundle_id(mut self, bundle_id: &str) -> Result<Self, ProductError> {
        if !is_bundle_id(bundle_id) {
            return Err(ProductError(format!(
                "macOS bundle id {bundle_id:?} is not reverse-DNS (at least two dot-separated labels of [A-Za-z0-9-], at most 155 bytes)"
            )));
        }
        self.macos_bundle_id = Some(bundle_id.to_owned());
        Ok(self)
    }

    /// The macOS package's identifier, the bundle id: `None` for a product
    /// with no macOS outputs.
    #[must_use]
    pub fn macos_package_id(&self) -> Option<&str> {
        self.macos_bundle_id.as_deref()
    }

    /// The vendor (`Acme`).
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// The product id (`agent`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The product's directory name (`Agent`, `seaworthy.toml`'s
    /// `windows-directory`): the Windows install, state and staging
    /// directories and the registry keys, and the macOS support and log
    /// directories.
    #[must_use]
    pub fn windows_directory(&self) -> &str {
        &self.windows_directory
    }

    /// The release channel (`stable`): every manifest names it.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// The service, if the product runs one.
    #[must_use]
    pub fn service(&self) -> Option<&ServiceNames> {
        self.service.as_ref()
    }

    /// The default update policy.
    #[must_use]
    pub fn default_policy(&self) -> UpdatePolicy {
        self.default_policy
    }

    /// The Linux package name, `<vendor>-<id>` in lowercase: also every
    /// release manifest's `product`.
    #[must_use]
    pub fn package(&self) -> String {
        format!("{}-{}", self.vendor.to_ascii_lowercase(), self.id)
    }

    /// The helper's systemd `CacheDirectory=`, `<vendor>/<id>` in
    /// lowercase: its staging directory, `/var/cache/<vendor>/<id>`.
    #[must_use]
    pub fn cache_directory(&self) -> String {
        format!("{}/{}", self.vendor.to_ascii_lowercase(), self.id)
    }

    /// The administrator's Linux policy file,
    /// `/etc/<vendor>/<id>/policy.toml` (vendor in lowercase).
    #[must_use]
    pub fn policy_file(&self) -> PathBuf {
        PathBuf::from("/etc")
            .join(self.vendor.to_ascii_lowercase())
            .join(&self.id)
            .join("policy.toml")
    }

    /// The update helper's name: `<service>-update`, its Windows service
    /// and its systemd units' stem. `None` without a service.
    #[must_use]
    pub fn helper_service(&self) -> Option<String> {
        self.service
            .as_ref()
            .map(|service| format!("{}-update", service.name))
    }

    /// The update helper's name on every platform: `<service>-update` for
    /// a service product ([`helper_service`](Self::helper_service)), else
    /// `<package>-update` (a desktop or tool product, whose helper the
    /// interactive user starts).
    #[must_use]
    pub fn helper_name(&self) -> String {
        self.helper_service()
            .unwrap_or_else(|| format!("{}-update", self.package()))
    }

    /// The Linux update request file,
    /// `/var/lib/<state_directory>/update-request`, which the helper's
    /// path unit watches. `None` without a service or state directory.
    #[must_use]
    pub fn request_file(&self) -> Option<PathBuf> {
        let state = self.service.as_ref()?.state_directory.as_ref()?;
        Some(
            PathBuf::from("/var/lib")
                .join(state)
                .join(UPDATE_REQUEST_FILE),
        )
    }

    /// The macOS support directory,
    /// `/Library/Application Support/<Vendor>/<Directory>`, the counterpart
    /// of Windows' `%ProgramData%\<Vendor>\<Directory>`: the service's
    /// `state` and the helper's `updates` live below it.
    #[must_use]
    pub fn macos_support_directory(&self) -> PathBuf {
        PathBuf::from("/Library/Application Support")
            .join(&self.vendor)
            .join(&self.windows_directory)
    }

    /// The macOS log directory, `/Library/Logs/<Vendor>/<Directory>`: the
    /// service's and the helper's daemons write their output there.
    #[must_use]
    pub fn macos_log_directory(&self) -> PathBuf {
        PathBuf::from("/Library/Logs")
            .join(&self.vendor)
            .join(&self.windows_directory)
    }

    /// The macOS helper's staging directory,
    /// `<support directory>/updates` (beside the service's state, outside
    /// it, as on Windows).
    #[must_use]
    pub fn macos_staging_directory(&self) -> PathBuf {
        self.macos_support_directory().join("updates")
    }

    /// The macOS update request file, `<support directory>/state/`
    /// [`UPDATE_REQUEST_FILE`], which the helper's LaunchDaemon watches
    /// (`WatchPaths`). `None` without a service or state directory, as on
    /// Linux: a product ships the helper only with one (the seaworthy CLI
    /// requires it), though macOS's path doesn't use its value.
    #[must_use]
    pub fn macos_request_file(&self) -> Option<PathBuf> {
        self.service.as_ref()?.state_directory.as_ref()?;
        Some(
            self.macos_support_directory()
                .join("state")
                .join(UPDATE_REQUEST_FILE),
        )
    }

    /// The Windows data directory, `<ProgramData>\<Vendor>\<Directory>`
    /// (`program_data` is `%ProgramData%`): the service's `state`
    /// and the helper's `updates` live below it, each with the DACL the MSI
    /// gives it.
    #[must_use]
    pub fn windows_data_directory(&self, program_data: &Path) -> PathBuf {
        program_data
            .join(&self.vendor)
            .join(&self.windows_directory)
    }

    /// The Windows log directory, `<data directory>\logs`: the service's
    /// and its update helper's logs. The MSI creates it, locked like
    /// `state`: never readable by every user (logs can carry what users
    /// must not read).
    #[must_use]
    pub fn windows_log_directory(&self, program_data: &Path) -> PathBuf {
        self.windows_data_directory(program_data).join("logs")
    }

    /// The Windows helper's staging directory, `<data directory>\updates`:
    /// SYSTEM and Administrators only.
    #[must_use]
    pub fn windows_staging_directory(&self, program_data: &Path) -> PathBuf {
        self.windows_data_directory(program_data).join("updates")
    }

    /// The Group Policy key under `HKLM`:
    /// `SOFTWARE\Policies\<Vendor>\<Directory>`.
    #[must_use]
    pub fn policy_key(&self) -> String {
        format!(
            "SOFTWARE\\Policies\\{}\\{}",
            self.vendor, self.windows_directory
        )
    }

    /// The installer's key under `HKLM`, holding the MSI's update-policy
    /// default and its installed release ([`MSI_RELEASE_VALUE`]):
    /// `SOFTWARE\<Vendor>\<Directory>`.
    #[must_use]
    pub fn install_key(&self) -> String {
        format!("SOFTWARE\\{}\\{}", self.vendor, self.windows_directory)
    }
}

/// The name of the update request file in a service's state directory
/// (seaworthy-service's systemd renderer renders the path unit watching
/// it, and must use the same name).
pub const UPDATE_REQUEST_FILE: &str = "update-request";

/// The registry value holding the installed release under
/// [`Product::install_key`], beside the MSI's `UpdatePolicy`: the seaworthy
/// CLI's MSI writes it (in deb's spelling,
/// [`PackageVersions::msi_release`](crate::release::PackageVersions::msi_release)),
/// and the update helper's MSI installer reads it back.
pub const MSI_RELEASE_VALUE: &str = "Release";

/// The subset of `seaworthy.toml` that names things.
#[derive(serde::Deserialize)]
struct ConfigFile {
    defaults: Defaults,
    product: BTreeMap<String, ProductTable>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Defaults {
    vendor: String,
    channel: String,
    #[serde(default)]
    release_trust: ReleaseTrust,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProductTable {
    display_name: String,
    executable: String,
    windows_directory: Option<String>,
    service: Option<ServiceTable>,
    #[serde(default)]
    updates: UpdatesTable,
    macos: Option<MacosTable>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct MacosTable {
    bundle_id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ServiceTable {
    name: String,
    state_directory: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct UpdatesTable {
    #[serde(default)]
    default: UpdatePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
[defaults]
vendor = "Acme"
channel = "stable"
targets = ["x86-64-v3"]

[product.agent]
display-name = "Acme Agent"
executable = "AcmeAgent"
helper = "AcmeAgentUpdate"
updates.default = "notify"

[product.agent.service]
name = "AcmeAgent"
state-directory = "acme/agent"

[product.agent.macos]
bundle-id = "com.acme.agent"
category = "public.app-category.utilities"

[product.console]
display-name = "Acme Console"
executable = "AcmeConsole"
windows-directory = "Desk"
"#;

    #[test]
    fn names_follow_the_config() {
        let agent = Product::from_config(CONFIG, "agent").unwrap();
        assert_eq!(agent.package(), "acme-agent");
        assert_eq!(agent.windows_directory(), "Agent");
        assert_eq!(agent.channel(), "stable");
        assert_eq!(agent.default_policy(), UpdatePolicy::Notify);
        assert_eq!(agent.cache_directory(), "acme/agent");
        assert_eq!(
            agent.policy_file(),
            PathBuf::from("/etc/acme/agent/policy.toml")
        );
        assert_eq!(
            agent.request_file(),
            Some(PathBuf::from("/var/lib/acme/agent/update-request"))
        );
        assert_eq!(agent.helper_service().as_deref(), Some("AcmeAgent-update"));
        // macOS: Windows' layout under /Library.
        assert_eq!(
            agent.macos_support_directory(),
            PathBuf::from("/Library/Application Support/Acme/Agent")
        );
        assert_eq!(
            agent.macos_log_directory(),
            PathBuf::from("/Library/Logs/Acme/Agent")
        );
        assert_eq!(
            agent.macos_staging_directory(),
            PathBuf::from("/Library/Application Support/Acme/Agent/updates")
        );
        assert_eq!(
            agent.macos_request_file(),
            Some(PathBuf::from(
                "/Library/Application Support/Acme/Agent/state/update-request"
            ))
        );
        assert_eq!(agent.policy_key(), "SOFTWARE\\Policies\\Acme\\Agent");
        assert_eq!(agent.install_key(), "SOFTWARE\\Acme\\Agent");
        assert_eq!(agent.helper_name(), "AcmeAgent-update");
        let program_data = Path::new("/ProgramData");
        assert_eq!(
            agent.windows_data_directory(program_data),
            program_data.join("Acme").join("Agent")
        );
        assert_eq!(
            agent.windows_staging_directory(program_data),
            program_data.join("Acme").join("Agent").join("updates")
        );
        assert_eq!(
            agent.windows_log_directory(program_data),
            program_data.join("Acme").join("Agent").join("logs")
        );
        let console = Product::from_config(CONFIG, "console").unwrap();
        assert_eq!(console.windows_directory(), "Desk");
        assert_eq!(console.default_policy(), UpdatePolicy::Auto);
        assert_eq!(
            (console.request_file(), console.helper_service()),
            (None, None)
        );
        // A desktop product's helper goes by its package.
        assert_eq!(console.helper_name(), "acme-console-update");
        assert_eq!(console.macos_request_file(), None);
        // The bundle id is the macOS package's identifier.
        assert_eq!(agent.macos_package_id(), Some("com.acme.agent"));
        assert_eq!(console.macos_package_id(), None);
        for bad in [
            "agent",
            "com..acme",
            "com.acme_agent",
            ".com.acme",
            &"a.".repeat(80),
        ] {
            assert!(
                Product::new("Acme", "agent", "Agent", "stable")
                    .unwrap()
                    .with_macos_bundle_id(bad)
                    .is_err(),
                "{bad:?}"
            );
        }
        let no_state = console
            .with_service(ServiceNames {
                name: "AcmeDesk".into(),
                state_directory: None,
            })
            .unwrap();
        assert_eq!(
            (no_state.request_file(), no_state.macos_request_file()),
            (None, None),
            "no state directory, no helper to ask, on either platform"
        );
        assert!(Product::from_config(CONFIG, "other").is_err());
        assert!(Product::from_config("not toml [", "agent").is_err());
    }

    #[test]
    fn the_release_trust_follows_the_config() {
        let agent = Product::from_config(CONFIG, "agent").unwrap();
        assert_eq!(agent.release_trust(), ReleaseTrust::AnyKey);
        let every = CONFIG.replace(
            "channel = \"stable\"\n",
            "channel = \"stable\"\nrelease-trust = \"every-algorithm\"\n",
        );
        let agent = Product::from_config(&every, "agent").unwrap();
        assert_eq!(agent.release_trust(), ReleaseTrust::EveryAlgorithm);
        assert_eq!(agent.release_trust().as_str(), "every-algorithm");
        let any = CONFIG.replace(
            "channel = \"stable\"\n",
            "channel = \"stable\"\nrelease-trust = \"any-key\"\n",
        );
        assert_eq!(
            Product::from_config(&any, "agent").unwrap().release_trust(),
            ReleaseTrust::AnyKey
        );
        for bad in ["\"all\"", "\"Every-Algorithm\"", "true", "\"\""] {
            let text = CONFIG.replace(
                "channel = \"stable\"\n",
                &format!("channel = \"stable\"\nrelease-trust = {bad}\n"),
            );
            assert!(Product::from_config(&text, "agent").is_err(), "{bad}");
        }
    }

    #[test]
    fn names_that_would_become_odd_paths_are_refused() {
        for (vendor, id, dir, channel) in [
            ("", "agent", "Agent", "stable"),
            ("../x", "agent", "Agent", "stable"),
            ("Acme", "Agent", "Agent", "stable"),
            ("Acme", "agent/x", "Agent", "stable"),
            ("Acme", "agent", "A\\B", "stable"),
            ("Acme", "agent", "Agent", "Stable"),
            ("Acme", "agent", "Agent", ""),
            ("Ac me", "agent", "Agent", "stable"),
        ] {
            assert!(
                Product::new(vendor, id, dir, channel).is_err(),
                "{vendor} {id} {dir} {channel}"
            );
        }
        let product = Product::new("Acme", "agent", "Agent", "stable").unwrap();
        for state in ["", "/var/lib/x", "a/../b", "a//b", "a b", "./a"] {
            assert!(
                product
                    .clone()
                    .with_service(ServiceNames {
                        name: "AcmeAgent".into(),
                        state_directory: Some(state.into())
                    })
                    .is_err(),
                "{state:?}"
            );
        }
        assert!(
            product
                .with_service(ServiceNames {
                    name: "-x".into(),
                    state_directory: None
                })
                .is_err()
        );
    }
}
