//! The repository package:
//! `<vendor>-repository`, which sets a machine's package manager up to
//! install and update the vendor's packages from the published
//! repositories, trusting the OpenPGP keys `seaworthy.toml` pins for them alone.
//!
//! | Format | File | What |
//! | --- | --- | --- |
//! | deb | `/usr/share/keyrings/<repo>-archive-keyring.asc` | the pinned keys, armored |
//! | deb | `/etc/apt/sources.list.d/<repo>.sources` | a deb822 source: `<url>/apt`, suite `<channel>`, component `main`, `amd64`, `Signed-By:` that keyring alone (a conffile) |
//! | rpm | `/etc/pki/rpm-gpg/RPM-GPG-KEY-<repo>` | the pinned keys, armored |
//! | rpm | `/etc/yum.repos.d/<repo>.repo` | `[<repo>]`: `<url>/rpm/<channel>/x86_64`, `gpgcheck=1`, `repo_gpgcheck=1`, `gpgkey=` that key file (`%config(noreplace)`) |
//!
//! `<repo>` is the repositories' name (the vendor in lowercase,
//! [`crate::repo::repository_name`]), `<url>` is `[defaults.repository]`'s
//! `url`. The package is architecture-independent (deb `all`, rpm
//! `noarch`), has no scripts and no dependencies, and is versioned with the
//! release it's built with: every publication carries a new one, so a key
//! rotation reaches machines through the repositories themselves (pin the
//! new key beside the old, so both ship; switch the signer once machines
//! have it; then drop the old key). The rpm is signed like every rpm.
//!
//! The definitions name the repositories' one architecture (`amd64`,
//! `x86_64`) rather than the machine's (`$basearch`): installed on an arm64
//! host, the package sets up a repository with nothing installable there,
//! where `$basearch` would point dnf at metadata that doesn't exist and,
//! with RHEL's `skip_if_unavailable=False`, fail every dnf command.
//! `seaworthy repo` reads the package back and refuses one whose files
//! aren't exactly these, as this `seaworthy.toml` generates them.
//!
//! The definitions are configuration files, so an administrator's edit
//! survives an upgrade (dpkg keeps a changed conffile when the package's
//! own didn't change, and asks — defaulting to the administrator's — when
//! both did, which holds the package back under unattended-upgrades; rpm's
//! `noreplace` keeps it and writes the package's beside it as `.rpmnew`).
//! The keys aren't: they're the vendor's, replaced on every upgrade. To remove the package: `apt purge`
//! (`apt remove` leaves the conffile, whose keyring went with the package)
//! or `dnf remove`.
//!
//! No product depends on it, not even with `Recommends:`. On a host fed by
//! a mirror (Satellite, Artifactory, an air gap) such a dependency would
//! pull in a definition pointing at the vendor's public URL, which dnf
//! refuses to work without (`skip_if_unavailable=False`, RHEL's default),
//! and apt refuses outright beside a source an administrator already
//! configured with another `Signed-By:` (conflicting values). An
//! administrator installs it once, deliberately (the crate README's client
//! setup).
//!
//! There's no pacman package. Arch has no drop-in directory for
//! repositories (an `Include` in `pacman.conf` is the administrator's to
//! add), and trusting a key takes `pacman-key --lsign-key`, an
//! administrator's decision; the README gives the section and the
//! commands.

use std::path::Path;

use crate::DistError;
use crate::config::{Config, Output, REPOSITORY_ID};
use crate::linux::{LinuxPackage, PackagedFile, Source};
use crate::scripts::Units;

/// What the repository package carries in one format.
#[derive(Debug, Clone)]
pub struct Contents {
    /// Its name, files and (no) units.
    pub package: LinuxPackage,
    /// The install paths that are configuration files.
    pub config_files: Vec<String>,
    /// Its one-line description.
    pub description: String,
}

/// The armor header every pinned key file must start with: apt reads a
/// `.asc` keyring as armored, and dnf's `gpgkey=` takes armored keys only.
const ARMOR: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/// The largest pinned key file read (a key with many signatures is still
/// well under this).
const MAX_KEY_BYTES: u64 = 1024 * 1024;

/// Every OpenPGP key `seaworthy.toml` pins (`defaults.openpgp-keys`), armored,
/// one after the other: the keys the repositories' signatures may come
/// from (a rotation pins two). The repository package and `repo`'s
/// `keys/<repo>.asc` both carry exactly this.
///
/// # Errors
/// [`DistError::Config`] for no pinned key, or one that isn't an armored
/// public key block; [`DistError::Io`] when one can't be read.
pub fn pinned_keys(config: &Config) -> Result<String, DistError> {
    if config.defaults.openpgp_keys.is_empty() {
        return Err(DistError::Config(
            "defaults.openpgp-keys is empty: pin the repositories' signing key to publish them"
                .to_owned(),
        ));
    }
    let mut keys = String::new();
    for key in &config.defaults.openpgp_keys {
        let path = config.dir.join(key);
        let text = read_key(&path)?;
        if !text.trim_start().starts_with(ARMOR) {
            return Err(DistError::Config(format!(
                "defaults.openpgp-keys: {} isn't an armored public key ({ARMOR}): apt's `.asc` keyrings and dnf's gpgkey= read armored keys only (gpg --armor --export)",
                path.display()
            )));
        }
        keys.push_str(text.trim_start());
        if !keys.ends_with('\n') {
            keys.push('\n');
        }
    }
    Ok(keys)
}

fn read_key(path: &Path) -> Result<String, DistError> {
    let size = std::fs::metadata(path)
        .map_err(|e| DistError::io(path, e))?
        .len();
    if size > MAX_KEY_BYTES {
        return Err(DistError::Config(format!(
            "defaults.openpgp-keys: {} is over {MAX_KEY_BYTES} bytes",
            path.display()
        )));
    }
    let bytes = std::fs::read(path).map_err(|e| DistError::io(path, e))?;
    String::from_utf8(bytes).map_err(|_| {
        DistError::Config(format!(
            "defaults.openpgp-keys: {} isn't an armored public key (not text)",
            path.display()
        ))
    })
}

/// Where the deb's keyring is installed.
#[must_use]
pub fn keyring_path(config: &Config) -> String {
    format!(
        "/usr/share/keyrings/{}-archive-keyring.asc",
        crate::repo::repository_name(config)
    )
}

/// Where the deb's source definition is installed.
#[must_use]
pub fn sources_path(config: &Config) -> String {
    format!(
        "/etc/apt/sources.list.d/{}.sources",
        crate::repo::repository_name(config)
    )
}

/// Where the rpm's key file is installed.
#[must_use]
pub fn rpm_key_path(config: &Config) -> String {
    format!(
        "/etc/pki/rpm-gpg/RPM-GPG-KEY-{}",
        crate::repo::repository_name(config)
    )
}

/// Where the rpm's repository definition is installed.
#[must_use]
pub fn repo_file_path(config: &Config) -> String {
    format!(
        "/etc/yum.repos.d/{}.repo",
        crate::repo::repository_name(config)
    )
}

/// The `[defaults.repository]` URL.
fn url(config: &Config) -> Result<&str, DistError> {
    config
        .defaults
        .repository
        .as_ref()
        .map(|r| r.url.as_str())
        .ok_or_else(|| {
            DistError::Config(
                "no [defaults.repository]: the repository package needs the repositories' url"
                    .to_owned(),
            )
        })
}

/// The first line of each definition: what it is and where it came from.
fn header(config: &Config) -> String {
    format!(
        "# {}'s packages, set up by {} (a configuration file: local edits are kept on upgrade).\n",
        config.defaults.vendor,
        crate::linux::package_name(config, REPOSITORY_ID)
    )
}

/// The deb822 source: the published APT repository, verified against the
/// package's keyring alone.
///
/// # Errors
/// [`DistError::Config`] without `[defaults.repository]`.
pub fn sources(config: &Config) -> Result<String, DistError> {
    Ok(format!(
        "{}Types: deb\nURIs: {}/apt\nSuites: {}\nComponents: main\nArchitectures: {}\nSigned-By: {}\n",
        header(config),
        url(config)?,
        config.defaults.channel,
        crate::repo::deb_architecture(crate::inputs::LINUX)?,
        keyring_path(config)
    ))
}

/// The dnf repository definition: packages and metadata both checked
/// against the package's key file.
///
/// # Errors
/// [`DistError::Config`] without `[defaults.repository]`.
pub fn repo_file(config: &Config) -> Result<String, DistError> {
    let name = crate::repo::repository_name(config);
    Ok(format!(
        "{}[{name}]\nname={} ({})\nbaseurl={}/rpm/{}/{}\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://{}\n",
        header(config),
        config.defaults.vendor,
        config.defaults.channel,
        url(config)?,
        config.defaults.channel,
        crate::repo::rpm_architecture(crate::inputs::LINUX)?,
        rpm_key_path(config)
    ))
}

/// The repository package's contents for `format` (deb or rpm).
///
/// # Errors
/// [`DistError::Config`] without `[defaults.repository]`, for a format
/// with no repository package, or a pinned key [`pinned_keys`] refuses;
/// [`DistError::Io`] when a key can't be read.
pub fn contents(config: &Config, format: Output) -> Result<Contents, DistError> {
    let keys = pinned_keys(config)?;
    let vendor = &config.defaults.vendor;
    let file = |dst: String, text: String| PackagedFile {
        dst,
        mode: 0o644,
        source: Source::Generated(text),
    };
    let (files, config_files, description) = match format {
        Output::Deb => (
            vec![
                file(keyring_path(config), keys),
                file(sources_path(config), sources(config)?),
            ],
            vec![sources_path(config)],
            format!("Sets apt up for {vendor}'s packages: their repository and signing keys"),
        ),
        Output::Rpm => (
            vec![
                file(rpm_key_path(config), keys),
                file(repo_file_path(config), repo_file(config)?),
            ],
            vec![repo_file_path(config)],
            format!("Sets dnf up for {vendor}'s packages: their repository and signing keys"),
        ),
        other => {
            return Err(DistError::Config(format!(
                "no repository package for {other:?}: deb and rpm only"
            )));
        }
    };
    Ok(Contents {
        package: LinuxPackage {
            name: crate::linux::package_name(config, REPOSITORY_ID),
            directories: Vec::new(),
            files,
            units: Units::default(),
            links: Vec::new(),
        },
        config_files,
        description,
    })
}

/// The formats the repository package is built in: deb when a product
/// builds a deb, rpm when one builds an rpm.
#[must_use]
pub fn formats(config: &Config) -> Vec<Output> {
    [Output::Deb, Output::Rpm]
        .into_iter()
        .filter(|format| config.products.values().any(|p| p.outputs.contains(format)))
        .collect()
}
