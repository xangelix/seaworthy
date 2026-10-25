//! Release versions, their order, and how every package format spells
//! them.
//!
//! A release is a semver version plus a **sequence**: the release
//! pipeline's build number (a CI pipeline counter that only grows within a
//! project). Every deploy is a new build, and two builds of the same
//! version must still install in order. The update helper's version floor
//! (`seaworthy-updater`'s `helper`) installs a release only when its
//! version is higher, or equal with a higher sequence. Each package manager
//! must order releases exactly the same way, or the helper could verify a
//! release the package manager then refuses, or ignores as already
//! installed. This module is the one definition both sides use: the
//! seaworthy CLI spells package versions with it, and the helper reads the
//! installed package's version back with it
//! ([`Release::from_package_version`]).
//!
//! | Format | Spelling of `1.4.0-rc.2`, sequence 812 |
//! | --- | --- |
//! | deb | `Version: 1.4.0~rc.2-812` |
//! | rpm | `Version: 1.4.0~rc.2`, `Release: 812` |
//! | pacman | `pkgver=1.4.0rc.2`, `pkgrel=812` |
//! | MSI | `ProductVersion: 1.4.0` (same-version upgrades allowed; the helper's floor orders builds) |
//!
//! The pre-release grammar is deliberately narrow: **`alpha`, `beta` or
//! `rc`, optionally followed by one number** (`alpha`, `beta.2`, `rc.1`).
//! Each wider grammar breaks one of the formats:
//!
//! - semver orders `rc2` before `rc10` lexically, while dpkg, rpm and pacman
//!   compare digit runs numerically;
//! - semver orders a numeric identifier before an alphabetic one, where the
//!   package managers disagree;
//! - dpkg ranks a letter below `.`, so of two tags where one is a prefix of
//!   the other (`pre`/`preview`, `rc`/`rcx`) it orders the longer first —
//!   semver, rpm and pacman order it last. No two of the three tags is a
//!   prefix of another.
//!
//! In this grammar all four orders agree, and the seaworthy CLI's tests
//! prove it against the real `dpkg`, `rpm` and `vercmp`. Build metadata
//! (`+…`) is refused: semver ignores it for ordering, but every package
//! format would compare it.

use std::cmp::Ordering;
use std::fmt;

/// MSI's `ProductVersion` limits: major and minor at most 255, build
/// (our patch) at most 65535.
pub const MSI_MAX_MAJOR: u64 = 255;
/// See [`MSI_MAX_MAJOR`].
pub const MSI_MAX_MINOR: u64 = 255;
/// See [`MSI_MAX_MAJOR`].
pub const MSI_MAX_PATCH: u64 = 65_535;

/// Why a version or sequence was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// Not `MAJOR.MINOR.PATCH[-PRERELEASE]` with numeric parts.
    #[error("{0:?} is not a release version (MAJOR.MINOR.PATCH, optionally -PRERELEASE)")]
    Syntax(String),
    /// A numeric part with a leading zero, or out of range.
    #[error("{0:?}: numeric parts must be decimal without leading zeros")]
    Number(String),
    /// Build metadata.
    #[error(
        "{0:?}: build metadata (+…) is refused — every package format would order by it, semver doesn't"
    )]
    BuildMetadata(String),
    /// A pre-release outside the grammar every package manager orders alike.
    #[error(
        "{0:?}: the pre-release must be alpha, beta or rc, optionally followed by one number (alpha, beta.2, rc.1), so dpkg, rpm, pacman and the update helper all order it the same way"
    )]
    PreRelease(String),
    /// The sequence must be at least 1 (pacman's `pkgrel` and the deb
    /// revision start at 1).
    #[error("the release sequence must be at least 1")]
    Sequence,
    /// A version MSI can't represent.
    #[error(
        "{0} can't be an MSI ProductVersion (major and minor at most 255, patch at most 65535)"
    )]
    Msi(String),
}

/// The pre-release tags: none is a prefix of another, so dpkg orders
/// them as semver does.
pub const PRE_RELEASE_TAGS: [&str; 3] = ["alpha", "beta", "rc"];

/// A pre-release: `alpha`, `beta` or `rc`, optionally followed by
/// `.<number>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreRelease {
    /// One of [`PRE_RELEASE_TAGS`].
    pub tag: String,
    /// The optional number after it.
    pub number: Option<u64>,
}

impl PartialOrd for PreRelease {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreRelease {
    /// Semver precedence, which for this grammar is: the tag by ASCII
    /// order, then no number before any number, then the numbers.
    fn cmp(&self, other: &Self) -> Ordering {
        self.tag.as_bytes().cmp(other.tag.as_bytes()).then_with(|| {
            match (self.number, other.number) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(&b),
            }
        })
    }
}

impl fmt::Display for PreRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.number {
            Some(number) => write!(f, "{}.{number}", self.tag),
            None => f.write_str(&self.tag),
        }
    }
}

/// A release version: `MAJOR.MINOR.PATCH[-PRERELEASE]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
    /// The pre-release, if any. A pre-release orders before its release.
    pub pre: Option<PreRelease>,
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

fn number(text: &str, whole: &str) -> Result<u64, VersionError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VersionError::Syntax(whole.to_owned()));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(VersionError::Number(whole.to_owned()));
    }
    text.parse()
        .map_err(|_| VersionError::Number(whole.to_owned()))
}

impl Version {
    /// Parses `MAJOR.MINOR.PATCH[-PRERELEASE]` (a leading `v` is accepted,
    /// as release tags carry one).
    ///
    /// # Errors
    /// [`VersionError`] naming what is wrong.
    pub fn parse(text: &str) -> Result<Self, VersionError> {
        let bare = text.strip_prefix('v').unwrap_or(text);
        if bare.contains('+') {
            return Err(VersionError::BuildMetadata(text.to_owned()));
        }
        let (core, pre) = match bare.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (bare, None),
        };
        let mut parts = core.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VersionError::Syntax(text.to_owned()));
        };
        let pre = match pre {
            None => None,
            Some(pre) => {
                let (tag, num) = match pre.split_once('.') {
                    Some((tag, num)) => (tag, Some(num)),
                    None => (pre, None),
                };
                if !PRE_RELEASE_TAGS.contains(&tag) {
                    return Err(VersionError::PreRelease(text.to_owned()));
                }
                let number = match num {
                    None => None,
                    Some(num) => Some(
                        number(num, text).map_err(|_| VersionError::PreRelease(text.to_owned()))?,
                    ),
                };
                Some(PreRelease {
                    tag: tag.to_owned(),
                    number,
                })
            }
        };
        Ok(Self {
            major: number(major, text)?,
            minor: number(minor, text)?,
            patch: number(patch, text)?,
            pre,
        })
    }

    /// The upstream part shared by deb and rpm: the pre-release joined with
    /// `~`, which both sort before the release (`1.4.0~rc.2`).
    #[must_use]
    pub fn tilde_form(&self) -> String {
        match &self.pre {
            Some(pre) => format!("{}.{}.{}~{pre}", self.major, self.minor, self.patch),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }

    /// pacman's `pkgver`: pacman has no `~`, but an alphabetic segment
    /// attached directly to the patch number sorts before the bare release
    /// (`1.4.0rc.2` < `1.4.0`). This is why the pre-release must start
    /// with a letter.
    #[must_use]
    pub fn pacman_form(&self) -> String {
        match &self.pre {
            Some(pre) => format!("{}.{}.{}{pre}", self.major, self.minor, self.patch),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }

    /// MSI's `ProductVersion` (`MAJOR.MINOR.PATCH`). Windows Installer
    /// compares only these three fields, so two builds or a pre-release
    /// and its release share it: the MSI allows same-version upgrades and
    /// refuses downgrades, and the update helper's floor orders the rest.
    ///
    /// # Errors
    /// [`VersionError::Msi`] beyond MSI's limits ([`MSI_MAX_MAJOR`] …).
    pub fn msi_form(&self) -> Result<String, VersionError> {
        if self.major > MSI_MAX_MAJOR || self.minor > MSI_MAX_MINOR || self.patch > MSI_MAX_PATCH {
            return Err(VersionError::Msi(self.to_string()));
        }
        Ok(format!("{}.{}.{}", self.major, self.minor, self.patch))
    }
}

/// A release: a version and its sequence, ordered as the update helper's
/// floor orders them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// The version.
    pub version: Version,
    /// The release pipeline's build number (at least 1).
    pub sequence: u64,
}

impl PartialOrd for Release {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Release {
    fn cmp(&self, other: &Self) -> Ordering {
        self.version
            .cmp(&other.version)
            .then(self.sequence.cmp(&other.sequence))
    }
}

/// Every format's spelling of one release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersions {
    /// deb `Version:` (`<upstream>-<sequence>`).
    pub deb: String,
    /// rpm `Version:`.
    pub rpm_version: String,
    /// rpm `Release:`.
    pub rpm_release: String,
    /// pacman `pkgver`.
    pub pacman_pkgver: String,
    /// pacman `pkgrel`.
    pub pacman_pkgrel: String,
    /// MSI `ProductVersion`.
    pub msi: String,
    /// The macOS package's version (`pkgbuild --version`, what `pkgutil
    /// --pkg-info` reports): deb's spelling, `<upstream>-<sequence>`.
    pub pkg: String,
    /// The MSI's installed release, `HKLM\SOFTWARE\<Vendor>\<Directory>`
    /// `Release` ([`MSI_RELEASE_VALUE`](crate::MSI_RELEASE_VALUE)): deb's
    /// spelling, since [`msi`](Self::msi) can't hold a pre-release or the
    /// sequence the helper's floor compares.
    pub msi_release: String,
}

impl Release {
    /// Parses a version and pairs it with `sequence`.
    ///
    /// # Errors
    /// As [`Version::parse`]; [`VersionError::Sequence`] for 0.
    pub fn new(version: &str, sequence: u64) -> Result<Self, VersionError> {
        if sequence == 0 {
            return Err(VersionError::Sequence);
        }
        Ok(Self {
            version: Version::parse(version)?,
            sequence,
        })
    }

    /// Every format's spelling.
    ///
    /// # Errors
    /// [`VersionError::Msi`] for a version MSI can't represent: one
    /// product version for every format, so a release that can't be an MSI
    /// is refused everywhere.
    pub fn package_versions(&self) -> Result<PackageVersions, VersionError> {
        let tilde = self.version.tilde_form();
        Ok(PackageVersions {
            deb: format!("{tilde}-{}", self.sequence),
            pkg: format!("{tilde}-{}", self.sequence),
            msi_release: format!("{tilde}-{}", self.sequence),
            rpm_version: tilde,
            rpm_release: self.sequence.to_string(),
            pacman_pkgver: self.version.pacman_form(),
            pacman_pkgrel: self.sequence.to_string(),
            msi: self.version.msi_form()?,
        })
    }

    /// Reads back the release a package manager reports as installed:
    /// deb's `Version` (`1.4.0~rc.2-812`), rpm's `%{VERSION}-%{RELEASE}`,
    /// the macOS package's version and the MSI's `Release` registry value
    /// (the same spelling) or pacman's `<pkgver>-<pkgrel>`
    /// (`1.4.0rc.2-812`).
    ///
    /// Only exactly what [`package_versions`](Self::package_versions)
    /// writes is accepted: the text must spell back byte for byte. A
    /// package from elsewhere (an epoch, a distribution suffix, a
    /// hand-built version) is refused rather than guessed at, since the
    /// version floor compares against it.
    ///
    /// # Errors
    /// [`VersionError::Syntax`] for anything else, including a format with
    /// no installed-version spelling here (the archives).
    pub fn from_package_version(
        format: crate::ArtifactFormat,
        text: &str,
    ) -> Result<Self, VersionError> {
        use crate::ArtifactFormat;
        let refused = || VersionError::Syntax(text.to_owned());
        let (upstream, sequence) = text.rsplit_once('-').ok_or_else(refused)?;
        let sequence = number(sequence, text).map_err(|_| refused())?;
        let version = match format {
            ArtifactFormat::Deb
            | ArtifactFormat::Rpm
            | ArtifactFormat::Pkg
            | ArtifactFormat::Msi => upstream.replacen('~', "-", 1),
            ArtifactFormat::Pacman => {
                // The pre-release starts at the first letter (every tag
                // starts with one, and the core is digits and dots).
                match upstream
                    .find(|c: char| c.is_ascii_alphabetic())
                    .and_then(|at| upstream.split_at_checked(at))
                {
                    Some((core, pre)) => format!("{core}-{pre}"),
                    None => upstream.to_owned(),
                }
            }
            ArtifactFormat::Zip | ArtifactFormat::Tar => {
                return Err(refused());
            }
        };
        let release = Self::new(&version, sequence).map_err(|_| refused())?;
        let spelled = release.package_versions().map_err(|_| refused())?;
        let back = match format {
            ArtifactFormat::Deb => spelled.deb,
            ArtifactFormat::Pkg => spelled.pkg,
            ArtifactFormat::Msi => spelled.msi_release,
            ArtifactFormat::Rpm => format!("{}-{}", spelled.rpm_version, spelled.rpm_release),
            _ => format!("{}-{}", spelled.pacman_pkgver, spelled.pacman_pkgrel),
        };
        if back != text {
            return Err(refused());
        }
        Ok(release)
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (sequence {})", self.version, self.sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spells_every_format() {
        let release = Release::new("v1.4.0-rc.2", 812).unwrap();
        let v = release.package_versions().unwrap();
        assert_eq!(v.deb, "1.4.0~rc.2-812");
        assert_eq!(
            (v.rpm_version.as_str(), v.rpm_release.as_str()),
            ("1.4.0~rc.2", "812")
        );
        assert_eq!(
            (v.pacman_pkgver.as_str(), v.pacman_pkgrel.as_str()),
            ("1.4.0rc.2", "812")
        );
        assert_eq!(v.msi, "1.4.0");
        assert_eq!(v.pkg, "1.4.0~rc.2-812");
        let plain = Release::new("2.0.1", 3)
            .unwrap()
            .package_versions()
            .unwrap();
        assert_eq!(
            (plain.deb.as_str(), plain.pacman_pkgver.as_str()),
            ("2.0.1-3", "2.0.1")
        );
    }

    #[test]
    fn refuses_what_the_formats_would_order_differently() {
        for bad in [
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-1",
            "1.0.0-rc1",
            "1.0.0-rc.01",
            "1.0.0-rc.1.2",
            "1.0.0-alpha.beta",
            "1.0.0-r-c",
            "1.0.0+abc",
            "1.0.0-rc.1+abc",
            "x.y.z",
            "",
            "1..0",
            "1.0.0-rc.x",
            // Tags outside the closed set: dpkg orders prefix pairs
            // (pre/preview, rc/rcx, a/alpha) the other way round.
            "1.0.0-pre.1",
            "1.0.0-preview",
            "1.0.0-rcx.1",
            "1.0.0-a",
            "1.0.0-RC.1",
            "1.0.0-Alpha",
            "1.0.0-dev",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad:?} accepted");
        }
        assert_eq!(Release::new("1.0.0", 0), Err(VersionError::Sequence));
        assert!(matches!(
            Release::new("256.0.0", 1).unwrap().package_versions(),
            Err(VersionError::Msi(_))
        ));
        assert!(
            Release::new("1.255.65535", 1)
                .unwrap()
                .package_versions()
                .is_ok()
        );
    }

    #[test]
    fn installed_versions_read_back_exactly_what_was_written() {
        use crate::ArtifactFormat::{Deb, Msi, Pacman, Pkg, Rpm, Tar, Zip};
        for (version, sequence) in [("1.4.0-rc.2", 812), ("2.0.1", 3), ("0.1.0-alpha", 1)] {
            let release = Release::new(version, sequence).unwrap();
            let v = release.package_versions().unwrap();
            assert_eq!(
                Release::from_package_version(Deb, &v.deb),
                Ok(release.clone())
            );
            let rpm = format!("{}-{}", v.rpm_version, v.rpm_release);
            assert_eq!(
                Release::from_package_version(Rpm, &rpm),
                Ok(release.clone())
            );
            let pacman = format!("{}-{}", v.pacman_pkgver, v.pacman_pkgrel);
            assert_eq!(
                Release::from_package_version(Pacman, &pacman),
                Ok(release.clone())
            );
            assert_eq!(v.pkg, v.deb, "the macOS package spells it as deb does");
            assert_eq!(
                Release::from_package_version(Pkg, &v.pkg),
                Ok(release.clone())
            );
            assert_eq!(
                v.msi_release, v.deb,
                "the MSI's Release spells it as deb does"
            );
            assert_eq!(
                Release::from_package_version(Msi, &v.msi_release),
                Ok(release.clone())
            );
        }
        for (format, bad) in [
            (Deb, "1:1.4.0-812"),
            (Deb, "1.4.0-812ubuntu1"),
            (Deb, "1.4.0~rc.2"),
            (Deb, "1.4.0-rc.2-812"),
            (Deb, "1.4.0~rc.2~x-812"),
            (Deb, "1.4.0-0"),
            (Deb, "1.4.0-012"),
            (Deb, "v1.4.0-812"),
            (Rpm, "1.4.0-812.el9"),
            (Pkg, "1.4.0"),
            (Pkg, "1.4.0-rc.2-812"),
            (Rpm, "1.4.0~rc2-812"),
            (Pacman, "1.4.0~rc.2-812"),
            (Pacman, "1.4.0-rc.2-812"),
            (Pacman, "1:1.4.0-812"),
            (Pacman, "1.4.0rc.2-812.1"),
            (Msi, "1.4.0"),
            (Msi, "1.4.0.812"),
            (Msi, "1.4.0-rc.2-812"),
            (Zip, "1.4.0-1"),
            (Tar, "1.4.0-1"),
        ] {
            assert!(
                Release::from_package_version(format, bad).is_err(),
                "{format} {bad:?} accepted"
            );
        }
    }

    #[test]
    fn orders_like_semver_then_sequence() {
        let order = [
            ("0.9.9", 50),
            ("1.0.0-alpha", 1),
            ("1.0.0-alpha.1", 1),
            ("1.0.0-alpha.2", 1),
            ("1.0.0-alpha.10", 1),
            ("1.0.0-beta", 1),
            ("1.0.0-rc.1", 1),
            ("1.0.0", 1),
            ("1.0.0", 2),
            ("1.0.1", 1),
        ];
        let releases: Vec<Release> = order
            .iter()
            .map(|(v, s)| Release::new(v, *s).unwrap())
            .collect();
        for pair in releases.windows(2) {
            assert!(pair[0] < pair[1], "{:?} !< {:?}", pair[0], pair[1]);
        }
    }
}
