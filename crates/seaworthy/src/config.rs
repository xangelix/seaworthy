//! `seaworthy.toml`: one file per product repository describing what to ship.
//!
//! ```toml
//! [defaults]
//! vendor = "Acme"
//! targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]   # preference order
//! channel = "stable"
//! release-signatures = ["ml-dsa-87"]
//! fips = true                     # the cores carry the AWS-LC FIPS module
//! maintainer = "Acme <packages@example.com>"
//! license = "LicenseRef-Acme-Proprietary"
//! homepage = "https://example.com"
//! openpgp-keys = ["keys/packages.asc"]   # signs rpm, pacman and the repositories
//!
//! [defaults.repository]           # where `publish` puts them: <vendor>-repository points there
//! url = "https://files.example.com/packages"
//!
//! [product.collector]
//! display-name = "Acme Forensic Collector"
//! description = "Collects forensic data for Acme."
//! executable = "AcmeForensicCollector"   # the launcher's file stem
//! core = "acme_collector_core"                     # the cdylib's crate name
//! helper = "AcmeCollectorUpdate"          # the update helper's file stem
//! helper-crate = "crates/acme_collector/update"    # its crate (built from its own manifest)
//! windows-directory = "Collector"                # required with msi: never follows the display name
//! sidecars.windows = ["aws_lc_fips_*_crypto.dll"]    # the FIPS module's DLL (aws-lc-fips-sys 0.14)
//! outputs = ["msi", "zip", "deb", "rpm", "pacman", "tar"]
//! updates.default = "auto"
//!
//! [product.collector.service]
//! name = "AcmeLiveResponseService"
//! account = "local-system"
//! arguments = ["service"]
//! restart-delays = ["15s", "60s", "300s", "900s"]
//! state-directory = "acme/collector"
//! ```
//!
//! Unknown keys are refused, so a typo can't silently drop a setting.
//! [`Config::load`] parses and validates. Validation includes rendering
//! every service through `seaworthy_service::render` for both platforms, so a
//! `seaworthy.toml` that loads is one every generator can package.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use seaworthy_service::{
    FailurePolicy, ServiceSpec, SystemdHardening, SystemdSandbox, WindowsServiceAccount,
};
use serde::Deserialize;

use crate::DistError;

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Settings every product shares.
    pub defaults: Defaults,
    /// The products, by id (`collector`, `console`).
    #[serde(rename = "product")]
    pub products: BTreeMap<String, Product>,
    /// The directory `seaworthy.toml` was loaded from: relative paths in it
    /// (`release-keys`) resolve here. Empty when parsed from text.
    #[serde(skip)]
    pub dir: PathBuf,
    /// Whether `release-keys` and `openpgp-keys` are the CI test keys'
    /// ([`Config::use_ci_test_keys`]): a build that signs with
    /// them is never a release.
    #[serde(skip)]
    pub ci_test: bool,
}

/// `[defaults]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Defaults {
    /// The vendor: the install directories' parent (`Acme` →
    /// `%ProgramFiles%\Acme`, `/opt/acme`).
    pub vendor: String,
    /// The CPU targets, most preferred first. Each needs a core.
    pub targets: Vec<String>,
    /// The release channel (`stable`).
    pub channel: String,
    /// The algorithms release manifests are signed with; must match the
    /// products' `AlgorithmPolicy` (for example `ml-dsa-87` only). Empty
    /// (or left out): no release manifests at all — only when no product
    /// ships an update helper, the one client that verifies them. Packages
    /// keep their own signatures (OpenPGP, Authenticode) either way.
    #[serde(default)]
    pub release_signatures: Vec<SignatureAlgorithm>,
    /// The release public keys the products' clients trust (the files the
    /// update helper embeds): a manifest signer must hold one of them.
    /// Required to sign.
    #[serde(default)]
    pub release_keys: Vec<ReleaseKeyFile>,
    /// The Authenticode signer Windows and its policies trust:
    /// every Authenticode signature is checked against it. Required to
    /// sign with Authenticode.
    #[serde(default)]
    pub authenticode: Option<AuthenticodeIdentity>,
    /// The Apple developer team whose Developer ID signs the macOS
    /// outputs: every Developer ID signature is checked against it.
    /// Required to sign with `signing.toml`'s `[apple]`.
    #[serde(default)]
    pub apple: Option<AppleIdentity>,
    /// The OpenPGP public key files package managers trust
    /// (ASCII-armored public key blocks, relative to `seaworthy.toml`): every rpm
    /// and pacman signature must verify against one of them alone, here
    /// and in the update helper, which compiles the same files in.
    /// Required to sign packages. Checked at load: a binary key, or a
    /// private one, is refused before anything is built.
    #[serde(default)]
    pub openpgp_keys: Vec<PathBuf>,
    /// The public CI test keys a product's NON-release builds also trust,
    /// which `--ci-test-signing` signs with instead of
    /// `release-keys` and `openpgp-keys`: none of them may be one of
    /// those. A release never trusts or signs with them.
    #[serde(default)]
    pub ci_test_keys: Option<CiTestKeys>,
    /// The cores carry the AWS-LC FIPS module: `verify` applies the FIPS
    /// binary checks (Linux); on Windows and macOS, where AWS-LC builds the
    /// module as a dynamic library, every core loads the pinned module's
    /// crypto library and the sidecars ship every module library the cores
    /// load (on macOS the module's own symbols pass the Linux checks).
    #[serde(default)]
    pub fips: bool,
    /// The package maintainer (deb `Maintainer:`, rpm `Packager:`).
    pub maintainer: String,
    /// The license expression (rpm `License:`, deb copyright, pacman).
    pub license: String,
    /// The vendor's web address.
    #[serde(default)]
    pub homepage: Option<String>,
    /// The macOS cores' CPU targets (Apple Silicon), most preferred first
    /// (default `["apple-m1"]`: every arm64 Mac runs it — seaworthy_levels'
    /// Apple M1 baseline). Used by products with a macOS output only.
    #[serde(default = "default_macos_targets")]
    pub macos_targets: Vec<String>,
    /// The oldest macOS the products run on (default `"11.0"`, the oldest
    /// Apple Silicon runs and Rust's floor for the target): the binaries'
    /// deployment target (the build plan sets `MACOSX_DEPLOYMENT_TARGET`)
    /// and the bundle's `LSMinimumSystemVersion`; `verify` refuses a binary
    /// that needs a newer one.
    #[serde(default = "default_macos_minimum")]
    pub macos_minimum: String,
    /// Where the packages are published (`seaworthy repo` and `publish`):
    /// with it, `package` also builds `<vendor>-repository`, which sets apt
    /// and dnf up to use those repositories, trusting the pinned keys
    /// (`crate::repository_package`), and `repo` publishes it.
    #[serde(default)]
    pub repository: Option<RepositorySettings>,
}

fn default_macos_targets() -> Vec<String> {
    vec!["apple-m1".to_owned()]
}

fn default_macos_minimum() -> String {
    "11.0".to_owned()
}

/// A macOS version (`11.0`, `13.5.1`) as `(major, minor, patch)`, or `None`
/// for anything else.
#[must_use]
pub fn parse_macos_version(text: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = text.split('.').collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    let mut numbers = [0_u32; 3];
    for (slot, part) in numbers.iter_mut().zip(&parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    let [major, minor, patch] = numbers;
    Some((major, minor, patch))
}

/// The product id the repository package is listed under (no product may
/// take it while `[defaults.repository]` is set).
pub const REPOSITORY_ID: &str = "repository";

/// `[defaults.repository]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RepositorySettings {
    /// The URL clients fetch the published repositories through
    /// (`publish.toml`'s `public-url`): https (http only to a loopback
    /// address), no credentials, query, fragment or trailing slash.
    pub url: String,
}

/// `[defaults.ci-test-keys]`: the CI test keys' public halves,
/// relative to `seaworthy.toml`, as `release-keys` and `openpgp-keys` name the
/// real ones.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct CiTestKeys {
    /// The test release keys (a manifest signed with one verifies in a
    /// non-release build alone).
    #[serde(default)]
    pub release_keys: Vec<ReleaseKeyFile>,
    /// The test OpenPGP keys (rpm and pacman signatures).
    #[serde(default)]
    pub openpgp_keys: Vec<PathBuf>,
}

/// One trusted release public key: its algorithm and a file holding its
/// hex (as `seaworthy keygen --public` writes it), relative to `seaworthy.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ReleaseKeyFile {
    /// The key's algorithm.
    pub algorithm: SignatureAlgorithm,
    /// The public key file.
    pub public_key: PathBuf,
}

/// `[defaults.authenticode]`: who may Authenticode-sign. Pinned by
/// subject and chain, not by certificate: Azure Trusted Signing's
/// certificates last days, while the identity and its CA stay.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AuthenticodeIdentity {
    /// The signing certificate's subject exactly as `osslsigncode verify`
    /// (the pinned 2.14) prints it: RFC 2253 form, the last RDN first
    /// (`O=Acme,CN=Acme Code Signing` for `/CN=Acme Code Signing/O=Acme`).
    pub subject: String,
    /// A PEM file of the trust anchors the signer's chain, and its
    /// timestamp's, must verify to (relative to `seaworthy.toml`). Azure Trusted
    /// Signing's chains and Microsoft's timestamps both end in Microsoft
    /// Identity Verification Root Certificate Authority 2020.
    pub trust: PathBuf,
}

/// `[defaults.apple]`: who may Developer ID-sign the macOS outputs.
/// Pinned by team, not by certificate: Developer ID certificates are
/// renewed (and an app's identity survives them) while the team stays.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AppleIdentity {
    /// The team identifier every Developer ID signature must carry
    /// (`codesign --display` prints it as `TeamIdentifier`): ten
    /// characters of `[A-Z0-9]`.
    pub team_id: String,
}

/// Whether `text` is an Apple team identifier: ten of `[A-Z0-9]`.
#[must_use]
pub fn is_team_id(text: &str) -> bool {
    text.len() == 10
        && text
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// A release-manifest signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204).
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
    /// ECDSA P-256 with SHA-256.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// Ed25519.
    Ed25519,
}

/// What kind of program a product is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A service (needs `[product.<id>.service]`).
    #[default]
    Service,
    /// A desktop app run by the logged-in user: no service; the helper is
    /// started through the interactive-users grant (Windows) or a polkit
    /// rule (Linux).
    Desktop,
    /// A command-line tool: no service, no helper start right.
    Tool,
}

/// A deliverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Output {
    /// A Windows Installer package.
    Msi,
    /// A Windows zip of the install tree.
    Zip,
    /// A Debian package.
    Deb,
    /// An RPM package.
    Rpm,
    /// An Arch Linux package.
    Pacman,
    /// A Linux tarball of the install tree.
    Tar,
    /// A macOS disk image holding the app bundle (desktop products).
    Dmg,
    /// A macOS flat installer package: the app bundle and its
    /// LaunchDaemons (service products).
    Pkg,
}

impl Output {
    /// Whether the output is for Windows.
    #[must_use]
    pub fn is_windows(self) -> bool {
        matches!(self, Self::Msi | Self::Zip)
    }

    /// Whether the output is for macOS.
    #[must_use]
    pub fn is_macos(self) -> bool {
        matches!(self, Self::Dmg | Self::Pkg)
    }

    /// The platform the output installs on.
    #[must_use]
    pub fn platform(self) -> Platform {
        if self.is_windows() {
            Platform::Windows
        } else if self.is_macos() {
            Platform::Macos
        } else {
            Platform::Linux
        }
    }

    /// The output's name in `seaworthy.toml` (`msi`, `zip`, …).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Zip => "zip",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Pacman => "pacman",
            Self::Tar => "tar",
            Self::Dmg => "dmg",
            Self::Pkg => "pkg",
        }
    }
}

/// The update policy a fresh install starts with (`updates.default`):
/// `auto`, `notify` or `off`. The same type the app side and the update
/// helper read the machine's policy into.
pub use seaworthy_updater::UpdatePolicy;

/// `[product.<id>.updates]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    /// The install-time default policy.
    #[serde(default)]
    pub default: UpdatePolicy,
}

/// `[product.<id>.sidecars]`: files shipped beside the cores, per platform.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecars {
    /// File-name globs (`*` only) matched in each Windows core build's
    /// sidecar directory; each must match exactly one file, identical in
    /// every target build.
    #[serde(default)]
    pub windows: Vec<String>,
    /// The same for macOS (the FIPS module's dylib,
    /// `libaws_lc_fips_*_crypto.dylib`): shipped once in the bundle's
    /// `Contents/Frameworks`, beside the cores, which load it through their
    /// `@loader_path` search path (executables through
    /// `@executable_path/../Frameworks`).
    #[serde(default)]
    pub macos: Vec<String>,
}

impl Sidecars {
    /// The globs for `os` (none on Linux).
    #[must_use]
    pub fn for_os(&self, os: crate::inputs::Os) -> &[String] {
        match os {
            crate::inputs::Os::Windows => &self.windows,
            crate::inputs::Os::Macos => &self.macos,
            crate::inputs::Os::Linux => &[],
        }
    }
}

/// `[product.<id>.linux]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Linux {
    /// Package dependencies per format, in each format's own syntax.
    #[serde(default)]
    pub depends: Depends,
    /// Shared libraries the binaries may need (`DT_NEEDED`) beyond the base
    /// system's (`verify::BASE_NEEDED`); each needs its package in
    /// `depends`.
    #[serde(default)]
    pub needed: Vec<String>,
    /// The oldest glibc the product's Linux binaries must run on, `2.N`
    /// (default [`DEFAULT_GLIBC_FLOOR`], RHEL 9's). `verify` refuses a
    /// binary whose symbols need a newer one: it would install (the
    /// packages' dependency says nothing about symbol versions) and then
    /// fail to start.
    #[serde(default)]
    pub glibc: Option<String>,
    /// `/usr/bin/<command>`: a link to the launcher the Linux packages
    /// install, so the program runs by name (`[a-z0-9][a-z0-9._+-]*`, at
    /// most 64 bytes; no link without it). The launcher finds its cores
    /// through the link: it resolves its own path (`/proc/self/exe`).
    #[serde(default)]
    pub command: Option<String>,
    /// Packages this product's Linux packages replace: packages of the same
    /// program another tool built under other names (`acme-tool`, built
    /// before the product took its `<vendor>-<id>` name). Every format
    /// conflicts with them and replaces them (deb `Conflicts:` and
    /// `Replaces:`, rpm `Conflicts:` and `Obsoletes:`, pacman `conflicts`
    /// and `replaces`), so installing or upgrading to this product removes
    /// them instead of failing on the files both install (a `/usr/bin`
    /// link, a menu entry).
    #[serde(default)]
    pub replaces: Vec<String>,
}

/// The default glibc floor: 2.34, RHEL 9's (and so Rocky's and Alma's),
/// the oldest glibc on the distributions the Linux conformance lane
/// installs on.
pub const DEFAULT_GLIBC_FLOOR: (u32, u32) = (2, 34);

/// `2.N` (or `M.N`) as `(M, N)`.
pub fn parse_glibc_version(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.split_once('.')?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(major) || !digits(minor) {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

impl Linux {
    /// The glibc floor: `glibc`, or [`DEFAULT_GLIBC_FLOOR`].
    pub fn glibc_floor(&self) -> (u32, u32) {
        self.glibc
            .as_deref()
            .and_then(parse_glibc_version)
            .unwrap_or(DEFAULT_GLIBC_FLOOR)
    }
}

/// Package dependencies per Linux format.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Depends {
    /// deb `Depends:` entries (alternatives with `|`).
    #[serde(default)]
    pub deb: Vec<String>,
    /// rpm `Requires:` entries.
    #[serde(default)]
    pub rpm: Vec<String>,
    /// pacman `depends` entries.
    #[serde(default)]
    pub pacman: Vec<String>,
}

/// `[product.<id>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Product {
    /// The name shown to people.
    pub display_name: String,
    /// One-line package description.
    pub description: String,
    /// The launcher crate's path, relative to the workspace root (the
    /// directory of the CI template's `manifest`, build-plan's
    /// `--manifest`), for the CI templates that build it; `seaworthy`
    /// reads only built artifacts.
    #[serde(default)]
    pub launcher: Option<PathBuf>,
    /// The launcher executable's file stem (`AcmeForensicCollector`).
    pub executable: String,
    /// The core cdylib's crate name (`acme_collector_core`).
    pub core: String,
    /// The update helper executable's file stem. Required unless
    /// `updates.default = "off"`.
    #[serde(default)]
    pub helper: Option<String>,
    /// The update helper's crate path, relative to the workspace root like
    /// `launcher`'s, for the CI templates: the build plan builds it from that
    /// manifest, so only its own features are enabled. Without it the
    /// helper is built `--bin <helper>` from the workspace root, which
    /// unifies the features of every workspace member.
    #[serde(default)]
    pub helper_crate: Option<PathBuf>,
    /// The Windows install directory under the vendor directory (default:
    /// the display name's last word, `Collector`).
    #[serde(default)]
    pub windows_directory: Option<String>,
    /// The program kind.
    #[serde(default)]
    pub kind: Kind,
    /// Sidecar files.
    #[serde(default)]
    pub sidecars: Sidecars,
    /// The deliverables.
    pub outputs: Vec<Output>,
    /// The update policy.
    #[serde(default)]
    pub updates: Updates,
    /// Linux packaging extras.
    #[serde(default)]
    pub linux: Linux,
    /// The service, for `kind = "service"`.
    #[serde(default)]
    pub service: Option<Service>,
    /// The MSI's UpgradeCode (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`),
    /// which ties every release of the product together and must never
    /// change. Default: derived from the vendor and the product id
    /// (`crate::wix::upgrade_code`); set it to keep an existing code.
    #[serde(default)]
    pub upgrade_code: Option<String>,
    /// `[product.<id>.desktop]`: a desktop app's menu entry, icons and
    /// shortcuts (`kind = "desktop"` only). Without it a desktop
    /// product installs its files and nothing else.
    #[serde(default)]
    pub desktop: Option<Desktop>,
    /// `[[product.<id>.files]]`: data files installed under the install
    /// root beside the launcher (fonts, images, documents, licenses).
    #[serde(default)]
    pub files: Vec<ExtraFiles>,
    /// `[product.<id>.macos]`: the app bundle's identity, required
    /// with a macOS output.
    #[serde(default)]
    pub macos: Option<Macos>,
}

/// `[product.<id>.macos]`: what the app bundle says about itself.
///
/// ```toml
/// [product.console.macos]
/// bundle-id = "com.acme.console"
/// icon = "assets/console.icns"
/// category = "public.app-category.utilities"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Macos {
    /// `CFBundleIdentifier`, reverse-DNS (`com.acme.console`).
    /// Required and never derived: macOS keys an app's permissions
    /// (Full Disk Access), preferences and notarization to it, so it must
    /// never change — like the MSI's UpgradeCode.
    pub bundle_id: String,
    /// The app icon (`.icns`, relative to `seaworthy.toml`): the bundle's
    /// `CFBundleIconFile`, in `Contents/Resources`.
    #[serde(default)]
    pub icon: Option<PathBuf>,
    /// `LSApplicationCategoryType` (`public.app-category.utilities`).
    #[serde(default)]
    pub category: Option<String>,
    /// The entitlements a Developer ID signature gives the app (an XML
    /// property list, relative to `seaworthy.toml`): the hardened
    /// runtime's exceptions it needs, such as
    /// `com.apple.security.cs.allow-jit`. Signed into the main executable
    /// alone; an ad hoc signature carries none.
    #[serde(default)]
    pub entitlements: Option<PathBuf>,
}

/// `[product.<id>.desktop]`: what a desktop app shows people.
///
/// ```toml
/// [product.console.desktop]
/// linux-icons = ["assets/console-256.png", "assets/console.svg"]
/// windows-icon = "assets/console.ico"
/// categories = ["Office", "Viewer"]
/// wm-class = "AcmeConsole"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Desktop {
    /// The menu entry's id: the Linux `.desktop` file's name and the
    /// icons' name (default `<vendor>-<id>`, lowercase). A reverse-DNS id
    /// (`com.acme.Console`) suits an app that also names its Wayland
    /// `app_id` that way.
    #[serde(default)]
    pub app_id: Option<String>,
    /// The Linux icons, relative to `seaworthy.toml`: square PNGs of the
    /// hicolor theme's sizes ([`HICOLOR_SIZES`]), one per size, and at
    /// most one SVG (the `scalable` icon).
    #[serde(default)]
    pub linux_icons: Vec<PathBuf>,
    /// The Windows icon (`.ico`, relative to `seaworthy.toml`): the MSI's
    /// Programs and Features icon and the shortcuts'. Without it the
    /// shortcuts show the launcher's own icon resource.
    #[serde(default)]
    pub windows_icon: Option<PathBuf>,
    /// A Start-menu shortcut to the launcher (default true).
    #[serde(default = "default_true")]
    pub start_menu: bool,
    /// A shortcut on every user's desktop (default false).
    #[serde(default)]
    pub desktop_shortcut: bool,
    /// The `.desktop` entry's `Categories` (default `["Utility"]`): at
    /// least one of the freedesktop main categories ([`MAIN_CATEGORIES`]).
    #[serde(default = "default_categories")]
    pub categories: Vec<String>,
    /// The `.desktop` entry's `Keywords`, for the menu's search.
    #[serde(default)]
    pub keywords: Vec<String>,
    /// The `.desktop` entry's `StartupWMClass`: the window class (X11) or
    /// app id (Wayland) the app's windows carry, so a dock groups them
    /// under the entry (winit: the `app_id`/`name` it sets).
    #[serde(default)]
    pub wm_class: Option<String>,
}

/// The hicolor icon theme's fixed sizes a `linux-icons` PNG may have.
pub const HICOLOR_SIZES: [u32; 11] = [16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512];

/// The freedesktop menu's main categories: a `.desktop` entry needs one.
pub const MAIN_CATEGORIES: [&str; 13] = [
    "AudioVideo",
    "Audio",
    "Video",
    "Development",
    "Education",
    "Game",
    "Graphics",
    "Network",
    "Office",
    "Science",
    "Settings",
    "System",
    "Utility",
];

fn default_true() -> bool {
    true
}

fn default_categories() -> Vec<String> {
    vec!["Utility".to_owned()]
}

impl Desktop {
    /// The menu entry's id: `app-id`, or `<vendor>-<id>` lowercase.
    #[must_use]
    pub fn app_id(&self, config: &Config, id: &str) -> String {
        self.app_id
            .clone()
            .unwrap_or_else(|| crate::linux::package_name(config, id))
    }
}

/// `[[product.<id>.files]]`: a file, or a directory with everything below
/// it, installed under the install root. Data only: `layout` refuses
/// executable code (ELF, PE, Mach-O), which ships as the launcher, a core,
/// a sidecar or the helper, the files `verify` checks.
///
/// ```toml
/// [[product.console.files]]
/// source = "assets/fonts"
/// destination = "share/fonts"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ExtraFiles {
    /// The file or directory, relative to `seaworthy.toml`.
    pub source: PathBuf,
    /// Where it installs, relative to the install root and `/`-separated
    /// (default: the source's own name).
    #[serde(default)]
    pub destination: Option<String>,
    /// The platforms that ship it (default every one: on macOS, data files
    /// install in the bundle's `Contents/Resources`).
    #[serde(default = "both_platforms")]
    pub platforms: Vec<Platform>,
    /// Ship hidden files (`.name`) found below a directory source (default
    /// false: an editor's or a tool's leftovers, `.env` files). Version
    /// control directories (`.git`, `.hg`, `.svn`, `.bzr`) never ship.
    #[serde(default)]
    pub hidden: bool,
}

/// Version control directories: never shipped (a `.git/config` can hold a
/// CI token in its remote URL).
pub const VCS_DIRECTORIES: [&str; 4] = [".git", ".hg", ".svn", ".bzr"];

/// The longest display name with an MSI shortcut: `Shortcut.Name` holds
/// 128 characters, `.lnk` included, with room to spare.
pub const MAX_SHORTCUT_NAME: usize = 100;

/// An operating system a product ships for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Linux (the tarball and the packages).
    Linux,
    /// Windows (the MSI and the zip).
    Windows,
    /// macOS (the app bundle, in its disk image).
    Macos,
}

fn both_platforms() -> Vec<Platform> {
    vec![Platform::Linux, Platform::Windows, Platform::Macos]
}

impl Platform {
    /// Every platform, in the order the tools list them.
    pub const ALL: [Self; 3] = [Self::Linux, Self::Windows, Self::Macos];

    /// Its name in `seaworthy.toml` and on the command line.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
        }
    }

    /// The platforms a comma-separated list names (`--platforms`): each
    /// once, at least one.
    ///
    /// # Errors
    /// The refusal, for an empty list, an unknown name or a repeated one.
    pub fn parse_list(text: &str) -> Result<Vec<Self>, String> {
        let mut platforms = Vec::new();
        for name in text.split(',') {
            let platform = Self::ALL
                .into_iter()
                .find(|p| p.name() == name)
                .ok_or_else(|| format!("{name:?} isn't a platform (linux, windows, macos)"))?;
            if platforms.contains(&platform) {
                return Err(format!("{name} is named twice"));
            }
            platforms.push(platform);
        }
        Ok(platforms)
    }
}

impl ExtraFiles {
    /// Where it installs: `destination`, or the source's file name.
    #[must_use]
    pub fn destination(&self) -> String {
        self.destination.clone().unwrap_or_else(|| {
            self.source
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
    }
}

/// A service's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Account {
    /// The per-service virtual account `NT SERVICE\<name>` on Windows; a
    /// sandbox user (or root without one) under systemd.
    #[default]
    Virtual,
    /// `NT AUTHORITY\LocalService`.
    LocalService,
    /// `NT AUTHORITY\NetworkService`.
    NetworkService,
    /// LocalSystem on Windows, root under systemd (the collector).
    LocalSystem,
}

/// `[product.<id>.service.sandbox]`: the systemd identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    /// `User=`.
    pub user: String,
    /// `Group=` (default: the user).
    #[serde(default)]
    pub group: Option<String>,
    /// Ambient capabilities.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// `[product.<id>.service]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Service {
    /// The service name (SCM name, systemd unit basename).
    pub name: String,
    /// The account.
    #[serde(default)]
    pub account: Account,
    /// The launch arguments.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Restart delays (`15s`, `5m`, `1h`), the last repeating forever.
    #[serde(default = "default_restart_delays")]
    pub restart_delays: Vec<String>,
    /// Windows: stable uptime after which the escalation resets.
    #[serde(default = "default_reset_period")]
    pub reset_period: String,
    /// systemd `StateDirectory=` (relative to `/var/lib`). Required when
    /// the helper is shipped: the update request file lives there.
    #[serde(default)]
    pub state_directory: Option<String>,
    /// The systemd sandbox identity. Without one the unit runs as root.
    #[serde(default)]
    pub sandbox: Option<Sandbox>,
    /// systemd hardening: `"default"` (all on), `"none"`, or a table
    /// changing one ([`HardeningTable`]).
    #[serde(default)]
    pub hardening: Hardening,
}

/// A systemd hardening preset: the starting point of `hardening`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardeningPreset {
    /// `SystemdHardening::default()`: every directive on.
    #[default]
    Default,
    /// `SystemdHardening::none()`: every directive off.
    None,
}

/// `[product.<id>.service.hardening]`: a preset, then each directive the
/// service changes from it. A service that must read the whole host (the
/// collector) starts from `none` and turns back on everything it can keep,
/// rather than dropping all hardening.
///
/// ```toml
/// [product.collector.service.hardening]
/// preset = "none"
/// no-new-privileges = true
/// protect-kernel-tunables = true
/// restrict-address-families = true
/// extra-address-families = ["AF_NETLINK"]
/// ```
///
/// `extra-address-families` needs `restrict-address-families`, and
/// `read-write-paths` needs `protect-system-strict` (each is refused
/// without it: the renderer would drop it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HardeningTable {
    /// The preset the directives below change.
    #[serde(default)]
    pub preset: HardeningPreset,
    /// `NoNewPrivileges=true`.
    pub no_new_privileges: Option<bool>,
    /// `ProtectSystem=strict`.
    pub protect_system_strict: Option<bool>,
    /// `ProtectHome=true`.
    pub protect_home: Option<bool>,
    /// `PrivateTmp=true`.
    pub private_tmp: Option<bool>,
    /// `PrivateDevices=true`.
    pub private_devices: Option<bool>,
    /// `ProtectKernelTunables=true`.
    pub protect_kernel_tunables: Option<bool>,
    /// `ProtectKernelModules=true`.
    pub protect_kernel_modules: Option<bool>,
    /// `ProtectKernelLogs=true`.
    pub protect_kernel_logs: Option<bool>,
    /// `ProtectControlGroups=true`.
    pub protect_control_groups: Option<bool>,
    /// `ProtectClock=true`.
    pub protect_clock: Option<bool>,
    /// `ProtectHostname=true`.
    pub protect_hostname: Option<bool>,
    /// `ProtectProc=invisible` and `ProcSubset=pid`.
    pub protect_proc: Option<bool>,
    /// `RestrictNamespaces=true`.
    pub restrict_namespaces: Option<bool>,
    /// `RestrictRealtime=true`.
    pub restrict_realtime: Option<bool>,
    /// `RestrictSUIDSGID=true`.
    pub restrict_suid_sgid: Option<bool>,
    /// `LockPersonality=true`.
    pub lock_personality: Option<bool>,
    /// `MemoryDenyWriteExecute=true`.
    pub memory_deny_write_execute: Option<bool>,
    /// `RemoveIPC=true`.
    pub remove_ipc: Option<bool>,
    /// `SystemCallArchitectures=native`.
    pub system_call_architectures_native: Option<bool>,
    /// The `@system-service` system call filter.
    pub system_call_filter: Option<bool>,
    /// `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, plus
    /// `extra-address-families`.
    pub restrict_address_families: Option<bool>,
    /// `UMask=0077`.
    pub umask_0077: Option<bool>,
    /// `DevicePolicy=closed`.
    pub device_policy_closed: Option<bool>,
    /// More `AF_*` families for `RestrictAddressFamilies=` (`AF_NETLINK`).
    #[serde(default)]
    pub extra_address_families: Vec<String>,
    /// Paths that stay writable under `ProtectSystem=strict`.
    #[serde(default)]
    pub read_write_paths: Vec<PathBuf>,
}

/// The systemd hardening: a preset name (`"default"`, every directive on;
/// `"none"`), or a [`HardeningTable`] changing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hardening {
    /// A preset as it is.
    Preset(HardeningPreset),
    /// A preset with directives changed.
    Table(Box<HardeningTable>),
}

impl Default for Hardening {
    fn default() -> Self {
        Self::Preset(HardeningPreset::Default)
    }
}

impl<'de> Deserialize<'de> for Hardening {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Hardening;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("\"default\", \"none\", or a table of systemd directives")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Hardening, E> {
                HardeningPreset::deserialize(serde::de::value::StrDeserializer::new(value))
                    .map(Hardening::Preset)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Hardening, A::Error> {
                HardeningTable::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(|table| Hardening::Table(Box::new(table)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl Hardening {
    /// The directives `seaworthy_service` renders.
    #[must_use]
    pub fn systemd(&self) -> SystemdHardening {
        let preset = |p: HardeningPreset| match p {
            HardeningPreset::Default => SystemdHardening::default(),
            HardeningPreset::None => SystemdHardening::none(),
        };
        let table = match self {
            Self::Preset(p) => return preset(*p),
            Self::Table(table) => table,
        };
        let mut h = preset(table.preset);
        let set = |field: &mut bool, value: Option<bool>| {
            if let Some(value) = value {
                *field = value;
            }
        };
        set(&mut h.no_new_privileges, table.no_new_privileges);
        set(&mut h.protect_system_strict, table.protect_system_strict);
        set(&mut h.protect_home, table.protect_home);
        set(&mut h.private_tmp, table.private_tmp);
        set(&mut h.private_devices, table.private_devices);
        set(
            &mut h.protect_kernel_tunables,
            table.protect_kernel_tunables,
        );
        set(&mut h.protect_kernel_modules, table.protect_kernel_modules);
        set(&mut h.protect_kernel_logs, table.protect_kernel_logs);
        set(&mut h.protect_control_groups, table.protect_control_groups);
        set(&mut h.protect_clock, table.protect_clock);
        set(&mut h.protect_hostname, table.protect_hostname);
        set(&mut h.protect_proc, table.protect_proc);
        set(&mut h.restrict_namespaces, table.restrict_namespaces);
        set(&mut h.restrict_realtime, table.restrict_realtime);
        set(&mut h.restrict_suid_sgid, table.restrict_suid_sgid);
        set(&mut h.lock_personality, table.lock_personality);
        set(
            &mut h.memory_deny_write_execute,
            table.memory_deny_write_execute,
        );
        set(&mut h.remove_ipc, table.remove_ipc);
        set(
            &mut h.system_call_architectures_native,
            table.system_call_architectures_native,
        );
        set(&mut h.system_call_filter, table.system_call_filter);
        set(
            &mut h.restrict_address_families,
            table.restrict_address_families,
        );
        set(&mut h.umask_0077, table.umask_0077);
        set(&mut h.device_policy_closed, table.device_policy_closed);
        h.extra_address_families
            .extend(table.extra_address_families.iter().cloned());
        h.read_write_paths
            .extend(table.read_write_paths.iter().cloned());
        h
    }
}

fn default_restart_delays() -> Vec<String> {
    ["15s", "60s", "300s", "900s"]
        .iter()
        .map(|d| (*d).to_owned())
        .collect()
}

fn default_reset_period() -> String {
    "24h".to_owned()
}

/// Parses `15s`, `5m`, `1h`, `2d`, or `1500ms`.
///
/// # Errors
/// [`DistError::Config`] for anything else.
pub fn parse_duration(text: &str) -> Result<Duration, DistError> {
    let bad = || {
        DistError::Config(format!(
            "{text:?} is not a duration (a whole number followed by ms, s, m, h or d)"
        ))
    };
    let split = text.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
    let (digits, unit) = text.split_at(split);
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(bad());
    }
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let secs = |factor: u64| {
        n.checked_mul(factor)
            .map(Duration::from_secs)
            .ok_or_else(bad)
    };
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => secs(1),
        "m" => secs(60),
        "h" => secs(3600),
        "d" => secs(86_400),
        _ => Err(bad()),
    }
}

/// A lowercase identifier: `[a-z0-9][a-z0-9-]*` (product ids, Linux
/// directory and package names).
fn is_identifier(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A file stem or directory name usable on both platforms:
/// `[A-Za-z0-9][A-Za-z0-9._-]*`, at most 64 bytes.
fn is_file_stem(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A reverse-DNS bundle identifier (`CFBundleIdentifier`): two or more
/// dot-separated labels of `[A-Za-z0-9-]`, at most 155 characters (Apple's
/// limit for an identifier a provisioning profile or notarization takes).
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

/// A plain file name usable on both platforms (the [`is_file_stem`] rule),
/// for names that come from artifacts.
pub(crate) fn is_file_name(text: &str) -> bool {
    is_file_stem(text)
}

/// A name Windows reserves for a device (`CON`, `NUL`, `COM1`, …, with or
/// without an extension), or one ending in `.` or a space (which Windows
/// silently drops).
pub(crate) fn is_windows_reserved(text: &str) -> bool {
    let stem = text.split('.').next().unwrap_or(text).to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    device || text.ends_with('.') || text.ends_with(' ')
}

/// A URL machines fetch packages through: https, or http to a loopback
/// address; no userinfo, port 0, query, fragment or trailing slash; written
/// as a URL parser writes it back (a lowercase host, no default port, no
/// `https:host` shorthand: apt reads the text as given, not as a parser
/// would mend it); only ASCII letters, digits and `-._~:/[]` (nothing a
/// repository definition reads specially: dnf splits `baseurl` at commas,
/// nFPM expands `$`). `[defaults.repository]`'s `url` and `publish.toml`'s
/// `public-url` both follow it, so the two compare as text.
pub(crate) fn client_url_ok(text: &str) -> bool {
    let Ok(url) = url::Url::parse(text) else {
        return false;
    };
    let canonical =
        url.as_str() == text || (url.path() == "/" && url.as_str().strip_suffix('/') == Some(text));
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    };
    (url.scheme() == "https" || (url.scheme() == "http" && loopback))
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.port() != Some(0)
        && url.query().is_none()
        && url.fragment().is_none()
        && !text.ends_with('/')
        && canonical
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~:/[]".contains(&b))
}

/// A name for a Windows file or directory: a file stem, not reserved.
fn is_windows_name(text: &str) -> bool {
    is_file_stem(text) && !is_windows_reserved(text)
}

/// Text that goes into package metadata: non-empty, no control
/// characters, and no `$`. nFPM expands `$VAR` and `${VAR}` in metadata
/// with no escape, so a `$` would let the build's environment change, or
/// leak into, a package (and WiX expands `$(…)` likewise).
fn is_plain_text(text: &str) -> bool {
    !text.is_empty() && !text.chars().any(|c| c.is_control() || c == '$')
}

/// The longest display name: the SCM keeps 256 characters, and the
/// helper's display name adds " updater".
const MAX_DISPLAY_NAME: usize = 200;

/// The longest description (the SCM keeps 2048 characters; package
/// managers show one line).
const MAX_DESCRIPTION: usize = 1000;

/// A GUID in registry form: `{` 8-4-4-4-12 hex digits `}`.
pub(crate) fn is_guid(text: &str) -> bool {
    let Some(inner) = text.strip_prefix('{').and_then(|t| t.strip_suffix('}')) else {
        return false;
    };
    let groups: Vec<&str> = inner.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A Linux package name every format accepts: Debian's rule
/// (`[a-z0-9][a-z0-9+.-]+`) without `+`, which rpm and pacman file names
/// and URLs handle badly.
fn is_package_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() >= 2
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

/// A `/usr/bin` command name: `[a-z0-9][a-z0-9._+-]*`, at most 64 bytes.
fn is_command_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    text.len() <= 64
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
}

/// A desktop entry id (the `.desktop` file's stem and the icons' name):
/// non-empty `[A-Za-z0-9_-]` segments joined by `.`, starting with a letter
/// or digit, at most 200 bytes (reverse-DNS ids qualify).
fn is_app_id(text: &str) -> bool {
    text.len() <= 200
        && text
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && text.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        })
}

/// A `.desktop` category name: `[A-Za-z0-9-]`, at most 64 bytes.
fn is_category(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A name a Windows shortcut file can carry (`<name>.lnk`).
fn is_shortcut_name(text: &str) -> bool {
    is_plain_text(text)
        && !text.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|'])
        && !text.starts_with(' ')
        && !is_windows_reserved(text)
}

/// A path relative to `seaworthy.toml`: normal components only (no `..`, `.`,
/// root or drive), each valid UTF-8 without control characters or `$`.
fn is_relative_path(path: &Path) -> bool {
    let mut components = path.components().peekable();
    components.peek().is_some()
        && components.all(|c| match c {
            std::path::Component::Normal(name) => name
                .to_str()
                .is_some_and(|n| !n.chars().any(|ch| ch.is_control() || ch == '$')),
            _ => false,
        })
}

/// A path relative to an install root, `/`-separated: segments of printable
/// ASCII that both Windows and the Linux package tools accept, at most 200
/// bytes.
pub(crate) fn is_install_relative(text: &str) -> bool {
    text.len() <= 200
        && text.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.starts_with(' ')
                && !is_windows_reserved(segment)
                && segment
                    .bytes()
                    .all(|b| (0x20..0x7F).contains(&b) && !b"$\\<>:\"|?*".contains(&b))
                && !segment.contains("!(")
                && !is_short_name_alias(segment)
        })
}

/// A name with `~` and a digit, the shape of a Windows 8.3 short name
/// (`ACME_C~1.DLL`): on a volume with short names it can name another file
/// of the install directory, the core DLL among them (git's
/// `core.protectNTFS` refuses it too).
fn is_short_name_alias(segment: &str) -> bool {
    segment
        .as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'~' && pair[1].is_ascii_digit())
}

/// A path's extension, lowercase (empty without one).
pub(crate) fn extension_of(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

impl Config {
    /// Reads and validates a `seaworthy.toml`.
    ///
    /// # Errors
    /// [`DistError::Io`], [`DistError::Config`] naming the refused key.
    pub fn load(path: &Path) -> Result<Self, DistError> {
        let text = std::fs::read_to_string(path).map_err(|e| DistError::io(path, e))?;
        let mut config = Self::parse(&text)?;
        config.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        // Trusted keys are read and checked at load, so `check` catches a
        // bad one before a release.
        config.release_keys()?;
        if let Some(identity) = &config.defaults.authenticode {
            let trust = config.dir.join(&identity.trust);
            std::fs::metadata(&trust).map_err(|e| DistError::io(&trust, e))?;
        }
        let mut openpgp = Vec::new();
        for key in &config.defaults.openpgp_keys {
            let path = config.dir.join(key);
            openpgp.push(std::fs::read(&path).map_err(|e| DistError::io(&path, e))?);
        }
        if !openpgp.is_empty() {
            seaworthy_updater::openpgp::OpenPgpKeys::new(openpgp)
                .map_err(|e| DistError::Config(format!("defaults.openpgp-keys: {e}")))?;
        }
        // The CI test keys are checked at load too, and against the real
        // ones (a copy would let a test signature verify as a release's).
        if config.defaults.ci_test_keys.is_some() {
            config.clone().use_ci_test_keys()?;
        }
        Ok(config)
    }

    /// What `seaworthy check` notes beside a valid file, as `(product,
    /// note)`: settings that suit a new product but decide whether an
    /// existing product's next release upgrades it in place. One per
    /// product with an `msi` output and no `upgrade-code`: its UpgradeCode
    /// is derived ([`crate::wix::upgrade_code`]), and an MSI another tool
    /// built carries another, which the next MSI would install beside
    /// instead of upgrading. Pinning a code, the derived one included,
    /// silences it.
    #[must_use]
    pub fn notes(&self) -> Vec<(String, String)> {
        self.products
            .iter()
            .filter(|(_, p)| p.outputs.contains(&Output::Msi) && p.upgrade_code.is_none())
            .filter_map(|(id, _)| {
                let code = crate::wix::upgrade_code(self, id).ok()?;
                Some((
                    id.clone(),
                    format!(
                        "the MSI's UpgradeCode is derived, {code}: if this product already shipped MSIs built another way, pin their UpgradeCode as upgrade-code, or its next MSI installs beside them instead of upgrading them (docs/packaging.md, \"Migrating an existing product\"); a new product can pin upgrade-code = \"{code}\""
                    ),
                ))
            })
            .collect()
    }

    /// This configuration with the CI test keys trusted instead of
    /// `release-keys` and `openpgp-keys` (`seaworthy package` and
    /// `adopt-msi` `--ci-test-signing`): every signature made and checked
    /// is then a test key's, and the listing says so, which `repo`
    /// refuses. A test key that is also a real one is refused.
    ///
    /// # Errors
    /// [`DistError::Config`] without `[defaults.ci-test-keys]` or its
    /// `release-keys` (when `release-signatures` lists an algorithm), for a
    /// test key that is a real one, or one that doesn't read as its kind.
    pub fn use_ci_test_keys(mut self) -> Result<Self, DistError> {
        let keys = self.defaults.ci_test_keys.clone().ok_or_else(|| {
            DistError::Config(
                "--ci-test-signing: seaworthy.toml has no [defaults.ci-test-keys]".to_owned(),
            )
        })?;
        if keys.release_keys.is_empty() && !self.defaults.release_signatures.is_empty() {
            return Err(DistError::Config(
                "defaults.ci-test-keys: no release-keys, while release-signatures signs manifests"
                    .to_owned(),
            ));
        }
        let real = self.release_keys()?;
        let mut real_openpgp = Vec::new();
        for key in &self.defaults.openpgp_keys {
            let path = self.dir.join(key);
            real_openpgp.push(std::fs::read(&path).map_err(|e| DistError::io(&path, e))?);
        }
        self.defaults.release_keys = keys.release_keys;
        self.defaults.openpgp_keys = keys.openpgp_keys;
        let test = self.release_keys()?;
        if let Some(both) = test
            .iter()
            .find(|key| real.iter().any(|r| r.public_key() == key.public_key()))
        {
            return Err(DistError::Config(format!(
                "defaults.ci-test-keys: release key {} is also in release-keys: a test key must never be a release key",
                hex::encode(both.key_id())
            )));
        }
        let mut test_openpgp = Vec::new();
        for key in &self.defaults.openpgp_keys {
            let path = self.dir.join(key);
            let bytes = std::fs::read(&path).map_err(|e| DistError::io(&path, e))?;
            if real_openpgp
                .iter()
                .any(|real| real.trim_ascii() == bytes.trim_ascii())
            {
                return Err(DistError::Config(format!(
                    "defaults.ci-test-keys: {} is also in openpgp-keys: a test key must never be a release key",
                    key.display()
                )));
            }
            test_openpgp.push(bytes);
        }
        if !test_openpgp.is_empty() {
            seaworthy_updater::openpgp::OpenPgpKeys::new(test_openpgp).map_err(|e| {
                DistError::Config(format!("defaults.ci-test-keys.openpgp-keys: {e}"))
            })?;
        }
        self.ci_test = true;
        Ok(self)
    }

    /// The trusted release keys, read from `release-keys` (relative to
    /// [`dir`](Self::dir)) and checked by `seaworthy_updater`'s own intake.
    ///
    /// # Errors
    /// [`DistError::Io`]; [`DistError::Config`] for a file that isn't a
    /// valid public key of its algorithm, or an algorithm `release-signatures`
    /// doesn't list.
    pub fn release_keys(&self) -> Result<Vec<seaworthy_updater::ReleaseKey>, DistError> {
        let mut keys = Vec::new();
        for entry in &self.defaults.release_keys {
            if !self.defaults.release_signatures.contains(&entry.algorithm) {
                return Err(DistError::Config(format!(
                    "defaults.release-keys: {} lists an algorithm release-signatures doesn't",
                    entry.public_key.display()
                )));
            }
            let path = self.dir.join(&entry.public_key);
            let text = std::fs::read_to_string(&path).map_err(|e| DistError::io(&path, e))?;
            let text = text.trim();
            let bytes = (!text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| hex::decode(text).ok())
                .flatten()
                .ok_or_else(|| {
                    DistError::Config(format!(
                        "defaults.release-keys: {} is not hex",
                        path.display()
                    ))
                })?;
            let key =
                seaworthy_updater::ReleaseKey::new(bytes, crate::sign::algorithm(entry.algorithm))
                    .map_err(|e| {
                        DistError::Config(format!("defaults.release-keys: {}: {e}", path.display()))
                    })?;
            keys.push(key);
        }
        Ok(keys)
    }

    /// Keeps only the outputs for `platforms` (`--platforms`: CI packages
    /// macOS on the Mac and everything else on Linux). A product
    /// left with no outputs is dropped; returns the dropped products' ids.
    /// The result isn't validated again (a `[macos]` section outlives its
    /// dmg, say): the rest of the tool reads only what the remaining
    /// outputs use.
    pub fn only_platforms(&mut self, platforms: &[Platform]) -> Vec<String> {
        for product in self.products.values_mut() {
            product
                .outputs
                .retain(|o| platforms.contains(&o.platform()));
        }
        let dropped: Vec<String> = self
            .products
            .iter()
            .filter(|(_, p)| p.outputs.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &dropped {
            self.products.remove(id);
        }
        dropped
    }

    /// Parses and validates `seaworthy.toml` text.
    ///
    /// # Errors
    /// [`DistError::Config`] naming the refused key or value.
    pub fn parse(text: &str) -> Result<Self, DistError> {
        let config: Self = toml::from_str(text).map_err(|e| DistError::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), DistError> {
        let d = &self.defaults;
        if let Some(identity) = &d.authenticode
            && (identity.subject.trim().is_empty()
                || identity.subject.chars().any(char::is_control))
        {
            return Err(DistError::Config(
                "defaults.authenticode.subject must name the signing certificate's subject"
                    .to_owned(),
            ));
        }
        if let Some(apple) = &d.apple
            && !is_team_id(&apple.team_id)
        {
            return Err(DistError::Config(format!(
                "defaults.apple.team-id {:?} must be an Apple team identifier (ten of [A-Z0-9])",
                apple.team_id
            )));
        }
        if !is_windows_name(&d.vendor) {
            return Err(DistError::Config(format!(
                "defaults.vendor {:?} must be a directory name ([A-Za-z0-9][A-Za-z0-9._-]*)",
                d.vendor
            )));
        }
        if d.targets.is_empty() {
            return Err(DistError::Config("defaults.targets is empty".to_owned()));
        }
        for (i, target) in d.targets.iter().enumerate() {
            if !is_file_stem(target) || d.targets[..i].contains(target) {
                return Err(DistError::Config(format!(
                    "defaults.targets: {target:?} is not a CPU name, or is listed twice"
                )));
            }
        }
        if d.macos_targets.is_empty() {
            return Err(DistError::Config(
                "defaults.macos-targets is empty".to_owned(),
            ));
        }
        for (i, target) in d.macos_targets.iter().enumerate() {
            if !is_file_stem(target) || d.macos_targets[..i].contains(target) {
                return Err(DistError::Config(format!(
                    "defaults.macos-targets: {target:?} is not a CPU name, or is listed twice"
                )));
            }
        }
        if !parse_macos_version(&d.macos_minimum).is_some_and(|version| version >= (11, 0, 0)) {
            return Err(DistError::Config(format!(
                "defaults.macos-minimum {:?} must be a macOS version, 11.0 or later (MAJOR.MINOR[.PATCH]; Apple Silicon starts at 11.0)",
                d.macos_minimum
            )));
        }
        if !is_identifier(&d.channel) || d.channel.len() > 64 {
            return Err(DistError::Config(format!(
                "defaults.channel {:?} must be at most 64 characters of [a-z0-9-] (a release manifest's channel)",
                d.channel
            )));
        }
        if d.vendor.contains("..") {
            return Err(DistError::Config(format!(
                "defaults.vendor {:?} must not contain \"..\" (release manifests refuse it)",
                d.vendor
            )));
        }
        if d.release_signatures.is_empty() && !d.release_keys.is_empty() {
            return Err(DistError::Config(
                "defaults.release-keys lists keys, but defaults.release-signatures is empty: no release manifest is signed, so list the algorithm or drop the keys".to_owned(),
            ));
        }
        for (i, algorithm) in d.release_signatures.iter().enumerate() {
            if d.release_signatures[..i].contains(algorithm) {
                return Err(DistError::Config(
                    "defaults.release-signatures lists an algorithm twice".to_owned(),
                ));
            }
        }
        if let Some(homepage) = &d.homepage {
            let url = homepage
                .strip_prefix("https://")
                .or_else(|| homepage.strip_prefix("http://"));
            if !url.is_some_and(|rest| {
                !rest.is_empty() && rest.chars().all(|c| c.is_ascii_graphic() && c != '$')
            }) {
                return Err(DistError::Config(format!(
                    "defaults.homepage {homepage:?} must be an http(s) URL without spaces, control characters or `$`"
                )));
            }
        }
        if let Some(repository) = &d.repository {
            if !client_url_ok(&repository.url) {
                return Err(DistError::Config(format!(
                    "defaults.repository.url {:?} must be an https URL (http only to a loopback address), written as a URL parser writes it (lowercase host, no default port), without credentials, a query, a fragment or a trailing slash, of ASCII letters, digits and -._~:/[] only",
                    repository.url
                )));
            }
            let package = crate::linux::package_name(self, REPOSITORY_ID);
            if package.len() > 64 {
                return Err(DistError::Config(format!(
                    "defaults.repository: the repository package's name {package:?} (<vendor>-repository) must be at most 64 characters: it's its release manifests' product"
                )));
            }
            if d.openpgp_keys.is_empty() {
                return Err(DistError::Config(
                    "defaults.repository needs defaults.openpgp-keys: the repository package ships the key the repositories are signed with".to_owned(),
                ));
            }
            if self.products.contains_key(REPOSITORY_ID) {
                return Err(DistError::Config(format!(
                    "product.{REPOSITORY_ID}: the id is the repository package's while defaults.repository is set"
                )));
            }
            if !self.products.values().any(|p| {
                p.outputs
                    .iter()
                    .any(|o| matches!(o, Output::Deb | Output::Rpm))
            }) {
                return Err(DistError::Config(
                    "defaults.repository: no product builds a deb or an rpm, so there is no APT or DNF repository to set up".to_owned(),
                ));
            }
        }
        for (key, value) in [("maintainer", &d.maintainer), ("license", &d.license)] {
            if !is_plain_text(value) {
                return Err(DistError::Config(format!(
                    "defaults.{key} must be non-empty text without control characters or `$` (nFPM expands $VAR)"
                )));
            }
        }
        if self.products.is_empty() {
            return Err(DistError::Config("no [product.<id>] sections".to_owned()));
        }
        for (id, product) in &self.products {
            self.validate_product(id, product)?;
        }
        self.validate_across_products()
    }

    /// Whether releases carry signed manifests (`defaults.release-signatures`
    /// lists an algorithm). Without them `package` writes none and `repo`
    /// expects none; validation allows that only when no product ships an
    /// update helper.
    #[must_use]
    pub fn signs_manifests(&self) -> bool {
        !self.defaults.release_signatures.is_empty()
    }

    /// The repository package's name (`<vendor>-repository`), when
    /// `[defaults.repository]` is set.
    #[must_use]
    pub fn repository_package(&self) -> Option<String> {
        self.defaults
            .repository
            .as_ref()
            .map(|_| crate::linux::package_name(self, REPOSITORY_ID))
    }

    /// Two products may not install into, or register, the same thing.
    fn validate_across_products(&self) -> Result<(), DistError> {
        let mut seen: BTreeMap<(&str, String), &str> = BTreeMap::new();
        for (id, p) in &self.products {
            let mut claims = vec![(
                "windows-directory",
                p.windows_directory().to_ascii_lowercase(),
            )];
            if let Some(upgrade_code) = &p.upgrade_code {
                claims.push(("upgrade-code", upgrade_code.to_ascii_uppercase()));
            }
            if let Some(service) = &p.service {
                // SCM names are case-insensitive; the helper's service is
                // `<name>-update` on both platforms.
                claims.push(("service.name", service.name.to_ascii_lowercase()));
                claims.push((
                    "service.name",
                    format!("{}-update", service.name.to_ascii_lowercase()),
                ));
                if let Some(state) = &service.state_directory {
                    claims.push(("service.state-directory", state.clone()));
                }
            }
            if let Some(command) = &p.linux.command {
                claims.push(("linux.command", command.clone()));
            }
            if let Some(desktop) = &p.desktop {
                claims.push((
                    "desktop.app-id",
                    desktop.app_id(self, id).to_ascii_lowercase(),
                ));
                // The shortcuts every user sees, `<display name>.lnk`: one
                // product's uninstall would delete the other's.
                if (desktop.start_menu || desktop.desktop_shortcut)
                    && p.outputs.contains(&Output::Msi)
                {
                    claims.push((
                        "display-name (the MSI's shortcut)",
                        p.display_name.to_lowercase(),
                    ));
                }
            }
            for (key, value) in claims {
                if let Some(other) = seen.insert((key, value.clone()), id) {
                    return Err(DistError::Config(format!(
                        "products {other} and {id} share {key} {value:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_product(&self, id: &str, p: &Product) -> Result<(), DistError> {
        let at = |key: &str, why: &str| DistError::Config(format!("product.{id}.{key}: {why}"));
        if !is_identifier(id) {
            return Err(DistError::Config(format!(
                "product id {id:?} must be [a-z0-9][a-z0-9-]*"
            )));
        }
        if !is_plain_text(&p.display_name) || !is_plain_text(&p.description) {
            return Err(at(
                "display-name/description",
                "non-empty text without control characters or `$` (nFPM expands $VAR)",
            ));
        }
        if p.display_name.chars().count() > MAX_DISPLAY_NAME
            || p.description.chars().count() > MAX_DESCRIPTION
        {
            return Err(at(
                "display-name/description",
                &format!("at most {MAX_DISPLAY_NAME} and {MAX_DESCRIPTION} characters"),
            ));
        }
        if !is_windows_name(&p.executable) {
            return Err(at(
                "executable",
                "a file stem ([A-Za-z0-9][A-Za-z0-9._-]*), not a Windows device name",
            ));
        }
        let core_ok = p
            .core
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic())
            && p.core
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !core_ok {
            return Err(at("core", "a crate name ([A-Za-z][A-Za-z0-9_]*)"));
        }
        if p.helper.is_some() && !self.signs_manifests() {
            return Err(at(
                "helper",
                "an update helper installs only releases whose signed manifest it verifies: list defaults.release-signatures (and release-keys)",
            ));
        }
        match (&p.helper, p.updates.default) {
            (None, UpdatePolicy::Auto | UpdatePolicy::Notify) => {
                return Err(at(
                    "helper",
                    "required unless updates.default = \"off\" (the helper is what installs updates)",
                ));
            }
            (Some(helper), _)
                if !is_windows_name(helper) || helper.eq_ignore_ascii_case(&p.executable) =>
            {
                return Err(at(
                    "helper",
                    "a file stem, not a Windows device name, different from the executable (case-insensitively: NTFS)",
                ));
            }
            _ => {}
        }
        if p.helper_crate.is_some() && !p.ships_helper() {
            return Err(at(
                "helper-crate",
                "names the helper's crate, but no helper ships (no `helper`, or updates.default = \"off\")",
            ));
        }
        if !is_windows_name(&p.windows_directory()) {
            return Err(at(
                "windows-directory",
                "a directory name ([A-Za-z0-9][A-Za-z0-9._-]*); the default is the display name's last word",
            ));
        }
        if let Some(glibc) = &p.linux.glibc
            && parse_glibc_version(glibc).is_none_or(|(major, _)| major != 2)
        {
            return Err(at(
                "linux.glibc",
                "the oldest glibc the binaries must run on, as 2.N (\"2.34\")",
            ));
        }
        for lib in &p.linux.needed {
            if !is_file_stem(lib) {
                return Err(at(
                    "linux.needed",
                    "shared-library file names ([A-Za-z0-9][A-Za-z0-9._-]*)",
                ));
            }
        }
        if !p.linux.needed.is_empty() {
            let d = &p.linux.depends;
            for (output, depends) in [
                (Output::Deb, &d.deb),
                (Output::Rpm, &d.rpm),
                (Output::Pacman, &d.pacman),
            ] {
                if p.outputs.contains(&output) && depends.is_empty() {
                    return Err(at(
                        "linux.depends",
                        "linux.needed names libraries beyond the base system; every Linux package format in outputs must declare the packages that provide them",
                    ));
                }
            }
        }
        if p.outputs.is_empty() {
            return Err(at("outputs", "empty"));
        }
        let linux_package = p
            .outputs
            .iter()
            .any(|o| matches!(o, Output::Deb | Output::Rpm | Output::Pacman));
        let package = format!("{}-{id}", self.defaults.vendor.to_ascii_lowercase());
        if package.len() > 64 {
            return Err(at(
                "id",
                &format!(
                    "the package name {package:?} (<vendor>-<id>) must be at most 64 characters: it's every release manifest's product"
                ),
            ));
        }
        if linux_package && !is_package_name(&package) {
            return Err(at(
                "outputs",
                &format!(
                    "the Linux package name {package:?} (<vendor>-<id>, lowercase) must be [a-z0-9][a-z0-9.-]+: defaults.vendor has a character deb, rpm or pacman refuse"
                ),
            ));
        }
        let macos_output = p.outputs.iter().any(|o| o.is_macos());
        match (&p.macos, macos_output) {
            (None, true) => {
                return Err(at(
                    "macos",
                    "a macOS output needs [product.<id>.macos] with its bundle-id",
                ));
            }
            (Some(_), false) => {
                return Err(at("macos", "set, but no output is for macOS"));
            }
            (Some(macos), true) => {
                if p.display_name.contains(['/', ':'])
                    || p.display_name.starts_with('.')
                    || p.display_name.len() > 250
                {
                    return Err(at(
                        "display-name",
                        "names the app bundle (<display-name>.app) with a macOS output: no `/` or `:`, no leading `.`, at most 250 bytes",
                    ));
                }
                if !is_bundle_id(&macos.bundle_id) {
                    return Err(at(
                        "macos.bundle-id",
                        "a reverse-DNS identifier (com.example.app): two or more dot-separated labels of [A-Za-z0-9-], at most 155 characters",
                    ));
                }
                if let Some(icon) = &macos.icon
                    && extension_of(icon) != "icns"
                {
                    return Err(at("macos.icon", "an .icns file"));
                }
                if let Some(entitlements) = &macos.entitlements
                    && (!is_relative_path(entitlements)
                        || !matches!(
                            extension_of(entitlements).as_str(),
                            "plist" | "entitlements"
                        ))
                {
                    return Err(at(
                        "macos.entitlements",
                        &format!(
                            "{} must be a .plist or .entitlements path relative to seaworthy.toml (no `..`, no `$`)",
                            entitlements.display()
                        ),
                    ));
                }
                if let Some(category) = &macos.category
                    && !category
                        .strip_prefix("public.app-category.")
                        .is_some_and(|rest| {
                            !rest.is_empty()
                                && rest.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
                        })
                {
                    return Err(at(
                        "macos.category",
                        "a public.app-category.* type (public.app-category.utilities)",
                    ));
                }
            }
            (None, false) => {}
        }
        if p.outputs.contains(&Output::Dmg) && p.kind != Kind::Desktop {
            return Err(at(
                "outputs",
                "dmg holds a desktop app (kind = \"desktop\"); a macOS service ships as a pkg",
            ));
        }
        if p.outputs.contains(&Output::Pkg) && p.kind != Kind::Service {
            return Err(at(
                "outputs",
                "pkg holds a macOS service (kind = \"service\"): its LaunchDaemon; a desktop app ships as a dmg",
            ));
        }
        if p.outputs.contains(&Output::Pkg)
            && p.service.as_ref().is_some_and(|s| s.sandbox.is_some())
        {
            return Err(at(
                "service.sandbox",
                "a macOS service runs as root for now (its package doesn't create daemon accounts yet): leave out the sandbox user, or the pkg output",
            ));
        }
        if p.outputs.contains(&Output::Msi) && p.windows_directory.is_none() {
            return Err(at(
                "windows-directory",
                "required with an msi output: it names the install directory, the state directory, the update-policy registry key and the Group Policy namespace, so it must not follow a display-name change",
            ));
        }
        if let Some(upgrade_code) = &p.upgrade_code
            && !is_guid(upgrade_code)
        {
            return Err(at(
                "upgrade-code",
                "a GUID in registry form, {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}",
            ));
        }
        let mut sorted = p.outputs.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != p.outputs.len() {
            return Err(at("outputs", "lists an output twice"));
        }
        for (key, globs) in [
            ("sidecars.windows", &p.sidecars.windows),
            ("sidecars.macos", &p.sidecars.macos),
        ] {
            for glob in globs {
                let ok = !glob.is_empty()
                    && glob.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'*')
                    });
                if !ok {
                    return Err(at(key, "file-name globs over [A-Za-z0-9._-] and '*'"));
                }
            }
        }
        if !p.sidecars.macos.is_empty() && !macos_output {
            return Err(at("sidecars.macos", "set, but no output is for macOS"));
        }
        if self.defaults.fips && macos_output && p.sidecars.macos.is_empty() {
            return Err(at(
                "sidecars.macos",
                "with fips, a macOS build ships the FIPS module's dylib beside the cores (AWS-LC builds the module only as a dynamic library off Linux): sidecars.macos = [\"libaws_lc_fips_*_crypto.dylib\"]",
            ));
        }
        for entry in p
            .linux
            .depends
            .deb
            .iter()
            .chain(&p.linux.depends.rpm)
            .chain(&p.linux.depends.pacman)
        {
            if !is_plain_text(entry) || entry.contains(',') {
                return Err(at(
                    "linux.depends",
                    "one dependency per entry, without commas, control characters or `$`",
                ));
            }
        }
        match (p.kind, &p.service) {
            (Kind::Service, None) => {
                return Err(at(
                    "service",
                    "kind = \"service\" needs a [service] section",
                ));
            }
            (Kind::Desktop | Kind::Tool, Some(_)) => {
                return Err(at("service", "only kind = \"service\" has a service"));
            }
            _ => {}
        }
        if let Some(service) = &p.service {
            if p.helper.is_some()
                && p.updates.default != UpdatePolicy::Off
                && service.state_directory.is_none()
            {
                return Err(at(
                    "service.state-directory",
                    "required when the helper ships: the service requests updates by writing a file there",
                ));
            }
            // The renderers are the authority on what a spec may say.
            let spec = self.service_spec(id, p, Path::new("/opt/x/x"))?;
            // Linux identity: root only by explicit choice. A less privileged
            // Windows account must come with a systemd sandbox user, and
            // LocalSystem (root under systemd) with none.
            match (service.account, &service.sandbox) {
                (Account::LocalSystem, Some(_)) => {
                    return Err(at(
                        "service.sandbox",
                        "account = \"local-system\" runs as root under systemd; a sandbox user contradicts it",
                    ));
                }
                (Account::Virtual | Account::LocalService | Account::NetworkService, None) => {
                    return Err(at(
                        "service.sandbox",
                        "a less privileged Windows account needs a systemd sandbox user, or the Linux unit would run as root (use account = \"local-system\" to run as root deliberately)",
                    ));
                }
                _ => {}
            }
            if p.outputs.contains(&Output::Msi)
                && matches!(
                    service.account,
                    Account::LocalService | Account::NetworkService
                )
            {
                return Err(at(
                    "service.account",
                    "local-service and network-service are shared by every service running as them, so an MSI's grants (the state directory, starting the update helper) would reach all of them; use account = \"virtual\" (NT SERVICE\\<name>, this service alone) or \"local-system\"",
                ));
            }
            // A setting the renderer would silently drop is refused: the
            // extra families extend RestrictAddressFamilies= only when it is
            // on, the writable paths matter only under ProtectSystem=strict.
            let hardening = &spec.systemd_hardening;
            if !hardening.extra_address_families.is_empty() && !hardening.restrict_address_families
            {
                return Err(at(
                    "service.hardening",
                    "extra-address-families needs restrict-address-families = true (without it the unit restricts no family at all)",
                ));
            }
            if !hardening.read_write_paths.is_empty() && !hardening.protect_system_strict {
                return Err(at(
                    "service.hardening",
                    "read-write-paths needs protect-system-strict = true (without it every path is writable anyway)",
                ));
            }
            let render = |e: seaworthy_service::ServiceError| at("service", &e.to_string());
            seaworthy_service::render::systemd::validate(&spec).map_err(render)?;
            seaworthy_service::render::systemd::sysusers(&spec).map_err(render)?;
            if p.ships_helper() {
                let cache = self.update_product(id, p)?.cache_directory();
                seaworthy_service::render::systemd::update_path_unit(&spec).map_err(render)?;
                seaworthy_service::render::systemd::update_service_unit(
                    &spec,
                    Path::new("/opt/x/libexec/x-update"),
                    &cache,
                )
                .map_err(render)?;
            }
            seaworthy_service::render::windows::service_record(&spec).map_err(render)?;
            seaworthy_service::render::windows::program_dir_sddl(&spec).map_err(render)?;
            seaworthy_service::render::windows::state_dir_sddl(&spec).map_err(render)?;
            if p.outputs.contains(&Output::Pkg) {
                crate::macos::launch_daemons(self, id, p).map_err(|e| match e {
                    DistError::Config(why) => at("service", &why),
                    other => other,
                })?;
            }
        }
        self.validate_desktop_and_files(id, p)
    }

    /// `[product.<id>.desktop]`, `[[product.<id>.files]]` and
    /// `linux.command`. The icons' and files' contents are checked
    /// when `layout` reads them.
    fn validate_desktop_and_files(&self, id: &str, p: &Product) -> Result<(), DistError> {
        let at = |key: &str, why: &str| DistError::Config(format!("product.{id}.{key}: {why}"));
        let linux_package = p
            .outputs
            .iter()
            .any(|o| matches!(o, Output::Deb | Output::Rpm | Output::Pacman));
        if let Some(command) = &p.linux.command {
            if !is_command_name(command) {
                return Err(at(
                    "linux.command",
                    "a command name ([a-z0-9][a-z0-9._+-]*, at most 64 bytes)",
                ));
            }
            if !linux_package {
                return Err(at(
                    "linux.command",
                    "only a Linux package (deb, rpm, pacman) installs /usr/bin links",
                ));
            }
        }
        if !p.linux.replaces.is_empty() && !linux_package {
            return Err(at(
                "linux.replaces",
                "only a Linux package (deb, rpm, pacman) replaces packages",
            ));
        }
        let mut replaced = BTreeSet::new();
        for name in &p.linux.replaces {
            if !is_package_name(name) || name.len() > 64 {
                return Err(at(
                    "linux.replaces",
                    &format!(
                        "{name:?} isn't a package name every format accepts ([a-z0-9][a-z0-9.-]+, at most 64 characters)"
                    ),
                ));
            }
            if !replaced.insert(name.as_str()) {
                return Err(at("linux.replaces", &format!("{name:?} is listed twice")));
            }
            // A package this seaworthy.toml builds: replacing it would
            // remove a sibling (or the product itself) on every install.
            let built = self
                .products
                .keys()
                .map(|other| crate::linux::package_name(self, other))
                .chain(self.repository_package());
            if built.into_iter().any(|package| package == *name) {
                return Err(at(
                    "linux.replaces",
                    &format!("{name:?} is a package this seaworthy.toml builds"),
                ));
            }
        }
        if let Some(desktop) = &p.desktop {
            if p.kind != Kind::Desktop {
                return Err(at(
                    "desktop",
                    "only a desktop app (kind = \"desktop\") has a menu entry, icons and shortcuts",
                ));
            }
            if let Some(app_id) = &desktop.app_id
                && !is_app_id(app_id)
            {
                return Err(at(
                    "desktop.app-id",
                    "a desktop entry id: [A-Za-z0-9_-] segments joined by `.`, starting with a letter or digit, at most 200 bytes",
                ));
            }
            let mut svgs = 0;
            for icon in &desktop.linux_icons {
                let extension = extension_of(icon);
                if !is_relative_path(icon) || !matches!(extension.as_str(), "png" | "svg") {
                    return Err(at(
                        "desktop.linux-icons",
                        &format!(
                            "{} must be a .png or .svg path relative to seaworthy.toml (no `..`, no `$`)",
                            icon.display()
                        ),
                    ));
                }
                svgs += usize::from(extension == "svg");
            }
            if svgs > 1 {
                return Err(at(
                    "desktop.linux-icons",
                    "at most one SVG (the theme's one scalable icon)",
                ));
            }
            if let Some(icon) = &desktop.windows_icon
                && (!is_relative_path(icon) || extension_of(icon) != "ico")
            {
                return Err(at(
                    "desktop.windows-icon",
                    &format!(
                        "{} must be a .ico path relative to seaworthy.toml (no `..`, no `$`)",
                        icon.display()
                    ),
                ));
            }
            if (desktop.start_menu || desktop.desktop_shortcut)
                && p.outputs.contains(&Output::Msi)
                && (!is_shortcut_name(&p.display_name)
                    || p.display_name.chars().count() > MAX_SHORTCUT_NAME)
            {
                return Err(at(
                    "display-name",
                    "names the MSI's shortcuts (<display name>.lnk), so it can't contain \\ / : * ? \" < > |, start with a space, end in a space or a dot, be a device name, or run past 100 characters",
                ));
            }
            let mut seen: Vec<&str> = Vec::new();
            for category in &desktop.categories {
                if !is_category(category) || seen.contains(&category.as_str()) {
                    return Err(at(
                        "desktop.categories",
                        &format!(
                            "{category:?} must be a category name ([A-Za-z0-9-]), listed once"
                        ),
                    ));
                }
                seen.push(category);
            }
            if !desktop
                .categories
                .iter()
                .any(|c| MAIN_CATEGORIES.contains(&c.as_str()))
            {
                return Err(at(
                    "desktop.categories",
                    &format!(
                        "needs one of the freedesktop main categories ({}), or menus file the entry nowhere",
                        MAIN_CATEGORIES.join(", ")
                    ),
                ));
            }
            // The specification's one dependent main pair: Audio and Video
            // each need AudioVideo beside them (desktop-file-validate refuses
            // the entry otherwise).
            if desktop
                .categories
                .iter()
                .any(|c| c == "Audio" || c == "Video")
                && !desktop.categories.iter().any(|c| c == "AudioVideo")
            {
                return Err(at(
                    "desktop.categories",
                    "Audio and Video each need AudioVideo listed too",
                ));
            }
            for keyword in &desktop.keywords {
                if !is_plain_text(keyword) || keyword.contains([';', '\\']) {
                    return Err(at(
                        "desktop.keywords",
                        &format!(
                            "{keyword:?} must be non-empty text without control characters, `$`, `;` or `\\`"
                        ),
                    ));
                }
            }
            if let Some(class) = &desktop.wm_class
                && (class.is_empty()
                    || class.len() > 255
                    || !class
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
            {
                return Err(at(
                    "desktop.wm-class",
                    "a window class or app id ([A-Za-z0-9._-], at most 255 bytes)",
                ));
            }
        }
        for (n, files) in p.files.iter().enumerate() {
            let key = |field: &str| format!("files[{n}].{field}");
            if !is_relative_path(&files.source)
                || files
                    .source
                    .components()
                    .any(|c| VCS_DIRECTORIES.contains(&c.as_os_str().to_string_lossy().as_ref()))
            {
                return Err(at(
                    &key("source"),
                    &format!(
                        "{} must be a path relative to seaworthy.toml (no `..`, no `$`, no version control directory)",
                        files.source.display()
                    ),
                ));
            }
            let destination = files.destination();
            if !is_install_relative(&destination) {
                return Err(at(
                    &key("destination"),
                    &format!(
                        "{destination:?} must be a relative `/`-separated path of names both platforms accept (printable ASCII; no `..`, `$`, `!(`, `\\`, `<>:\"|?*`, device names, short-name aliases like `X~1`, or names starting with a space or ending in a space or a dot), at most 200 bytes"
                    ),
                ));
            }
            let twice = files
                .platforms
                .iter()
                .enumerate()
                .any(|(i, p)| files.platforms[..i].contains(p));
            if files.platforms.is_empty() || twice {
                return Err(at(&key("platforms"), "linux and/or windows, each once"));
            }
        }
        Ok(())
    }

    /// The product's service as a [`ServiceSpec`], with `program` the
    /// launcher's installed path on the platform being rendered.
    ///
    /// # Errors
    /// [`DistError::Config`] for a product without a service, or a bad
    /// duration.
    pub fn service_spec(
        &self,
        id: &str,
        product: &Product,
        program: &Path,
    ) -> Result<ServiceSpec, DistError> {
        let service = product
            .service
            .as_ref()
            .ok_or_else(|| DistError::Config(format!("product.{id} has no service")))?;
        let restart_delays = service
            .restart_delays
            .iter()
            .map(|d| parse_duration(d))
            .collect::<Result<Vec<_>, _>>()?;
        let sandbox = service.sandbox.as_ref().map(|s| SystemdSandbox {
            user: s.user.clone(),
            group: s.group.clone().unwrap_or_else(|| s.user.clone()),
            capabilities: s.capabilities.clone(),
            allow_root: false,
        });
        Ok(ServiceSpec {
            name: service.name.clone(),
            display_name: product.display_name.clone(),
            description: product.description.clone(),
            program: program.to_path_buf(),
            arguments: service.arguments.iter().map(OsString::from).collect(),
            environment_files: vec![],
            open_files_limit: None,
            failure_policy: FailurePolicy {
                reset_period: parse_duration(&service.reset_period)?,
                restart_delays,
            },
            sandbox,
            systemd_hardening: service.hardening.systemd(),
            windows_account: match service.account {
                Account::Virtual => WindowsServiceAccount::Virtual,
                Account::LocalService => WindowsServiceAccount::LocalService,
                Account::NetworkService => WindowsServiceAccount::NetworkService,
                Account::LocalSystem => WindowsServiceAccount::LocalSystem,
            },
            state_directory: service.state_directory.clone(),
        })
    }

    /// Product `id`'s names as the app side and the update helper derive
    /// them ([`seaworthy_updater::Product`]): the package, the manifests'
    /// product and channel, the helper's cache directory, the request
    /// file, the policy file and registry keys. The generators take these
    /// names from here (the ADMX template's key is checked against
    /// [`seaworthy_updater::Product::policy_key`] in the tests), and a helper
    /// reading the same `seaworthy.toml` with
    /// [`seaworthy_updater::Product::from_config`] gets the same ones.
    ///
    /// # Errors
    /// [`DistError::Config`] for a name `seaworthy_updater` refuses (validation
    /// keeps every loaded config inside its grammar, so this is defense in
    /// depth).
    pub fn update_product(
        &self,
        id: &str,
        product: &Product,
    ) -> Result<seaworthy_updater::Product, DistError> {
        let refused =
            |e: seaworthy_updater::ProductError| DistError::Config(format!("product.{id}: {e}"));
        let mut names = seaworthy_updater::Product::new(
            &self.defaults.vendor,
            id,
            &product.windows_directory(),
            &self.defaults.channel,
        )
        .map_err(refused)?
        .with_default_policy(product.updates.default);
        if let Some(service) = &product.service {
            names = names
                .with_service(seaworthy_updater::ServiceNames {
                    name: service.name.clone(),
                    state_directory: service.state_directory.clone(),
                })
                .map_err(refused)?;
        }
        if let Some(macos) = &product.macos {
            names = names
                .with_macos_bundle_id(&macos.bundle_id)
                .map_err(refused)?;
        }
        Ok(names)
    }
}

impl Product {
    /// The Windows install directory name under the vendor directory.
    #[must_use]
    pub fn windows_directory(&self) -> String {
        self.windows_directory.clone().unwrap_or_else(|| {
            self.display_name
                .split_whitespace()
                .last()
                .unwrap_or(&self.executable)
                .to_owned()
        })
    }

    /// Whether the update helper ships with this product.
    #[must_use]
    pub fn ships_helper(&self) -> bool {
        self.helper.is_some() && self.updates.default != UpdatePolicy::Off
    }

    /// Whether the helper ships for `os`: [`ships_helper`](Self::ships_helper),
    /// except a desktop product on macOS, whose dmg carries none (a
    /// helper there needs a LaunchDaemon, which only a service's pkg
    /// installs, and an interactive user's start right macOS doesn't have
    /// yet; the app updates by download there, as before).
    #[must_use]
    pub fn ships_helper_on(&self, os: crate::inputs::Os) -> bool {
        self.ships_helper() && !(os == crate::inputs::Os::Macos && self.kind == Kind::Desktop)
    }
}
