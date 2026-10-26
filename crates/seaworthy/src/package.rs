//! Step 4 of the pipeline: build every deliverable a product's `outputs`
//! names, from its laid-out trees.
//!
//! | Output | Built from | File |
//! | --- | --- | --- |
//! | `deb`, `rpm`, `pacman` | the Linux tree, units and scripts, through nFPM ([`crate::nfpm`]) | each ecosystem's name ([`crate::nfpm::file_name`]) |
//! | `tar` | the Linux tree ([`crate::archive::tar_zst`]) | `<stem>-linux-x86_64.tar.zst` |
//! | `zip` | the Windows tree ([`crate::archive::zip`]) | `<stem>-windows-x86_64.zip` |
//! | `msi` | the Windows tree ([`crate::wix`]) | `<stem>-windows-x86_64.wxs`, and the `.msi` when WiX is given |
//! | (with `msi`, when the helper ships) | [`crate::admx`] | `<stem>-policy-templates.zip` |
//!
//! `<stem>` is `<package>-<version>-<sequence>`
//! (`acme-collector-1.4.0-rc.2-812`), the package name being
//! `<vendor>-<product>` in lowercase on every platform.
//!
//! The tarball and the zip hold the install tree's contents under one
//! top-level directory named `<stem>`, so they unpack anywhere (the
//! launcher finds its cores beside itself). They carry no units and no
//! service: those are the packages' job.
//!
//! Everything lands in `<out>/<product>/packages/`, with scratch files
//! (nFPM configurations, scripts, generated units) in
//! `<out>/<product>/work/`. Both directories carry `layout`'s marker
//! file and are replaced only when they do. `<out>/<product>/packages.json`
//! lists every artifact with its kind and SHA-256: the input of the
//! release manifests.
//!
//! The order, so every digest describes the final bytes:
//!
//! 0. **Before any work**: the manifest signers against `release-signatures`
//!    and `release-keys`, the Authenticode and OpenPGP signers
//!    against the identities `seaworthy.toml` pins, the pinned OpenPGP
//!    keys against what clients accept (`Pins::check_key_strength`), and a
//!    previous run's `packages.json` removed.
//! 1. **The Windows tree**: a version resource stamped into the launcher,
//!    each core and the helper ([`crate::pe_version`]; the FIPS
//!    DLL pair is the module's own and is never stamped), every record read
//!    back, then every Windows binary Authenticode-signed (the FIPS DLLs
//!    included; a sidecar already carrying its publisher's signature keeps
//!    it), each signature checked against the pins, and `layout.json`
//!    rewritten.
//! 2. **The outputs**, from the prepared trees; the MSI Authenticode-
//!    signed after WiX builds it, the rpm signed in place, the pacman
//!    package given a detached `.sig` ([`crate::codesign`]), each signature
//!    checked against the pins.
//! 3. **Release manifests** ([`crate::sign`]) and **SBOMs**
//!    ([`crate::sbom`]) beside every installable artifact, over its final
//!    bytes.
//! 4. **A last check**: every artifact re-read and compared with its
//!    recorded SHA-256 and with its manifest.
//!
//! Every timestamp in every archive and package is `mtime`
//! (`SOURCE_DATE_EPOCH`), so an unsigned build's tarball, zip, policy
//! templates, SBOMs and, with the pinned nFPM, deb, rpm and pacman packages
//! are reproducible byte for byte (the version resource is deterministic
//! too). Signatures carry their signing time, so a signed build reproduces
//! up to them. The MSI isn't reproducible: WiX gives every build a fresh
//! package code.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::DistError;
use crate::archive::{self, Entry};
use crate::config::{Config, Output};
use crate::inputs::{LINUX, MACOS, WINDOWS};
use crate::layout::Layout;
use crate::version::Release;

/// Packaging options.
#[derive(Debug, Clone)]
pub struct Options {
    /// The release: version and sequence.
    pub release: Release,
    /// Every timestamp (`SOURCE_DATE_EPOCH`).
    pub mtime: u64,
    /// The nFPM binary (the CLI: `$NFPM`, else `nfpm`).
    pub nfpm: PathBuf,
    /// The WiX binary (the CLI: `$SEAWORTHY_WIX`). `None` writes the
    /// `.wxs` only, for the Windows runner to build.
    pub wix: Option<PathBuf>,
    /// The build's identity beyond its version (the manifests' `build`).
    pub build: crate::sign::BuildId,
}

/// Every signer packaging uses. All optional: an unsigned build
/// writes no manifests and signs nothing.
#[derive(Default)]
pub struct Signing {
    /// The release-manifest signers ([`crate::sign::check_policy`]).
    pub manifest: Vec<Box<dyn crate::sign::ManifestSigner>>,
    /// Authenticode for the Windows binaries and the MSI.
    pub authenticode: Option<Box<dyn crate::codesign::AuthenticodeSigner>>,
    /// OpenPGP for the rpm and pacman packages.
    pub openpgp: Option<Box<dyn crate::codesign::OpenPgpSigner>>,
    /// Apple's Developer ID for the macOS bundle and its disk image or
    /// pkg, then notarization (`seaworthy.toml`'s `defaults.apple` pins the
    /// team). Without it the macOS outputs are signed ad hoc.
    pub apple: Option<crate::macos::DeveloperId>,
    /// The osslsigncode that checks Authenticode signatures against
    /// `seaworthy.toml`'s pins; default `osslsigncode` on `PATH`.
    pub osslsigncode: Option<PathBuf>,
    /// The gpg that checks detached signatures; default `gpg`.
    pub gpg: Option<PathBuf>,
    /// A dev build (`--authenticode-only`): Authenticode alone, no
    /// manifests, no OpenPGP. Its listing says so: `adopt-msi` signs its MSI
    /// the same way, and `repo` refuses it like an unsigned build.
    pub authenticode_only: bool,
    /// A non-release build signed by the CI test keys
    /// (`--ci-test-signing`): its manifests and OpenPGP signatures verify
    /// only in the products' non-release builds. Its listing says so:
    /// `adopt-msi` signs its MSI's manifest the same way, and `repo`
    /// refuses it.
    pub ci_test: bool,
}

impl Signing {
    /// Whether any signer is configured.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.manifest.is_empty()
            || self.authenticode.is_some()
            || self.openpgp.is_some()
            || self.apple.is_some()
    }

    /// Whether this is a release's signing (`package --signing`, not a dev
    /// build): its listing says so, `adopt-msi` must sign into it, and
    /// `repo` publishes nothing else.
    #[must_use]
    pub fn is_release(&self) -> bool {
        self.is_signed() && !self.authenticode_only && !self.ci_test
    }
}

impl std::fmt::Debug for Signing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signing")
            .field(
                "manifest",
                &self
                    .manifest
                    .iter()
                    .map(|s| s.describe())
                    .collect::<Vec<_>>(),
            )
            .field(
                "authenticode",
                &self.authenticode.as_ref().map(|s| s.describe()),
            )
            .field("openpgp", &self.openpgp.as_ref().map(|s| s.describe()))
            .field("apple", &self.apple)
            .field("osslsigncode", &self.osslsigncode)
            .field("gpg", &self.gpg)
            .field("authenticode_only", &self.authenticode_only)
            .field("ci_test", &self.ci_test)
            .finish()
    }
}

/// What an artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A Debian package.
    Deb,
    /// An RPM package.
    Rpm,
    /// An Arch Linux package.
    Pacman,
    /// The Linux tarball.
    Tar,
    /// The Windows zip.
    Zip,
    /// A Windows Installer package.
    Msi,
    /// The MSI's WiX source.
    Wxs,
    /// The Group Policy templates (ADMX and en-US ADML).
    PolicyTemplates,
    /// A signed release manifest (`<artifact>.manifest`).
    Manifest,
    /// A pacman package's detached OpenPGP signature (`<package>.sig`).
    Signature,
    /// An artifact's SBOM (`<artifact>.cdx.json`).
    Sbom,
    /// A macOS disk image holding the signed app bundle. No release
    /// manifest: no update helper installs a desktop app's dmg.
    Dmg,
    /// A macOS service's flat package: the bundle and its
    /// LaunchDaemons, which the macOS update helper installs.
    Pkg,
}

impl Kind {
    /// The release-manifest format of an installable artifact; `None` for
    /// the rest (the `.wxs`, the policy templates, manifests).
    #[must_use]
    pub fn artifact_format(self) -> Option<seaworthy_updater::ArtifactFormat> {
        use seaworthy_updater::ArtifactFormat as F;
        match self {
            Self::Deb => Some(F::Deb),
            Self::Rpm => Some(F::Rpm),
            Self::Pacman => Some(F::Pacman),
            Self::Tar => Some(F::Tar),
            Self::Zip => Some(F::Zip),
            Self::Msi => Some(F::Msi),
            Self::Pkg => Some(F::Pkg),
            Self::Wxs
            | Self::PolicyTemplates
            | Self::Manifest
            | Self::Signature
            | Self::Sbom
            | Self::Dmg => None,
        }
    }

    /// The format tag an installable artifact's SBOM names: its release
    /// manifest format's, or `dmg`; `None` for the rest.
    #[must_use]
    pub fn sbom_format(self) -> Option<&'static str> {
        match self {
            Self::Dmg => Some("dmg"),
            other => other.artifact_format().map(|format| format.tag()),
        }
    }

    /// The target triple an installable artifact is for. Meaningless for
    /// a manifest, a detached signature or an SBOM, which describe another
    /// artifact: use that artifact's.
    #[must_use]
    pub fn target(self) -> &'static str {
        match self {
            Self::Zip | Self::Msi | Self::Wxs | Self::PolicyTemplates => WINDOWS,
            Self::Dmg | Self::Pkg => MACOS,
            Self::Deb
            | Self::Rpm
            | Self::Pacman
            | Self::Tar
            | Self::Manifest
            | Self::Signature
            | Self::Sbom => LINUX,
        }
    }
}

/// One built artifact.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    /// What it is.
    pub kind: Kind,
    /// Where it is.
    pub path: PathBuf,
    /// SHA-256 of its bytes, hex.
    pub sha256: String,
}

/// The target of `artifact`'s binaries: a manifest's, a signature's or an
/// SBOM's is the artifact's it accompanies (an MSI's manifest is Windows').
fn listed_target(artifact: &Artifact, all: &[Artifact]) -> &'static str {
    let accompanied = match artifact.kind {
        Kind::Manifest | Kind::Signature | Kind::Sbom => {
            let name = artifact.path.to_string_lossy();
            [".manifest", ".sig", ".cdx.json"]
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
                .and_then(|base| all.iter().find(|a| a.path.to_string_lossy() == base))
        }
        _ => None,
    };
    accompanied.map_or_else(|| artifact.kind.target(), |a| a.kind.target())
}

/// `packages.json`: the release and its artifacts, what `seaworthy repo`
/// publishes ([`crate::repo`]).
#[derive(Serialize)]
struct Listing<'a> {
    product: &'a str,
    /// The Linux package name (`<vendor>-<id>`), every manifest's product.
    package: String,
    channel: &'a str,
    version: String,
    /// The version token's build metadata (empty: none).
    build: &'a str,
    /// The version token the server names (`version[+build]`).
    token: String,
    sequence: u64,
    /// Packaged with signers (a release): `repo` publishes signed
    /// listings only, and an MSI adopted into one is signed too.
    signed: bool,
    /// A dev build: Authenticode alone, never published; an MSI
    /// adopted into it is Authenticode-signed too.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    authenticode_only: bool,
    /// Signed by the CI test keys: never published; an MSI
    /// adopted into it gets its manifest from the same keys.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ci_test: bool,
    artifacts: Vec<ListedArtifact<'a>>,
}

#[derive(Serialize)]
struct ListedArtifact<'a> {
    kind: Kind,
    file: String,
    /// The target triple of the binaries inside.
    target: &'static str,
    sha256: &'a str,
}

/// The artifact stem: `<package>-<version>-<sequence>`.
#[must_use]
pub fn stem(config: &Config, id: &str, release: &Release) -> String {
    format!(
        "{}-{}-{}",
        crate::linux::package_name(config, id),
        release.version,
        release.sequence
    )
}

/// Builds every output product `id` names from its freshly laid-out
/// `layouts` (one per platform, as [`crate::layout::layout`] returns them;
/// the Windows tree is stamped and signed in place) under `out`, in the
/// order the module docs give. The manifest signers are checked against
/// `release-signatures` and `release-keys` before anything is built.
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Config`] for an unknown product, a
/// missing layout, or a version some format can't spell;
/// [`DistError::Layout`] for an archive the formats can't hold or a
/// staging directory `seaworthy` didn't create; [`DistError::Tool`] when
/// nFPM or WiX can't run or fails; [`DistError::Sign`] for signers outside
/// the policy or a failing signer.
pub fn package(
    config: &Config,
    id: &str,
    layouts: &[Layout],
    out: &Path,
    options: &Options,
    signing: &Signing,
) -> Result<Vec<Artifact>, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    let versions = options.release.package_versions()?;
    let pins = signing_pins(config, signing)?;
    let base = out.join(id);
    remove_listing(&base)?;
    let mut layouts = layouts.to_vec();
    if product.outputs.iter().any(|o| o.is_windows())
        && let Some(windows) = layouts
            .iter_mut()
            .find(|l| l.product == id && l.triple == WINDOWS)
    {
        prepare_windows(
            config,
            product,
            &options.release,
            windows,
            signing.authenticode.as_deref(),
            &pins,
        )?;
    }
    // The macOS bundle: its Info.plist, then signed (ad hoc, or with the
    // Developer ID of the pinned team) — on a Mac only.
    let mac_tools = crate::macos::Tools::find();
    let team_id = match &signing.apple {
        Some(_) => Some(
            config
                .defaults
                .apple
                .as_ref()
                .map(|a| a.team_id.as_str())
                .ok_or_else(|| {
                    DistError::Sign(
                        "[apple] signs with a Developer ID, but seaworthy.toml pins no team: set defaults.apple.team-id".to_owned(),
                    )
                })?,
        ),
        None => None,
    };
    if product.outputs.iter().any(|o| o.is_macos())
        && let Some(macos) = layouts
            .iter_mut()
            .find(|l| l.product == id && l.triple == MACOS)
    {
        let tools = mac_tools.as_ref().ok_or_else(|| {
            DistError::Tool(format!(
                "product {id}'s {} needs macOS's own codesign, hdiutil, pkgbuild and productbuild: package it on a Mac",
                product
                    .outputs
                    .iter()
                    .filter(|o| o.is_macos())
                    .map(|o| o.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        // The entitlements a Developer ID signature carries: read once,
        // from seaworthy.toml's directory, into a copy beside the tree.
        let entitlements = match (
            &signing.apple,
            product.macos.as_ref().and_then(|m| m.entitlements.as_ref()),
        ) {
            (Some(_), Some(path)) => Some(stage_entitlements(config, path, macos)?),
            _ => None,
        };
        prepare_macos(
            config,
            product,
            &options.release,
            macos,
            tools,
            &mac_signer(signing.apple.as_ref(), team_id, entitlements.as_deref()),
        )?;
    }
    let layouts = layouts;
    let layout_for = |triple: &str| {
        layouts
            .iter()
            .find(|l| l.product == id && l.triple == triple)
            .ok_or_else(|| {
                DistError::Config(format!("product {id} has no {triple} layout to package"))
            })
    };
    let packages = base.join("packages");
    let work = base.join("work");
    crate::layout::prepare(&packages)?;
    crate::layout::prepare(&work)?;
    let stem = stem(config, id, &options.release);
    let mut artifacts = Vec::new();
    let mut outputs = product.outputs.clone();
    outputs.sort();
    for output in outputs {
        match output {
            Output::Deb | Output::Rpm | Output::Pacman => {
                let layout = layout_for(LINUX)?;
                let linux = crate::linux::linux_package(config, id, layout)?;
                crate::linux::validate_desktop_entries(&linux, &work)?;
                let nfpm_config = crate::nfpm::write_config(
                    config,
                    id,
                    &linux,
                    output,
                    &versions,
                    options.mtime,
                    &work,
                )?;
                let target = packages.join(crate::nfpm::file_name(
                    &linux.name,
                    output,
                    &versions,
                    crate::nfpm::Arch::X86_64,
                )?);
                crate::nfpm::run(&options.nfpm, &nfpm_config, output, &target)?;
                let kind = match output {
                    Output::Deb => Kind::Deb,
                    Output::Rpm => Kind::Rpm,
                    _ => Kind::Pacman,
                };
                let mut signature = None;
                if let Some(openpgp) = &signing.openpgp {
                    match kind {
                        Kind::Rpm => {
                            openpgp.sign_rpm(&target)?;
                            pins.check_rpm(&target)?;
                        }
                        Kind::Pacman => {
                            let sig = crate::codesign::signature_path(&target);
                            openpgp.detach_sign(&target, &sig)?;
                            pins.check_detached(&sig, &target)?;
                            signature = Some(sig);
                        }
                        // apt verifies the repository's signed index instead.
                        _ => {}
                    }
                }
                artifacts.push(artifact(kind, target)?);
                if let Some(sig) = signature {
                    artifacts.push(artifact(Kind::Signature, sig)?);
                }
            }
            Output::Tar => {
                let layout = layout_for(LINUX)?;
                let bytes = archive::tar_zst(&tree_entries(layout, &stem)?, options.mtime)
                    .map_err(|e| DistError::Layout(e.to_string()))?;
                let path = packages.join(format!("{stem}-linux-x86_64.tar.zst"));
                write(&path, &bytes)?;
                artifacts.push(artifact(Kind::Tar, path)?);
            }
            Output::Zip => {
                let layout = layout_for(WINDOWS)?;
                let bytes = archive::zip(&tree_entries(layout, &stem)?, options.mtime)
                    .map_err(|e| DistError::Layout(e.to_string()))?;
                let path = packages.join(format!("{stem}-windows-x86_64.zip"));
                write(&path, &bytes)?;
                artifacts.push(artifact(Kind::Zip, path)?);
            }
            Output::Msi => {
                let layout = layout_for(WINDOWS)?;
                let text = crate::wix::wxs(config, id, layout, &options.release)?;
                let wxs = packages.join(format!("{stem}-windows-x86_64.wxs"));
                write(&wxs, text.as_bytes())?;
                artifacts.push(artifact(Kind::Wxs, wxs.clone())?);
                if let Some(wix) = &options.wix {
                    let msi = packages.join(format!("{stem}-windows-x86_64.msi"));
                    let pdb = work.join(format!("{stem}-windows-x86_64.wixpdb"));
                    build_msi(wix, &wxs, &layout.tree, &msi, &pdb)?;
                    if let Some(authenticode) = &signing.authenticode {
                        authenticode.sign(&msi, &product.display_name)?;
                        pins.check_authenticode(&msi)?;
                    }
                    artifacts.push(artifact(Kind::Msi, msi)?);
                }
                if layout.helper().is_some() {
                    let template = crate::admx::template(
                        &config.defaults.vendor,
                        &product.windows_directory(),
                        &product.display_name,
                    );
                    let entries = vec![
                        Entry {
                            path: format!("PolicyDefinitions/{}.admx", template.stem),
                            mode: 0o644,
                            data: Some(template.admx.into_bytes()),
                        },
                        Entry {
                            path: format!("PolicyDefinitions/en-US/{}.adml", template.stem),
                            mode: 0o644,
                            data: Some(template.adml.into_bytes()),
                        },
                    ];
                    let bytes = archive::zip(&entries, options.mtime)
                        .map_err(|e| DistError::Layout(e.to_string()))?;
                    let path = packages.join(format!("{stem}-policy-templates.zip"));
                    write(&path, &bytes)?;
                    artifacts.push(artifact(Kind::PolicyTemplates, path)?);
                }
            }
            Output::Dmg => {
                let layout = layout_for(MACOS)?;
                let tools = mac_tools.as_ref().ok_or_else(|| {
                    DistError::Tool("a dmg needs macOS's codesign and hdiutil".to_owned())
                })?;
                let path = packages.join(format!("{stem}-macos-arm64.dmg"));
                crate::macos::build_dmg(
                    tools,
                    &layout.tree.join(crate::macos::bundle_name(product)),
                    &product.display_name,
                    &path,
                    &work,
                    &mac_signer(signing.apple.as_ref(), team_id, None),
                )?;
                artifacts.push(artifact(Kind::Dmg, path)?);
            }
            Output::Pkg => {
                let layout = layout_for(MACOS)?;
                let tools = mac_tools.as_ref().ok_or_else(|| {
                    DistError::Tool("a pkg needs macOS's pkgbuild and productbuild".to_owned())
                })?;
                let path = packages.join(format!("{stem}-macos-arm64.pkg"));
                crate::macos::build_pkg(
                    tools,
                    &crate::macos::pkg_names(config, id, product)?,
                    &layout.tree.join(crate::macos::bundle_name(product)),
                    &crate::macos::launch_daemons(config, id, product)?,
                    &versions.pkg,
                    &config.defaults.macos_minimum,
                    &path,
                    &work,
                    &mac_signer(signing.apple.as_ref(), team_id, None),
                )?;
                artifacts.push(artifact(Kind::Pkg, path)?);
            }
        }
    }
    let manifests = sign_manifests(config, id, options, signing, &artifacts)?;
    artifacts.extend(manifests);
    let mut sboms = Vec::new();
    for built in &artifacts {
        let Some(format) = built.kind.sbom_format() else {
            continue;
        };
        let files =
            match built.kind {
                Kind::Deb | Kind::Rpm | Kind::Pacman => package_files(
                    &crate::linux::linux_package(config, id, layout_for(LINUX)?)?,
                )?,
                Kind::Tar => tree_files(layout_for(LINUX)?),
                Kind::Dmg => tree_files(layout_for(MACOS)?),
                Kind::Pkg => {
                    let mut files = tree_files(layout_for(MACOS)?);
                    for (label, plist) in crate::macos::launch_daemons(config, id, product)? {
                        files.push(crate::sbom::SbomFile {
                            path: crate::macos::PkgNames::daemon_path(&label),
                            sha256: seaworthy_crypto::digest::sha256_hex(plist.as_bytes()),
                            binary: None,
                        });
                    }
                    files
                }
                _ => tree_files(layout_for(WINDOWS)?),
            };
        let info = crate::sbom::ArtifactInfo {
            path: &built.path,
            format,
            target: built.kind.target(),
            files: &files,
        };
        let text = crate::sbom::sbom(config, id, &options.release, &info, options.mtime)?;
        let path = crate::sbom::sbom_path(&built.path);
        write(&path, text.as_bytes())?;
        sboms.push(artifact(Kind::Sbom, path)?);
    }
    artifacts.extend(sboms);
    final_check(&artifacts)?;
    write_listing(
        config,
        id,
        options,
        &artifacts,
        &base,
        SignedAs::of(signing),
    )?;
    Ok(artifacts)
}

/// Builds the repository package ([`crate::repository_package`]) under
/// `<out>/repository/`, as [`package`] builds a product: a deb when a
/// product builds a deb, an rpm (signed, with an OpenPGP signer) when one
/// builds an rpm, each with its signed release manifest (with manifest
/// signers; `repo` checks the package against it, as every package) and
/// its SBOM, listed in `packages.json` under the product id
/// `repository`, versioned with `options`' release.
///
/// # Errors
/// [`DistError::Config`] without `[defaults.repository]`, or for a
/// pinned key the package can't carry; otherwise as [`package`].
pub fn repository(
    config: &Config,
    out: &Path,
    options: &Options,
    signing: &Signing,
) -> Result<Vec<Artifact>, DistError> {
    let id = crate::config::REPOSITORY_ID;
    if config.defaults.repository.is_none() {
        return Err(DistError::Config(
            "no [defaults.repository] in seaworthy.toml: no repository package to build".to_owned(),
        ));
    }
    let versions = options.release.package_versions()?;
    let pins = signing_pins(config, signing)?;
    let base = out.join(id);
    remove_listing(&base)?;
    let packages = base.join("packages");
    let work = base.join("work");
    crate::layout::prepare(&packages)?;
    crate::layout::prepare(&work)?;
    let mut artifacts = Vec::new();
    let mut contents = Vec::new();
    for format in crate::repository_package::formats(config) {
        let built = crate::repository_package::contents(config, format)?;
        let nfpm_config = crate::nfpm::write_repository_config(
            config,
            &built,
            format,
            &versions,
            options.mtime,
            &work,
        )?;
        let target = packages.join(crate::nfpm::file_name(
            &built.package.name,
            format,
            &versions,
            crate::nfpm::Arch::Independent,
        )?);
        crate::nfpm::run(&options.nfpm, &nfpm_config, format, &target)?;
        let kind = if format == Output::Rpm {
            if let Some(openpgp) = &signing.openpgp {
                openpgp.sign_rpm(&target)?;
                pins.check_rpm(&target)?;
            }
            Kind::Rpm
        } else {
            Kind::Deb
        };
        artifacts.push(artifact(kind, target)?);
        contents.push((kind, built));
    }
    let manifests = sign_manifests(config, id, options, signing, &artifacts)?;
    artifacts.extend(manifests);
    let mut sboms = Vec::new();
    for (kind, built) in &contents {
        let Some(package) = artifacts.iter().find(|a| a.kind == *kind) else {
            continue;
        };
        let Some(format) = kind.artifact_format() else {
            continue;
        };
        let files = package_files(&built.package)?;
        let info = crate::sbom::ArtifactInfo {
            path: &package.path,
            format: format.tag(),
            target: kind.target(),
            files: &files,
        };
        let text = crate::sbom::sbom(config, id, &options.release, &info, options.mtime)?;
        let path = crate::sbom::sbom_path(&package.path);
        write(&path, text.as_bytes())?;
        sboms.push(artifact(Kind::Sbom, path)?);
    }
    artifacts.extend(sboms);
    final_check(&artifacts)?;
    write_listing(
        config,
        id,
        options,
        &artifacts,
        &base,
        SignedAs::of(signing),
    )?;
    Ok(artifacts)
}

/// The pins every signature is checked against, after checking the
/// manifest signers against `release-signatures` and `release-keys`,
/// every signer against a pin, and the pinned OpenPGP keys
/// against what clients accept.
/// The msitools programs [`adopt_msi`] reads an MSI with.
#[derive(Debug, Clone)]
pub struct MsiTools {
    /// `msiextract`: the payload, under `PFiles64/<Vendor>/<Directory>/`.
    pub msiextract: PathBuf,
    /// `msiinfo`: the Property table.
    pub msiinfo: PathBuf,
}

impl Default for MsiTools {
    fn default() -> Self {
        Self {
            msiextract: PathBuf::from("msiextract"),
            msiinfo: PathBuf::from("msiinfo"),
        }
    }
}

/// How long one msitools run may take (a large payload extracts in
/// seconds; this is a hang's deadline).
const MSI_TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Adopts `msi`, built by WiX on Windows from the `.wxs` [`package`] wrote
/// for product `id` under `out`, into that product's packages: the
/// MSI's payload must be exactly the signed Windows tree's files (its
/// layout, byte for byte: no file more, none less, none other,
/// `msiextract`) at the release's ProductVersion and the product's
/// UpgradeCode (`msiinfo`). Then, as [`package`] treats an MSI it builds
/// itself: Authenticode-signed with `signing`'s signer and checked against
/// the pins, its release manifest (when the release's other artifacts
/// carry them) and its SBOM written with `mtime`, a last check of every
/// artifact, and the MSI and its companions added to `packages.json`.
/// `msi` is read once: the checks read a private copy, and that copy is
/// what's signed and listed. Returns the new artifacts.
///
/// The checks catch an MSI that isn't this release's (another tree, a
/// stale build, another version or product). They aren't a boundary
/// against the Windows runner: it builds the Windows binaries [`package`]
/// signs, so it's trusted for a Windows release, and the MSI's
/// tables (its custom actions, services, registry values and ACLs) are
/// taken as WiX built them from the `.wxs`.
///
/// # Errors
/// [`DistError::Config`] for an unknown product or one without an `msi`
/// output; [`DistError::Layout`] for a listing without the `.wxs`, one that
/// already lists an MSI, a tree that changed since packaging, or an MSI
/// whose payload or properties differ; [`DistError::Sign`] for signers that
/// don't match the release (manifests on one side only) or a failing
/// signer; [`DistError::Tool`] when msitools can't run.
pub fn adopt_msi(
    config: &Config,
    id: &str,
    out: &Path,
    msi: &Path,
    mtime: u64,
    signing: &Signing,
    tools: &MsiTools,
) -> Result<Vec<Artifact>, DistError> {
    let product = config
        .products
        .get(id)
        .ok_or_else(|| DistError::Config(format!("no product {id:?} in seaworthy.toml")))?;
    if !product.outputs.contains(&Output::Msi) {
        return Err(DistError::Config(format!(
            "product {id} has no msi output to adopt an MSI into"
        )));
    }
    let base = out.join(id);
    let listing = crate::repo::read_listing(&base)?;
    if listing.product != id {
        return Err(DistError::Layout(format!(
            "{}: the listing is product {:?}'s, not {id:?}'s",
            base.display(),
            listing.product
        )));
    }
    if listing.artifacts.iter().any(|a| a.kind == Kind::Msi) {
        return Err(DistError::Layout(format!(
            "{}: an MSI is already listed",
            base.display()
        )));
    }
    if !listing.artifacts.iter().any(|a| a.kind == Kind::Wxs) {
        return Err(DistError::Layout(format!(
            "{}: no .wxs listed: package the product's msi output first",
            base.display()
        )));
    }
    // A signed release's MSI is Authenticode-signed, and an
    // unsigned build's isn't: the listing says which it is, manifests or
    // not (a client-only release carries none).
    // A dev build's is Authenticode-signed and nothing else.
    if listing.authenticode_only != signing.authenticode_only {
        return Err(DistError::Sign(if listing.authenticode_only {
            "the build was packaged as a dev build (Authenticode alone): adopt its MSI with --signing and --authenticode-only".to_owned()
        } else {
            "the build wasn't packaged as a dev build: adopt its MSI as it was packaged (no --authenticode-only)".to_owned()
        }));
    }
    // A CI test build's MSI gets its manifest from the same test
    // keys, never a release's.
    if listing.ci_test != signing.ci_test {
        return Err(DistError::Sign(if listing.ci_test {
            "the build was packaged with the CI test keys: adopt its MSI with the same --ci-test-signing".to_owned()
        } else {
            "the build wasn't packaged with the CI test keys: adopt its MSI as it was packaged (no --ci-test-signing)".to_owned()
        }));
    }
    if (listing.signed || listing.authenticode_only) && signing.authenticode.is_none() {
        return Err(DistError::Sign(
            "the release was packaged signed: its MSI is Authenticode-signed too — adopt it with the release's --signing".to_owned(),
        ));
    }
    if !listing.signed && signing.is_release() {
        return Err(DistError::Sign(
            "the release was packaged unsigned: adopt its MSI unsigned (no --signing)".to_owned(),
        ));
    }
    // The release decides: one packaged signed by a configuration that
    // signs manifests (`release-signatures`) gets its MSI's manifest too,
    // an unsigned build's none. Its other artifacts' manifests alone can't
    // say: an MSI-only product's package step had nothing installable to
    // sign, only the .wxs.
    let manifests = listing.artifacts.iter().any(|a| a.kind == Kind::Manifest)
        || ((listing.signed || listing.ci_test) && config.signs_manifests());
    if manifests != !signing.manifest.is_empty() {
        return Err(DistError::Sign(if manifests {
            "the release carries signed manifests: adopt its MSI with the same --signing".to_owned()
        } else {
            "the release's artifacts carry no manifests: adopt its MSI as it was packaged (no manifest signer)".to_owned()
        }));
    }
    if !signing.manifest.is_empty() {
        crate::sign::check_policy(config, &signing.manifest)?;
    }
    let pins = signing_pins(config, signing)?;
    let release = Release::new(&listing.version, listing.sequence)?;
    let versions = release.package_versions()?;
    let options = Options {
        release,
        mtime,
        nfpm: PathBuf::new(),
        wix: None,
        build: crate::sign::BuildId {
            metadata: listing.build.clone(),
        },
    };

    // The signed Windows tree, as package left it (layout.json's digests).
    let layout_dir = base.join(WINDOWS);
    let manifest_path = layout_dir.join("layout.json");
    let text =
        std::fs::read_to_string(&manifest_path).map_err(|e| DistError::io(&manifest_path, e))?;
    let manifest: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| DistError::Layout(format!("{}: {e}", manifest_path.display())))?;
    let tree = layout_dir.join("tree");
    let mut expected: std::collections::BTreeMap<String, (PathBuf, String, String)> =
        std::collections::BTreeMap::new();
    for file in manifest["files"].as_array().into_iter().flatten() {
        let field = |key: &str| {
            file[key].as_str().map(str::to_owned).ok_or_else(|| {
                DistError::Layout(format!("{}: a file without {key}", manifest_path.display()))
            })
        };
        // The icon goes into the Icon table, not the payload.
        if file["role"]["kind"].as_str() == Some("icon") {
            continue;
        }
        let install_path = field("install_path")?;
        let staged = tree.join(field("path")?);
        let sha256 = field("sha256")?;
        let bytes = std::fs::read(&staged).map_err(|e| DistError::io(&staged, e))?;
        if seaworthy_crypto::digest::sha256_hex(&bytes) != sha256 {
            return Err(DistError::Layout(format!(
                "{}: changed since it was packaged (its SHA-256 isn't layout.json's)",
                staged.display()
            )));
        }
        expected.insert(
            format!("PFiles64/{}", install_path.replace('\\', "/")),
            (staged, sha256, install_path),
        );
    }
    if expected.is_empty() {
        return Err(DistError::Layout(format!(
            "{}: no files to compare the MSI with",
            manifest_path.display()
        )));
    }

    // The MSI's payload, extracted, against the tree.
    let work = base.join("adopt-msi");
    crate::layout::prepare(&work)?;
    let candidate = work.join("candidate.msi");
    std::fs::copy(msi, &candidate).map_err(|e| DistError::io(msi, e))?;
    let extracted = work.join("payload");
    crate::process::run_ok(
        msi_tool(&tools.msiextract)
            .arg("-C")
            .arg(&extracted)
            .arg(&candidate),
        "msiextract",
        MSI_TOOL_TIMEOUT,
    )?;
    let mut found = std::collections::BTreeMap::new();
    collect_files(&extracted, &extracted, &mut found)?;
    for (relative, path) in &found {
        let Some((staged, sha256, _)) = expected.get(relative) else {
            return Err(DistError::Layout(format!(
                "{}: carries {relative}, which the signed tree has no file for",
                msi.display()
            )));
        };
        let bytes = std::fs::read(path).map_err(|e| DistError::io(path, e))?;
        if &seaworthy_crypto::digest::sha256_hex(&bytes) != sha256 {
            return Err(DistError::Layout(format!(
                "{}: its {relative} isn't the signed tree's {}",
                msi.display(),
                staged.display()
            )));
        }
    }
    if let Some(missing) = expected.keys().find(|k| !found.contains_key(*k)) {
        return Err(DistError::Layout(format!(
            "{}: lacks {missing}, which the signed tree carries",
            msi.display()
        )));
    }
    let properties = crate::process::run_ok(
        msi_tool(&tools.msiinfo)
            .arg("export")
            .arg(&candidate)
            .arg("Property"),
        "msiinfo",
        MSI_TOOL_TIMEOUT,
    )?;
    let property = |name: &str| {
        properties.lines().find_map(|line| {
            line.split_once('\t')
                .filter(|(key, _)| *key == name)
                .map(|(_, value)| value.trim_end_matches('\r').to_owned())
        })
    };
    let upgrade = crate::wix::upgrade_code(config, id)?;
    for (name, wanted) in [
        ("ProductVersion", versions.msi.clone()),
        ("UpgradeCode", upgrade),
    ] {
        let actual = property(name);
        if actual.as_deref() != Some(wanted.as_str()) {
            return Err(DistError::Layout(format!(
                "{}: its {name} is {actual:?}, not this release's {wanted:?}",
                msi.display()
            )));
        }
    }

    // In place beside the release's other artifacts, signed, its
    // manifest and SBOM over the final bytes.
    let packages = base.join("packages");
    let target = packages.join(format!(
        "{}-windows-x86_64.msi",
        stem(config, id, &options.release)
    ));
    if target.exists() {
        return Err(DistError::Layout(format!(
            "{} exists: an MSI was adopted without being listed",
            target.display()
        )));
    }
    std::fs::rename(&candidate, &target).map_err(|e| DistError::io(&candidate, e))?;
    if let Some(authenticode) = &signing.authenticode {
        authenticode.sign(&target, &product.display_name)?;
        pins.check_authenticode(&target)?;
    }
    let msi_artifact = artifact(Kind::Msi, target)?;
    let mut new = vec![msi_artifact.clone()];
    new.extend(sign_manifests(
        config,
        id,
        &options,
        signing,
        std::slice::from_ref(&msi_artifact),
    )?);
    let files: Vec<crate::sbom::SbomFile> = expected
        .values()
        .map(|(staged, sha256, install_path)| crate::sbom::SbomFile {
            path: install_path.clone(),
            sha256: sha256.clone(),
            binary: Some(staged.clone()),
        })
        .collect();
    let format = Kind::Msi
        .artifact_format()
        .ok_or_else(|| DistError::Layout("an MSI has no release-manifest format".to_owned()))?;
    let info = crate::sbom::ArtifactInfo {
        path: &msi_artifact.path,
        format: format.tag(),
        target: Kind::Msi.target(),
        files: &files,
    };
    let sbom_text = crate::sbom::sbom(config, id, &options.release, &info, mtime)?;
    let sbom_path = crate::sbom::sbom_path(&msi_artifact.path);
    write(&sbom_path, sbom_text.as_bytes())?;
    new.push(artifact(Kind::Sbom, sbom_path)?);
    let mut all: Vec<Artifact> = listing
        .artifacts
        .iter()
        .map(|a| Artifact {
            kind: a.kind,
            path: base.join(&a.file),
            sha256: a.sha256.clone(),
        })
        .collect();
    all.extend(new.iter().cloned());
    final_check(&all)?;
    write_listing(
        config,
        id,
        &options,
        &all,
        &base,
        SignedAs {
            signed: listing.signed,
            authenticode_only: listing.authenticode_only,
            ci_test: listing.ci_test,
        },
    )?;
    std::fs::remove_dir_all(&work).map_err(|e| DistError::io(&work, e))?;
    Ok(new)
}

/// An msitools command: a tool ([`crate::process::tool`]), so none of
/// the signers' credentials a release's environment holds reaches a parser
/// of the MSI.
fn msi_tool(program: &Path) -> Command {
    crate::process::tool(program)
}

/// Every regular file under `dir`, by its `/`-separated path relative to
/// `root`; anything else (a link, a special file) refused.
fn collect_files(
    root: &Path,
    dir: &Path,
    found: &mut std::collections::BTreeMap<String, PathBuf>,
) -> Result<(), DistError> {
    let entries = std::fs::read_dir(dir).map_err(|e| DistError::io(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| DistError::io(dir, e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| DistError::io(&path, e))?;
        if kind.is_dir() {
            collect_files(root, &path, found)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            found.insert(relative, path);
        } else {
            return Err(DistError::Layout(format!(
                "{}: msiextract left a link or a special file",
                path.display()
            )));
        }
    }
    Ok(())
}

fn signing_pins(config: &Config, signing: &Signing) -> Result<crate::codesign::Pins, DistError> {
    if !signing.manifest.is_empty() {
        crate::sign::check_policy(config, &signing.manifest)?;
    }
    let mut pins = crate::codesign::Pins::of(config);
    if let Some(tool) = &signing.osslsigncode {
        pins.osslsigncode.clone_from(tool);
    }
    if let Some(tool) = &signing.gpg {
        pins.gpg.clone_from(tool);
    }
    pins.require(signing.authenticode.is_some(), signing.openpgp.is_some())?;
    if signing.openpgp.is_some() {
        // A key gpg signs with but apt's sqv or RHEL's crypto policy
        // refuses fails here, not on customers' machines.
        pins.check_key_strength()?;
    }
    Ok(pins)
}

/// Removes `<base>/packages.json`: a failed run must not leave the
/// previous run's listing beside new, partial packages.
fn remove_listing(base: &Path) -> Result<(), DistError> {
    let path = base.join("packages.json");
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DistError::io(&path, e)),
    }
}

/// A signed release manifest beside every installable artifact, when there
/// are manifest signers.
fn sign_manifests(
    config: &Config,
    id: &str,
    options: &Options,
    signing: &Signing,
    artifacts: &[Artifact],
) -> Result<Vec<Artifact>, DistError> {
    let mut manifests = Vec::new();
    if signing.manifest.is_empty() {
        return Ok(manifests);
    }
    for built in artifacts {
        let Some(format) = built.kind.artifact_format() else {
            continue;
        };
        let manifest = crate::sign::manifest_for(
            config,
            id,
            &options.release,
            &options.build,
            built.kind.target(),
            format,
            &built.path,
        )?;
        let path = crate::sign::manifest_path(&built.path);
        write(
            &path,
            &crate::sign::sign_manifest(&manifest, &signing.manifest)?,
        )?;
        manifests.push(artifact(Kind::Manifest, path)?);
    }
    Ok(manifests)
}

/// How a listing was signed: a release, a dev build, a CI test
/// build, or none of them (unsigned).
#[derive(Debug, Clone, Copy)]
struct SignedAs {
    signed: bool,
    authenticode_only: bool,
    ci_test: bool,
}

impl SignedAs {
    fn of(signing: &Signing) -> Self {
        Self {
            signed: signing.is_release(),
            authenticode_only: signing.authenticode_only,
            ci_test: signing.ci_test,
        }
    }
}

/// Writes `<base>/packages.json`, listing `artifacts` (paths relative to
/// `base`).
fn write_listing(
    config: &Config,
    id: &str,
    options: &Options,
    artifacts: &[Artifact],
    base: &Path,
    signed_as: SignedAs,
) -> Result<(), DistError> {
    let SignedAs {
        signed,
        authenticode_only,
        ci_test,
    } = signed_as;
    let version = options.release.version.to_string();
    let build = options.build.metadata.as_str();
    let listing = Listing {
        product: id,
        package: crate::linux::package_name(config, id),
        channel: &config.defaults.channel,
        token: if build.is_empty() {
            version.clone()
        } else {
            format!("{version}+{build}")
        },
        version,
        build,
        sequence: options.release.sequence,
        signed,
        authenticode_only,
        ci_test,
        artifacts: artifacts
            .iter()
            .map(|a| ListedArtifact {
                kind: a.kind,
                target: listed_target(a, artifacts),
                file: a
                    .path
                    .strip_prefix(base)
                    .unwrap_or(&a.path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                sha256: &a.sha256,
            })
            .collect(),
    };
    let json =
        serde_json::to_string_pretty(&listing).map_err(|e| DistError::Layout(e.to_string()))?;
    write(&base.join("packages.json"), format!("{json}\n").as_bytes())
}

/// Stamps the version resource into the Windows tree's launcher, cores and
/// helper, reads every record back, Authenticode-signs every binary when a
/// signer is given (checking each signature against the pins), and
/// rewrites the tree's digests and `layout.json`. A sidecar that already
/// carries a signature (a vendor-signed redistributable) keeps its
/// publisher's.
fn prepare_windows(
    config: &Config,
    product: &crate::config::Product,
    release: &Release,
    layout: &mut Layout,
    authenticode: Option<&dyn crate::codesign::AuthenticodeSigner>,
    pins: &crate::codesign::Pins,
) -> Result<(), DistError> {
    use crate::layout::Role;
    let display = &product.display_name;
    for file in &mut layout.files {
        // Data files are shipped as read: never stamped or signed (layout
        // refused any carrying code).
        if matches!(file.role, Role::Asset | Role::Icon) {
            continue;
        }
        let name = file
            .staged
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let description = match &file.role {
            Role::Launcher => Some(display.clone()),
            Role::Core { cpu } => Some(format!("{display} ({cpu})")),
            Role::Helper => Some(format!("{display} updater")),
            // The FIPS DLL pair is the module's own: never stamped (it is
            // Authenticode-signed like every binary).
            Role::Sidecar
            | Role::Asset
            | Role::Icon
            | Role::BundleInfo
            | Role::CodeSignature
            | Role::Uninstaller => None,
        };
        if let Some(description) = description {
            let bytes = std::fs::read(&file.staged).map_err(|e| DistError::io(&file.staged, e))?;
            let info = crate::pe_version::VersionInfo {
                company: &config.defaults.vendor,
                product: display,
                description: &description,
                file_name: &name,
                dll: matches!(file.role, Role::Core { .. }),
            };
            let stamped = crate::pe_version::stamp_version(&bytes, release, &info)
                .map_err(|e| DistError::Layout(format!("{}: {e}", file.staged.display())))?;
            write(&file.staged, &stamped)?;
            crate::layout::recheck_record(&file.staged, &file.role, "stamped")?;
        }
        if let Some(signer) = authenticode {
            let bytes = std::fs::read(&file.staged).map_err(|e| DistError::io(&file.staged, e))?;
            let publisher_signed = matches!(file.role, Role::Sidecar)
                && crate::pe_version::is_signed(&bytes)
                    .map_err(|e| DistError::Layout(format!("{}: {e}", file.staged.display())))?;
            if !publisher_signed {
                signer.sign(&file.staged, display)?;
                crate::layout::recheck_record(&file.staged, &file.role, "signed")?;
                pins.check_authenticode(&file.staged)?;
            }
        }
        let bytes = std::fs::read(&file.staged).map_err(|e| DistError::io(&file.staged, e))?;
        file.sha256 = seaworthy_crypto::digest::sha256_hex(&bytes);
    }
    crate::layout::write_manifest(layout)
}

/// The macOS signer: the Developer ID with its pinned team (and the main
/// executable's entitlements), or ad hoc without one.
fn mac_signer<'a>(
    apple: Option<&'a crate::macos::DeveloperId>,
    team_id: Option<&'a str>,
    entitlements: Option<&'a Path>,
) -> crate::macos::MacSigner<'a> {
    match (apple, team_id) {
        (Some(id), Some(team_id)) => crate::macos::MacSigner::DeveloperId {
            id,
            team_id,
            entitlements,
        },
        _ => crate::macos::MacSigner::AdHoc,
    }
}

/// `macos.entitlements`, read once from `seaworthy.toml`'s directory (a
/// regular file inside it, as data files are read) and checked to be an
/// XML property list, copied beside the macOS tree (outside the bundle, so
/// its seal never covers it) for `codesign`. Returns the copy's path.
fn stage_entitlements(
    config: &Config,
    relative: &Path,
    layout: &Layout,
) -> Result<PathBuf, DistError> {
    let bytes = crate::layout::read_project_file(&config.dir, relative)?;
    let text = std::str::from_utf8(&bytes).unwrap_or_default();
    let body = text.trim_start_matches('\u{feff}').trim_start();
    if !body.starts_with("<?xml") || !body.contains("<plist") || !body.contains("</plist>") {
        return Err(DistError::Layout(format!(
            "{}: not an XML property list (macos.entitlements)",
            relative.display()
        )));
    }
    let dir = layout.tree.parent().ok_or_else(|| {
        DistError::Layout(format!("{} has no parent directory", layout.tree.display()))
    })?;
    let staged = dir.join("entitlements.plist");
    write(&staged, &bytes)?;
    Ok(staged)
}

/// Completes the macOS bundle in place: writes `Contents/Info.plist`,
/// signs the bundle from the inside out (`crate::macos`: ad hoc, or with
/// the Developer ID `signer` names), checks
/// every signed binary still carries its record, lists the plist and the
/// signature seal with the bundle's files, and rewrites `layout.json`.
fn prepare_macos(
    config: &Config,
    product: &crate::config::Product,
    release: &Release,
    layout: &mut Layout,
    tools: &crate::macos::Tools,
    signer: &crate::macos::MacSigner<'_>,
) -> Result<(), DistError> {
    use crate::layout::{File, Role};
    let bundle = layout.tree.join(crate::macos::bundle_name(product));
    let icon = layout.files.iter().any(|f| f.role == Role::Icon);
    let text = crate::macos::info_plist(product, release, &config.defaults.macos_minimum, icon)?;
    let plist = bundle.join("Contents").join("Info.plist");
    write(&plist, text.as_bytes())?;
    layout.files.push(File {
        install_path: format!("{}/Contents/Info.plist", layout.install_root),
        staged: plist,
        role: Role::BundleInfo,
        mode: 0o644,
        sha256: seaworthy_crypto::digest::sha256_hex(text.as_bytes()),
    });
    // A service's pkg: its uninstaller, inside the bundle so the signature
    // seals it (macOS has no uninstall for a package).
    if product.outputs.contains(&Output::Pkg) {
        let names = crate::macos::pkg_names(config, &layout.product, product)?;
        let text = crate::macos::uninstaller(&names);
        let staged = bundle.join(crate::macos::UNINSTALLER);
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
        }
        write(&staged, text.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| DistError::io(&staged, e))?;
        }
        layout.files.push(File {
            install_path: format!("{}/{}", layout.install_root, crate::macos::UNINSTALLER),
            staged,
            role: Role::Uninstaller,
            mode: 0o755,
            sha256: seaworthy_crypto::digest::sha256_hex(text.as_bytes()),
        });
    }
    let nested: Vec<PathBuf> = layout
        .files
        .iter()
        .filter(|f| matches!(f.role, Role::Core { .. } | Role::Helper | Role::Sidecar))
        .map(|f| f.staged.clone())
        .collect();
    crate::macos::sign_bundle(tools, &bundle, &nested, signer)?;
    let seal = bundle
        .join("Contents")
        .join("_CodeSignature")
        .join("CodeResources");
    layout.files.push(File {
        install_path: format!(
            "{}/Contents/_CodeSignature/CodeResources",
            layout.install_root
        ),
        staged: seal,
        role: Role::CodeSignature,
        mode: 0o644,
        sha256: String::new(),
    });
    for file in &mut layout.files {
        crate::layout::recheck_record(&file.staged, &file.role, "signed")?;
        let bytes = std::fs::read(&file.staged).map_err(|e| DistError::io(&file.staged, e))?;
        file.sha256 = seaworthy_crypto::digest::sha256_hex(&bytes);
    }
    crate::layout::write_manifest(layout)
}

/// A laid-out tree's files, for an SBOM.
fn tree_files(layout: &Layout) -> Vec<crate::sbom::SbomFile> {
    layout
        .files
        .iter()
        .map(|f| crate::sbom::SbomFile {
            path: f.install_path.clone(),
            sha256: f.sha256.clone(),
            binary: Some(f.staged.clone()),
        })
        .collect()
}

/// A Linux package's files (the tree plus generated ones), for an SBOM.
fn package_files(
    package: &crate::linux::LinuxPackage,
) -> Result<Vec<crate::sbom::SbomFile>, DistError> {
    package
        .files
        .iter()
        .map(|f| {
            Ok(match &f.source {
                crate::linux::Source::Staged(path) => {
                    let bytes = std::fs::read(path).map_err(|e| DistError::io(path, e))?;
                    crate::sbom::SbomFile {
                        path: f.dst.clone(),
                        sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
                        binary: Some(path.clone()),
                    }
                }
                crate::linux::Source::Generated(text) => crate::sbom::SbomFile {
                    path: f.dst.clone(),
                    sha256: seaworthy_crypto::digest::sha256_hex(text.as_bytes()),
                    binary: None,
                },
            })
        })
        .collect()
}

/// Every artifact still has the bytes recorded for it, and every manifest
/// names its artifact's exact size and digest.
fn final_check(artifacts: &[Artifact]) -> Result<(), DistError> {
    for built in artifacts {
        let bytes = std::fs::read(&built.path).map_err(|e| DistError::io(&built.path, e))?;
        if seaworthy_crypto::digest::sha256_hex(&bytes) != built.sha256 {
            return Err(DistError::Layout(format!(
                "{} changed after it was recorded",
                built.path.display()
            )));
        }
        if built.kind == Kind::Manifest {
            let (manifest, _) = seaworthy_updater::ReleaseManifest::decode_signed(&bytes)
                .map_err(|e| DistError::Sign(format!("{}: {e}", built.path.display())))?;
            let target = built.path.with_extension("");
            let data = std::fs::read(&target).map_err(|e| DistError::io(&target, e))?;
            if manifest.size != data.len() as u64
                || manifest.digest != manifest.digest_algorithm.hash(&data)
            {
                return Err(DistError::Sign(format!(
                    "{} doesn't match {}",
                    built.path.display(),
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), DistError> {
    std::fs::write(path, bytes).map_err(|e| DistError::io(path, e))
}

fn artifact(kind: Kind, path: PathBuf) -> Result<Artifact, DistError> {
    let bytes = std::fs::read(&path).map_err(|e| DistError::io(&path, e))?;
    Ok(Artifact {
        kind,
        sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
        path,
    })
}

/// The tree's files under `<top>/`, with their directories, for the
/// tarball and the zip.
fn tree_entries(layout: &Layout, top: &str) -> Result<Vec<Entry>, DistError> {
    let separator = if layout.triple == WINDOWS { '\\' } else { '/' };
    let prefix = format!("{}{separator}", layout.install_root);
    let mut entries = vec![Entry {
        path: top.to_owned(),
        mode: 0o755,
        data: None,
    }];
    let mut directories = std::collections::BTreeSet::new();
    for file in &layout.files {
        let relative = file
            .install_path
            .strip_prefix(&prefix)
            .ok_or_else(|| {
                DistError::Layout(format!(
                    "{} is outside {}",
                    file.install_path, layout.install_root
                ))
            })?
            .replace(separator, "/");
        let mut parent = Path::new(&relative).parent();
        while let Some(dir) = parent.and_then(Path::to_str).filter(|d| !d.is_empty()) {
            directories.insert(dir.to_owned());
            parent = Path::new(dir).parent();
        }
        let data = std::fs::read(&file.staged).map_err(|e| DistError::io(&file.staged, e))?;
        entries.push(Entry {
            path: format!("{top}/{relative}"),
            mode: file.mode,
            data: Some(data),
        });
    }
    entries.extend(directories.into_iter().map(|dir| Entry {
        path: format!("{top}/{dir}"),
        mode: 0o755,
        data: None,
    }));
    Ok(entries)
}

/// `wix build` for one `.wxs`: x64, the staged tree as the bind path
/// `tree` (the `.wxs` names every file through it), run from the tree, and
/// the debug database kept out of `packages/`.
fn build_msi(wix: &Path, wxs: &Path, tree: &Path, msi: &Path, pdb: &Path) -> Result<(), DistError> {
    let mut bindpath = std::ffi::OsString::from("tree=");
    bindpath.push(tree);
    let output = crate::process::tool(wix)
        .current_dir(tree)
        .arg("build")
        .arg("-arch")
        .arg("x64")
        .arg("-nologo")
        .arg("-bindpath")
        .arg(bindpath)
        .arg("-pdb")
        .arg(pdb)
        .arg("-o")
        .arg(msi)
        .arg(wxs)
        .output()
        .map_err(|e| DistError::Tool(format!("cannot run {} (WiX v5.0.2): {e}", wix.display())))?;
    if !output.status.success() || !msi.is_file() {
        return Err(DistError::Tool(format!(
            "wix build failed ({}): {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use seaworthy_updater::{
        ArtifactFormat, DigestAlgorithm, ManifestSignature, ReleaseManifest, SignatureAlgorithm,
    };

    fn manifest_file(bytes: &[u8]) -> Vec<u8> {
        let manifest = ReleaseManifest {
            product: "acme-tool".into(),
            channel: Some("stable".into()),
            version: "1.0.0".into(),
            build: String::new(),
            sequence: 1,
            target: LINUX.into(),
            format: ArtifactFormat::Tar,
            size: bytes.len() as u64,
            digest_algorithm: DigestAlgorithm::Sha512,
            digest: DigestAlgorithm::Sha512.hash(bytes),
        };
        // The final check never verifies signatures (they're verified as
        // they're made); any well-formed line does.
        let signature = ManifestSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: [1; seaworthy_updater::KEY_ID_LEN],
            signature: vec![2; 64],
        };
        manifest.encode_signed(&[signature]).unwrap()
    }

    #[test]
    fn the_final_check_refuses_a_changed_artifact_and_a_manifest_naming_other_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let tar = tmp.path().join("a.tar.zst");
        std::fs::write(&tar, b"the artifact").unwrap();
        let path = crate::sign::manifest_path(&tar);
        std::fs::write(&path, manifest_file(b"the artifact")).unwrap();
        let recorded = [
            artifact(Kind::Tar, tar.clone()).unwrap(),
            artifact(Kind::Manifest, path.clone()).unwrap(),
        ];
        final_check(&recorded).unwrap();
        // A manifest naming other bytes of the same length, recorded as it is.
        std::fs::write(&path, manifest_file(b"the artefact")).unwrap();
        let stale = [
            artifact(Kind::Tar, tar.clone()).unwrap(),
            artifact(Kind::Manifest, path).unwrap(),
        ];
        let err = final_check(&stale).unwrap_err().to_string();
        assert!(err.contains("doesn't match"), "{err}");
        // An artifact changed after it was recorded.
        std::fs::write(&tar, b"the artifact!").unwrap();
        let err = final_check(&recorded[..1]).unwrap_err().to_string();
        assert!(err.contains("changed after it was recorded"), "{err}");
    }
}
