//! Package repositories on object storage: every product's current
//! release, as `seaworthy package` listed it (`packages.json`), laid out
//! as the static files of an APT, a DNF and a pacman repository, the
//! releases the update helper fetches, and the repositories' OpenPGP key — plus the publish plan
//! that names every file with its hash, size and cache class, immutable
//! files first and indexes last.
//!
//! ```text
//! apt/pool/main/<package>/<file>.deb                               immutable
//! apt/dists/<channel>/main/binary-amd64/by-hash/SHA256/<sha256>    immutable
//! apt/dists/<channel>/main/binary-amd64/Packages{,.gz}             index
//! apt/dists/<channel>/{Release,Release.gpg,InRelease}              index
//! rpm/<channel>/x86_64/Packages/<file>.rpm                         immutable
//! rpm/<channel>/x86_64/repodata/<sha256>-<name>.xml.gz             immutable
//! rpm/<channel>/x86_64/repodata/repomd.xml{,.asc}                  index
//! pacman/<channel>/x86_64/<file>.pkg.tar.zst{,.sig}                immutable
//! pacman/<channel>/x86_64/<repo>.{files,db}{.tar.zst,}{,.sig}      index
//! releases/<package>/<channel>/<token>/<target>/<package>.<format>{,.manifest,.sig,.cdx.json}
//!                                                                  immutable
//! keys/<repo>.asc                                                  index
//! setup/<repo>-repository.{deb,deb.asc,rpm}                        index
//! publish-plan.json
//! ```
//!
//! - **APT**: `dpkg-scanpackages` writes the `Packages` stanzas (each
//!   package's own control fields, its path, size and SHA-256, which must
//!   be the listed file's); `seaworthy` writes `Packages.gz`
//!   (deterministic), the by-hash copies (`Acquire-By-Hash: yes`: a client
//!   mid-update reads the index its `Release` names, never a newer one
//!   under the same name), `Release` with every index's size and SHA-256,
//!   `Release.gpg` and the clear-signed `InRelease`. One component, `main`,
//!   and one architecture, `amd64`; the suite and codename are the channel.
//!   No `Valid-Until`: releases can be months apart, and a repository that
//!   expires between them would stop admins' patch cycles (the update
//!   helper doesn't read the repositories at all).
//! - **DNF**: `createrepo_c` writes `repodata/` (hash-named metadata,
//!   gzip so every dnf reads it, no sqlite databases, every timestamp the
//!   index date); `repomd.xml.asc` signs `repomd.xml`. Each rpm carries its
//!   own signature (`gpgcheck=1`).
//! - **pacman**: `repo-add` writes the `<repo>.db.tar.zst` and
//!   `<repo>.files.tar.zst` databases; the names pacman reads (`<repo>.db`,
//!   `<repo>.files`) are copies, not links (object storage has none), and
//!   every database gets its detached signature. Each package's `.sig` sits
//!   beside it, where pacman fetches it (pacman 6.1's `repo-add` stopped
//!   embedding signatures in the database).
//! - **Releases**: each installable artifact (deb, rpm, pacman, tar, zip,
//!   msi) under the name the update helper's URL template builds
//!   (`{product}/{channel}/{version}/{target}/{product}.{format}`),
//!   with its signed manifest, its SBOM and, for pacman, its signature.
//! - **The key**: `keys/<repo>.asc`, every OpenPGP key `seaworthy.toml` pins
//!   (`defaults.openpgp-keys`), which the repository definitions name.
//! - **The repository package** (with `[defaults.repository]`,
//!   [`crate::repository_package`]): `<repo>-repository`, listed by
//!   `package` under the product id `repository`, is in the APT and DNF
//!   repositories like every package (so a key rotation reaches machines
//!   through them), and under stable names in `setup/` for a first
//!   install, which is how a machine gets it: the deb with a detached
//!   armored signature (`.asc`, by the indexes' key: an administrator can
//!   check it with `gpgv` before trusting anything), the rpm signed like
//!   every rpm. Its signed manifest binds its bytes, not what they
//!   configure, so `repo` also reads the copy back (`dpkg-deb`, `bsdtar`)
//!   and refuses a package whose files aren't exactly what this `seaworthy.toml`
//!   generates: another URL, channel or set of keys (a stale package)
//!   would set machines up for repositories this publication isn't, or
//!   without the key it's about to be signed with. It isn't in the release
//!   tree (the update helper never fetches it), and the plan records its
//!   URL, which `publish` checks against the URL it publishes to.
//!
//! The repository name is the vendor in lowercase (`acme`): pacman's
//! `[acme]` section and the key file's name.
//!
//! **Nothing is published that a client would refuse.** Each listed file
//! is read once, as `repo` trusts it: a regular file reached through no
//! link, within the update helper's limit for its kind (an artifact up to
//! 1 GiB, a manifest or signature up to 64 KiB), its bytes the SHA-256
//! `packages.json` lists. Those bytes go into the release tree, and every
//! check runs on that copy: each installable artifact's signed release
//! manifest verifies against `release-keys` and names exactly it
//! ([`crate::sign::check_manifest`]), each rpm carries a signature by a
//! pinned OpenPGP key and each pacman package a detached one, and the
//! pinned keys are ones clients accept ([`Pins::check_key_strength`]).
//! Every repository copies from the release tree, checked against the
//! listing again. After signing, every index signature is checked against
//! the pinned keys alone (`InRelease` must sign exactly `Release`).
//!
//! **Immutable means immutable.** Immutable files are cached for a year,
//! by a CDN and by every proxy between a customer and the store, so a path
//! once published must never get other bytes. Given the last publication's
//! plan (`--previous`), `repo` refuses one that would: a version token
//! packaged again (a retried pipeline) re-signs its manifests and
//! packages under the same release-tree paths. The indexes' date must
//! also move forward: apt silently keeps a `Release` it holds when the new
//! one is older.
//!
//! The repositories hold exactly the releases given, one of each product
//! `seaworthy.toml` defines ("latest only"): a product left out
//! would vanish from the indexes. The publisher keeps the previous
//! release's files for the retention period. A failed build removes its
//! output directory: nothing half-built is left to publish.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::DistError;
use crate::codesign::{OpenPgpSigner, Pins};
use crate::config::{Config, REPOSITORY_ID};
use crate::package::Kind;
use crate::sign::BuildId;
use crate::version::Release;

/// The publish plan's file name, in the output directory.
pub const PLAN_FILE: &str = "publish-plan.json";

/// One release as `seaworthy package` listed it (`packages.json`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listing {
    /// The product id (`agent`).
    pub product: String,
    /// The package name (`<vendor>-<id>`), every manifest's product.
    pub package: String,
    /// The channel.
    pub channel: String,
    /// The release version.
    pub version: String,
    /// The version token's build metadata (empty: none).
    pub build: String,
    /// The version token (`version[+build]`).
    pub token: String,
    /// The release sequence.
    pub sequence: u64,
    /// Packaged with signers (`package --signing`): the repositories
    /// publish signed releases only.
    #[serde(default)]
    pub signed: bool,
    /// A dev build: Authenticode alone, never published.
    #[serde(default)]
    pub authenticode_only: bool,
    /// Signed by the CI test keys: never published.
    #[serde(default)]
    pub ci_test: bool,
    /// The artifacts.
    pub artifacts: Vec<ListedArtifact>,
    /// The directory `packages.json` is in, the artifacts' base.
    #[serde(skip)]
    pub dir: PathBuf,
}

/// One listed artifact.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListedArtifact {
    /// What it is.
    pub kind: Kind,
    /// Its path, relative to the listing's directory, `/`-separated.
    pub file: String,
    /// The target triple of the binaries inside (an installable
    /// artifact's own; a manifest's, signature's or SBOM's is the
    /// artifact's it accompanies).
    pub target: String,
    /// Its SHA-256, hex.
    pub sha256: String,
}

impl ListedArtifact {
    /// Its path on disk.
    #[must_use]
    pub fn path(&self, listing: &Listing) -> PathBuf {
        listing.dir.join(&self.file)
    }

    /// Its file name.
    fn file_name(&self) -> &str {
        self.file.rsplit('/').next().unwrap_or(&self.file)
    }

    /// The most the update helper accepts for this kind (`None`: the
    /// helper never fetches it).
    fn limit(&self) -> Option<u64> {
        if self.kind.artifact_format().is_some() {
            Some(seaworthy_updater::MAX_ARTIFACT_BYTES)
        } else if matches!(self.kind, Kind::Manifest | Kind::Signature) {
            Some(seaworthy_updater::MAX_METADATA_BYTES)
        } else {
            None
        }
    }

    /// Its bytes, read as `repo` trusts them: a regular file reached
    /// through no link, within the update helper's limit for its kind,
    /// and the SHA-256 `packages.json` lists.
    ///
    /// # Errors
    /// [`DistError::Layout`] for a link, anything but a regular file, a
    /// file over its limit, or other bytes; [`DistError::Io`] when it
    /// can't be read.
    pub fn read(&self, listing: &Listing) -> Result<Vec<u8>, DistError> {
        let mut path = listing.dir.clone();
        for part in self.file.split('/') {
            path.push(part);
            let meta = std::fs::symlink_metadata(&path).map_err(|e| DistError::io(&path, e))?;
            if meta.file_type().is_symlink() {
                return Err(DistError::Layout(format!(
                    "{} is a link: a listed file must be the file itself",
                    path.display()
                )));
            }
        }
        let bytes = read_regular(&path, self.limit())?;
        self.check(&path, &bytes)?;
        Ok(bytes)
    }

    /// `bytes`, read from `path`, are the listed ones.
    fn check(&self, path: &Path, bytes: &[u8]) -> Result<(), DistError> {
        if seaworthy_crypto::digest::sha256_hex(bytes) == self.sha256 {
            Ok(())
        } else {
            Err(DistError::Layout(format!(
                "{} changed since it was packaged (its SHA-256 isn't the one packages.json lists)",
                path.display()
            )))
        }
    }
}

impl Listing {
    /// The artifact accompanying `artifact` as `<file><suffix>` (its
    /// manifest, signature or SBOM), when listed as `kind`.
    fn companion(
        &self,
        artifact: &ListedArtifact,
        suffix: &str,
        kind: Kind,
    ) -> Option<&ListedArtifact> {
        let file = format!("{}{suffix}", artifact.file);
        self.artifacts
            .iter()
            .find(|a| a.file == file && a.kind == kind)
    }
}

/// The companions an installable artifact may have, and the suffix each
/// is published under.
const COMPANIONS: [(&str, Kind); 3] = [
    (".manifest", Kind::Manifest),
    (".sig", Kind::Signature),
    (".cdx.json", Kind::Sbom),
];

/// Reads `<dir>/packages.json` and every file it lists
/// ([`ListedArtifact::read`]), refusing a path that leaves the directory
/// and a file listed twice.
///
/// # Errors
/// [`DistError::Io`] for an unreadable file, [`DistError::Layout`] for a
/// malformed listing, a path outside the directory, a file listed twice,
/// or a listed file `read` refuses.
pub fn read_listing(dir: &Path) -> Result<Listing, DistError> {
    let path = dir.join("packages.json");
    let text = std::fs::read_to_string(&path).map_err(|e| DistError::io(&path, e))?;
    let mut listing: Listing = serde_json::from_str(&text)
        .map_err(|e| DistError::Layout(format!("{}: {e}", path.display())))?;
    listing.dir = dir.to_path_buf();
    let mut files = BTreeSet::new();
    for artifact in &listing.artifacts {
        let relative = Path::new(&artifact.file);
        if artifact.file.contains('\\')
            || artifact.file.is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(DistError::Layout(format!(
                "{}: the artifact path {:?} leaves its directory",
                path.display(),
                artifact.file
            )));
        }
        if !files.insert(artifact.file.as_str()) {
            return Err(DistError::Layout(format!(
                "{}: {} is listed twice",
                path.display(),
                artifact.file
            )));
        }
        artifact.read(&listing)?;
    }
    Ok(listing)
}

/// How the publisher caches a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Never changes once published (a package, hash-named metadata, a
    /// release): uploaded first, cached for a year.
    Immutable,
    /// Changes with every release (an index, a signature over one, the
    /// key): uploaded last, cached briefly.
    Index,
}

/// One file the publisher uploads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEntry {
    /// Its path under the repository root, `/`-separated.
    pub path: String,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// Its size in bytes.
    pub size: u64,
    /// How it is cached.
    pub class: Class,
}

/// One release a plan publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRelease {
    /// The product id.
    pub product: String,
    /// The package name.
    pub package: String,
    /// The version token.
    pub token: String,
    /// The release sequence.
    pub sequence: u64,
}

/// The publish plan: every file, in upload order (the immutable files,
/// then the indexes in the order each repository needs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The repositories' name (pacman's `[<repo>]`, the key file's name).
    pub repository: String,
    /// The channel.
    pub channel: String,
    /// The URL the repository package points machines at
    /// (`[defaults.repository]`), when there is one: `publish` refuses
    /// another public URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A deliberate rollback: some release is older than the last
    /// publication's (`repo --allow-older`); `publish` refuses an older
    /// release otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
    /// The indexes' date (seconds since the epoch).
    pub date: u64,
    /// The releases published, one per product.
    pub releases: Vec<PlanRelease>,
    /// Each repository tool that ran, with what its `--version` printed
    /// (evidence: the tools come from the build image's distribution).
    pub tools: BTreeMap<String, String>,
    /// The files, in upload order.
    pub files: Vec<PlanEntry>,
}

impl Plan {
    /// Reads a plan `repo` wrote (`--previous`).
    ///
    /// # Errors
    /// [`DistError::Io`] for an unreadable file, [`DistError::Layout`] for
    /// one that isn't a plan.
    pub fn read(path: &Path) -> Result<Self, DistError> {
        let text = std::fs::read_to_string(path).map_err(|e| DistError::io(path, e))?;
        serde_json::from_str(&text)
            .map_err(|e| DistError::Layout(format!("{}: not a publish plan: {e}", path.display())))
    }
}

/// The programs the repositories are built with.
#[derive(Debug, Clone)]
pub struct Tools {
    /// `dpkg-scanpackages` (dpkg-dev).
    pub dpkg_scanpackages: PathBuf,
    /// `createrepo_c`.
    pub createrepo_c: PathBuf,
    /// `repo-add` (pacman).
    pub repo_add: PathBuf,
    /// `dpkg-deb` (dpkg), which reads the repository package's deb back.
    pub dpkg_deb: PathBuf,
    /// `bsdtar` (libarchive, which `repo-add` runs too), which reads the
    /// repository package's payloads back.
    pub bsdtar: PathBuf,
    /// One program's deadline.
    pub timeout: Duration,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            dpkg_scanpackages: PathBuf::from("dpkg-scanpackages"),
            createrepo_c: PathBuf::from("createrepo_c"),
            repo_add: PathBuf::from("repo-add"),
            dpkg_deb: PathBuf::from("dpkg-deb"),
            bsdtar: PathBuf::from("bsdtar"),
            timeout: Duration::from_secs(600),
        }
    }
}

/// The repositories' name: the vendor in lowercase (already
/// `[a-z0-9][a-z0-9.-]*`, as every package name's prefix).
#[must_use]
pub fn repository_name(config: &Config) -> String {
    config.defaults.vendor.to_ascii_lowercase()
}

/// The architecture names each format uses for a target triple.
struct Arch {
    deb: &'static str,
    rpm: &'static str,
    pacman: &'static str,
}

/// The deb architecture of `target`'s packages (the repository package's
/// `Architectures:`).
///
/// # Errors
/// [`DistError::Layout`] for a target with no Linux repository.
pub(crate) fn deb_architecture(target: &str) -> Result<&'static str, DistError> {
    arch(target).map(|a| a.deb)
}

/// The rpm architecture of `target`'s packages (the repository package's
/// `baseurl`).
///
/// # Errors
/// [`DistError::Layout`] for a target with no Linux repository.
pub(crate) fn rpm_architecture(target: &str) -> Result<&'static str, DistError> {
    arch(target).map(|a| a.rpm)
}

fn arch(target: &str) -> Result<Arch, DistError> {
    match target {
        crate::inputs::LINUX => Ok(Arch {
            deb: "amd64",
            rpm: "x86_64",
            pacman: "x86_64",
        }),
        other => Err(DistError::Layout(format!(
            "no Linux repository architecture for target {other:?}"
        ))),
    }
}

/// What signs the repositories, and what their signatures must verify to.
pub struct Signers<'a> {
    /// The OpenPGP signer of the indexes.
    pub openpgp: &'a dyn OpenPgpSigner,
    /// The pins every signature is checked against.
    pub pins: &'a Pins,
}

/// When and after what a build publishes.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a> {
    /// Every index's date (seconds since the epoch): the publication time,
    /// so each publication's indexes are newer than the last.
    pub date: u64,
    /// The last publication's plan: no immutable path may get other bytes,
    /// `date` must be later, and no release older than its (by version,
    /// then sequence, as clients order releases).
    pub previous: Option<&'a Plan>,
    /// Publish releases older than the last publication's on purpose (a
    /// rollback): the plan says so, and `publish` accepts it.
    pub allow_older: bool,
}

/// Builds the repositories for `listings` under `out` (which must not
/// exist yet), signs their indexes, checks every signature against the
/// pins, and writes the publish plan. On any failure `out` is removed.
///
/// # Errors
/// [`DistError::Layout`] for listings that don't belong together (another
/// channel, a product listed twice or missing, a product `seaworthy.toml`
/// doesn't define), a listed file that isn't what was listed, an existing
/// `out`, or a publication `previous` contradicts; [`DistError::Sign`] for
/// a release a client would refuse, a weak pinned key or a signature no
/// pinned key made; [`DistError::Tool`] when a repository tool fails;
/// [`DistError::Io`] on a filesystem error.
pub fn build(
    config: &Config,
    listings: &[Listing],
    out: &Path,
    tools: &Tools,
    signers: &Signers<'_>,
    options: &Options<'_>,
) -> Result<Plan, DistError> {
    // The repository tools run inside the output directory and are handed
    // paths in it: they must not depend on the caller's directory.
    let out = &std::path::absolute(out).map_err(|e| DistError::io(out, e))?;
    check_listings(config, listings)?;
    for listing in listings {
        check_shape(config, listing)?;
    }
    let name = repository_name(config);
    let mut rollback = false;
    if let Some(previous) = options.previous {
        check_previous(config, &name, previous, options.date)?;
        rollback = check_older(listings, previous, options.allow_older)?;
    }
    signers.pins.check_key_strength()?;
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
    }
    match std::fs::create_dir(out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DistError::Layout(format!(
                "{} already exists: the repositories are built into a new directory",
                out.display()
            )));
        }
        Err(e) => return Err(DistError::io(out, e)),
    }
    let built = build_into(
        config, listings, out, &name, tools, signers, options, rollback,
    );
    if built.is_err() {
        // This run created it: nothing half-built is left to publish.
        let _ = std::fs::remove_dir_all(out);
    }
    built
}

#[allow(clippy::too_many_arguments)]
fn build_into(
    config: &Config,
    listings: &[Listing],
    out: &Path,
    name: &str,
    tools: &Tools,
    signers: &Signers<'_>,
    options: &Options<'_>,
    rollback: bool,
) -> Result<Plan, DistError> {
    let channel = config.defaults.channel.as_str();
    releases(listings, out)?;
    for listing in listings {
        check_release(config, signers.pins, listing, out)?;
    }
    let mut versions = BTreeMap::new();
    if let Some(listing) = listings.iter().find(|l| is_repository_package(l)) {
        for (tool, what) in [(&tools.dpkg_deb, "dpkg-deb"), (&tools.bsdtar, "bsdtar")] {
            versions.insert(
                what.to_owned(),
                tool_version(tool, what, out, tools.timeout)?,
            );
        }
        check_repository_contents(config, out, listing, tools)?;
    }
    let mut indexes = vec![key_file(config, out, name)?];
    indexes.extend(setup(out, listings, signers)?);
    let of = |kind: Kind| -> Vec<(&Listing, &ListedArtifact)> {
        listings
            .iter()
            .flat_map(|l| l.artifacts.iter().map(move |a| (l, a)))
            .filter(|(_, a)| a.kind == kind)
            .collect()
    };
    let debs = of(Kind::Deb);
    if !debs.is_empty() {
        versions.insert(
            "dpkg-scanpackages".to_owned(),
            tool_version(
                &tools.dpkg_scanpackages,
                "dpkg-scanpackages",
                out,
                tools.timeout,
            )?,
        );
        indexes.extend(apt(
            out,
            channel,
            name,
            &debs,
            tools,
            signers,
            options.date,
        )?);
    }
    let rpms = of(Kind::Rpm);
    if !rpms.is_empty() {
        versions.insert(
            "createrepo_c".to_owned(),
            tool_version(&tools.createrepo_c, "createrepo_c", out, tools.timeout)?,
        );
        indexes.extend(dnf(out, channel, &rpms, tools, signers, options.date)?);
    }
    let pacman_packages = of(Kind::Pacman);
    if !pacman_packages.is_empty() {
        versions.insert(
            "repo-add".to_owned(),
            tool_version(&tools.repo_add, "repo-add", out, tools.timeout)?,
        );
        indexes.extend(pacman(
            out,
            channel,
            name,
            &pacman_packages,
            tools,
            signers,
        )?);
    }

    let mut plan = plan(out, name, channel, &indexes)?;
    plan.date = options.date;
    plan.url = config.defaults.repository.as_ref().map(|r| r.url.clone());
    plan.rollback = rollback;
    plan.tools = versions;
    plan.releases = listings
        .iter()
        .map(|l| PlanRelease {
            product: l.product.clone(),
            package: l.package.clone(),
            token: l.token.clone(),
            sequence: l.sequence,
        })
        .collect();
    if let Some(previous) = options.previous {
        check_immutables(previous, &plan)?;
    }
    let json = serde_json::to_string_pretty(&plan).map_err(|e| DistError::Layout(e.to_string()))?;
    write_new(&out.join(PLAN_FILE), format!("{json}\n").as_bytes())?;
    Ok(plan)
}

/// The listings must be one channel's releases of every product this
/// `seaworthy.toml` defines, each once, under the names it gives them.
fn check_listings(config: &Config, listings: &[Listing]) -> Result<(), DistError> {
    let mut seen = BTreeSet::new();
    for listing in listings {
        let known = config.products.contains_key(&listing.product)
            || (listing.product == REPOSITORY_ID && config.defaults.repository.is_some());
        if !known || crate::linux::package_name(config, &listing.product) != listing.package {
            return Err(DistError::Layout(format!(
                "{} (product {:?}) isn't a product of this seaworthy.toml under that name",
                listing.package, listing.product
            )));
        }
        if listing.channel != config.defaults.channel {
            return Err(DistError::Layout(format!(
                "{} {} is a release for channel {:?}, not {:?}",
                listing.package, listing.token, listing.channel, config.defaults.channel
            )));
        }
        if !seen.insert(listing.product.as_str()) {
            return Err(DistError::Layout(format!(
                "{} is listed twice: the repositories hold one release of each product",
                listing.package
            )));
        }
        // A publication is a release, and a release is signed: never an
        // unsigned build's packages (unsigned Windows executables, manifests
        // or package signatures missing), however they got here.
        if listing.authenticode_only {
            return Err(DistError::Sign(format!(
                "{} {} is a dev build (Authenticode alone, --authenticode-only): the repositories publish signed releases only",
                listing.package, listing.token
            )));
        }
        if listing.ci_test {
            return Err(DistError::Sign(format!(
                "{} {} is signed by the CI test keys (--ci-test-signing): the repositories publish releases only",
                listing.package, listing.token
            )));
        }
        if !listing.signed {
            return Err(DistError::Sign(format!(
                "{} {} was packaged unsigned (no --signing): the repositories publish signed releases only",
                listing.package, listing.token
            )));
        }
        let expected = if listing.build.is_empty() {
            listing.version.clone()
        } else {
            format!("{}+{}", listing.version, listing.build)
        };
        if listing.token != expected {
            return Err(DistError::Layout(format!(
                "{}: the token {:?} isn't version[+build] ({expected:?})",
                listing.package, listing.token
            )));
        }
        if !is_plain_segment(&listing.token) {
            return Err(DistError::Layout(format!(
                "{}: the token {:?} isn't a plain path segment",
                listing.package, listing.token
            )));
        }
    }
    if let Some(missing) = config
        .products
        .keys()
        .find(|id| !seen.contains(id.as_str()))
    {
        return Err(DistError::Layout(format!(
            "no release of product {missing:?}: the indexes list only what they're given, so a product left out would vanish from them"
        )));
    }
    if config.defaults.repository.is_some() {
        let Some(repository) = listings.iter().find(|l| is_repository_package(l)) else {
            return Err(DistError::Layout(format!(
                "no repository package ({}): seaworthy.toml sets [defaults.repository], so `package` builds it and machines install it from setup/",
                crate::linux::package_name(config, REPOSITORY_ID)
            )));
        };
        // One for each repository it sets up: a deb when there's an APT
        // repository, an rpm when there's a DNF one.
        for kind in [Kind::Deb, Kind::Rpm] {
            let products = listings
                .iter()
                .filter(|l| !is_repository_package(l))
                .any(|l| l.artifacts.iter().any(|a| a.kind == kind));
            let packaged = repository.artifacts.iter().any(|a| a.kind == kind);
            if products != packaged {
                let (one, format) = if kind == Kind::Deb {
                    ("a deb", "deb")
                } else {
                    ("an rpm", "rpm")
                };
                let why = if packaged {
                    format!("has {one}, but no product has one")
                } else {
                    format!("has no {format}, but the products have one")
                };
                return Err(DistError::Layout(format!(
                    "{} {}: {why}: package it with the products' seaworthy.toml",
                    repository.package, repository.token,
                )));
            }
        }
    }
    Ok(())
}

/// The repository package's listing (`package`'s product id
/// `repository`; [`check_listings`] accepts it only with
/// `[defaults.repository]`).
fn is_repository_package(listing: &Listing) -> bool {
    listing.product == REPOSITORY_ID
}

/// A path segment with nothing a URL or a filesystem treats specially.
fn is_plain_segment(text: &str) -> bool {
    !text.is_empty()
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
}

/// Before anything is written: each installable artifact is for its own
/// target and has its signed manifest beside it — none when seaworthy.toml signs
/// no manifests — a pacman package its detached signature too, and
/// there is one.
fn check_shape(config: &Config, listing: &Listing) -> Result<(), DistError> {
    let mut installable = 0;
    let mut kinds: Vec<Kind> = Vec::new();
    for artifact in &listing.artifacts {
        let Some(format) = artifact.kind.artifact_format() else {
            continue;
        };
        installable += 1;
        let named =
            |why: &str| DistError::Sign(format!("{}: {why}", artifact.path(listing).display()));
        if is_repository_package(listing)
            && (!matches!(artifact.kind, Kind::Deb | Kind::Rpm) || kinds.contains(&artifact.kind))
        {
            return Err(DistError::Layout(format!(
                "{}: the repository package is one deb and one rpm at most",
                artifact.path(listing).display()
            )));
        }
        kinds.push(artifact.kind);
        if artifact.target != artifact.kind.target() {
            return Err(named(&format!(
                "listed for {}, but a {} is for {}",
                artifact.target,
                format.tag(),
                artifact.kind.target()
            )));
        }
        let manifest = listing.companion(artifact, ".manifest", Kind::Manifest);
        if config.signs_manifests() && manifest.is_none() {
            return Err(named(
                "no signed release manifest beside it (package with --signing)",
            ));
        }
        if !config.signs_manifests() && manifest.is_some() {
            return Err(named(
                "a release manifest beside it, but seaworthy.toml signs none (defaults.release-signatures is empty): repackage it with this seaworthy.toml",
            ));
        }
        if artifact.kind == Kind::Pacman
            && listing
                .companion(artifact, ".sig", Kind::Signature)
                .is_none()
        {
            return Err(named(
                "no detached signature beside it (package with an [openpgp] signer)",
            ));
        }
    }
    if installable == 0 {
        return Err(DistError::Layout(format!(
            "{} {}: nothing installable to publish",
            listing.package, listing.token
        )));
    }
    Ok(())
}

/// The last publication (`previous`) is this repository's, and older.
fn check_previous(
    config: &Config,
    name: &str,
    previous: &Plan,
    date: u64,
) -> Result<(), DistError> {
    if previous.repository != name || previous.channel != config.defaults.channel {
        return Err(DistError::Layout(format!(
            "the previous plan publishes {}'s {} channel, not {name}'s {}",
            previous.repository, previous.channel, config.defaults.channel
        )));
    }
    if date <= previous.date {
        return Err(DistError::Layout(format!(
            "the indexes' date {date} isn't after the last publication's ({}): apt keeps the Release it holds when a new one is older",
            previous.date
        )));
    }
    Ok(())
}

/// A published release's (version, sequence): its token's version (the
/// part before `+`) with its sequence, ordered as every client orders
/// releases ([`Release`]: the version first, then the sequence).
///
/// # Errors
/// [`DistError::Layout`] for a token whose version doesn't parse: an
/// unreadable published release is never taken for an older one.
pub fn published_release(release: &PlanRelease) -> Result<Release, DistError> {
    let version = release
        .token
        .split_once('+')
        .map_or(release.token.as_str(), |(version, _)| version);
    Release::new(version, release.sequence).map_err(|e| {
        DistError::Layout(format!(
            "the published {} {} (sequence {}) names no release this seaworthy orders: {e}",
            release.package, release.token, release.sequence
        ))
    })
}

/// Whether a release is older than the last publication's of the same
/// product, ordered as the clients order releases — (version, sequence),
/// the version first ([`Release`]): refused unless `allow_older` (a
/// deliberate rollback), since a pipeline running out of order, or a
/// maintenance release of an older line cut after a newer one (1.2.1 after
/// 1.3.0, with the higher sequence), would otherwise roll the
/// repositories back: apt, dnf and pacman would offer it as the latest.
fn check_older(
    listings: &[Listing],
    previous: &Plan,
    allow_older: bool,
) -> Result<bool, DistError> {
    let mut older = Vec::new();
    for listing in listings {
        let ours = Release::new(&listing.version, listing.sequence)?;
        for published in previous
            .releases
            .iter()
            .filter(|r| r.product == listing.product)
        {
            if published_release(published)? > ours {
                older.push(format!(
                    "{} {} (sequence {}) is older than the published {} (sequence {})",
                    listing.package,
                    listing.token,
                    listing.sequence,
                    published.token,
                    published.sequence
                ));
            }
        }
    }
    if older.is_empty() {
        return Ok(false);
    }
    if !allow_older {
        return Err(DistError::Layout(format!(
            "{}: releases are ordered by version, then sequence, as clients order them; publishing an older one rolls the repositories back (to roll back on purpose, repo --allow-older)",
            older.join("; ")
        )));
    }
    Ok(true)
}

/// No path the last publication marked immutable gets other bytes, and no
/// path changes class.
fn check_immutables(previous: &Plan, plan: &Plan) -> Result<(), DistError> {
    let before: BTreeMap<&str, &PlanEntry> = previous
        .files
        .iter()
        .map(|f| (f.path.as_str(), f))
        .collect();
    let changed: Vec<&str> = plan
        .files
        .iter()
        .filter(|f| {
            before.get(f.path.as_str()).is_some_and(|old| {
                old.class != f.class || (f.class == Class::Immutable && old.sha256 != f.sha256)
            })
        })
        .map(|f| f.path.as_str())
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    let shown: Vec<&str> = changed.iter().copied().take(5).collect();
    Err(DistError::Layout(format!(
        "{} published immutable file(s) would get other bytes: {}{} — immutable files are cached for a year, so a path is published once: a version token packaged again (a retried pipeline) needs other build metadata, or publish the packages already published",
        changed.len(),
        shown.join(", "),
        if changed.len() > shown.len() {
            ", …"
        } else {
            ""
        }
    )))
}

/// Where installable `artifact` is published (`None`: it isn't): a
/// product's in the release tree, the repository package's in `setup/`
/// under its stable name.
fn release_path(out: &Path, listing: &Listing, artifact: &ListedArtifact) -> Option<PathBuf> {
    let format = artifact.kind.artifact_format()?;
    if is_repository_package(listing) {
        return Some(setup_path(out, listing, format.tag()));
    }
    Some(
        out.join("releases")
            .join(&listing.package)
            .join(&listing.channel)
            .join(&listing.token)
            .join(&artifact.target)
            .join(format!("{}.{}", listing.package, format.tag())),
    )
}

/// `setup/<package>.<extension>`: the repository package's stable name.
fn setup_path(out: &Path, listing: &Listing, extension: &str) -> PathBuf {
    out.join("setup")
        .join(format!("{}.{extension}", listing.package))
}

/// `path` with `suffix` appended to its file name.
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// `releases/<package>/<channel>/<token>/<target>/<package>.<format>`,
/// with its manifest, SBOM and (pacman) signature: the listed bytes, read
/// once ([`ListedArtifact::read`]). Every check and every repository works
/// from these copies.
fn releases(listings: &[Listing], out: &Path) -> Result<(), DistError> {
    for listing in listings {
        for artifact in &listing.artifacts {
            let Some(target) = release_path(out, listing, artifact) else {
                continue;
            };
            write_new(&target, &artifact.read(listing)?)?;
            if is_repository_package(listing) {
                // Its manifest and SBOM aren't published: nothing fetches
                // them (check_release reads the manifest from the listing).
                continue;
            }
            for (suffix, kind) in COMPANIONS {
                if let Some(companion) = listing.companion(artifact, suffix, kind) {
                    write_new(&suffixed(&target, suffix), &companion.read(listing)?)?;
                }
            }
        }
    }
    Ok(())
}

/// Reads one of this run's own copies, checked against the listing again.
fn read_copy(path: &Path, listed: &ListedArtifact) -> Result<Vec<u8>, DistError> {
    let bytes = read_regular(path, listed.limit())?;
    listed.check(path, &bytes)?;
    Ok(bytes)
}

/// Refuses a release a client would refuse, checking the published
/// copies: an installable artifact whose signed manifest doesn't name
/// exactly it, an rpm no pinned key signed, a pacman package whose
/// detached signature no pinned key made.
fn check_release(
    config: &Config,
    pins: &Pins,
    listing: &Listing,
    out: &Path,
) -> Result<(), DistError> {
    let release = Release::new(&listing.version, listing.sequence)?;
    let build = BuildId {
        metadata: listing.build.clone(),
    };
    for artifact in &listing.artifacts {
        let (Some(format), Some(path)) = (
            artifact.kind.artifact_format(),
            release_path(out, listing, artifact),
        ) else {
            continue;
        };
        let named = |why: String| DistError::Sign(format!("{}: {why}", artifact.file));
        // Read (and hash-checked against the listing) either way: the
        // signatures below are checked on this copy.
        let bytes = read_copy(&path, artifact)?;
        let companion = |suffix: &str, kind: Kind| {
            listing
                .companion(artifact, suffix, kind)
                .ok_or_else(|| named(format!("no {suffix} beside it")))
                .map(|listed| (suffixed(&path, suffix), listed))
        };
        // Without release manifests the package managers' own
        // signatures below are what clients check.
        if config.signs_manifests() {
            let expected = crate::sign::manifest_for_bytes(
                config,
                &listing.product,
                &release,
                &build,
                &artifact.target,
                format,
                &bytes,
            )?;
            let (manifest_path, manifest) = companion(".manifest", Kind::Manifest)?;
            let signed = if is_repository_package(listing) {
                manifest.read(listing)?
            } else {
                read_copy(&manifest_path, manifest)?
            };
            crate::sign::check_manifest(config, &signed, &expected).map_err(|e| match e {
                DistError::Sign(why) => named(format!("its manifest: {why}")),
                other => other,
            })?;
        }
        match artifact.kind {
            Kind::Rpm => pins.check_rpm(&path)?,
            Kind::Pacman => {
                let (signature, listed) = companion(".sig", Kind::Signature)?;
                read_copy(&signature, listed)?;
                pins.check_detached(&signature, &path)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// The one architecture of a format's packages.
fn single_arch(
    packages: &[(&Listing, &ListedArtifact)],
    pick: fn(&Arch) -> &'static str,
    format: &str,
) -> Result<&'static str, DistError> {
    let mut architectures = BTreeSet::new();
    for (_, package) in packages {
        architectures.insert(pick(&arch(&package.target)?));
    }
    match architectures.iter().collect::<Vec<_>>().as_slice() {
        [one] => Ok(one),
        _ => Err(DistError::Layout(format!(
            "the {format} packages are for {architectures:?}: a repository holds one architecture"
        ))),
    }
}

/// Copies a package from the release tree to `to`, checked against the
/// listing on the way.
fn copy_release(
    out: &Path,
    listing: &Listing,
    artifact: &ListedArtifact,
    to: &Path,
) -> Result<(), DistError> {
    let from = release_path(out, listing, artifact)
        .ok_or_else(|| DistError::Layout(format!("{} isn't published", artifact.file)))?;
    write_new(to, &read_copy(&from, artifact)?)
}

/// The APT repository; returns its index files, in upload order.
fn apt(
    out: &Path,
    channel: &str,
    name: &str,
    debs: &[(&Listing, &ListedArtifact)],
    tools: &Tools,
    signers: &Signers<'_>,
    date: u64,
) -> Result<Vec<PathBuf>, DistError> {
    let architecture = single_arch(debs, |a| a.deb, "deb")?;
    let root = out.join("apt");
    let pool = |listing: &Listing, deb: &ListedArtifact| {
        format!("pool/main/{}/{}", listing.package, deb.file_name())
    };
    for (listing, deb) in debs {
        copy_release(out, listing, deb, &root.join(pool(listing, deb)))?;
    }
    let mut command = crate::process::tool(&tools.dpkg_scanpackages);
    command
        .current_dir(&root)
        .args(["--hash", "sha256", "pool"]);
    let finished = crate::process::run(
        &mut command,
        "dpkg-scanpackages",
        None,
        tools.timeout,
        64 * 1024 * 1024,
    )?;
    if !finished.status.success() || finished.stdout_overflow {
        return Err(DistError::Tool(format!(
            "dpkg-scanpackages failed: {}",
            finished.shown()
        )));
    }
    let packages = finished.stdout;
    // One stanza per package given, naming exactly the listed file: a deb
    // the tool skipped, one it found that isn't ours, or one with other
    // bytes fails here.
    let text = String::from_utf8_lossy(&packages);
    let stanzas: Vec<BTreeMap<&str, &str>> = text
        .split("\n\n")
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.lines().filter_map(|l| l.split_once(": ")).collect())
        .collect();
    let mut found: Vec<&str> = stanzas
        .iter()
        .filter_map(|s| s.get("Package").copied())
        .collect();
    let mut expected: Vec<&str> = debs.iter().map(|(l, _)| l.package.as_str()).collect();
    found.sort_unstable();
    expected.sort_unstable();
    if found != expected {
        return Err(DistError::Tool(format!(
            "dpkg-scanpackages listed {found:?}, not the packages given ({expected:?})"
        )));
    }
    for (listing, deb) in debs {
        let filename = pool(listing, deb);
        let described = stanzas
            .iter()
            .find(|s| s.get("Package") == Some(&listing.package.as_str()))
            .map(|s| {
                (
                    s.get("Filename").copied().unwrap_or(""),
                    s.get("SHA256").copied().unwrap_or(""),
                )
            });
        if described != Some((filename.as_str(), deb.sha256.as_str())) {
            return Err(DistError::Tool(format!(
                "dpkg-scanpackages describes {} as {described:?}, not the listed {filename} ({})",
                listing.package, deb.sha256
            )));
        }
    }
    let component = format!("main/binary-{architecture}");
    let dists = root.join("dists").join(channel);
    let index_dir = dists.join(&component);
    let gz = gzip(&packages);
    let mut release = format!(
        "Origin: {name}\nLabel: {name}\nSuite: {channel}\nCodename: {channel}\nDate: {}\n\
         Architectures: {architecture}\nComponents: main\nAcquire-By-Hash: yes\nSHA256:\n",
        rfc2822(date)
    );
    let mut indexes = Vec::new();
    for (file, bytes) in [("Packages", &packages), ("Packages.gz", &gz)] {
        let hash = seaworthy_crypto::digest::sha256_hex(bytes);
        write_new(&index_dir.join("by-hash/SHA256").join(&hash), bytes)?;
        write_new(&index_dir.join(file), bytes)?;
        release.push_str(&format!(" {hash} {:>16} {component}/{file}\n", bytes.len()));
        indexes.push(index_dir.join(file));
    }
    let release_path = dists.join("Release");
    let detached = dists.join("Release.gpg");
    let inline = dists.join("InRelease");
    write_new(&release_path, release.as_bytes())?;
    signers
        .openpgp
        .armored_detach_sign(&release_path, &detached)?;
    signers.openpgp.clear_sign(&release_path, &inline)?;
    signers.pins.check_detached(&detached, &release_path)?;
    if signers.pins.check_clearsigned(&inline)? != release.as_bytes() {
        return Err(DistError::Sign(format!(
            "{} signs something other than Release",
            inline.display()
        )));
    }
    indexes.extend([release_path, detached, inline]);
    Ok(indexes)
}

/// The DNF repository; returns its index files, in upload order.
fn dnf(
    out: &Path,
    channel: &str,
    rpms: &[(&Listing, &ListedArtifact)],
    tools: &Tools,
    signers: &Signers<'_>,
    date: u64,
) -> Result<Vec<PathBuf>, DistError> {
    let architecture = single_arch(rpms, |a| a.rpm, "rpm")?;
    let root = out.join("rpm").join(channel).join(architecture);
    for (listing, rpm) in rpms {
        copy_release(
            out,
            listing,
            rpm,
            &root.join("Packages").join(rpm.file_name()),
        )?;
    }
    let mut command = crate::process::tool(&tools.createrepo_c);
    command
        .current_dir(out)
        .args([
            "--quiet",
            "--no-database",
            "--general-compress-type=gz",
            "--revision",
        ])
        .arg(date.to_string())
        .arg("--set-timestamp-to-revision")
        .arg(&root);
    run_ok(&mut command, "createrepo_c", tools.timeout)?;
    let repomd = root.join("repodata/repomd.xml");
    let text = std::fs::read_to_string(&repomd).map_err(|e| DistError::io(&repomd, e))?;
    if !text.contains("<data type=\"primary\">") {
        return Err(DistError::Tool(format!(
            "createrepo_c wrote {} without primary metadata",
            repomd.display()
        )));
    }
    let signature = root.join("repodata/repomd.xml.asc");
    signers.openpgp.armored_detach_sign(&repomd, &signature)?;
    signers.pins.check_detached(&signature, &repomd)?;
    Ok(vec![repomd, signature])
}

/// The pacman repository; returns its index files, in upload order.
fn pacman(
    out: &Path,
    channel: &str,
    name: &str,
    packages: &[(&Listing, &ListedArtifact)],
    tools: &Tools,
    signers: &Signers<'_>,
) -> Result<Vec<PathBuf>, DistError> {
    let architecture = single_arch(packages, |a| a.pacman, "pacman")?;
    let root = out.join("pacman").join(channel).join(architecture);
    let mut files = Vec::new();
    for (listing, package) in packages {
        let file = package.file_name();
        copy_release(out, listing, package, &root.join(file))?;
        // Beside the package, where pacman fetches it (check_shape
        // required it, check_release checked it).
        if let (Some(signature), Some(published)) = (
            listing.companion(package, ".sig", Kind::Signature),
            release_path(out, listing, package),
        ) {
            write_new(
                &root.join(format!("{file}.sig")),
                &read_copy(&suffixed(&published, ".sig"), signature)?,
            )?;
        }
        files.push(file.to_owned());
    }
    let database = format!("{name}.db.tar.zst");
    // Absolute paths: a word starting with `/` is never an option, in any
    // repo-add. `--` would not do: repo-add's implementations (pacman's
    // shell script across releases, distributions' rewrites) don't agree
    // on ending the options with it. The names are the vendor's and the
    // packages' anyway, which never start with `-`.
    let mut command = crate::process::tool(&tools.repo_add);
    command
        .current_dir(&root)
        .args(["--quiet", "--nocolor"])
        .arg(root.join(&database))
        .args(files.iter().map(|file| root.join(file)));
    run_ok(&mut command, "repo-add", tools.timeout)?;
    let mut indexes = Vec::new();
    // The files database before the one `pacman -Sy` reads.
    for (archive, alias) in [
        (format!("{name}.files.tar.zst"), format!("{name}.files")),
        (database.clone(), format!("{name}.db")),
    ] {
        let archive_path = root.join(&archive);
        let alias_path = root.join(&alias);
        let bytes = std::fs::read(&archive_path).map_err(|e| DistError::io(&archive_path, e))?;
        // repo-add links the alias; object storage has no links: the same
        // bytes.
        match std::fs::symlink_metadata(&alias_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                std::fs::remove_file(&alias_path).map_err(|e| DistError::io(&alias_path, e))?;
            }
            Ok(_) => {
                return Err(DistError::Tool(format!(
                    "repo-add left {} as a file, not a link to {archive}",
                    alias_path.display()
                )));
            }
            Err(e) => return Err(DistError::io(&alias_path, e)),
        }
        write_new(&alias_path, &bytes)?;
        let archive_sig = root.join(format!("{archive}.sig"));
        signers.openpgp.detach_sign(&archive_path, &archive_sig)?;
        signers.pins.check_detached(&archive_sig, &archive_path)?;
        let alias_sig = root.join(format!("{alias}.sig"));
        copy(&archive_sig, &alias_sig)?;
        indexes.extend([archive_path, archive_sig, alias_path, alias_sig]);
    }
    Ok(indexes)
}

/// `keys/<repo>.asc`: the OpenPGP public keys `seaworthy.toml` pins, every one
/// the repositories' signatures may come from (a rotation lists two).
fn key_file(config: &Config, out: &Path, name: &str) -> Result<PathBuf, DistError> {
    let keys = crate::repository_package::pinned_keys(config)?;
    let path = out.join("keys").join(format!("{name}.asc"));
    write_new(&path, keys.as_bytes())?;
    Ok(path)
}

/// The most of a repository package's payload read back: it holds two
/// small text files.
const MAX_REPOSITORY_PAYLOAD: usize = 16 * 1024 * 1024;

/// The repository package's copies in `setup/` install exactly what this
/// `seaworthy.toml` sets machines up with
/// ([`crate::repository_package::contents`]): those files, byte for byte,
/// and nothing else — no other file, and in the deb no maintainer script
/// and exactly the expected conffiles — read back with `dpkg-deb` and
/// `bsdtar`. Its signed manifest binds its bytes, not what they configure:
/// a package built from another `seaworthy.toml` (another URL, channel or set of
/// pinned keys), or left from an earlier run, would set every machine up
/// for repositories this publication isn't, or without the key it's about
/// to be signed with.
fn check_repository_contents(
    config: &Config,
    out: &Path,
    listing: &Listing,
    tools: &Tools,
) -> Result<(), DistError> {
    for artifact in &listing.artifacts {
        let (format, Some(path)) = (
            match artifact.kind {
                Kind::Deb => crate::config::Output::Deb,
                Kind::Rpm => crate::config::Output::Rpm,
                _ => continue,
            },
            release_path(out, listing, artifact),
        ) else {
            continue;
        };
        let expected = crate::repository_package::contents(config, format)?;
        let refused = |why: String| {
            DistError::Layout(format!(
                "setup/{}: the repository package doesn't set machines up as this seaworthy.toml does: {why} (package it again with this seaworthy.toml: [defaults.repository], the channel and openpgp-keys)",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ))
        };
        let payload = if format == crate::config::Output::Deb {
            let control = Archive::Bytes(read_tool(
                tools,
                &tools.dpkg_deb,
                "dpkg-deb",
                &[OsStr::new("--ctrl-tarfile"), path.as_os_str()],
                None,
            )?);
            let mut members = control.files(tools)?;
            members.sort();
            if members != ["conffiles", "control", "md5sums"] {
                return Err(refused(format!(
                    "its control archive holds {members:?}, not exactly conffiles, control and md5sums (no maintainer scripts)"
                )));
            }
            let conffiles = control.read(tools, "conffiles")?;
            let wanted: String = expected
                .config_files
                .iter()
                .map(|f| format!("{f}\n"))
                .collect();
            if conffiles != wanted.as_bytes() {
                return Err(refused(format!(
                    "its conffiles are {:?}, not {wanted:?}",
                    String::from_utf8_lossy(&conffiles)
                )));
            }
            Archive::Bytes(read_tool(
                tools,
                &tools.dpkg_deb,
                "dpkg-deb",
                &[OsStr::new("--fsys-tarfile"), path.as_os_str()],
                None,
            )?)
        } else {
            Archive::File(path.clone())
        };
        let mut files = payload.files(tools)?;
        files.sort();
        let mut wanted: Vec<String> = expected
            .package
            .files
            .iter()
            .map(|f| f.dst.trim_start_matches('/').to_owned())
            .collect();
        wanted.sort();
        if files != wanted {
            return Err(refused(format!(
                "it installs {files:?}, not exactly {wanted:?}"
            )));
        }
        for file in &expected.package.files {
            let crate::linux::Source::Generated(text) = &file.source else {
                continue;
            };
            if payload.read(tools, file.dst.trim_start_matches('/'))? != text.as_bytes() {
                return Err(refused(format!("{} differs", file.dst)));
            }
        }
    }
    Ok(())
}

/// An archive `bsdtar` reads: a file, or bytes on its standard input.
enum Archive {
    File(PathBuf),
    Bytes(Vec<u8>),
}

impl Archive {
    fn source(&self) -> (OsString, Option<Vec<u8>>) {
        match self {
            Self::File(path) => (path.as_os_str().to_owned(), None),
            Self::Bytes(bytes) => (OsString::from("-"), Some(bytes.clone())),
        }
    }

    /// Every member that isn't a directory, as a path relative to the root
    /// (`./` or `/` stripped).
    fn files(&self, tools: &Tools) -> Result<Vec<String>, DistError> {
        let (source, stdin) = self.source();
        let listed = read_tool(
            tools,
            &tools.bsdtar,
            "bsdtar",
            &[OsStr::new("-tf"), &source],
            stdin,
        )?;
        Ok(String::from_utf8_lossy(&listed)
            .lines()
            .filter(|l| !l.is_empty() && !l.ends_with('/'))
            .map(|l| member_path(l).to_owned())
            .collect())
    }

    /// The bytes of member `path` (relative to the root, however the
    /// archive spells it).
    fn read(&self, tools: &Tools, path: &str) -> Result<Vec<u8>, DistError> {
        let (source, stdin) = self.source();
        let listed = read_tool(
            tools,
            &tools.bsdtar,
            "bsdtar",
            &[OsStr::new("-tf"), &source],
            stdin.clone(),
        )?;
        let text = String::from_utf8_lossy(&listed);
        let Some(name) = text.lines().find(|l| member_path(l) == path) else {
            return Err(DistError::Tool(format!(
                "bsdtar lists no {path} in {}",
                source.to_string_lossy()
            )));
        };
        read_tool(
            tools,
            &tools.bsdtar,
            "bsdtar",
            &[OsStr::new("-xOf"), &source, OsStr::new(name)],
            stdin,
        )
    }
}

/// An archive member's path relative to the root.
fn member_path(name: &str) -> &str {
    name.trim_start_matches("./").trim_start_matches('/')
}

/// `tool args` (with `stdin`), which must succeed within the deadline and
/// print at most [`MAX_REPOSITORY_PAYLOAD`]; its stdout.
fn read_tool(
    tools: &Tools,
    tool: &Path,
    what: &str,
    args: &[&OsStr],
    stdin: Option<Vec<u8>>,
) -> Result<Vec<u8>, DistError> {
    let mut command = crate::process::tool(tool);
    command.args(args);
    let finished = crate::process::run(
        &mut command,
        what,
        stdin,
        tools.timeout,
        MAX_REPOSITORY_PAYLOAD,
    )?;
    if !finished.status.success() || finished.stdout_overflow {
        return Err(DistError::Tool(format!(
            "{what} failed: {}",
            finished.shown()
        )));
    }
    Ok(finished.stdout)
}

/// The repository package's `setup/` files, in upload order: the deb and
/// its detached armored signature (made by the indexes' signer, checked
/// against the pins), the rpm (signed itself; `check_release` checked it).
fn setup(
    out: &Path,
    listings: &[Listing],
    signers: &Signers<'_>,
) -> Result<Vec<PathBuf>, DistError> {
    let mut indexes = Vec::new();
    let Some(listing) = listings.iter().find(|l| is_repository_package(l)) else {
        return Ok(indexes);
    };
    for kind in [Kind::Deb, Kind::Rpm] {
        let Some(artifact) = listing.artifacts.iter().find(|a| a.kind == kind) else {
            continue;
        };
        let path = release_path(out, listing, artifact)
            .ok_or_else(|| DistError::Layout(format!("{} isn't published", artifact.file)))?;
        read_copy(&path, artifact)?;
        indexes.push(path.clone());
        if kind == Kind::Deb {
            let signature = suffixed(&path, ".asc");
            signers.openpgp.armored_detach_sign(&path, &signature)?;
            signers.pins.check_detached(&signature, &path)?;
            indexes.push(signature);
        }
    }
    Ok(indexes)
}

/// Every file under `out`: the immutable ones (sorted by path), then
/// `indexes` in their order.
fn plan(out: &Path, name: &str, channel: &str, indexes: &[PathBuf]) -> Result<Plan, DistError> {
    let mut all = Vec::new();
    walk(out, &mut all)?;
    all.sort();
    let relative = |path: &Path| -> Result<String, DistError> {
        let rel = path
            .strip_prefix(out)
            .map_err(|_| DistError::Layout(format!("{} is outside the output", path.display())))?;
        Ok(rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"))
    };
    let entry = |path: &Path, class: Class| -> Result<PlanEntry, DistError> {
        let bytes = std::fs::read(path).map_err(|e| DistError::io(path, e))?;
        Ok(PlanEntry {
            path: relative(path)?,
            sha256: seaworthy_crypto::digest::sha256_hex(&bytes),
            size: bytes.len() as u64,
            class,
        })
    };
    let index_set: BTreeSet<&Path> = indexes.iter().map(PathBuf::as_path).collect();
    if index_set.len() != indexes.len() || indexes.iter().any(|i| !all.contains(i)) {
        return Err(DistError::Layout(
            "an index named twice, or one that wasn't written".to_owned(),
        ));
    }
    let mut files = Vec::with_capacity(all.len());
    for path in all.iter().filter(|p| !index_set.contains(p.as_path())) {
        files.push(entry(path, Class::Immutable)?);
    }
    for path in indexes {
        files.push(entry(path, Class::Index)?);
    }
    Ok(Plan {
        repository: name.to_owned(),
        channel: channel.to_owned(),
        url: None,
        rollback: false,
        date: 0,
        releases: Vec::new(),
        tools: BTreeMap::new(),
        files,
    })
}

/// Every regular file under `dir`; anything else (a link a tool left) is
/// refused: object storage has none.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), DistError> {
    for entry in std::fs::read_dir(dir).map_err(|e| DistError::io(dir, e))? {
        let entry = entry.map_err(|e| DistError::io(dir, e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| DistError::io(&path, e))?;
        if kind.is_dir() {
            walk(&path, out)?;
        } else if kind.is_file() {
            out.push(path);
        } else {
            return Err(DistError::Layout(format!(
                "{} is neither a file nor a directory (object storage has no links)",
                path.display()
            )));
        }
    }
    Ok(())
}

/// The first line `tool --version` prints, run in `dir` (the output: a
/// tool never writes where the caller stands).
fn tool_version(
    tool: &Path,
    what: &str,
    dir: &Path,
    timeout: Duration,
) -> Result<String, DistError> {
    let mut command = crate::process::tool(tool);
    command.current_dir(dir).arg("--version");
    let finished = crate::process::run(&mut command, what, None, timeout, 64 * 1024)?;
    let text = String::from_utf8_lossy(&finished.stdout);
    match text.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(line) if finished.status.success() => Ok(line.to_owned()),
        _ => Err(DistError::Tool(format!(
            "{what} --version failed: {}",
            finished.shown()
        ))),
    }
}

fn run_ok(command: &mut Command, what: &str, timeout: Duration) -> Result<(), DistError> {
    let finished = crate::process::run(command, what, None, timeout, 1024 * 1024)?;
    if finished.status.success() {
        Ok(())
    } else {
        Err(DistError::Tool(format!(
            "{what} failed: {}",
            finished.shown()
        )))
    }
}

/// A regular file's bytes, the last component never followed if it's a
/// link, at most `limit` of them.
fn read_regular(path: &Path, limit: Option<u64>) -> Result<Vec<u8>, DistError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| DistError::io(path, e))?;
    let meta = file.metadata().map_err(|e| DistError::io(path, e))?;
    if !meta.is_file() {
        return Err(DistError::Layout(format!(
            "{} isn't a regular file",
            path.display()
        )));
    }
    let limit = limit.unwrap_or(u64::MAX);
    let too_large = || {
        DistError::Layout(format!(
            "{} is larger than the update helper accepts ({limit} bytes)",
            path.display()
        ))
    };
    if meta.len() > limit {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| DistError::io(path, e))?;
    // It grew since: still refused.
    if bytes.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(bytes)
}

fn copy(from: &Path, to: &Path) -> Result<(), DistError> {
    let bytes = std::fs::read(from).map_err(|e| DistError::io(from, e))?;
    write_new(to, &bytes)
}

/// Writes a new file: two inputs that would land on one path are an
/// error, never one silently replacing the other.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), DistError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DistError::io(parent, e))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| DistError::io(path, e))?;
    file.write_all(bytes).map_err(|e| DistError::io(path, e))
}

/// gzip with no name and no timestamp: the same bytes for the same input.
#[must_use]
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 3];
    out.extend(miniz_oxide::deflate::compress_to_vec(data, 9));
    out.extend(crate::archive::crc32(data).to_le_bytes());
    // ISIZE: the length modulo 2^32 (RFC 1952).
    out.extend(((data.len() as u64 & 0xffff_ffff) as u32).to_le_bytes());
    out
}

/// `Tue, 14 Oct 2025 00:00:00 UTC`: the date format APT's `Release` uses
/// (RFC 2822, always UTC).
#[must_use]
pub fn rfc2822(epoch: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = epoch / 86_400;
    let seconds = epoch % 86_400;
    // Howard Hinnant's days-to-civil, on unsigned days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} UTC",
        DAYS[(days % 7) as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_apts_format() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 UTC");
        assert_eq!(rfc2822(1_760_400_000), "Tue, 14 Oct 2025 00:00:00 UTC");
        assert_eq!(rfc2822(951_782_400), "Tue, 29 Feb 2000 00:00:00 UTC");
        assert_eq!(rfc2822(951_868_800), "Wed, 01 Mar 2000 00:00:00 UTC");
        assert_eq!(rfc2822(4_102_444_799), "Thu, 31 Dec 2099 23:59:59 UTC");
        assert_eq!(rfc2822(4_294_967_295), "Sun, 07 Feb 2106 06:28:15 UTC");
    }

    #[test]
    fn gzip_is_deterministic_and_readable() {
        let data = b"Package: acme-agent\nVersion: 1.0.0-1\n".repeat(50);
        let a = gzip(&data);
        assert_eq!(a, gzip(&data));
        assert_eq!(&a[..4], &[0x1f, 0x8b, 8, 0]);
        let inflated = miniz_oxide::inflate::decompress_to_vec(&a[10..a.len() - 8]).unwrap();
        assert_eq!(inflated, data);
        assert_eq!(&a[a.len() - 4..], &(data.len() as u32).to_le_bytes());
        assert_eq!(
            &a[a.len() - 8..a.len() - 4],
            &crate::archive::crc32(&data).to_le_bytes()
        );
    }

    #[test]
    fn gzip_records_the_length_past_16_bits() {
        let data = vec![b'p'; 70_000];
        let a = gzip(&data);
        assert_eq!(&a[a.len() - 4..], &70_000_u32.to_le_bytes());
        let inflated = miniz_oxide::inflate::decompress_to_vec(&a[10..a.len() - 8]).unwrap();
        assert_eq!(inflated.len(), 70_000);
    }

    #[test]
    fn plain_segments() {
        for ok in [
            "acme-agent",
            "1.4.0+abc123",
            "x86_64-unknown-linux-gnu",
            "1.0_rc",
        ] {
            assert!(is_plain_segment(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "a%2f", "a\\b", "a?b", "a#b"] {
            assert!(!is_plain_segment(bad), "{bad:?}");
        }
    }
}
