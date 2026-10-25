//! # seaworthy-updater: verified updates for applications shipped with seaworthy
//!
//! When an app's server requires another version, that version becomes an
//! installed package, and no app writes its own binaries. Native only.
//!
//! - **The app side** ([`UpdateRequester`], always available): when the
//!   product's server rejects this version, read the machine's update
//!   policy ([`read_policy`]) and, under `auto`, ask the update helper to
//!   run. Asking carries nothing.
//! - **The helper** (`helper`, feature `helper`): a per-product binary
//!   running as root (LocalSystem on Windows) that learns the server's
//!   version itself (a caller-supplied version source), verifies the signed
//!   release manifest ([`ManifestTrust`]) and the package, applies the
//!   version floor ([`release`]), and hands the exact file to the OS
//!   package manager (`installer`, feature `installers`).
//! - **A desktop app around its own update** (`relaunch`, feature
//!   `relaunch`): the release installed now, and the app back once the
//!   helper has installed another (a watcher that restarts it on Windows,
//!   a restart offer on Linux).
//! - **What both sides agree on** comes from one place, `seaworthy-formats`,
//!   re-exported here: the product's names ([`Product`], read from the
//!   `seaworthy.toml` the seaworthy CLI packages with) and the manifest
//!   format ([`ReleaseManifest`]).
//!
//! The seaworthy CLI shares the bounded process runner ([`process`]) and
//! the OpenPGP checks ([`openpgp`]).
//!
//! ## The security boundary
//!
//! The helper installs only a release the product's server named, signed
//! by a key compiled into the helper, naming this product, channel, exact
//! build, target and package format, newer than the installed release,
//! downloaded to its exact size and digest into a root-only directory, of
//! the right format, and (for rpm and pacman, with pinned keys) carrying its
//! own OpenPGP signature from a pinned key. Every download is https-or-
//! loopback, redirect-refusing unless allowlisted, and bounded in size and
//! time. The machine's administrator decides whether it runs at all.
//!
//! ## Order at boot
//!
//! `seaworthy-crypto`'s TLS policy and algorithm policy are install-once
//! process globals. A process that installs either
//! (`seaworthy_crypto::tls::install_policy`,
//! `seaworthy_crypto::fips_policy::install_policy`) does so first thing,
//! before it builds a release key ([`ReleaseKey::new`] consults the
//! algorithm policy) or the helper's first download (which builds the TLS
//! configuration).
//!
//! ## Features
//!
//! | Feature | Adds |
//! |---|---|
//! | (none) | the request API, the policy readers, [`process`], [`openpgp`] |
//! | `installers` | `installer`: apt, dnf, pacman, macOS's installer, msiexec |
//! | `helper` | `helper` and its download path, staging, failure memo (implies `installers`) |
//! | `relaunch` | `relaunch` (implies `installers`) |

// The security baseline beyond the workspace lints: no panicking index or
// slice and no `unreachable!` in library code (tests may index). Unsafe
// code exists only in the Windows FFI and two libc calls, each block
// allowed on its own with its invariant.
#![deny(clippy::indexing_slicing, clippy::unreachable)]

#[cfg(feature = "helper")]
pub mod helper;
#[cfg(feature = "installers")]
pub mod installer;
mod log;
#[cfg(feature = "helper")]
mod memo;
#[cfg(feature = "helper")]
mod net;
pub mod openpgp;
#[cfg(not(windows))]
mod pacman_conf;
mod policy;
pub mod process;
#[cfg(feature = "relaunch")]
pub mod relaunch;
mod request;
#[cfg(feature = "helper")]
mod staging;

pub use policy::{
    AdminServer, PolicyDecision, PolicyFile, PolicySource, dpkg_holds, is_machine_server,
    parse_policy_file, parse_policy_settings, read_admin_server, read_policy, versionlock_holds,
};
pub use request::{
    DEFAULT_REQUEST_INTERVAL, RequestError, RequestOutcome, UpdateRequester, request_update,
};
// The contract, re-exported so a caller can use one crate.
pub use seaworthy_formats::{
    ArtifactFormat, DigestAlgorithm, FormatError, KEY_ID_LEN, MAX_ARTIFACT_BYTES,
    MAX_METADATA_BYTES, MAX_SERVER_BYTES, MAX_VERSION_LEN, MSI_RELEASE_VALUE, ManifestSignature,
    ManifestTrust, Product, ProductError, RELEASE_MANIFEST_DOMAIN, ReleaseKey, ReleaseManifest,
    ServiceNames, SignatureAlgorithm, TARGET_TRIPLE, UPDATE_REQUEST_FILE, UpdatePolicy,
    format_check, release, release_key_id, validate_version,
};

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

/// Errors of the release fetch and verification the update helper runs.
/// Nothing is installed after one, and the run's staged files are removed.
#[cfg(feature = "helper")]
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Filesystem or process i/o failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The download failed (connect, TLS, HTTP status, redirect refusal, or
    /// stream error). URL-stripped at construction: the URL may be a
    /// presigned GET carrying credentials in its query string.
    #[error("http error: {0}")]
    Http(reqwest::Error),
    /// The release server answered a redirect to a host outside
    /// [`helper::HelperConfig::allow_redirect_hosts`] (redirects are
    /// refused by default). Carries no URL.
    #[error("redirect refused: the target host is not on the helper's redirect allowlist")]
    RedirectRefused,
    /// The downloaded bytes do not match the authenticated digest.
    #[error("digest mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The authenticated digest (lowercase hex).
        expected: String,
        /// The digest of the bytes actually downloaded (lowercase hex).
        actual: String,
    },
    /// The download's size differs from the signed manifest's exact size
    /// (refused up front on a disagreeing `content-length`, mid-stream past
    /// it, or at the end when short).
    #[error("artifact size mismatch: the manifest says {expected} bytes, got {actual}")]
    SizeMismatch {
        /// The manifest's size.
        expected: u64,
        /// The announced or streamed size.
        actual: u64,
    },
    /// The verified artifact isn't a package of the format its manifest
    /// names (an error page, another format, an empty file).
    #[error("the verified artifact isn't the format its manifest names: {reason}")]
    WrongFormat {
        /// What did not match.
        reason: String,
    },
    /// A blocking task (a package-manager call, a signature check) failed
    /// to run to completion.
    #[error("update task failed: {0}")]
    Task(String),
    /// Resolving a release failed before any artifact download: an invalid
    /// URL or version, or a malformed manifest.
    #[error("failed to resolve release: {0}")]
    Resolve(String),
    /// The artifact (announced, manifested, or streamed) exceeds the size
    /// cap.
    #[error("update artifact exceeds the {limit}-byte size cap")]
    ArtifactTooLarge {
        /// The size cap that was exceeded.
        limit: u64,
    },
    /// An update URL is not TLS-protected (`https`, or `http` to a loopback
    /// host only). Carries a short reason, never the URL.
    #[error("insecure update url: {0}")]
    InsecureUrl(String),
    /// No trusted release key verified the release manifest: a forged or
    /// corrupt manifest, or a release signed only by keys this build does
    /// not trust.
    #[error("release manifest signature verification failed: no trusted release key verified it")]
    SignatureMismatch,
    /// A correctly signed manifest names a different release than this
    /// device asked for: another product, channel, version, or target.
    #[error("release manifest {field} mismatch: expected {expected:?}, got {actual:?}")]
    ManifestMismatch {
        /// `product`, `channel`, `version`, `target`, or `format`.
        field: &'static str,
        /// What this device expected.
        expected: String,
        /// What the (authenticated) manifest says.
        actual: String,
    },
    /// An embedded release public key was refused ([`ReleaseKey::new`]):
    /// wrong shape, degenerate, or not admitted by `seaworthy-crypto`'s
    /// algorithm gate.
    #[error("invalid release public key ({algorithm:?}): {reason}")]
    InvalidReleaseKey {
        /// The algorithm the key was declared under.
        algorithm: SignatureAlgorithm,
        /// What was wrong (never key material).
        reason: String,
    },
    /// A configuration value was refused (an empty key set, a malformed
    /// product or channel id, an invalid manifest field in release tooling).
    #[error("invalid updater configuration: {0}")]
    InvalidConfig(String),
    /// Another holder has the staging directory's lock.
    #[error("an update is already in progress")]
    UpdateInProgress,
}

#[cfg(feature = "helper")]
impl From<FormatError> for UpdateError {
    /// Each refusal of the contract keeps its variant and its meaning.
    fn from(error: FormatError) -> Self {
        match error {
            FormatError::Resolve(why) => Self::Resolve(why),
            FormatError::ArtifactTooLarge { limit } => Self::ArtifactTooLarge { limit },
            FormatError::SignatureMismatch => Self::SignatureMismatch,
            FormatError::ManifestMismatch {
                field,
                expected,
                actual,
            } => Self::ManifestMismatch {
                field,
                expected,
                actual,
            },
            FormatError::InvalidReleaseKey { algorithm, reason } => {
                Self::InvalidReleaseKey { algorithm, reason }
            }
            FormatError::InvalidConfig(why) => Self::InvalidConfig(why),
            FormatError::WrongFormat { reason } => Self::WrongFormat { reason },
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Fuzzing access (feature `fuzzing`)
// ------------------------------------------------------------------------------------------------

/// Doc-hidden, NOT-API access to the crate-private network-input helpers
/// for the repository's fuzz crate. Behind the off-by-default `fuzzing`
/// feature, so no normal build carries it.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod __fuzz {
    /// `net::metadata_url` (the query-preserving manifest/signature URL
    /// derivation).
    ///
    /// # Errors
    /// The derivation's refusal, as text.
    pub fn metadata_url(artifact_url: &str, extension: &str) -> Result<String, String> {
        crate::net::metadata_url(artifact_url, extension).map_err(|e| e.to_string())
    }

    /// `helper::expand_package_url` for a fixed product (`Fuzz`, id
    /// `fuzz`, channel `stable`, format `deb`): the server's version token
    /// reaches the package URL only through it.
    ///
    /// # Errors
    /// The expansion's refusal, as text.
    pub fn expand_package_url(template: &str, version: &str) -> Result<String, String> {
        let product =
            crate::Product::new("Fuzz", "fuzz", "Fuzz", "stable").map_err(|e| e.to_string())?;
        crate::helper::expand_package_url(template, version, &product, crate::ArtifactFormat::Deb)
            .map_err(|e| e.to_string())
    }
}

// ------------------------------------------------------------------------------------------------
// Digests
// ------------------------------------------------------------------------------------------------

/// An incremental digest context under a [`DigestAlgorithm`].
#[cfg(feature = "helper")]
pub(crate) enum DigestStream {
    Sha256(seaworthy_crypto::digest::Sha256),
    Sha512(seaworthy_crypto::digest::Sha512),
}

#[cfg(feature = "helper")]
impl DigestStream {
    pub(crate) fn new(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha256 => Self::Sha256(seaworthy_crypto::digest::Sha256::new()),
            DigestAlgorithm::Sha512 => Self::Sha512(seaworthy_crypto::digest::Sha512::new()),
        }
    }

    pub(crate) fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Sha256(ctx) => ctx.update(chunk),
            Self::Sha512(ctx) => ctx.update(chunk),
        }
    }

    pub(crate) fn finish_hex(self) -> String {
        hex::encode(match self {
            Self::Sha256(ctx) => ctx.finish().to_vec(),
            Self::Sha512(ctx) => ctx.finish().to_vec(),
        })
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_support;

// ---------------------------------------------------------------------------
// README doctests: the crate README's Rust examples compile as doctests
// (`cargo test --doc`), so the crates.io front page can never drift from
// the API. The helper example needs the `helper` feature.
// ---------------------------------------------------------------------------

#[cfg(all(doctest, feature = "helper"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
