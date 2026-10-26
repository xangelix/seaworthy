//! # seaworthy-formats: the signed contract between release tooling and the update helper
//!
//! Everything the seaworthy CLI (which builds, signs and publishes
//! releases) and `seaworthy-updater` (whose helper verifies and installs
//! them) must agree on, defined once:
//!
//! - **The signed release manifest** ([`ReleaseManifest`],
//!   [`ManifestTrust`], [`ReleaseKey`], [`ReleaseTrust`]): what one
//!   artifact is (product, channel, version and build, sequence, target,
//!   format, exact size, digest), signed by one or more release keys under
//!   ML-DSA-87, ECDSA P-256 or Ed25519 (any one trusted key, or one per
//!   trusted algorithm), and verified before any artifact byte is fetched.
//! - **Release versions** ([`release`]): the version grammar every package
//!   manager orders alike, the sequence that orders two builds of one
//!   version, each format's spelling, and the byte-exact read-back of an
//!   installed version.
//! - **The product's names** ([`Product`], read from `seaworthy.toml` with
//!   [`Product::from_config`]): the package, the channel, the staging and
//!   request paths, the policy file and registry keys.
//! - **Artifact formats** ([`ArtifactFormat`]) and the format check of a
//!   verified package ([`format_check`]).
//! - **The CI test-key switch** ([`ci_test`], [`ci_test_keys!`]): only a
//!   build made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` can trust a
//!   product's public CI test keys, and such a build carries a marker that
//!   `seaworthy verify` and release pipelines refuse.
//! - **The update-policy values** ([`UpdatePolicy`]; reading the machine's
//!   policy is `seaworthy-updater`'s), the digest and signature algorithms
//!   ([`DigestAlgorithm`], [`SignatureAlgorithm`]), the version-token gate
//!   ([`validate_version`]) and the size limits ([`MAX_ARTIFACT_BYTES`] …).
//!
//! **Pure.** No I/O, no async runtime, no network, process or OS
//! dependency: the parser of signed, network-delivered data sits in the
//! smallest reviewable crate. Cryptography goes through `seaworthy-crypto`,
//! whose key validation is the only defense against keyless ML-DSA
//! forgeries and small-order Ed25519 keys (defense in depth: embed only
//! keys you generated, or received from their holder over an
//! authenticated channel). No index or arithmetic here can
//! panic, and the network-facing parsers are fuzzed (the repository's
//! `fuzz/` crate, target `updater_manifest`).
//!
//! **Order at boot.** `seaworthy-crypto`'s algorithm policy is an
//! install-once process global that [`ReleaseKey::new`] consults: a
//! process that installs one (`seaworthy_crypto::fips_policy::install_policy`)
//! does so before it builds any release key.
//!
//! ```
//! use seaworthy_formats::release::Release;
//! use seaworthy_formats::{ArtifactFormat, ReleaseManifest};
//!
//! // Two builds of one version order by their sequence; a pre-release
//! // orders before its release.
//! assert!(Release::new("1.4.0", 812)? > Release::new("1.4.0", 811)?);
//! assert!(Release::new("1.4.0-rc.2", 900)? < Release::new("1.4.0", 1)?);
//! // Every format's spelling reads back byte for byte, and nothing else.
//! let spelled = Release::new("1.4.0-rc.2", 812)?.package_versions()?;
//! assert_eq!(spelled.deb, "1.4.0~rc.2-812");
//! assert_eq!(
//!     Release::from_package_version(ArtifactFormat::Deb, &spelled.deb)?,
//!     Release::new("1.4.0-rc.2", 812)?
//! );
//! // A signed manifest that isn't canonical is refused before any
//! // signature is even looked at.
//! assert!(ReleaseManifest::decode_signed(b"seaworthy-release-manifest:1\n\n").is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
// Parsers of signed, network-delivered bytes: no index or slice that can
// panic, no arithmetic that can overflow, no `unreachable!` (tests may
// index).
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

pub mod ci_test;
pub mod format_check;
mod log;
mod manifest;
mod policy;
mod product;
pub mod release;

pub use manifest::{
    ArtifactFormat, KEY_ID_LEN, ManifestSignature, ManifestTrust, RELEASE_MANIFEST_DOMAIN,
    ReleaseKey, ReleaseManifest, ReleaseTrust, release_key_id,
};
pub use policy::UpdatePolicy;
pub use product::{MSI_RELEASE_VALUE, Product, ProductError, ServiceNames, UPDATE_REQUEST_FILE};

// ------------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------------

/// Why a manifest, a release key, a version token or a package's format
/// was refused. `seaworthy-updater`'s `UpdateError` has a variant of the
/// same name and meaning for each, and converts from this.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    /// A malformed manifest or version token (never echoing manifest
    /// content; a version is shown line-safe and cut short).
    #[error("failed to resolve release: {0}")]
    Resolve(String),
    /// The manifested artifact exceeds the size cap.
    #[error("update artifact exceeds the {limit}-byte size cap")]
    ArtifactTooLarge {
        /// The size cap that was exceeded.
        limit: u64,
    },
    /// No trusted release key verified the release manifest: a forged or
    /// corrupt manifest, or a release signed only by keys this build does
    /// not trust.
    #[error("release manifest signature verification failed: no trusted release key verified it")]
    SignatureMismatch,
    /// A correctly signed manifest names a different release than the one
    /// asked for: another product, channel, version, target or format.
    #[error("release manifest {field} mismatch: expected {expected:?}, got {actual:?}")]
    ManifestMismatch {
        /// `product`, `channel`, `version`, `target`, or `format`.
        field: &'static str,
        /// What was expected.
        expected: String,
        /// What the (authenticated) manifest says.
        actual: String,
    },
    /// A release public key was refused ([`ReleaseKey::new`]): wrong
    /// shape, degenerate, or not admitted by `seaworthy-crypto`'s
    /// algorithm gate (the `fips` feature, or the installed policy).
    #[error("invalid release public key ({algorithm:?}): {reason}")]
    InvalidReleaseKey {
        /// The algorithm the key was declared under.
        algorithm: SignatureAlgorithm,
        /// What was wrong (never key material).
        reason: String,
    },
    /// A configuration value was refused (an empty key set, a malformed
    /// product or channel id, an invalid manifest field in release
    /// tooling).
    #[error("invalid updater configuration: {0}")]
    InvalidConfig(String),
    /// The verified artifact isn't a package of the format its manifest
    /// names (an error page, another format, an empty file).
    #[error("the verified artifact isn't the format its manifest names: {reason}")]
    WrongFormat {
        /// What did not match.
        reason: String,
    },
}

// ------------------------------------------------------------------------------------------------
// Limits
// ------------------------------------------------------------------------------------------------

/// Hard ceiling on a downloaded artifact: a compromised or malfunctioning
/// endpoint must not fill the disk (the update helper's staged file lives
/// on it). The seaworthy CLI refuses to publish a larger artifact.
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

/// Hard ceiling on a metadata body (the signed manifest or a package's
/// detached signature): a manifest signed by two ML-DSA-87 keys is ~19 KB,
/// an OpenPGP signature well under 1 KB. The seaworthy CLI refuses to
/// publish a larger one.
pub const MAX_METADATA_BYTES: u64 = 64 * 1024;

/// The longest update-server URL an administrator may set for a machine
/// (`seaworthy-updater`'s `read_admin_server`; the seaworthy CLI's Group
/// Policy template caps the value at the same length).
pub const MAX_SERVER_BYTES: usize = 2048;

/// The longest version token accepted ([`validate_version`]).
pub const MAX_VERSION_LEN: usize = 128;

// ------------------------------------------------------------------------------------------------
// Versions
// ------------------------------------------------------------------------------------------------

/// Validates a version token from the network, once, where it enters (it
/// reaches the package URL, the manifest comparison and the update
/// helper's failure memo): non-empty, at most [`MAX_VERSION_LEN`] bytes,
/// the semver-ish charset `A-Z a-z 0-9 . - _ +`, and no `..`
/// (path-traversal-shaped input).
///
/// # Errors
/// [`FormatError::Resolve`] naming the rule, the token shown line-safe
/// and cut to 64 characters.
pub fn validate_version(version: &str) -> Result<(), FormatError> {
    if version.is_empty()
        || version.len() > MAX_VERSION_LEN
        || version.contains("..")
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        let shown: String = log::line_safe(version).chars().take(64).collect();
        return Err(FormatError::Resolve(format!(
            "version {shown:?} is not a valid release version (1-{MAX_VERSION_LEN} characters \
             of A-Z a-z 0-9 . - _ +, no \"..\")"
        )));
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Algorithms
// ------------------------------------------------------------------------------------------------

/// The compile-time target triple: the `{target}` placeholder of the
/// update helper's package URL, and the target every signed manifest it
/// accepts must name.
pub const TARGET_TRIPLE: &str = env!("SEAWORTHY_FORMATS_TARGET_TRIPLE");

/// A digest algorithm for artifacts. SHA-512 is the recommended choice
/// (64-bit-native, faster on large artifacts); SHA-256 is the interop
/// option.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256: 32-byte digests, 64 hex chars.
    Sha256,
    /// SHA-512: 64-byte digests, 128 hex chars.
    #[default]
    Sha512,
}

impl DigestAlgorithm {
    /// The digest of `data`.
    #[must_use]
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => seaworthy_crypto::digest::sha256(data).to_vec(),
            Self::Sha512 => seaworthy_crypto::digest::sha512(data).to_vec(),
        }
    }

    /// The digest of `data`, lowercase hex.
    #[must_use]
    pub fn hash_hex(self, data: &[u8]) -> String {
        match self {
            Self::Sha256 => seaworthy_crypto::digest::sha256_hex(data),
            Self::Sha512 => seaworthy_crypto::digest::sha512_hex(data),
        }
    }

    /// The algorithm's name in a manifest's `digest=` line (`sha512`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// The byte length of this algorithm's digest (its lowercase hex is
    /// twice as long).
    pub(crate) const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

impl std::fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The signature algorithm of a [`ReleaseKey`].
///
/// - [`MlDsa87`](Self::MlDsa87): post-quantum; the AWS-LC FIPS 4.2.0 module
///   approves it (CMVP: in process; not on the AWS-LC 3 certificate).
/// - [`EcdsaP256`](Self::EcdsaP256): FIPS-approved today; not post-quantum.
/// - [`Ed25519`](Self::Ed25519): fast and compact; an approved service in
///   the validated AWS-LC 3 certificate (#5314) too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ML-DSA-87 (FIPS 204, pure): raw 2592-byte public keys.
    MlDsa87,
    /// ECDSA P-256 / SHA-256, DER signatures; SPKI DER (or raw X9.62)
    /// public keys.
    EcdsaP256,
    /// Ed25519: raw 32-byte public keys.
    Ed25519,
}

impl SignatureAlgorithm {
    /// The intake checks for an embedded release public key: admitted by
    /// `seaworthy-crypto`'s algorithm gate (the `fips` feature and the
    /// installed policy), and a well-formed key no one can forge under,
    /// checked by the facade (never by the backend directly: only the
    /// facade runs the ML-DSA-87 intake test, which refuses all-zero,
    /// low-weight and structured `t1` halves, and refuses small-order
    /// Ed25519 points; each verifies signatures anyone can compute).
    fn validate_public_key(self, public_key: &[u8]) -> Result<(), FormatError> {
        let invalid = |reason: String| FormatError::InvalidReleaseKey {
            algorithm: self,
            reason,
        };
        let service = match self {
            Self::MlDsa87 => seaworthy_crypto::fips_policy::Service::MlDsa87,
            Self::EcdsaP256 => seaworthy_crypto::fips_policy::Service::EcdsaP256,
            Self::Ed25519 => seaworthy_crypto::fips_policy::Service::Ed25519,
        };
        seaworthy_crypto::fips_policy::ensure_approved(service)
            .map_err(|e| invalid(e.to_string()))?;
        match self {
            Self::MlDsa87 => seaworthy_crypto::mldsa::validate_public_key(public_key),
            Self::EcdsaP256 => seaworthy_crypto::ecdsa::validate_public_key(public_key),
            Self::Ed25519 => seaworthy_crypto::ed25519::validate_public_key(public_key),
        }
        .map_err(|_| {
            invalid(format!(
                "a {}-byte key that is malformed or forgeable for this algorithm (an \
                 ML-DSA-87 key the intake test refuses, a small-order Ed25519 point, an \
                 off-curve P-256 point)",
                public_key.len()
            ))
        })
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic on bounds")]
mod tests;

// ---------------------------------------------------------------------------
// README doctests: the crate README's Rust examples compile as doctests
// (`cargo test --doc`), so the crates.io front page can never drift from
// the API.
// ---------------------------------------------------------------------------

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
