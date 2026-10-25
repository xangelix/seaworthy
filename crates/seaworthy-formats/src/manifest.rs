//! The signed release manifest.
//!
//! A release signature over a bare digest says *these bytes*, not *which
//! release*: a storage/CDN operator (exactly the party signed releases
//! distrust) could copy any validly signed artifact into the slot a device
//! requests (another target's build: a bricked fleet; an older build: the
//! CDN, not the product's server, becomes the version authority; another
//! product or channel: a privileged daemon running the desktop client).
//! The fix is to sign a release STATEMENT, fetched and verified BEFORE any
//! artifact byte is downloaded:
//!
//! ```text
//! seaworthy-release-manifest:1
//! product=10:acme-agent
//! channel=6:stable
//! version=5:2.0.0
//! build=12:a1b2c3d4e5f6
//! sequence=812
//! target=24:x86_64-unknown-linux-gnu
//! format=deb
//! size=48213504
//! digest=sha512:<128 lowercase hex>
//!
//! signature=ml-dsa-87:<16 hex key id>:<hex signature>
//! signature=ed25519:<16 hex key id>:<hex signature>
//! ```
//!
//! - The **statement** is everything up to the blank line; its first line is
//!   the domain separator ([`RELEASE_MANIFEST_DOMAIN`]), so a release key's
//!   signature can never be replayed from or into another context (pure
//!   ML-DSA carries no context string of its own). Text fields are
//!   length-prefixed (`name=<len>:<value>`), so no product string can alias
//!   a field boundary, and the channel line is always present (`0:` when
//!   the release has none). The encoding is CANONICAL: the verifier
//!   re-encodes the parsed statement and requires byte equality, so there
//!   is exactly one accepted spelling of any release.
//! - `build` is the version token's build metadata (the part after `+`,
//!   often the commit; `build=0:` when there is none): the product's server
//!   names a token, `version+build` ([`ReleaseManifest::token`]), and a
//!   manifest matches only the exact build it names, never another build
//!   of the same version. `version` itself carries no `+`. `sequence` is
//!   the release pipeline's build number (a CI pipeline counter that only
//!   grows, at least 1): it orders two builds of one version, and every
//!   package format spells it into its version; the update helper's
//!   version floor compares it. `format` ([`ArtifactFormat`]) is what the
//!   artifact is, so a signed package can't be substituted for another
//!   format of the same release (a deb served where an MSI is expected, or
//!   either written over a running binary).
//! - One or more **signature lines** follow (rotation: a release signed by
//!   the old AND the new key verifies on devices trusting either; the
//!   runbook: ship the new key in the helper's key set, sign with both for
//!   a release, then drop the old key). Lines naming a key the device does
//!   not trust are skipped; the manifest verifies when ANY trusted key
//!   verifies its line.
//!
//! The updater then checks product, channel, version (byte-equal to the
//! version the product's server named: the server keeps rollback
//! authority, the CDN can no longer substitute another version), and
//! target (this build's triple), downloads EXACTLY `size` bytes, and
//! compares the digest in constant time.

use std::sync::Arc;

use crate::{DigestAlgorithm, FormatError, SignatureAlgorithm};

/// The manifest statement's first line: the domain separator every release
/// signature covers.
pub const RELEASE_MANIFEST_DOMAIN: &str = "seaworthy-release-manifest:1";

/// The release key id's hash preimage prefix (then the algorithm tag, a
/// `:`, and the public key).
const RELEASE_KEY_DOMAIN: &[u8] = b"seaworthy-release-key:1:";

/// At most this many signature lines are considered (a rotation window
/// needs two; the bound keeps a hostile manifest from buying verify work).
const MAX_SIGNATURES: usize = 8;

/// The byte length of a release key id.
pub const KEY_ID_LEN: usize = 8;

impl SignatureAlgorithm {
    /// The manifest's wire tag for this algorithm.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml-dsa-87",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
        }
    }

    /// The algorithm a manifest tag names (`ml-dsa-87`, `ecdsa-p256`,
    /// `ed25519`).
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "ml-dsa-87" => Some(Self::MlDsa87),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// What a release artifact is, as a manifest's `format=` line names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArtifactFormat {
    /// A Windows Installer package.
    Msi,
    /// A zip of the Windows install tree.
    Zip,
    /// A Debian package.
    Deb,
    /// An RPM package.
    Rpm,
    /// An Arch Linux package.
    Pacman,
    /// A tarball of the Linux install tree.
    Tar,
    /// A macOS flat installer package (`productbuild`'s product archive).
    Pkg,
}

impl ArtifactFormat {
    /// Every format.
    pub const ALL: [Self; 7] = [
        Self::Msi,
        Self::Zip,
        Self::Deb,
        Self::Rpm,
        Self::Pacman,
        Self::Tar,
        Self::Pkg,
    ];

    /// The manifest's wire tag for this format.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Msi => "msi",
            Self::Zip => "zip",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Pacman => "pacman",
            Self::Tar => "tar",
            Self::Pkg => "pkg",
        }
    }

    /// The format a manifest tag names.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|format| format.tag() == tag)
    }
}

impl std::fmt::Display for ArtifactFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.tag())
    }
}

/// The id of a release public key as it appears on a manifest's signature
/// line: the first 8 bytes of SHA-256 over
/// `seaworthy-release-key:1:{algorithm tag}:` ‖ the public key bytes. An
/// id is a selector, never an authenticator: the signature is verified
/// under the full trusted key it selects.
#[must_use]
pub fn release_key_id(algorithm: SignatureAlgorithm, public_key: &[u8]) -> [u8; KEY_ID_LEN] {
    let mut preimage = Vec::with_capacity(
        RELEASE_KEY_DOMAIN
            .len()
            .saturating_add(16)
            .saturating_add(public_key.len()),
    );
    preimage.extend_from_slice(RELEASE_KEY_DOMAIN);
    preimage.extend_from_slice(algorithm.tag().as_bytes());
    preimage.push(b':');
    preimage.extend_from_slice(public_key);
    let digest = seaworthy_crypto::digest::sha256(&preimage);
    // The digest's first KEY_ID_LEN bytes (the digest is longer, so every
    // byte of the id is written).
    let mut id = [0u8; KEY_ID_LEN];
    for (out, byte) in id.iter_mut().zip(digest) {
        *out = byte;
    }
    id
}

/// The DER prefix of a P-256 SubjectPublicKeyInfo holding an uncompressed
/// point (`id-ecPublicKey`, `prime256v1`, then the 65-byte point).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The length of an uncompressed P-256 point (`04 ‖ x ‖ y`).
const P256_POINT_LEN: usize = 65;

/// One trusted release public key, validated at construction.
#[derive(Clone)]
pub struct ReleaseKey {
    algorithm: SignatureAlgorithm,
    public_key: Arc<[u8]>,
    key_id: [u8; KEY_ID_LEN],
}

impl std::fmt::Debug for ReleaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseKey")
            .field("algorithm", &self.algorithm)
            .field("key_id", &hex::encode(self.key_id))
            .finish_non_exhaustive()
    }
}

impl ReleaseKey {
    /// A trusted release key: release tooling's public-key export, embedded
    /// in the update helper at build time: ML-DSA-87 raw bytes, ECDSA P-256
    /// SPKI DER of an uncompressed point (or that raw 65-byte X9.62 point),
    /// Ed25519 raw bytes. Compressed P-256 spellings are refused: a key id
    /// hashes the encoding, so every spelling of one key would have its own
    /// id.
    ///
    /// The key is validated HERE, through `seaworthy-crypto`: a degenerate
    /// key (an ML-DSA-87 all-zero `t1`, an Ed25519 small-order point, both
    /// of which verify signatures anyone can compute), an off-curve P-256
    /// point, or an algorithm the crypto gate doesn't admit (under
    /// `seaworthy-crypto/fips`, or the process's installed algorithm
    /// policy) is a loud startup error, never a release channel that
    /// silently accepts forgeries. Install the algorithm policy, if any,
    /// before the first key is built: it freezes at its first read.
    ///
    /// # Errors
    /// [`FormatError::InvalidReleaseKey`] naming the problem.
    pub fn new(
        public_key: impl Into<Vec<u8>>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self, FormatError> {
        let public_key = public_key.into();
        algorithm.validate_public_key(&public_key)?;
        // One key, one id: a raw P-256 point is the same key as its SPKI
        // encoding, so it's stored (and hashed into its id) as SPKI; any
        // other spelling (a compressed point, raw or wrapped) is refused.
        let public_key = match algorithm {
            SignatureAlgorithm::EcdsaP256
                if public_key.len() == P256_POINT_LEN && public_key.first() == Some(&0x04) =>
            {
                let mut spki = P256_SPKI_PREFIX.to_vec();
                spki.extend_from_slice(&public_key);
                spki
            }
            SignatureAlgorithm::EcdsaP256
                if public_key
                    .strip_prefix(&P256_SPKI_PREFIX)
                    .is_some_and(|point| {
                        point.len() == P256_POINT_LEN && point.first() == Some(&0x04)
                    }) =>
            {
                public_key
            }
            SignatureAlgorithm::EcdsaP256 => {
                return Err(FormatError::InvalidReleaseKey {
                    algorithm,
                    reason: "a P-256 release key is an uncompressed point (65 bytes) or its SubjectPublicKeyInfo"
                        .to_string(),
                });
            }
            _ => public_key,
        };
        Ok(Self {
            key_id: release_key_id(algorithm, &public_key),
            algorithm,
            public_key: Arc::from(public_key.into_boxed_slice()),
        })
    }

    /// The key's algorithm.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The raw public key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The key id signature lines name ([`release_key_id`]).
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        self.key_id
    }
}

/// What a device trusts in signed-manifest mode: its product id, its
/// release channel (optional), and the set of release keys any one of which
/// may sign a release.
#[derive(Clone, Debug)]
pub struct ManifestTrust {
    product: String,
    channel: Option<String>,
    keys: Vec<ReleaseKey>,
}

impl ManifestTrust {
    /// Trust `keys` (at least one; rotation = several) for releases of
    /// `product` (`[A-Za-z0-9._-]{1,64}`). A manifest for any other product
    /// is refused even when validly signed: an organization signing two
    /// products with one key can no longer have them installed
    /// interchangeably.
    ///
    /// # Errors
    /// [`FormatError::InvalidConfig`] for an empty key set or a malformed
    /// product id.
    pub fn new(
        product: impl Into<String>,
        keys: impl IntoIterator<Item = ReleaseKey>,
    ) -> Result<Self, FormatError> {
        let product = product.into();
        check_token("product", &product).map_err(FormatError::InvalidConfig)?;
        let keys: Vec<ReleaseKey> = keys.into_iter().collect();
        if keys.is_empty() {
            return Err(FormatError::InvalidConfig(
                "a signed-manifest updater needs at least one release key".into(),
            ));
        }
        Ok(Self {
            product,
            channel: None,
            keys,
        })
    }

    /// Only accept releases published on `channel` (`[A-Za-z0-9._-]{1,64}`;
    /// e.g. `stable`, `beta`). Without it, only channel-less releases are
    /// accepted: a beta manifest never installs on a device that did not
    /// opt into beta.
    ///
    /// # Errors
    /// [`FormatError::InvalidConfig`] for a malformed channel name.
    pub fn channel(mut self, channel: impl Into<String>) -> Result<Self, FormatError> {
        let channel = channel.into();
        check_token("channel", &channel).map_err(FormatError::InvalidConfig)?;
        self.channel = Some(channel);
        Ok(self)
    }

    /// Trust `keys` for `product`'s packages: its package name
    /// ([`Product::package`](crate::Product::package)) and channel, exactly
    /// as the seaworthy CLI signs them. What an update helper uses.
    ///
    /// # Errors
    /// [`FormatError::InvalidConfig`] for an empty key set.
    pub fn for_product(
        product: &crate::Product,
        keys: impl IntoIterator<Item = ReleaseKey>,
    ) -> Result<Self, FormatError> {
        Self::new(product.package(), keys)?.channel(product.channel())
    }

    /// The product id manifests must name.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// The channel manifests must name, if any.
    #[must_use]
    pub fn channel_name(&self) -> Option<&str> {
        self.channel.as_deref()
    }

    /// Checks a signed manifest's statement as the update helper checks the
    /// one it fetches: a trusted key verifies it FIRST, then it must name
    /// this product and channel, `version` (the token `version+build`,
    /// prefix removed), this build's target ([`TARGET_TRIPLE`](crate::TARGET_TRIPLE):
    /// a manifest for another target can't be checked from here) and
    /// `format`, within [`MAX_ARTIFACT_BYTES`](crate::MAX_ARTIFACT_BYTES).
    /// For a product's own tests and release tooling: that the keys its
    /// helper compiles in accept what its pipeline signs, and refuse what
    /// they must.
    ///
    /// **The statement only: it verifies no artifact.** The helper goes on
    /// to check what this doesn't: the release version's grammar and a
    /// non-zero sequence, the version floor (never an older release), its
    /// own size cap, the downloaded package's exact size, digest and format
    /// magic, and (rpm, pacman) the package's OpenPGP signature. Never treat
    /// a package beside a manifest that passes here as verified.
    ///
    /// # Errors
    /// [`FormatError::Resolve`] for a malformed manifest,
    /// [`FormatError::SignatureMismatch`] when no trusted key verifies it,
    /// [`FormatError::ManifestMismatch`] naming the first field that
    /// differs, [`FormatError::ArtifactTooLarge`] past the cap.
    pub fn verify(
        &self,
        manifest: &[u8],
        version: &str,
        format: ArtifactFormat,
    ) -> Result<ReleaseManifest, FormatError> {
        verify_manifest(manifest, self, version, format, crate::MAX_ARTIFACT_BYTES)
    }

    /// [`verify`](Self::verify) under another size cap: the update
    /// helper's own (`HelperConfig::max_artifact_bytes`), which may be
    /// lower than [`MAX_ARTIFACT_BYTES`](crate::MAX_ARTIFACT_BYTES).
    ///
    /// # Errors
    /// As [`verify`](Self::verify), with [`FormatError::ArtifactTooLarge`]
    /// past `max_artifact_bytes`.
    pub fn verify_with_limit(
        &self,
        manifest: &[u8],
        version: &str,
        format: ArtifactFormat,
        max_artifact_bytes: u64,
    ) -> Result<ReleaseManifest, FormatError> {
        verify_manifest(manifest, self, version, format, max_artifact_bytes)
    }
}

/// A release statement: what one artifact is. Build one in release tooling,
/// sign its [`statement`](Self::statement) with each release key, and
/// publish [`encode_signed`](Self::encode_signed) as `{artifact url}.manifest`
/// (`seaworthy-updater`'s `examples/sign_release.rs` does all three).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// The product id (`[A-Za-z0-9._-]{1,64}`).
    pub product: String,
    /// The release channel, when the release is published on one.
    pub channel: Option<String>,
    /// The version (the version-token charset without `+`: `A-Z a-z 0-9 .
    /// - _`).
    pub version: String,
    /// The build metadata of the version token (`A-Z a-z 0-9 . -`, at most
    /// 64 characters; empty when the token has none).
    pub build: String,
    /// The release pipeline's build number (at least 1): it orders two
    /// builds of one version.
    pub sequence: u64,
    /// The target triple the artifact is built for.
    pub target: String,
    /// What the artifact is.
    pub format: ArtifactFormat,
    /// The artifact's exact size in bytes (non-zero).
    pub size: u64,
    /// The digest algorithm of [`digest`](Self::digest).
    pub digest_algorithm: DigestAlgorithm,
    /// The artifact's digest.
    pub digest: Vec<u8>,
}

/// One signature line of a signed manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestSignature {
    /// The algorithm of the signing key.
    pub algorithm: SignatureAlgorithm,
    /// The signing key's id ([`release_key_id`]).
    pub key_id: [u8; KEY_ID_LEN],
    /// The raw signature over the manifest's statement bytes.
    pub signature: Vec<u8>,
}

/// `[A-Za-z0-9._-]{1,64}` with no `..`: product, channel, and target ids.
fn check_token(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || value.contains("..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "{field} must be 1-64 characters of A-Z a-z 0-9 . - _ (no \"..\")"
        ));
    }
    Ok(())
}

fn malformed(reason: &str) -> FormatError {
    FormatError::Resolve(format!("malformed release manifest: {reason}"))
}

impl ReleaseManifest {
    fn validate(&self) -> Result<(), FormatError> {
        let invalid =
            |reason: String| FormatError::InvalidConfig(format!("release manifest: {reason}"));
        check_token("product", &self.product).map_err(invalid)?;
        if let Some(channel) = &self.channel {
            check_token("channel", channel).map_err(invalid)?;
        }
        crate::validate_version(&self.version)?;
        if self.version.contains('+') {
            return Err(invalid(
                "the version carries no `+`: build metadata is the build field".into(),
            ));
        }
        if self.build.len() > 64
            || self.build.contains("..")
            || !self
                .build
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err(invalid(
                "build must be at most 64 characters of A-Z a-z 0-9 . - (no \"..\")".into(),
            ));
        }
        crate::validate_version(&self.token())?;
        if self.sequence == 0 {
            return Err(invalid("sequence must be at least 1".into()));
        }
        check_token("target", &self.target).map_err(invalid)?;
        if self.size == 0 {
            return Err(invalid("size must be non-zero".into()));
        }
        if self.digest.len() != self.digest_algorithm.digest_len() {
            return Err(invalid(format!(
                "a {} digest is {} bytes, got {}",
                self.digest_algorithm,
                self.digest_algorithm.digest_len(),
                self.digest.len()
            )));
        }
        Ok(())
    }

    /// The version token this manifest names: `version`, or
    /// `version+build` when it has build metadata. The product's server's
    /// token must equal it byte for byte.
    #[must_use]
    pub fn token(&self) -> String {
        if self.build.is_empty() {
            self.version.clone()
        } else {
            format!("{}+{}", self.version, self.build)
        }
    }

    /// Parses a canonical statement (everything a signature covers), for
    /// signers that must refuse anything else.
    ///
    /// # Errors
    /// [`FormatError::Resolve`] for anything but a canonical statement.
    pub fn from_statement(statement: &[u8]) -> Result<Self, FormatError> {
        let manifest = Self::parse_statement(statement)?;
        if manifest.statement()? != statement {
            return Err(malformed("the statement is not canonically encoded"));
        }
        Ok(manifest)
    }

    /// The canonical statement bytes: exactly what every release signature
    /// covers.
    ///
    /// # Errors
    /// [`FormatError::InvalidConfig`]/[`FormatError::Resolve`] for a field
    /// outside its charset, a zero size, or a digest of the wrong length.
    pub fn statement(&self) -> Result<Vec<u8>, FormatError> {
        self.validate()?;
        let field = |out: &mut String, name: &str, value: &str| {
            out.push_str(&format!("{name}={}:{value}\n", value.len()));
        };
        let mut out = String::new();
        out.push_str(RELEASE_MANIFEST_DOMAIN);
        out.push('\n');
        field(&mut out, "product", &self.product);
        field(&mut out, "channel", self.channel.as_deref().unwrap_or(""));
        field(&mut out, "version", &self.version);
        field(&mut out, "build", &self.build);
        out.push_str(&format!("sequence={}\n", self.sequence));
        field(&mut out, "target", &self.target);
        out.push_str(&format!("format={}\n", self.format.tag()));
        out.push_str(&format!("size={}\n", self.size));
        out.push_str(&format!(
            "digest={}:{}\n",
            self.digest_algorithm,
            hex::encode(&self.digest)
        ));
        Ok(out.into_bytes())
    }

    /// The signed manifest file: the statement, a blank line, then one
    /// `signature=` line per signature.
    ///
    /// # Errors
    /// As [`statement`](Self::statement); also an empty signature list, or
    /// one key signing twice (the decoder refuses that file).
    pub fn encode_signed(&self, signatures: &[ManifestSignature]) -> Result<Vec<u8>, FormatError> {
        if signatures.is_empty() || signatures.len() > MAX_SIGNATURES {
            return Err(FormatError::InvalidConfig(format!(
                "a signed manifest carries 1-{MAX_SIGNATURES} signatures"
            )));
        }
        for (i, signature) in signatures.iter().enumerate() {
            if signatures
                .iter()
                .take(i)
                .any(|s| s.algorithm == signature.algorithm && s.key_id == signature.key_id)
            {
                return Err(FormatError::InvalidConfig(
                    "a signed manifest carries one signature per key".to_string(),
                ));
            }
        }
        let mut out = self.statement()?;
        out.push(b'\n');
        for signature in signatures {
            out.extend_from_slice(
                format!(
                    "signature={}:{}:{}\n",
                    signature.algorithm.tag(),
                    hex::encode(signature.key_id),
                    hex::encode(&signature.signature)
                )
                .as_bytes(),
            );
        }
        Ok(out)
    }

    /// Parses a signed manifest file STRICTLY (canonical statement, 1–8
    /// well-formed signature lines). Nothing here is authenticated: see
    /// [`ManifestTrust::verify`] for the trust decision.
    ///
    /// # Errors
    /// [`FormatError::Resolve`] naming the structural problem (never
    /// echoing manifest content).
    pub fn decode_signed(bytes: &[u8]) -> Result<(Self, Vec<ManifestSignature>), FormatError> {
        let split = bytes
            .windows(2)
            .position(|window| window == b"\n\n")
            .ok_or_else(|| malformed("no statement/signature separator"))?;
        // The statement keeps its last newline; the blank line after it is
        // the separator.
        let (statement, rest) = split
            .checked_add(1)
            .and_then(|at| bytes.split_at_checked(at))
            .ok_or_else(|| malformed("no statement/signature separator"))?;
        let rest = rest
            .strip_prefix(b"\n")
            .ok_or_else(|| malformed("no statement/signature separator"))?;
        let manifest = Self::parse_statement(statement)?;
        if manifest.statement()? != statement {
            return Err(malformed("the statement is not canonically encoded"));
        }
        let text =
            std::str::from_utf8(rest).map_err(|_| malformed("the signature block is not UTF-8"))?;
        if !text.ends_with('\n') {
            return Err(malformed("the signature block must end with a newline"));
        }
        let mut signatures: Vec<ManifestSignature> = Vec::new();
        for line in text.split_terminator('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(malformed("too many signature lines"));
            }
            let rest = line
                .strip_prefix("signature=")
                .ok_or_else(|| malformed("unexpected line in the signature block"))?;
            let mut parts = rest.splitn(3, ':');
            let (Some(tag), Some(key_id), Some(signature)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(malformed(
                    "a signature line needs algorithm:key-id:signature",
                ));
            };
            let algorithm = SignatureAlgorithm::from_tag(tag)
                .ok_or_else(|| malformed("unknown signature algorithm"))?;
            if !key_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(malformed("a key id is 16 lowercase hex characters"));
            }
            let key_id: [u8; KEY_ID_LEN] = hex::decode(key_id)
                .ok()
                .and_then(|id| id.try_into().ok())
                .ok_or_else(|| malformed("a key id is 16 lowercase hex characters"))?;
            if signatures
                .iter()
                .any(|s| s.algorithm == algorithm && s.key_id == key_id)
            {
                return Err(malformed("a key signs twice"));
            }
            if signature.is_empty()
                || !signature
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(malformed("a signature is lowercase hex"));
            }
            let signature =
                hex::decode(signature).map_err(|_| malformed("a signature is lowercase hex"))?;
            signatures.push(ManifestSignature {
                algorithm,
                key_id,
                signature,
            });
        }
        if signatures.is_empty() {
            return Err(malformed("no signature lines"));
        }
        Ok((manifest, signatures))
    }

    fn parse_statement(statement: &[u8]) -> Result<Self, FormatError> {
        let text =
            std::str::from_utf8(statement).map_err(|_| malformed("the statement is not UTF-8"))?;
        let mut lines = text.split_terminator('\n');
        if lines.next() != Some(RELEASE_MANIFEST_DOMAIN) {
            return Err(malformed("missing the seaworthy-release-manifest:1 header"));
        }
        let mut next = |name: &str| -> Result<&str, FormatError> {
            lines
                .next()
                .and_then(|line| line.strip_prefix(name))
                .and_then(|line| line.strip_prefix('='))
                .ok_or_else(|| malformed("fields out of order or missing"))
        };
        let text_field = |raw: &str| -> Result<String, FormatError> {
            let (len, value) = raw
                .split_once(':')
                .ok_or_else(|| malformed("a text field is <len>:<value>"))?;
            let len: usize = len.parse().map_err(|_| malformed("a bad field length"))?;
            if value.len() != len {
                return Err(malformed("a field length does not match its value"));
            }
            Ok(value.to_string())
        };
        let product = text_field(next("product")?)?;
        let channel = text_field(next("channel")?)?;
        let version = text_field(next("version")?)?;
        let build = text_field(next("build")?)?;
        let sequence: u64 = next("sequence")?
            .parse()
            .map_err(|_| malformed("sequence is a decimal integer"))?;
        let target = text_field(next("target")?)?;
        let format = ArtifactFormat::from_tag(next("format")?)
            .ok_or_else(|| malformed("unknown artifact format"))?;
        let size: u64 = next("size")?
            .parse()
            .map_err(|_| malformed("size is a decimal integer"))?;
        let (algorithm, digest_hex) = next("digest")?
            .split_once(':')
            .ok_or_else(|| malformed("digest is <algorithm>:<hex>"))?;
        let digest_algorithm = match algorithm {
            "sha256" => DigestAlgorithm::Sha256,
            "sha512" => DigestAlgorithm::Sha512,
            _ => return Err(malformed("unknown digest algorithm")),
        };
        let digest = hex::decode(digest_hex).map_err(|_| malformed("the digest is not hex"))?;
        if lines.next().is_some() {
            return Err(malformed("trailing statement lines"));
        }
        let manifest = Self {
            product,
            channel: (!channel.is_empty()).then_some(channel),
            version,
            build,
            sequence,
            target,
            format,
            size,
            digest_algorithm,
            digest,
        };
        manifest
            .validate()
            .map_err(|_| malformed("a field is outside its charset or shape"))?;
        Ok(manifest)
    }
}

impl SignatureAlgorithm {
    /// Verifies `signature` over `message` under `public_key`, through
    /// `seaworthy-crypto` (whose verify re-checks the key's shape). Malformed
    /// keys and signatures read as a plain verification failure.
    fn verify(self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::MlDsa87 => seaworthy_crypto::mldsa::verify(public_key, message, signature),
            Self::EcdsaP256 => seaworthy_crypto::ecdsa::verify(public_key, message, signature),
            Self::Ed25519 => seaworthy_crypto::ed25519::verify(public_key, message, signature),
        }
        .is_ok()
    }
}

/// Authenticates a fetched manifest and checks it names exactly the release
/// this device asked for. Order matters: the signature is verified FIRST,
/// so the field comparisons (and their error text) only ever run over
/// authenticated content.
///
/// # Errors
/// [`FormatError::Resolve`] for a malformed manifest,
/// [`FormatError::SignatureMismatch`] when no trusted key verifies it,
/// [`FormatError::ManifestMismatch`] when product/channel/version/target/
/// format differ, [`FormatError::ArtifactTooLarge`] when `size` exceeds the
/// cap.
fn verify_manifest(
    bytes: &[u8],
    trust: &ManifestTrust,
    requested_version: &str,
    expected_format: ArtifactFormat,
    max_artifact_bytes: u64,
) -> Result<ReleaseManifest, FormatError> {
    let (manifest, signatures) = ReleaseManifest::decode_signed(bytes)?;
    let statement = manifest.statement()?;
    let verified = signatures.iter().any(|signature| {
        trust.keys.iter().any(|key| {
            key.key_id == signature.key_id
                && key.algorithm == signature.algorithm
                && key
                    .algorithm
                    .verify(&key.public_key, &statement, &signature.signature)
        })
    });
    if !verified {
        return Err(FormatError::SignatureMismatch);
    }
    let mismatch = |field: &'static str, expected: &str, actual: &str| {
        Err(FormatError::ManifestMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    };
    if manifest.product != trust.product {
        return mismatch("product", &trust.product, &manifest.product);
    }
    if manifest.channel != trust.channel {
        return mismatch(
            "channel",
            trust.channel.as_deref().unwrap_or(""),
            manifest.channel.as_deref().unwrap_or(""),
        );
    }
    let token = manifest.token();
    if token != requested_version {
        return mismatch("version", requested_version, &token);
    }
    if manifest.target != crate::TARGET_TRIPLE {
        return mismatch("target", crate::TARGET_TRIPLE, &manifest.target);
    }
    if manifest.format != expected_format {
        return mismatch("format", expected_format.tag(), manifest.format.tag());
    }
    if manifest.size > max_artifact_bytes {
        return Err(FormatError::ArtifactTooLarge {
            limit: max_artifact_bytes,
        });
    }
    Ok(manifest)
}

/// Test signing keys (the release-side operation, in-process).
#[cfg(test)]
pub(crate) mod test_keys {
    use super::*;

    pub(crate) enum SigningKey {
        MlDsa87(seaworthy_crypto::mldsa::SigningKey),
        EcdsaP256(seaworthy_crypto::ecdsa::SigningKey),
        Ed25519(seaworthy_crypto::ed25519::SigningKey),
    }

    pub(crate) const ALGORITHMS: [SignatureAlgorithm; 3] = [
        SignatureAlgorithm::MlDsa87,
        SignatureAlgorithm::EcdsaP256,
        SignatureAlgorithm::Ed25519,
    ];

    impl SigningKey {
        pub(crate) fn generate(algorithm: SignatureAlgorithm) -> Self {
            match algorithm {
                SignatureAlgorithm::MlDsa87 => {
                    let mut seed = [0u8; 32];
                    seaworthy_crypto::rand::fill(&mut seed).unwrap();
                    Self::MlDsa87(seaworthy_crypto::mldsa::SigningKey::from_seed(&seed).unwrap())
                }
                SignatureAlgorithm::EcdsaP256 => Self::EcdsaP256(
                    seaworthy_crypto::ecdsa::SigningKey::generate_pkcs8()
                        .unwrap()
                        .0,
                ),
                SignatureAlgorithm::Ed25519 => Self::Ed25519(
                    seaworthy_crypto::ed25519::SigningKey::generate_pkcs8()
                        .unwrap()
                        .0,
                ),
            }
        }

        pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
            match self {
                Self::MlDsa87(_) => SignatureAlgorithm::MlDsa87,
                Self::EcdsaP256(_) => SignatureAlgorithm::EcdsaP256,
                Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
            }
        }

        pub(crate) fn public_key(&self) -> Vec<u8> {
            match self {
                Self::MlDsa87(key) => key.public_key().to_vec(),
                Self::EcdsaP256(key) => key.public_key_der(),
                Self::Ed25519(key) => key.public_key().to_vec(),
            }
        }

        pub(crate) fn release_key(&self) -> ReleaseKey {
            ReleaseKey::new(self.public_key(), self.algorithm()).unwrap()
        }

        pub(crate) fn sign(&self, statement: &[u8]) -> ManifestSignature {
            let signature = match self {
                Self::MlDsa87(key) => key.sign(statement).to_vec(),
                Self::EcdsaP256(key) => key.sign(statement).unwrap(),
                Self::Ed25519(key) => key.sign(statement).to_vec(),
            };
            ManifestSignature {
                algorithm: self.algorithm(),
                key_id: release_key_id(self.algorithm(), &self.public_key()),
                signature,
            }
        }
    }

    /// A manifest for `artifact` naming this build's target.
    pub(crate) fn manifest_for(product: &str, version: &str, artifact: &[u8]) -> ReleaseManifest {
        ReleaseManifest {
            product: product.into(),
            channel: None,
            version: version.into(),
            build: String::new(),
            sequence: 1,
            target: crate::TARGET_TRIPLE.into(),
            format: ArtifactFormat::Deb,
            size: artifact.len() as u64,
            digest_algorithm: DigestAlgorithm::Sha512,
            digest: DigestAlgorithm::Sha512.hash(artifact),
        }
    }

    /// `manifest` signed by every key in `keys`.
    pub(crate) fn signed(manifest: &ReleaseManifest, keys: &[&SigningKey]) -> Vec<u8> {
        let statement = manifest.statement().unwrap();
        let signatures: Vec<_> = keys.iter().map(|key| key.sign(&statement)).collect();
        manifest.encode_signed(&signatures).unwrap()
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic on offsets")]
mod tests {
    use super::test_keys::*;
    use super::*;

    fn trust(keys: &[&SigningKey]) -> ManifestTrust {
        ManifestTrust::new("acme-agent", keys.iter().map(|key| key.release_key())).unwrap()
    }

    #[test]
    fn statement_is_canonical_length_prefixed_and_domain_separated() {
        let manifest = ReleaseManifest {
            product: "acme-agent".into(),
            channel: Some("stable".into()),
            version: "2.0.0".into(),
            build: "a1b2c3d4e5f6".into(),
            sequence: 812,
            target: "x86_64-unknown-linux-gnu".into(),
            format: ArtifactFormat::Deb,
            size: 42,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest: vec![0xab; 32],
        };
        let statement = String::from_utf8(manifest.statement().unwrap()).unwrap();
        assert_eq!(
            statement,
            format!(
                "seaworthy-release-manifest:1\nproduct=10:acme-agent\nchannel=6:stable\n\
                 version=5:2.0.0\nbuild=12:a1b2c3d4e5f6\nsequence=812\n\
                 target=24:x86_64-unknown-linux-gnu\nformat=deb\nsize=42\ndigest=sha256:{}\n",
                "ab".repeat(32)
            )
        );
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let signed = signed(&manifest, &[&key]);
        let (decoded, signatures) = ReleaseManifest::decode_signed(&signed).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(signatures.len(), 1);
    }

    #[test]
    fn non_canonical_and_malformed_manifests_are_refused() {
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let good =
            String::from_utf8(signed(&manifest_for("acme-agent", "2.0.0", b"x"), &[&key])).unwrap();
        for bad in [
            good.replace("size=1\n", "size=01\n"),
            good.replace("product=10:", "product=11:"),
            good.replace("version=5:2.0.0", "version=5:2.0.00"),
            good.replace("\n\n", "\n"),
            // Another version of the format is not read.
            good.replace(
                "seaworthy-release-manifest:1",
                "seaworthy-release-manifest:2",
            ),
            good.replace(
                "seaworthy-release-manifest:1",
                "seaworthy-release-manifest:0",
            ),
            good.replace("sequence=1\n", "sequence=01\n"),
            good.replace("sequence=1\n", "sequence=0\n"),
            good.replace("sequence=1\n", "sequence=+1\n"),
            good.replace("sequence=1\n", ""),
            good.replace("format=deb\n", "format=exe\n"),
            good.replace("format=deb\n", "format=Deb\n"),
            // No self-replacing executable format exists.
            good.replace("format=deb\n", "format=executable\n"),
            good.replace("format=deb\n", ""),
            good.replace("build=0:\n", ""),
            good.replace("build=0:\n", "build=1:+\n"),
            good.replace("build=0:\n", "build=2:a b\n"),
            // The signature block is canonical too.
            good.trim_end_matches('\n').to_string(),
            {
                let at = good.find("signature=ed25519:").unwrap() + "signature=ed25519:".len();
                let mut upper = good.clone();
                upper.replace_range(at..at + 16, "ABCDEF0123456789");
                upper
            },
            format!("{good}{}", &good[good.find("signature=").unwrap()..]),
            good.replace("signature=ed25519", "signature=rsa"),
            format!("{good}garbage\n"),
            good.replace("digest=sha512:", "digest=sha512:AB"),
        ] {
            assert!(
                ReleaseManifest::decode_signed(bad.as_bytes()).is_err(),
                "must refuse: {bad:?}"
            );
        }
    }

    #[test]
    fn the_token_is_version_plus_build_and_matches_only_that_build() {
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let manifest = ReleaseManifest {
            build: "a1b2c3d4e5f6".into(),
            ..manifest_for("acme-agent", "2.0.0", b"x")
        };
        assert_eq!(manifest.token(), "2.0.0+a1b2c3d4e5f6");
        let bytes = signed(&manifest, &[&key]);
        let trusted = trust(&[&key]);
        verify_manifest(
            &bytes,
            &trusted,
            "2.0.0+a1b2c3d4e5f6",
            ArtifactFormat::Deb,
            u64::MAX,
        )
        .unwrap();
        // Another build of the same version, or the bare version, is refused.
        for other in ["2.0.0", "2.0.0+ffffffffffff"] {
            assert!(matches!(
                verify_manifest(&bytes, &trusted, other, ArtifactFormat::Deb, u64::MAX),
                Err(FormatError::ManifestMismatch {
                    field: "version",
                    ..
                })
            ));
        }
        // Build metadata never rides in `version`.
        let plus = ReleaseManifest {
            version: "2.0.0+abc".into(),
            ..manifest_for("acme-agent", "2.0.0", b"x")
        };
        assert!(plus.statement().is_err());
        // One key signs once: the encoder refuses what the decoder would.
        let twice = ManifestSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: [7; KEY_ID_LEN],
            signature: vec![1; 64],
        };
        assert!(manifest.encode_signed(&[twice.clone(), twice]).is_err());
        // The build field holds at most 64 characters.
        let at_limit = ReleaseManifest {
            build: "b".repeat(64),
            ..manifest_for("acme-agent", "2.0.0", b"x")
        };
        assert!(at_limit.statement().is_ok());
        let past = ReleaseManifest {
            build: "b".repeat(65),
            ..manifest_for("acme-agent", "2.0.0", b"x")
        };
        assert!(past.statement().is_err());
    }

    /// Format tags are exact and closed: every format round-trips through
    /// its tag, and nothing else parses (no case folding, and no
    /// `executable`: there is no self-replacing format).
    #[test]
    fn format_tags_are_exact_and_closed() {
        for format in ArtifactFormat::ALL {
            assert_eq!(ArtifactFormat::from_tag(format.tag()), Some(format));
            assert_eq!(
                ArtifactFormat::from_tag(&format.tag().to_ascii_uppercase()),
                None
            );
        }
        for tag in ["executable", "exe", "", "deb ", "tar.zst"] {
            assert_eq!(ArtifactFormat::from_tag(tag), None, "{tag:?}");
        }
    }

    #[test]
    fn a_statement_parses_only_when_canonical() {
        let manifest = manifest_for("acme-agent", "2.0.0", b"x");
        let statement = manifest.statement().unwrap();
        assert_eq!(
            ReleaseManifest::from_statement(&statement).unwrap(),
            manifest
        );
        let text = String::from_utf8(statement).unwrap();
        for bad in [
            text.replace("size=1\n", "size=01\n"),
            format!("{text}\n"),
            text.replace(
                "seaworthy-release-manifest:1",
                "seaworthy-release-manifest:2",
            ),
            "not a manifest at all".to_owned(),
            String::new(),
        ] {
            assert!(
                ReleaseManifest::from_statement(bad.as_bytes()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_p256_key_has_one_id_however_it_is_spelled() {
        let key = SigningKey::generate(SignatureAlgorithm::EcdsaP256);
        let spki = key.public_key();
        assert_eq!(spki.len(), 91);
        let raw = spki[spki.len() - 65..].to_vec();
        let from_spki = ReleaseKey::new(spki.clone(), SignatureAlgorithm::EcdsaP256).unwrap();
        let from_raw = ReleaseKey::new(raw, SignatureAlgorithm::EcdsaP256).unwrap();
        assert_eq!(from_spki.key_id(), from_raw.key_id());
        assert_eq!(from_raw.public_key(), spki.as_slice());
        // Signed with the key, a manifest verifies under either spelling.
        let bytes = signed(&manifest_for("acme-agent", "2.0.0", b"x"), &[&key]);
        let trusted = ManifestTrust::new("acme-agent", [from_raw]).unwrap();
        verify_manifest(&bytes, &trusted, "2.0.0", ArtifactFormat::Deb, u64::MAX).unwrap();
        // Compressed spellings (raw, and wrapped in an SPKI) would each get
        // an id of their own: refused.
        let point = &spki[spki.len() - 65..];
        let mut compressed = vec![if point[64] & 1 == 1 { 0x03 } else { 0x02 }];
        compressed.extend_from_slice(&point[1..33]);
        let mut wrapped = vec![
            0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00,
        ];
        wrapped.extend_from_slice(&compressed);
        for spelling in [compressed, wrapped] {
            assert!(matches!(
                ReleaseKey::new(spelling, SignatureAlgorithm::EcdsaP256),
                Err(FormatError::InvalidReleaseKey { .. })
            ));
        }
    }

    /// The public check is the helper's own: what verifies there verifies
    /// here, and the size cap is the helper's default.
    #[test]
    fn the_public_verify_is_the_helper_s_check() {
        let key = SigningKey::generate(SignatureAlgorithm::MlDsa87);
        let trusted = trust(&[&key]);
        let manifest = manifest_for("acme-agent", "2.0.0", b"artifact");
        let bytes = signed(&manifest, &[&key]);
        assert_eq!(
            trusted
                .verify(&bytes, "2.0.0", ArtifactFormat::Deb)
                .unwrap(),
            manifest
        );
        assert!(matches!(
            trusted.verify(&bytes, "2.0.0", ArtifactFormat::Rpm),
            Err(FormatError::ManifestMismatch {
                field: "format",
                ..
            })
        ));
        assert!(matches!(
            trust(&[&SigningKey::generate(SignatureAlgorithm::MlDsa87)]).verify(
                &bytes,
                "2.0.0",
                ArtifactFormat::Deb
            ),
            Err(FormatError::SignatureMismatch)
        ));
        let mut huge = manifest_for("acme-agent", "2.0.0", b"artifact");
        huge.size = crate::MAX_ARTIFACT_BYTES + 1;
        assert!(matches!(
            trusted.verify(&signed(&huge, &[&key]), "2.0.0", ArtifactFormat::Deb),
            Err(FormatError::ArtifactTooLarge { .. })
        ));
        // The helper's own, lower cap.
        assert!(matches!(
            trusted.verify_with_limit(&bytes, "2.0.0", ArtifactFormat::Deb, 7),
            Err(FormatError::ArtifactTooLarge { limit: 7 })
        ));
        assert_eq!(
            trusted
                .verify_with_limit(&bytes, "2.0.0", ArtifactFormat::Deb, 8)
                .unwrap(),
            manifest
        );
    }

    #[test]
    fn verifies_under_every_algorithm_and_any_key_of_a_rotating_set() {
        for algorithm in ALGORITHMS {
            let key = SigningKey::generate(algorithm);
            let manifest = manifest_for("acme-agent", "2.0.0", b"artifact");
            let bytes = signed(&manifest, &[&key]);
            assert_eq!(
                verify_manifest(
                    &bytes,
                    &trust(&[&key]),
                    "2.0.0",
                    ArtifactFormat::Deb,
                    u64::MAX
                )
                .unwrap(),
                manifest,
                "{algorithm:?}"
            );
        }
        // Rotation: old + new signatures; devices trusting either verify.
        let old = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let new = SigningKey::generate(SignatureAlgorithm::MlDsa87);
        let bytes = signed(&manifest_for("acme-agent", "2.0.0", b"x"), &[&old, &new]);
        for trusted in [trust(&[&old]), trust(&[&new]), trust(&[&new, &old])] {
            verify_manifest(&bytes, &trusted, "2.0.0", ArtifactFormat::Deb, u64::MAX).unwrap();
        }
        // A device trusting only a third key refuses.
        let other = SigningKey::generate(SignatureAlgorithm::Ed25519);
        assert!(matches!(
            verify_manifest(
                &bytes,
                &trust(&[&other]),
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX
            ),
            Err(FormatError::SignatureMismatch)
        ));
    }

    /// A validly signed manifest for another version, target, product,
    /// channel or format is refused.
    #[test]
    fn signed_manifests_for_another_release_are_refused() {
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let base = manifest_for("acme-agent", "2.0.0", b"x");
        let cases: Vec<(ReleaseManifest, &str)> = vec![
            (
                ReleaseManifest {
                    version: "1.0.0".into(),
                    ..base.clone()
                },
                "version",
            ),
            (
                ReleaseManifest {
                    target: "aarch64-unknown-linux-gnu".into(),
                    ..base.clone()
                },
                "target",
            ),
            (
                ReleaseManifest {
                    product: "acme-console".into(),
                    ..base.clone()
                },
                "product",
            ),
            (
                ReleaseManifest {
                    channel: Some("beta".into()),
                    ..base.clone()
                },
                "channel",
            ),
            // Another format of the same release is refused.
            (
                ReleaseManifest {
                    format: ArtifactFormat::Rpm,
                    ..base.clone()
                },
                "format",
            ),
        ];
        for (manifest, field) in cases {
            let bytes = signed(&manifest, &[&key]);
            match verify_manifest(
                &bytes,
                &trust(&[&key]),
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX,
            ) {
                Err(FormatError::ManifestMismatch { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{field}: expected ManifestMismatch, got {other:?}"),
            }
        }
        // A channel-configured device refuses a channel-less release.
        let trusted = trust(&[&key]).channel("stable").unwrap();
        assert!(matches!(
            verify_manifest(
                &signed(&base, &[&key]),
                &trusted,
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX
            ),
            Err(FormatError::ManifestMismatch {
                field: "channel",
                ..
            })
        ));
        // Oversized release refused before any download.
        assert!(matches!(
            verify_manifest(
                &signed(&base, &[&key]),
                &trust(&[&key]),
                "2.0.0",
                ArtifactFormat::Deb,
                0
            ),
            Err(FormatError::ArtifactTooLarge { limit: 0 })
        ));
    }

    #[test]
    fn a_tampered_statement_or_foreign_key_id_fails_the_signature() {
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let bytes = signed(&manifest_for("acme-agent", "2.0.0", b"x"), &[&key]);
        // Flip the digest (still canonical): the signature no longer covers it.
        let text = String::from_utf8(bytes.clone()).unwrap();
        let digest_start = text.find("digest=sha512:").unwrap() + "digest=sha512:".len();
        let mut tampered = text.into_bytes();
        tampered[digest_start] = if tampered[digest_start] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(matches!(
            verify_manifest(
                &tampered,
                &trust(&[&key]),
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX
            ),
            Err(FormatError::SignatureMismatch)
        ));
        // A signature line naming a key id the device doesn't trust is
        // skipped, even when its signature would verify.
        let mut foreign = ReleaseManifest::decode_signed(&bytes).unwrap();
        foreign.1[0].key_id = [0; KEY_ID_LEN];
        let relabeled = foreign.0.encode_signed(&foreign.1).unwrap();
        assert!(matches!(
            verify_manifest(
                &relabeled,
                &trust(&[&key]),
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX
            ),
            Err(FormatError::SignatureMismatch)
        ));
    }

    #[test]
    fn a_bare_digest_signature_never_verifies_as_a_manifest() {
        // A signature over `seaworthy-release:1:sha512:` ‖ digest (a
        // bare-digest release signature) is not a manifest statement, so it
        // can never be replayed as one.
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let manifest = manifest_for("acme-agent", "2.0.0", b"x");
        let mut bare_message = b"seaworthy-release:1:sha512:".to_vec();
        bare_message.extend_from_slice(&manifest.digest);
        let forged = manifest.encode_signed(&[key.sign(&bare_message)]).unwrap();
        assert!(matches!(
            verify_manifest(
                &forged,
                &trust(&[&key]),
                "2.0.0",
                ArtifactFormat::Deb,
                u64::MAX
            ),
            Err(FormatError::SignatureMismatch)
        ));
    }

    #[test]
    fn trust_configuration_is_validated() {
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        assert!(ManifestTrust::new("acme-agent", []).is_err());
        assert!(ManifestTrust::new("acme agent", [key.release_key()]).is_err());
        assert!(ManifestTrust::new("", [key.release_key()]).is_err());
        assert!(
            ManifestTrust::new("acme-agent", [key.release_key()])
                .unwrap()
                .channel("../beta")
                .is_err()
        );
    }

    #[test]
    fn key_ids_bind_the_algorithm_and_are_the_digests_prefix() {
        let key = [7u8; 32];
        assert_ne!(
            release_key_id(SignatureAlgorithm::Ed25519, &key),
            release_key_id(SignatureAlgorithm::MlDsa87, &key)
        );
        let mut preimage = b"seaworthy-release-key:1:ed25519:".to_vec();
        preimage.extend_from_slice(&key);
        assert_eq!(
            release_key_id(SignatureAlgorithm::Ed25519, &key),
            seaworthy_crypto::digest::sha256(&preimage)[..KEY_ID_LEN]
        );
    }
}
