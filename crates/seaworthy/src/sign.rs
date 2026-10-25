//! Release-manifest signing: one
//! `seaworthy-release-manifest:1` per installable artifact, encoded by
//! `seaworthy_updater`'s own encoder, so the release side and the update helper
//! can never disagree on the format.
//!
//! Signatures come from [`ManifestSigner`]s, one interface for every
//! custody model:
//!
//! - [`LocalKey`]: a key file on the build host (hex, as
//!   `seaworthy_updater`'s `sign_release` example and [`generate_key`] write
//!   it). For tests and throwaway CI keys; refused when the opened file is
//!   accessible to group or others (Unix; Windows has no such check).
//! - [`CommandSigner`]: any external program that reads the statement on
//!   stdin and writes the signature on stdout, with the public key from a
//!   file. The production signers (a secret store's ML-DSA key, a KMS)
//!   plug in here without code changes. It runs with no shell, under a
//!   timeout, with its output capped.
//!
//! Policy, before anything is signed ([`check_policy`]):
//!
//! - the signers cover exactly the algorithms `seaworthy.toml`'s
//!   `release-signatures` lists, one signer each;
//! - each signer's public key is one of `release-keys`, the keys the
//!   product's clients embed (the files the update helper is built with):
//!   a key that's merely well formed, a staging key or a stale one, would
//!   pass every other check and fail on every client;
//! - each key passes `seaworthy_updater`'s own intake (`ReleaseKey::new`: well
//!   formed, not degenerate, an approved service under `seaworthy_crypto/fips`).
//!
//! Every signature a signer returns is verified against its public key
//! before it's written, so a misconfigured command (the wrong key, a
//! truncated output) fails the build instead of every client.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use seaworthy_updater::{
    ArtifactFormat, DigestAlgorithm, ManifestSignature, ReleaseKey, ReleaseManifest,
    SignatureAlgorithm,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::DistError;
use crate::config::Config;
use crate::version::Release;

/// The longest key file read (a PKCS#8 ML-DSA-87 document is under 5 KiB of
/// hex).
const MAX_KEY_FILE: u64 = 64 << 10;

/// The most a command signer may print on stdout (an ML-DSA-87 signature
/// in hex is under 10 KiB).
const MAX_SIGNER_OUTPUT: usize = 1 << 20;

/// A command signer's default deadline.
pub const DEFAULT_SIGNER_TIMEOUT: Duration = Duration::from_secs(120);

/// The manifest file of an artifact: `<artifact>.manifest`, where the
/// update helper fetches it (`{artifact url}.manifest`).
#[must_use]
pub fn manifest_path(artifact: &Path) -> PathBuf {
    let mut name = artifact.as_os_str().to_owned();
    name.push(".manifest");
    PathBuf::from(name)
}

/// `seaworthy_updater`'s algorithm for a `seaworthy.toml` one.
#[must_use]
pub fn algorithm(configured: crate::config::SignatureAlgorithm) -> SignatureAlgorithm {
    match configured {
        crate::config::SignatureAlgorithm::MlDsa87 => SignatureAlgorithm::MlDsa87,
        crate::config::SignatureAlgorithm::EcdsaP256 => SignatureAlgorithm::EcdsaP256,
        crate::config::SignatureAlgorithm::Ed25519 => SignatureAlgorithm::Ed25519,
    }
}

/// A source of release-manifest signatures.
pub trait ManifestSigner {
    /// The key's algorithm.
    fn algorithm(&self) -> SignatureAlgorithm;
    /// The public key, as clients embed it (`ReleaseKey::new`).
    fn public_key(&self) -> &[u8];
    /// The raw signature over `statement`.
    ///
    /// # Errors
    /// [`DistError::Sign`] when the signer fails.
    fn sign(&self, statement: &[u8]) -> Result<Vec<u8>, DistError>;
    /// What this signer is, for messages (never secret material).
    fn describe(&self) -> String;
}

enum Secret {
    MlDsa87(seaworthy_crypto::mldsa::SigningKey),
    EcdsaP256(seaworthy_crypto::ecdsa::SigningKey),
    Ed25519(seaworthy_crypto::ed25519::SigningKey),
}

/// A release key held in a file on the build host.
pub struct LocalKey {
    secret: Secret,
    public_key: Vec<u8>,
    source: String,
}

impl std::fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKey")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Hex text decoded into a buffer sized up front, so no reallocation
/// leaves a copy of a secret behind.
fn decode_hex(text: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, DistError> {
    let text = text.trim();
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(DistError::Sign(format!("{what} must be hex")));
    }
    let mut bytes = Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode_to_slice(text, &mut bytes)
        .map_err(|_| DistError::Sign(format!("{what} must be hex")))?;
    Ok(bytes)
}

/// Opens a private key file and checks it on the opened handle (no window
/// between the check and the read): a regular file of at most `max`
/// bytes, and on Unix not accessible to group or others at all (`what`
/// names it in that message). The open doesn't block, so a FIFO at the
/// path is refused rather than waited on.
///
/// # Errors
/// [`DistError::Io`]; [`DistError::Sign`] for loose permissions or a path
/// that isn't a regular file of at most `max` bytes.
pub(crate) fn open_private(
    path: &Path,
    max: u64,
    what: &str,
) -> Result<(std::fs::File, u64), DistError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| DistError::io(path, e))?;
    let metadata = file.metadata().map_err(|e| DistError::io(path, e))?;
    // Only the Unix mode check names the file's role.
    #[cfg(not(unix))]
    let _ = what;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(DistError::Sign(format!(
                "{} is accessible to group or others (mode {:o}); {what} must be 0600",
                path.display(),
                mode & 0o777
            )));
        }
    }
    if !metadata.is_file() || metadata.len() > max {
        return Err(DistError::Sign(format!(
            "{} is not a key file",
            path.display()
        )));
    }
    Ok((file, metadata.len()))
}

impl LocalKey {
    /// A key from hex: ML-DSA-87's 32-byte seed or a PKCS#8 document;
    /// ECDSA P-256 and Ed25519 PKCS#8 documents.
    ///
    /// # Errors
    /// [`DistError::Sign`] for text that isn't a key of `algorithm`.
    pub fn from_hex(
        algorithm: SignatureAlgorithm,
        hex_text: &str,
        source: &str,
    ) -> Result<Self, DistError> {
        let bytes = decode_hex(hex_text, &format!("the key in {source}"))?;
        let refused = |e: seaworthy_crypto::CryptoError| {
            DistError::Sign(format!("{source} is not a {} key: {e}", algorithm.tag()))
        };
        let (secret, public_key) = match algorithm {
            SignatureAlgorithm::MlDsa87 => {
                let key = if bytes.len() == seaworthy_crypto::mldsa::SEED_LEN {
                    seaworthy_crypto::mldsa::SigningKey::from_seed(&bytes)
                } else {
                    seaworthy_crypto::mldsa::SigningKey::from_pkcs8(&bytes)
                }
                .map_err(refused)?;
                let public = key.public_key().to_vec();
                (Secret::MlDsa87(key), public)
            }
            SignatureAlgorithm::EcdsaP256 => {
                let key =
                    seaworthy_crypto::ecdsa::SigningKey::from_pkcs8(&bytes).map_err(refused)?;
                let public = key.public_key_der();
                (Secret::EcdsaP256(key), public)
            }
            SignatureAlgorithm::Ed25519 => {
                let key =
                    seaworthy_crypto::ed25519::SigningKey::from_pkcs8(&bytes).map_err(refused)?;
                let public = key.public_key().to_vec();
                (Secret::Ed25519(key), public)
            }
        };
        Ok(Self {
            secret,
            public_key,
            source: source.to_owned(),
        })
    }

    /// A key from a file holding its hex. The file is opened first and its
    /// permissions checked on the opened handle (no window between the
    /// check and the read): on Unix it must not be accessible to group or
    /// others at all.
    ///
    /// # Errors
    /// [`DistError::Io`]; [`DistError::Sign`] for loose permissions, an
    /// oversized file, or one that isn't a key of `algorithm`.
    pub fn from_file(algorithm: SignatureAlgorithm, path: &Path) -> Result<Self, DistError> {
        let (mut file, len) = open_private(path, MAX_KEY_FILE, "a release key file")?;
        let capacity = usize::try_from(len).unwrap_or(0);
        let mut text = Zeroizing::new(String::with_capacity(capacity));
        // Read into the buffer sized for the whole file: no reallocation.
        (&mut file)
            .take(MAX_KEY_FILE)
            .read_to_string(&mut text)
            .map_err(|e| DistError::io(path, e))?;
        Self::from_hex(algorithm, &text, &path.display().to_string())
    }
}

impl ManifestSigner for LocalKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        match self.secret {
            Secret::MlDsa87(_) => SignatureAlgorithm::MlDsa87,
            Secret::EcdsaP256(_) => SignatureAlgorithm::EcdsaP256,
            Secret::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, statement: &[u8]) -> Result<Vec<u8>, DistError> {
        match &self.secret {
            Secret::MlDsa87(key) => Ok(key.sign(statement).to_vec()),
            Secret::EcdsaP256(key) => key
                .sign(statement)
                .map_err(|e| DistError::Sign(format!("{}: {e}", self.source))),
            Secret::Ed25519(key) => Ok(key.sign(statement).to_vec()),
        }
    }

    fn describe(&self) -> String {
        format!("{} key file {}", self.algorithm().tag(), self.source)
    }
}

/// How a [`CommandSigner`]'s program writes the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Output {
    /// The raw signature bytes.
    Raw,
    /// The signature as hex (surrounding whitespace ignored).
    #[default]
    Hex,
}

/// An external signing program: the statement on stdin, the signature on
/// stdout. It runs with the build's environment (credentials for a KMS or
/// a secret store come from there), no shell, a deadline, and a cap on what
/// it may print.
#[derive(Debug)]
pub struct CommandSigner {
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
    command: Vec<String>,
    output: Output,
    timeout: Duration,
}

impl CommandSigner {
    /// A signer running `command` (program first) for a key of
    /// `algorithm` whose public key is `public_key`, under `timeout` (1 s
    /// to an hour).
    ///
    /// # Errors
    /// [`DistError::Sign`] for an empty command or a timeout out of range.
    pub fn new(
        algorithm: SignatureAlgorithm,
        public_key: Vec<u8>,
        command: Vec<String>,
        output: Output,
        timeout: Duration,
    ) -> Result<Self, DistError> {
        if command.first().is_none_or(String::is_empty) {
            return Err(DistError::Sign(
                "a command signer needs a program".to_owned(),
            ));
        }
        let timeout = crate::process::check_timeout(timeout, "a manifest signing command")?;
        Ok(Self {
            algorithm,
            public_key,
            command,
            output,
            timeout,
        })
    }
}

impl ManifestSigner for CommandSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, statement: &[u8]) -> Result<Vec<u8>, DistError> {
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| DistError::Sign("a command signer needs a program".to_owned()))?;
        let mut command = Command::new(program);
        command.args(args);
        let finished = crate::process::run(
            &mut command,
            "manifest signer",
            Some(statement.to_vec()),
            self.timeout,
            MAX_SIGNER_OUTPUT,
        )
        .map_err(|e| DistError::Sign(e.to_string()))?;
        if !finished.status.success() {
            return Err(DistError::Sign(format!(
                "{program} failed ({}): {}",
                finished.status,
                finished.shown()
            )));
        }
        if finished.stdout_overflow {
            return Err(DistError::Sign(format!(
                "{program} printed more than {MAX_SIGNER_OUTPUT} bytes"
            )));
        }
        match self.output {
            Output::Raw => Ok(finished.stdout),
            Output::Hex => {
                let text = String::from_utf8(finished.stdout).map_err(|_| {
                    DistError::Sign(format!("{program} printed something other than hex"))
                })?;
                decode_hex(&text, &format!("{program}'s output")).map(|bytes| bytes.to_vec())
            }
        }
    }

    fn describe(&self) -> String {
        format!(
            "{} command {}",
            self.algorithm.tag(),
            self.command.first().map_or("", String::as_str)
        )
    }
}

/// A freshly generated key: its secret as hex (for a 0600 file; ML-DSA-87
/// writes the 32-byte seed, the others PKCS#8) and its public key.
pub struct GeneratedKey {
    /// The secret, hex.
    pub secret_hex: Zeroizing<String>,
    /// The public key, as clients embed it.
    pub public_key: Vec<u8>,
    /// Its id on manifest signature lines.
    pub key_id: [u8; seaworthy_updater::KEY_ID_LEN],
}

/// A new release key of `algorithm`: for tests and throwaway CI keys. A
/// production key is generated in its custody system.
///
/// # Errors
/// [`DistError::Sign`] when the random source or key generation fails.
pub fn generate_key(algorithm: SignatureAlgorithm) -> Result<GeneratedKey, DistError> {
    let failed = |e: seaworthy_crypto::CryptoError| DistError::Sign(format!("key generation: {e}"));
    let (secret_hex, public_key) = match algorithm {
        SignatureAlgorithm::MlDsa87 => {
            let mut seed = Zeroizing::new([0u8; seaworthy_crypto::mldsa::SEED_LEN]);
            seaworthy_crypto::rand::fill(&mut *seed).map_err(failed)?;
            let key = seaworthy_crypto::mldsa::SigningKey::from_seed(&*seed).map_err(failed)?;
            (
                Zeroizing::new(hex::encode(seed.as_slice())),
                key.public_key().to_vec(),
            )
        }
        SignatureAlgorithm::EcdsaP256 => {
            let (key, pkcs8) =
                seaworthy_crypto::ecdsa::SigningKey::generate_pkcs8().map_err(failed)?;
            (Zeroizing::new(hex::encode(&*pkcs8)), key.public_key_der())
        }
        SignatureAlgorithm::Ed25519 => {
            let (key, pkcs8) =
                seaworthy_crypto::ed25519::SigningKey::generate_pkcs8().map_err(failed)?;
            (
                Zeroizing::new(hex::encode(&*pkcs8)),
                key.public_key().to_vec(),
            )
        }
    };
    let key = ReleaseKey::new(public_key, algorithm).map_err(|e| DistError::Sign(e.to_string()))?;
    Ok(GeneratedKey {
        secret_hex,
        public_key: key.public_key().to_vec(),
        key_id: key.key_id(),
    })
}

/// Checks `signers` against the product policy: exactly one signer per
/// `release-signatures` algorithm, none for another, every public key one
/// of `release-keys` and accepted by `seaworthy_updater`'s intake. Returns each
/// signer's key, as clients embed it.
///
/// # Errors
/// [`DistError::Sign`] naming the gap or the refused key;
/// [`DistError::Config`] / [`DistError::Io`] for unreadable `release-keys`.
pub fn check_policy(
    config: &Config,
    signers: &[Box<dyn ManifestSigner>],
) -> Result<Vec<ReleaseKey>, DistError> {
    let required: Vec<SignatureAlgorithm> = config
        .defaults
        .release_signatures
        .iter()
        .map(|a| algorithm(*a))
        .collect();
    if required.is_empty() {
        // No release manifests: nothing to sign, and a signer is a
        // mistake in the signing configuration.
        return match signers.first() {
            None => Ok(Vec::new()),
            Some(signer) => Err(DistError::Sign(format!(
                "{}: seaworthy.toml signs no release manifests (defaults.release-signatures is empty): drop the release-manifest signer from the signing configuration, or list the algorithm",
                signer.describe()
            ))),
        };
    }
    let trusted = config.release_keys()?;
    if trusted.is_empty() {
        return Err(DistError::Sign(
            "defaults.release-keys is empty: list the release public keys the products' clients trust, and sign only with one of them".to_owned(),
        ));
    }
    let mut keys: Vec<ReleaseKey> = Vec::new();
    for signer in signers {
        let alg = signer.algorithm();
        if !required.contains(&alg) {
            return Err(DistError::Sign(format!(
                "{}: defaults.release-signatures doesn't admit {} (it lists {}); the product's clients would refuse this key",
                signer.describe(),
                alg.tag(),
                required
                    .iter()
                    .map(|a| a.tag())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if keys.iter().any(|k| k.algorithm() == alg) {
            return Err(DistError::Sign(format!("two signers for {}", alg.tag())));
        }
        let key = ReleaseKey::new(signer.public_key().to_vec(), alg)
            .map_err(|e| DistError::Sign(format!("{}: {e}", signer.describe())))?;
        if !trusted
            .iter()
            .any(|t| t.algorithm() == alg && t.public_key() == key.public_key())
        {
            return Err(DistError::Sign(format!(
                "{}: key {} is not one of defaults.release-keys; no client would accept its manifests",
                signer.describe(),
                hex::encode(key.key_id())
            )));
        }
        keys.push(key);
    }
    for alg in &required {
        if !keys.iter().any(|k| k.algorithm() == *alg) {
            return Err(DistError::Sign(format!(
                "defaults.release-signatures requires a {} signature and no signer provides one",
                alg.tag()
            )));
        }
    }
    Ok(keys)
}

/// The manifest file for `manifest`, signed by every signer, each
/// signature verified against its signer's public key first.
///
/// # Errors
/// [`DistError::Sign`] when a signer fails or returns a signature its own
/// public key doesn't verify; the manifest's own validation errors.
pub fn sign_manifest(
    manifest: &ReleaseManifest,
    signers: &[Box<dyn ManifestSigner>],
) -> Result<Vec<u8>, DistError> {
    let statement = manifest
        .statement()
        .map_err(|e| DistError::Sign(format!("the release statement: {e}")))?;
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let alg = signer.algorithm();
        // The key as clients hold it: its id is theirs.
        let key = ReleaseKey::new(signer.public_key().to_vec(), alg)
            .map_err(|e| DistError::Sign(format!("{}: {e}", signer.describe())))?;
        let signature = signer.sign(&statement)?;
        if !verify_signature(alg, key.public_key(), &statement, &signature) {
            return Err(DistError::Sign(format!(
                "{} returned a signature its public key doesn't verify (the wrong key, or a damaged output)",
                signer.describe()
            )));
        }
        signatures.push(ManifestSignature {
            algorithm: alg,
            key_id: key.key_id(),
            signature,
        });
    }
    manifest
        .encode_signed(&signatures)
        .map_err(|e| DistError::Sign(format!("the signed manifest: {e}")))
}

/// Checks a signed manifest file the way a release is published: it
/// parses strictly, every algorithm `release-signatures` requires has a
/// signature by one of `release-keys` that verifies, and its statement is
/// exactly `expected` (the artifact's own [`manifest_for`]: product,
/// channel, version, build, sequence, target, format, size and digest).
///
/// # Errors
/// [`DistError::Sign`] naming the first problem;
/// [`DistError::Config`] / [`DistError::Io`] for unreadable `release-keys`.
pub fn check_manifest(
    config: &Config,
    signed: &[u8],
    expected: &ReleaseManifest,
) -> Result<(), DistError> {
    let (manifest, signatures) = ReleaseManifest::decode_signed(signed)
        .map_err(|e| DistError::Sign(format!("the manifest doesn't parse: {e}")))?;
    let statement = manifest
        .statement()
        .map_err(|e| DistError::Sign(format!("the manifest's statement: {e}")))?;
    let trusted = config.release_keys()?;
    for required in &config.defaults.release_signatures {
        let alg = algorithm(*required);
        let verified = signatures.iter().any(|signature| {
            signature.algorithm == alg
                && trusted.iter().any(|key| {
                    key.algorithm() == alg
                        && key.key_id() == signature.key_id
                        && verify_signature(alg, key.public_key(), &statement, &signature.signature)
                })
        });
        if !verified {
            return Err(DistError::Sign(format!(
                "no {} signature by one of defaults.release-keys verifies",
                alg.tag()
            )));
        }
    }
    if manifest != *expected {
        let describe = |m: &ReleaseManifest| {
            format!(
                "{} {} ({} {}, {} bytes)",
                m.product,
                m.token(),
                m.target,
                m.format.tag(),
                m.size
            )
        };
        return Err(DistError::Sign(format!(
            "it describes {}, not this artifact, {}{}",
            describe(&manifest),
            describe(expected),
            if manifest.digest == expected.digest {
                ""
            } else {
                ", or other bytes"
            }
        )));
    }
    Ok(())
}

/// One signature over `message` verifies under `public_key`.
fn verify_signature(
    alg: SignatureAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match alg {
        SignatureAlgorithm::MlDsa87 => {
            seaworthy_crypto::mldsa::verify(public_key, message, signature)
        }
        SignatureAlgorithm::EcdsaP256 => {
            seaworthy_crypto::ecdsa::verify(public_key, message, signature)
        }
        SignatureAlgorithm::Ed25519 => {
            seaworthy_crypto::ed25519::verify(public_key, message, signature)
        }
    }
    .is_ok()
}

/// What identifies a build beyond its version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildId {
    /// The version token's build metadata (after `+`, often the commit):
    /// the manifest's `build` field, so a manifest matches only the exact
    /// build the version-gate server names.
    pub metadata: String,
}

/// The release statement for one artifact of product `id`: its product
/// (the package name, `<vendor>-<id>`), channel, version, build and
/// sequence, target, format, size and SHA-512.
///
/// # Errors
/// [`DistError::Io`] when the artifact can't be read.
pub fn manifest_for(
    config: &Config,
    id: &str,
    release: &Release,
    build: &BuildId,
    target: &str,
    format: ArtifactFormat,
    artifact: &Path,
) -> Result<ReleaseManifest, DistError> {
    let bytes = std::fs::read(artifact).map_err(|e| DistError::io(artifact, e))?;
    manifest_for_bytes(config, id, release, build, target, format, &bytes)
}

/// [`manifest_for`] over an artifact's bytes already read (`repo` reads
/// each published file once, and checks what it read).
///
/// # Errors
/// [`DistError::Sign`] for an artifact over 2^64 bytes.
pub fn manifest_for_bytes(
    config: &Config,
    id: &str,
    release: &Release,
    build: &BuildId,
    target: &str,
    format: ArtifactFormat,
    bytes: &[u8],
) -> Result<ReleaseManifest, DistError> {
    let size = u64::try_from(bytes.len())
        .map_err(|_| DistError::Sign("an artifact over 2^64 bytes".to_owned()))?;
    Ok(ReleaseManifest {
        product: crate::linux::package_name(config, id),
        channel: Some(config.defaults.channel.clone()),
        version: release.version.to_string(),
        build: build.metadata.clone(),
        sequence: release.sequence,
        target: target.to_owned(),
        format,
        size,
        digest_algorithm: DigestAlgorithm::Sha512,
        digest: DigestAlgorithm::Sha512.hash(bytes),
    })
}

/// `signing.toml`: where `package`'s signatures come from. Environment
/// specific (CI), so it's never part of `seaworthy.toml`. Relative paths resolve
/// against the file's own directory, a command's program included when it
/// names a path (`./signer.sh`; a bare name is looked up on `PATH`).
///
/// ```toml
/// [[manifest]]                       # one per release-signatures algorithm
/// algorithm = "ml-dsa-87"
/// public-key = "release-mldsa87.pub" # hex; must be one of seaworthy.toml's release-keys
/// command = ["kms-sign", "release"]  # statement on stdin, signature on stdout
/// output = "hex"                     # or "raw"
/// timeout-seconds = 120
///
/// [[manifest]]
/// algorithm = "ed25519"
/// key = "test-ed25519.key"           # a local key file (hex, mode 0600)
///
/// [[manifest]]
/// algorithm = "ecdsa-p256"
/// key-env = "RELEASE_KEY_HEX"        # the key's hex in this environment variable
///
/// [authenticode]                     # Windows binaries and the MSI
/// certificate = "codesign.pem"       # osslsigncode: PEM chain, leaf first
/// key = "codesign.key"               # PEM, mode 0600
/// timestamp-url = "http://timestamp.example"
/// # or: command = ["jsign", "…", "{file}"]   ({description} is the product's name)
/// timeout-seconds = 600              # the default; 1 to 3600
///
/// [openpgp]                          # rpm (embedded) and pacman (.sig)
/// home = "gnupg"                     # the gpg home holding or reaching the key
/// # or: secret-key-env = "REPO_KEY_ASC"   (an armored secret key, imported
/// #     into a private throwaway gpg home for the run)
/// key = "<fingerprint>"              # 40 or 64 hex characters
/// ```
///
/// A secret named by `key-env` or `secret-key-env` (a key held in a custody
/// system, handed to `seaworthy` in its environment) is
/// taken out of the binary's environment before anything runs, so no tool
/// `seaworthy` starts inherits it ([`SigningConfig::secret_variables`],
/// [`EnvSecrets`]).
///
/// Whose Authenticode and OpenPGP signatures count is `seaworthy.toml`'s
/// (`[defaults.authenticode]`, `openpgp-keys`), not this file's.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningConfig {
    /// The release-manifest signers.
    #[serde(default)]
    pub manifest: Vec<ManifestSignerConfig>,
    /// Authenticode.
    #[serde(default)]
    pub authenticode: Option<AuthenticodeConfig>,
    /// OpenPGP.
    #[serde(default)]
    pub openpgp: Option<OpenPgpConfig>,
}

impl SigningConfig {
    /// A dev build's configuration (`--authenticode-only`):
    /// `[authenticode]` alone, the release-manifest signers and `[openpgp]`
    /// dropped before anything reads their secrets. A dev build never signs
    /// as a release: a manifest signed with the release key would let the
    /// update helper install it.
    ///
    /// # Errors
    /// [`DistError::Sign`] when the configuration has no `[authenticode]`.
    pub fn authenticode_only(self) -> Result<Self, DistError> {
        if self.authenticode.is_none() {
            return Err(DistError::Sign(
                "--authenticode-only: the signing configuration has no [authenticode]".to_owned(),
            ));
        }
        Ok(Self {
            manifest: Vec::new(),
            authenticode: self.authenticode,
            openpgp: None,
        })
    }
}

/// `[authenticode]`: osslsigncode with a local certificate and key, or a
/// command.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct AuthenticodeConfig {
    /// The PEM certificate chain (osslsigncode).
    #[serde(default)]
    pub certificate: Option<PathBuf>,
    /// The PEM private key (osslsigncode; mode 0600).
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// An RFC 3161 timestamping service (osslsigncode).
    #[serde(default)]
    pub timestamp_url: Option<String>,
    /// The vendor's URL signed in (osslsigncode).
    #[serde(default)]
    pub url: Option<String>,
    /// The osslsigncode binary (default `osslsigncode`).
    #[serde(default)]
    pub tool: Option<PathBuf>,
    /// A signing command instead (`{file}`, `{description}`).
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// One signature's deadline (default 600 s; at most 3600).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// `[openpgp]`: gpg (and rpmsign) with a key in a gpg home, or an armored
/// secret key from the environment imported into a throwaway one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct OpenPgpConfig {
    /// The gpg home (or `secret-key-env`).
    #[serde(default)]
    pub home: Option<PathBuf>,
    /// The environment variable holding the armored secret key (or `home`).
    #[serde(default)]
    pub secret_key_env: Option<String>,
    /// A file holding the armored secret key (or `home`): the CI test
    /// key's, a public test key kept in the repository — never a real
    /// one, which comes through `secret-key-env`.
    #[serde(default)]
    pub secret_key_file: Option<PathBuf>,
    /// The key's fingerprint (40 or 64 hex characters).
    pub key: String,
    /// The gpg binary (default `gpg`).
    #[serde(default)]
    pub gpg: Option<PathBuf>,
    /// The rpmsign binary (default `rpmsign`).
    #[serde(default)]
    pub rpmsign: Option<PathBuf>,
    /// One signature's deadline (default 600 s; at most 3600).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// `path` resolved against `base` when it names a relative path
/// (`./x`, `keys/x`), as given otherwise (an absolute path, a bare program
/// name for `PATH`).
fn beside(base: &Path, path: &Path, program: bool) -> PathBuf {
    let relative_path = !path.is_absolute() && (!program || path.components().count() > 1);
    if relative_path {
        base.join(path)
    } else {
        path.to_path_buf()
    }
}

/// One `[[manifest]]` entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ManifestSignerConfig {
    /// The key's algorithm.
    pub algorithm: crate::config::SignatureAlgorithm,
    /// A local key file (hex).
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// The environment variable holding the key's hex (a custody system's
    /// key, handed over for the run).
    #[serde(default)]
    pub key_env: Option<String>,
    /// The public key file (hex), with `command`.
    #[serde(default)]
    pub public_key: Option<PathBuf>,
    /// The signing program and its arguments.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// How the program writes the signature (with `command`).
    #[serde(default)]
    pub output: Option<Output>,
    /// The program's deadline (with `command`; default 120 s).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// One secret taken from the environment: wiped on drop, and never shown
/// by `Debug` (a stray `{:?}` prints `EnvSecret(..)`, not the key).
pub struct EnvSecret(Zeroizing<String>);

impl EnvSecret {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
}

impl std::ops::Deref for EnvSecret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for EnvSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvSecret(..)")
    }
}

/// The secrets a signing configuration takes from the environment, by
/// variable name ([`SigningConfig::secret_variables`]): the `seaworthy`
/// binary reads and removes them before it runs anything, and hands them
/// to [`SigningConfig::signing_with`].
pub type EnvSecrets = std::collections::BTreeMap<String, EnvSecret>;

/// The longest secret taken from the environment (an armored OpenPGP
/// secret key with an RSA-4096 subkey is under 16 KiB).
pub const MAX_ENV_SECRET: usize = 64 << 10;

/// Whether `name` is an environment variable name `key-env` and
/// `secret-key-env` accept: `[A-Z_][A-Z0-9_]*`, at most 128 characters.
#[must_use]
pub fn is_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && name.len() <= 128
}

/// The secret named `name` in `secrets`, or why it's missing.
fn env_secret<'a>(
    secrets: &'a EnvSecrets,
    name: &str,
    what: &str,
) -> Result<&'a EnvSecret, DistError> {
    secrets.get(name).ok_or_else(|| {
        DistError::Sign(format!(
            "{what}: the environment variable {name} isn't set (the secrets wrapper hands the key over in it)"
        ))
    })
}

impl SigningConfig {
    /// The environment variables this file takes secrets from
    /// (`key-env`, `secret-key-env`), in order, each once.
    #[must_use]
    pub fn secret_variables(&self) -> Vec<&str> {
        let mut names = self.manifest_variables();
        names.extend(self.openpgp_variables());
        let mut seen = std::collections::BTreeSet::new();
        names.retain(|n| seen.insert(*n));
        names
    }

    /// The variables the manifest signers take (`key-env`): what
    /// `package` needs, `repo` doesn't.
    #[must_use]
    pub fn manifest_variables(&self) -> Vec<&str> {
        self.manifest
            .iter()
            .filter_map(|m| m.key_env.as_deref())
            .collect()
    }

    /// The variable the OpenPGP signer takes (`secret-key-env`), if any:
    /// what `repo` needs (and `package`, for rpm and pacman).
    #[must_use]
    pub fn openpgp_variables(&self) -> Vec<&str> {
        self.openpgp
            .iter()
            .filter_map(|o| o.secret_key_env.as_deref())
            .collect()
    }

    /// Every signer this file names, checked and ready, with no secrets
    /// from the environment ([`SigningConfig::signing_with`]).
    ///
    /// # Errors
    /// As [`SigningConfig::signing_with`].
    pub fn signing(&self, base: &Path) -> Result<crate::package::Signing, DistError> {
        self.signing_with(base, &EnvSecrets::new())
    }

    /// Every signer this file names, checked and ready.
    ///
    /// # Errors
    /// As [`SigningConfig::manifest_signers`]; [`DistError::Sign`] for an
    /// `[authenticode]` with neither or both of the osslsigncode keys and a
    /// command, a signing key file others can read, an OpenPGP key not
    /// named by its fingerprint, or a timeout out of range.
    pub fn signing_with(
        &self,
        base: &Path,
        secrets: &EnvSecrets,
    ) -> Result<crate::package::Signing, DistError> {
        let deadline = |seconds: Option<u64>, what: &str| {
            seconds.map_or(Ok(crate::codesign::DEFAULT_TOOL_TIMEOUT), |s| {
                crate::process::check_timeout(Duration::from_secs(s), what)
            })
        };
        let mut osslsigncode = None;
        let authenticode: Option<Box<dyn crate::codesign::AuthenticodeSigner>> = match &self
            .authenticode
        {
            None => None,
            Some(a) => match (&a.certificate, &a.key, &a.command) {
                (Some(certificate), Some(key), None) => {
                    let tool = a
                        .tool
                        .as_ref()
                        .map_or_else(|| PathBuf::from("osslsigncode"), |t| beside(base, t, true));
                    osslsigncode = Some(tool.clone());
                    let signer = crate::codesign::Osslsigncode {
                        tool,
                        certificate: beside(base, certificate, false),
                        key: beside(base, key, false),
                        timestamp_url: a.timestamp_url.clone(),
                        url: a.url.clone(),
                        timeout: deadline(a.timeout_seconds, "[authenticode]")?,
                    };
                    signer.check_key()?;
                    Some(Box::new(signer))
                }
                (None, None, Some(command))
                    if a.tool.is_none() && a.timestamp_url.is_none() && a.url.is_none() =>
                {
                    let mut command = command.clone();
                    if let Some(program) = command.first_mut() {
                        *program = beside(base, Path::new(program.as_str()), true)
                            .to_string_lossy()
                            .into_owned();
                    }
                    let timeout = deadline(a.timeout_seconds, "[authenticode]")?;
                    Some(Box::new(crate::codesign::CommandAuthenticode {
                        command,
                        timeout,
                    }))
                }
                _ => {
                    return Err(DistError::Sign(
                        "[authenticode]: give either `certificate` and `key` (osslsigncode) or `command`".to_owned(),
                    ));
                }
            },
        };
        let (openpgp, gpg) = self.openpgp_with(base, secrets)?;
        Ok(crate::package::Signing {
            manifest: self.manifest_signers_with(base, secrets)?,
            authenticode,
            openpgp,
            osslsigncode,
            gpg,
            authenticode_only: false,
            ci_test: false,
        })
    }

    /// The `[openpgp]` signer (with the gpg it runs), if the file has one:
    /// a gpg home, or an armored key from `secrets` imported into a
    /// private throwaway home (`secret-key-env`). All `repo` needs.
    ///
    /// # Errors
    /// [`DistError::Sign`] for a key not named by its fingerprint, neither
    /// or both of `home` and `secret-key-env`, a missing secret, a timeout
    /// out of range, or a key that doesn't import (as
    /// [`crate::codesign::ImportedGpg::import`]).
    #[allow(clippy::type_complexity)]
    pub fn openpgp_with(
        &self,
        base: &Path,
        secrets: &EnvSecrets,
    ) -> Result<
        (
            Option<Box<dyn crate::codesign::OpenPgpSigner>>,
            Option<PathBuf>,
        ),
        DistError,
    > {
        let Some(o) = &self.openpgp else {
            return Ok((None, None));
        };
        if !crate::codesign::is_fingerprint(&o.key) {
            return Err(DistError::Sign(format!(
                "[openpgp] key must be the key's fingerprint (40 or 64 hex characters), not {:?}",
                o.key
            )));
        }
        let tool = o
            .gpg
            .as_ref()
            .map_or_else(|| PathBuf::from("gpg"), |g| beside(base, g, true));
        let timeout = o
            .timeout_seconds
            .map_or(Ok(crate::codesign::DEFAULT_TOOL_TIMEOUT), |s| {
                crate::process::check_timeout(Duration::from_secs(s), "[openpgp]")
            })?;
        let rpmsign = o
            .rpmsign
            .as_ref()
            .map_or_else(|| PathBuf::from("rpmsign"), |r| beside(base, r, true));
        let signer: Box<dyn crate::codesign::OpenPgpSigner> = match (
            &o.home,
            &o.secret_key_env,
            &o.secret_key_file,
        ) {
            (Some(home), None, None) => Box::new(crate::codesign::Gpg {
                home: beside(base, home, false),
                key: o.key.clone(),
                gpg: tool.clone(),
                rpmsign,
                timeout,
            }),
            (None, None, Some(file)) => {
                let path = beside(base, file, false);
                let armored = Zeroizing::new(
                    std::fs::read_to_string(&path).map_err(|e| DistError::io(&path, e))?,
                );
                Box::new(crate::codesign::ImportedGpg::import(
                    &armored,
                    &o.key,
                    tool.clone(),
                    rpmsign,
                    timeout,
                )?)
            }
            (None, Some(name), None) => {
                let armored = env_secret(secrets, name, "[openpgp] secret-key-env")?;
                Box::new(crate::codesign::ImportedGpg::import(
                    armored,
                    &o.key,
                    tool.clone(),
                    rpmsign,
                    timeout,
                )?)
            }
            _ => {
                return Err(DistError::Sign(
                    "[openpgp]: give one of `home` (a gpg home), `secret-key-env` (an armored secret key in the environment) or `secret-key-file` (the CI test key's file)".to_owned(),
                ));
            }
        };
        Ok((Some(signer), Some(tool)))
    }

    /// Reads `path`; returns it with the directory its relative paths
    /// resolve against.
    ///
    /// # Errors
    /// [`DistError::Io`]; [`DistError::Sign`] for invalid TOML.
    pub fn load(path: &Path) -> Result<(Self, PathBuf), DistError> {
        let text = std::fs::read_to_string(path).map_err(|e| DistError::io(path, e))?;
        let config: Self = toml::from_str(&text)
            .map_err(|e| DistError::Sign(format!("{}: {e}", path.display())))?;
        if let Some(bad) = config
            .manifest
            .iter()
            .filter_map(|m| m.key_env.as_deref())
            .chain(
                config
                    .openpgp
                    .iter()
                    .filter_map(|o| o.secret_key_env.as_deref()),
            )
            .find(|n| !is_variable_name(n))
        {
            return Err(DistError::Sign(format!(
                "{}: {bad:?} isn't an environment variable name ([A-Z_][A-Z0-9_]*, at most 128 characters)",
                path.display()
            )));
        }
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok((config, base))
    }

    /// The configured manifest signers, keys read and validated, with no
    /// secrets from the environment.
    ///
    /// # Errors
    /// As [`SigningConfig::manifest_signers_with`].
    pub fn manifest_signers(&self, base: &Path) -> Result<Vec<Box<dyn ManifestSigner>>, DistError> {
        self.manifest_signers_with(base, &EnvSecrets::new())
    }

    /// The configured manifest signers, keys read and validated: a local
    /// key file, a key from `secrets` (`key-env`), or a command.
    ///
    /// # Errors
    /// As [`LocalKey::from_file`]; [`DistError::Sign`] for an entry that
    /// isn't exactly one of a local key, a key from the environment or a
    /// command with a public key, that sets a command's options without a
    /// command, or whose `key-env` variable isn't in `secrets`.
    pub fn manifest_signers_with(
        &self,
        base: &Path,
        secrets: &EnvSecrets,
    ) -> Result<Vec<Box<dyn ManifestSigner>>, DistError> {
        let mut signers: Vec<Box<dyn ManifestSigner>> = Vec::new();
        for entry in &self.manifest {
            let alg = algorithm(entry.algorithm);
            let local = entry.output.is_none() && entry.timeout_seconds.is_none();
            match (
                &entry.key,
                &entry.key_env,
                &entry.command,
                &entry.public_key,
            ) {
                (Some(key), None, None, None) if local => {
                    signers.push(Box::new(LocalKey::from_file(alg, &base.join(key))?));
                }
                (None, Some(name), None, None) if local => {
                    let hex = env_secret(secrets, name, &format!("[[manifest]] {}", alg.tag()))?;
                    signers.push(Box::new(LocalKey::from_hex(alg, hex, &format!("${name}"))?));
                }
                (None, None, Some(command), Some(public_key)) => {
                    let path = base.join(public_key);
                    let text =
                        std::fs::read_to_string(&path).map_err(|e| DistError::io(&path, e))?;
                    let public =
                        decode_hex(&text, &format!("the public key in {}", path.display()))?;
                    let mut command = command.clone();
                    if let Some(program) = command.first_mut()
                        && program.contains('/')
                        && !Path::new(program.as_str()).is_absolute()
                    {
                        *program = base.join(&*program).to_string_lossy().into_owned();
                    }
                    let timeout = entry
                        .timeout_seconds
                        .map_or(DEFAULT_SIGNER_TIMEOUT, Duration::from_secs);
                    signers.push(Box::new(CommandSigner::new(
                        alg,
                        public.to_vec(),
                        command,
                        entry.output.unwrap_or_default(),
                        timeout,
                    )?));
                }
                _ => {
                    return Err(DistError::Sign(format!(
                        "[[manifest]] {}: give one of `key` (a local key file), `key-env` (the key's hex in an environment variable) or `command` with `public-key` (and `output`/`timeout-seconds` only with a command)",
                        alg.tag()
                    )));
                }
            }
        }
        Ok(signers)
    }
}
