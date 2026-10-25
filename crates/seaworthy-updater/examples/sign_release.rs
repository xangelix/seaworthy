//! Sign a release: the release-side half of the signed manifests the update
//! helper verifies ([`ManifestTrust`](seaworthy_updater::ManifestTrust)).
//!
//! Produces `{artifact}.manifest`: the canonical release statement
//! (product, channel, version, sequence, target triple, format, exact size,
//! digest — see [`ReleaseManifest`](seaworthy_updater::ReleaseManifest))
//! followed by one signature line per release key. The statement starts
//! with the `seaworthy-release-manifest:1` domain line, so a release key's
//! signature can never be replayed from or into another context; the
//! artifact itself is hashed here in 1 MiB chunks, never held whole in
//! memory. `--version` takes the version token the product's server
//! names; its build metadata (after `+`) becomes the manifest's `build`
//! field. `--format` names the package format (`deb`, `rpm`, `pacman`,
//! `msi`, `zip`, `tar`, `pkg`). Product packages are signed by the
//! seaworthy CLI when it packages; this example signs one artifact by
//! hand, for tests and one-off releases.
//!
//! Two modes, deliberately separate (secret-in-CI-logs hygiene: a signing
//! run never mints a key and prints it next to the build log):
//!
//! ```sh
//! # 1. Generate a release key — the ONLY way this tool prints a secret
//! #    (to stderr; move it into your secret store). The public key and its
//! #    key id go to stdout — embed the key in the app's ManifestTrust.
//! cargo run -p seaworthy-updater --example sign_release -- --generate-key <mldsa87|ecdsa-p256|ed25519>
//!
//! # 2. Sign — REQUIRES the key in the environment.
//! SEAWORTHY_RELEASE_KEY_HEX=<hex> cargo run -p seaworthy-updater --example sign_release -- \
//!   <mldsa87|ecdsa-p256|ed25519> <artifact> --product <id> --version <v> --sequence <n> \
//!   --target <triple> --format <tag> [--channel <name>] [--digest sha512|sha256] [--append]
//! ```
//!
//! **Key rotation** (the updater trusts a SET of keys; any one verifies):
//! ship an app build whose `ManifestTrust` lists the old AND the new key;
//! sign releases with both (`--append` adds the second signature to an
//! existing manifest — its statement must match byte-for-byte); once the
//! fleet runs the two-key build, drop the old key from the trust set and
//! sign with the new one only. A suspected key leak follows the same path
//! with the compromised key removed as fast as the fleet updates.
//!
//! Key custody (`SEAWORTHY_RELEASE_KEY_HEX`, lowercase hex): `mldsa87` — the
//! 32-byte seed (deterministic) or a PKCS#8 document; `ecdsa-p256` /
//! `ed25519` — the PKCS#8 document. The key material and its decoded bytes
//! ride `Zeroizing` to the drop.

use std::process::ExitCode;

use seaworthy_updater::{
    ArtifactFormat, DigestAlgorithm, ManifestSignature, ReleaseManifest, SignatureAlgorithm,
    release_key_id,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sign_release: {error}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage:\n  \
    sign_release --generate-key <mldsa87|ecdsa-p256|ed25519>\n  \
    SEAWORTHY_RELEASE_KEY_HEX=<hex> sign_release <mldsa87|ecdsa-p256|ed25519> <artifact> \
    --product <id> --version <v> --sequence <n> --target <triple> --format <tag> \
    [--channel <name>] [--digest sha512|sha256] [--append]";

type BoxError = Box<dyn std::error::Error>;

fn algorithm_named(name: &str) -> Result<SignatureAlgorithm, BoxError> {
    match name {
        "mldsa87" => Ok(SignatureAlgorithm::MlDsa87),
        "ecdsa-p256" => Ok(SignatureAlgorithm::EcdsaP256),
        "ed25519" => Ok(SignatureAlgorithm::Ed25519),
        other => Err(format!("unknown algorithm {other:?} (mldsa87|ecdsa-p256|ed25519)").into()),
    }
}

fn run() -> Result<(), BoxError> {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        eprintln!("{USAGE}");
        return Err("missing arguments".into());
    };
    if first == "--generate-key" {
        let (Some(algorithm), None) = (args.next(), args.next()) else {
            eprintln!("{USAGE}");
            return Err("--generate-key takes exactly one algorithm".into());
        };
        return generate_key(algorithm_named(&algorithm)?);
    }

    let algorithm = algorithm_named(&first)?;
    let Some(artifact) = args.next() else {
        eprintln!("{USAGE}");
        return Err("missing the artifact argument".into());
    };
    let (mut product, mut version, mut target, mut channel) = (None, None, None, None);
    let mut sequence = None;
    let mut format = None;
    let mut digest_algorithm = DigestAlgorithm::Sha512;
    let mut append = false;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--product" => product = Some(value()?),
            "--version" => version = Some(value()?),
            "--target" => target = Some(value()?),
            "--sequence" => {
                let text = value()?;
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("--sequence is a decimal number".into());
                }
                sequence = Some(text.parse::<u64>()?);
            }
            "--format" => {
                let tag = value()?;
                format = Some(
                    ArtifactFormat::from_tag(&tag)
                        .ok_or_else(|| format!("unknown format {tag:?}"))?,
                );
            }
            "--channel" => channel = Some(value()?),
            "--digest" => {
                digest_algorithm = match value()?.as_str() {
                    "sha256" => DigestAlgorithm::Sha256,
                    "sha512" => DigestAlgorithm::Sha512,
                    other => return Err(format!("unknown digest {other:?} (sha256|sha512)").into()),
                }
            }
            "--append" => append = true,
            other => {
                eprintln!("{USAGE}");
                return Err(format!("unexpected argument {other:?}").into());
            }
        }
    }
    let (Some(product), Some(version), Some(sequence), Some(target)) =
        (product, version, sequence, target)
    else {
        eprintln!("{USAGE}");
        return Err("--product, --version, --sequence, --target and --format are required".into());
    };
    let Some(format) = format else {
        eprintln!("{USAGE}");
        return Err("--product, --version, --sequence, --target and --format are required".into());
    };

    // Signing REQUIRES the key in the environment: never an implicit
    // generate-and-sign into the same CI log as the build output.
    let key_hex =
        zeroize::Zeroizing::new(std::env::var("SEAWORTHY_RELEASE_KEY_HEX").map_err(|_| {
            "SEAWORTHY_RELEASE_KEY_HEX is not set: signing requires the release private key in the \
             environment. Generate one first with `sign_release --generate-key <algorithm>`."
        })?);

    let (size, digest) = hash_file(&artifact, digest_algorithm)?;
    // `--version` takes the version token; its build metadata (after `+`)
    // is the manifest's build field.
    let (version, build) = match version.split_once('+') {
        Some((version, build)) => (version.to_owned(), build.to_owned()),
        None => (version, String::new()),
    };
    let manifest = ReleaseManifest {
        product,
        channel,
        version,
        build,
        sequence,
        target,
        format,
        size,
        digest_algorithm,
        digest,
    };
    let statement = manifest.statement()?;
    let (signature, public_key) = sign(algorithm, &key_hex, &statement)?;
    let new_signature = ManifestSignature {
        algorithm,
        key_id: release_key_id(algorithm, &public_key),
        signature,
    };

    let path = format!("{artifact}.manifest");
    let mut signatures = Vec::new();
    if append {
        let existing = std::fs::read(&path)
            .map_err(|e| format!("--append: cannot read the existing {path}: {e}"))?;
        let (existing_manifest, existing_signatures) = ReleaseManifest::decode_signed(&existing)?;
        if existing_manifest != manifest {
            return Err(
                "--append: the existing manifest describes a different release (its statement \
                 must match byte-for-byte)"
                    .into(),
            );
        }
        signatures = existing_signatures;
        signatures.retain(|s| s.key_id != new_signature.key_id);
    }
    signatures.push(new_signature);
    std::fs::write(&path, manifest.encode_signed(&signatures)?)?;
    println!(
        "wrote {path} ({size} bytes, {digest_algorithm} digest, {} signature(s))",
        signatures.len()
    );
    println!(
        "signing key {} ({}), embed via ReleaseKey::new:\n{}",
        hex::encode(release_key_id(algorithm, &public_key)),
        algorithm.tag(),
        hex::encode(public_key)
    );
    Ok(())
}

/// `--generate-key`: mint a fresh release key; the secret to stderr (the
/// ONLY secret-printing path), the public key and id to stdout.
fn generate_key(algorithm: SignatureAlgorithm) -> Result<(), BoxError> {
    let (secret_hex, public_key) = match algorithm {
        SignatureAlgorithm::MlDsa87 => {
            let mut seed = zeroize::Zeroizing::new([0u8; seaworthy_crypto::mldsa::SEED_LEN]);
            seaworthy_crypto::rand::fill(&mut *seed)?;
            let key = seaworthy_crypto::mldsa::SigningKey::from_seed(&*seed)?;
            (
                zeroize::Zeroizing::new(hex::encode(seed.as_slice())),
                key.public_key().to_vec(),
            )
        }
        SignatureAlgorithm::EcdsaP256 => {
            let (key, pkcs8) = seaworthy_crypto::ecdsa::SigningKey::generate_pkcs8()?;
            (
                zeroize::Zeroizing::new(hex::encode(&*pkcs8)),
                key.public_key_der(),
            )
        }
        SignatureAlgorithm::Ed25519 => {
            let (key, pkcs8) = seaworthy_crypto::ed25519::SigningKey::generate_pkcs8()?;
            (
                zeroize::Zeroizing::new(hex::encode(&*pkcs8)),
                key.public_key().to_vec(),
            )
        }
    };
    eprintln!(
        "generated a fresh {} release key.\nstore this secret as SEAWORTHY_RELEASE_KEY_HEX — it is \
         the root signing secret (KMS/HSM or a sealed secret store; treat this printout as a \
         one-time ceremony):\n{}",
        algorithm.tag(),
        secret_hex.as_str()
    );
    println!(
        "release key {} ({}), embed via ReleaseKey::new:\n{}",
        hex::encode(release_key_id(algorithm, &public_key)),
        algorithm.tag(),
        hex::encode(public_key)
    );
    Ok(())
}

/// Sign the manifest statement; answer the signature and the public key in
/// its embedding form. Decoded key bytes ride `Zeroizing`.
fn sign(
    algorithm: SignatureAlgorithm,
    key_hex: &zeroize::Zeroizing<String>,
    statement: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), BoxError> {
    // Decoded into a buffer sized up front: no reallocation leaves a copy
    // of the secret behind.
    let text = key_hex.trim();
    if !text.len().is_multiple_of(2) {
        return Err("SEAWORTHY_RELEASE_KEY_HEX is not hex".into());
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode_to_slice(text, &mut bytes)?;
    match algorithm {
        SignatureAlgorithm::MlDsa87 => {
            let key = if bytes.len() == seaworthy_crypto::mldsa::SEED_LEN {
                seaworthy_crypto::mldsa::SigningKey::from_seed(&bytes)?
            } else {
                seaworthy_crypto::mldsa::SigningKey::from_pkcs8(&bytes)?
            };
            Ok((key.sign(statement).to_vec(), key.public_key().to_vec()))
        }
        SignatureAlgorithm::EcdsaP256 => {
            let key = seaworthy_crypto::ecdsa::SigningKey::from_pkcs8(&bytes)?;
            Ok((key.sign(statement)?, key.public_key_der()))
        }
        SignatureAlgorithm::Ed25519 => {
            let key = seaworthy_crypto::ed25519::SigningKey::from_pkcs8(&bytes)?;
            Ok((key.sign(statement).to_vec(), key.public_key().to_vec()))
        }
    }
}

/// The artifact's size and digest, streamed in 1 MiB chunks.
fn hash_file(path: &str, algorithm: DigestAlgorithm) -> Result<(u64, Vec<u8>), BoxError> {
    use std::io::Read as _;
    enum Ctx {
        Sha256(seaworthy_crypto::digest::Sha256),
        Sha512(seaworthy_crypto::digest::Sha512),
    }
    let mut ctx = match algorithm {
        DigestAlgorithm::Sha256 => Ctx::Sha256(seaworthy_crypto::digest::Sha256::new()),
        DigestAlgorithm::Sha512 => Ctx::Sha512(seaworthy_crypto::digest::Sha512::new()),
    };
    let mut file = std::fs::File::open(path)?;
    let mut size = 0_u64;
    let mut chunk = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        match &mut ctx {
            Ctx::Sha256(c) => c.update(&chunk[..read]),
            Ctx::Sha512(c) => c.update(&chunk[..read]),
        }
    }
    let digest = match ctx {
        Ctx::Sha256(c) => c.finish().to_vec(),
        Ctx::Sha512(c) => c.finish().to_vec(),
    };
    Ok((size, digest))
}
