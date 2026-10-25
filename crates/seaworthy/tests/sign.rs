//! Release-manifest signing (`seaworthy::sign`):
//! keys for every algorithm, the product policy (`release-signatures` and
//! the trusted `release-keys`) enforced before anything is signed, one
//! signed `seaworthy-release-manifest:1` per installable artifact naming
//! exactly that artifact and build, the external command signer (wrong
//! key, raw output, a hang, paths relative to `signing.toml`), key-file
//! permissions, and the `keygen` / `sign-statement` / `package --signing`
//! commands.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use common::{layouts, release};
use seaworthy::config::Config;
use seaworthy::package::{Kind, Options};
use seaworthy::sign::{
    BuildId, CommandSigner, EnvSecret, EnvSecrets, LocalKey, ManifestSigner, Output, SigningConfig,
    check_manifest, check_policy, generate_key, manifest_for, manifest_path,
};
use seaworthy_updater::{
    ArtifactFormat, DigestAlgorithm, ReleaseKey, ReleaseManifest, SignatureAlgorithm,
};

const ALGORITHMS: [SignatureAlgorithm; 3] = [
    SignatureAlgorithm::MlDsa87,
    SignatureAlgorithm::EcdsaP256,
    SignatureAlgorithm::Ed25519,
];

/// A key pair in `dir`: the 0600 secret file and the public key file.
struct Pair {
    secret: PathBuf,
    public: PathBuf,
    public_key: Vec<u8>,
}

fn pair(dir: &Path, name: &str, algorithm: SignatureAlgorithm) -> Pair {
    let key = generate_key(algorithm).unwrap();
    let secret = dir.join(format!("{name}.key"));
    std::fs::write(&secret, format!("{}\n", *key.secret_hex)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let public = dir.join(format!("{name}.pub"));
    std::fs::write(&public, format!("{}\n", hex::encode(&key.public_key))).unwrap();
    Pair {
        secret,
        public,
        public_key: key.public_key,
    }
}

/// A `seaworthy.toml` in `dir` admitting `signatures`, trusting the public keys
/// `trusted`, loaded (so relative key paths resolve).
fn config(dir: &Path, signatures: &[&str], trusted: &[(&str, &Path)], outputs: &str) -> Config {
    let list = signatures
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let keys = trusted
        .iter()
        .map(|(alg, path)| {
            format!(
                "{{ algorithm = \"{alg}\", public-key = \"{}\" }}",
                path.display()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!(
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = [{list}]
release-keys = [{keys}]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
sidecars.windows = ["extra_*.dll"]
outputs = [{outputs}]
"#
    );
    let path = dir.join("seaworthy.toml");
    std::fs::write(&path, text).unwrap();
    Config::load(&path).unwrap()
}

fn verify(
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
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

fn local(path: &Path, algorithm: SignatureAlgorithm) -> Box<dyn ManifestSigner> {
    Box::new(LocalKey::from_file(algorithm, path).unwrap())
}

fn options(build: &str) -> Options {
    Options {
        release: release(),
        mtime: 1_700_000_000,
        nfpm: PathBuf::from("nfpm"),
        wix: None,
        build: BuildId {
            metadata: build.into(),
        },
    }
}

fn build_signed(
    config: &Config,
    out: &Path,
    build: &str,
    signers: Vec<Box<dyn ManifestSigner>>,
) -> Result<Vec<seaworthy::package::Artifact>, seaworthy::DistError> {
    let layouts = layouts(config, "console", out);
    let signing = seaworthy::package::Signing {
        manifest: signers,
        ..seaworthy::package::Signing::default()
    };
    seaworthy::package::package(
        config,
        "console",
        &layouts,
        &out.join("dist"),
        &options(build),
        &signing,
    )
}

#[test]
fn every_algorithm_generates_loads_and_signs() {
    let tmp = tempfile::tempdir().unwrap();
    for algorithm in ALGORITHMS {
        let p = pair(tmp.path(), algorithm.tag(), algorithm);
        let key = LocalKey::from_file(algorithm, &p.secret).unwrap();
        assert_eq!(key.algorithm(), algorithm);
        assert_eq!(key.public_key(), p.public_key.as_slice());
        let signature = key.sign(b"statement").unwrap();
        assert!(
            verify(algorithm, &p.public_key, b"statement", &signature),
            "{algorithm:?}"
        );
        assert!(
            ReleaseKey::new(p.public_key.clone(), algorithm).is_ok(),
            "{algorithm:?}"
        );
        let other = ALGORITHMS.into_iter().find(|a| *a != algorithm).unwrap();
        assert!(
            LocalKey::from_file(other, &p.secret).is_err(),
            "{algorithm:?} read as {other:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_key_file_any_other_user_can_touch_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let p = pair(tmp.path(), "k", SignatureAlgorithm::Ed25519);
    // Read, write or execute for group or others, write-only included.
    for mode in [0o644, 0o640, 0o604, 0o660, 0o602, 0o620, 0o601, 0o610] {
        std::fs::set_permissions(&p.secret, std::fs::Permissions::from_mode(mode)).unwrap();
        let err = LocalKey::from_file(SignatureAlgorithm::Ed25519, &p.secret)
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be 0600"), "{mode:o}: {err}");
    }
    std::fs::set_permissions(&p.secret, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(LocalKey::from_file(SignatureAlgorithm::Ed25519, &p.secret).is_ok());
    // Private but not a key file: oversized, or a directory.
    let big = tmp.path().join("big.key");
    std::fs::write(&big, "a".repeat((64 << 10) + 2)).unwrap();
    std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = LocalKey::from_file(SignatureAlgorithm::Ed25519, &big)
        .unwrap_err()
        .to_string();
    assert!(err.contains("is not a key file"), "{err}");
    let dir = tmp.path().join("dir.key");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = LocalKey::from_file(SignatureAlgorithm::Ed25519, &dir)
        .unwrap_err()
        .to_string();
    assert!(err.contains("is not a key file"), "{err}");
    // A FIFO is refused at once, not waited on (the open blocked
    // until a writer came).
    let fifo = tmp.path().join("fifo.key");
    let made = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(
            LocalKey::from_file(SignatureAlgorithm::Ed25519, &fifo)
                .map(|_| ())
                .map_err(|e| e.to_string()),
        );
    });
    let err = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("returns, doesn't block")
        .unwrap_err();
    assert!(err.contains("is not a key file"), "{err}");
}

#[test]
fn signers_must_match_the_policy_and_the_trusted_keys_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let ed = pair(tmp.path(), "ed", SignatureAlgorithm::Ed25519);
    let mldsa_only = config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", &mldsa.public)],
        "\"tar\"",
    );
    let ok = || local(&mldsa.secret, SignatureAlgorithm::MlDsa87);
    assert_eq!(check_policy(&mldsa_only, &[ok()]).unwrap().len(), 1);
    // An ML-DSA-only policy: an Ed25519 key would be refused by its clients at load.
    let err = check_policy(
        &mldsa_only,
        &[ok(), local(&ed.secret, SignatureAlgorithm::Ed25519)],
    )
    .unwrap_err();
    assert!(err.to_string().contains("doesn't admit ed25519"), "{err}");
    let err = check_policy(&mldsa_only, &[]).unwrap_err();
    assert!(
        err.to_string().contains("requires a ml-dsa-87 signature"),
        "{err}"
    );
    let err = check_policy(&mldsa_only, &[ok(), ok()]).unwrap_err();
    assert!(
        err.to_string().contains("two signers for ml-dsa-87"),
        "{err}"
    );
    // A well-formed key the clients don't trust (a staging key, a stale one).
    let staging = pair(tmp.path(), "staging", SignatureAlgorithm::MlDsa87);
    let err = check_policy(
        &mldsa_only,
        &[local(&staging.secret, SignatureAlgorithm::MlDsa87)],
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("is not one of defaults.release-keys"),
        "{err}"
    );
    // No trusted keys at all: nothing signs.
    let untrusted = config(tmp.path(), &["ml-dsa-87"], &[], "\"tar\"");
    let err = check_policy(&untrusted, &[ok()]).unwrap_err();
    assert!(err.to_string().contains("release-keys is empty"), "{err}");
    // A degenerate key (ML-DSA-87 with an all-zero t1) through a command.
    let degenerate = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![0; 2592],
        vec!["true".into()],
        Output::Hex,
        Duration::from_secs(5),
    )
    .unwrap();
    let err = check_policy(&mldsa_only, &[Box::new(degenerate)]).unwrap_err();
    assert!(
        err.to_string().contains("invalid release public key"),
        "{err}"
    );
    // A dual-signing policy needs both, each trusted.
    let dual = config(
        tmp.path(),
        &["ml-dsa-87", "ed25519"],
        &[("ml-dsa-87", &mldsa.public), ("ed25519", &ed.public)],
        "\"tar\"",
    );
    assert!(check_policy(&dual, &[ok()]).is_err());
    assert_eq!(
        check_policy(
            &dual,
            &[local(&ed.secret, SignatureAlgorithm::Ed25519), ok()]
        )
        .unwrap()
        .len(),
        2
    );
}

#[test]
fn a_dist_toml_that_signs_no_manifests_takes_no_manifest_signer() {
    // No helper, no release-signatures. A manifest signer in the
    // signing configuration is a mistake, named as one (not "doesn't admit").
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let path = tmp.path().join("seaworthy.toml");
    std::fs::write(
        &path,
        r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
channel = "stable"
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
kind = "desktop"
updates.default = "off"
outputs = ["tar"]
"#,
    )
    .unwrap();
    let config = Config::load(&path).unwrap();
    assert!(check_policy(&config, &[]).unwrap().is_empty());
    let err = check_policy(
        &config,
        &[local(&mldsa.secret, SignatureAlgorithm::MlDsa87)],
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains(
            "seaworthy.toml signs no release manifests (defaults.release-signatures is empty"
        ),
        "{err}"
    );
}

#[test]
fn a_trusted_key_that_release_signatures_doesnt_list_is_refused_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let ed = pair(tmp.path(), "ed", SignatureAlgorithm::Ed25519);
    let path = tmp.path().join("seaworthy.toml");
    let base = std::fs::read_to_string({
        config(tmp.path(), &["ml-dsa-87"], &[], "\"tar\"");
        &path
    })
    .unwrap();
    std::fs::write(
        &path,
        base.replace(
            "release-keys = []",
            &format!(
                "release-keys = [{{ algorithm = \"ed25519\", public-key = \"{}\" }}]",
                ed.public.display()
            ),
        ),
    )
    .unwrap();
    let err = Config::load(&path).unwrap_err().to_string();
    assert!(err.contains("release-keys"), "{err}");
    // A key file that isn't a key.
    std::fs::write(&ed.public, "not hex\n").unwrap();
    let text = base.replace(
        "release-keys = []",
        &format!(
            "release-keys = [{{ algorithm = \"ml-dsa-87\", public-key = \"{}\" }}]",
            ed.public.display()
        ),
    );
    std::fs::write(&path, text).unwrap();
    assert!(
        Config::load(&path)
            .unwrap_err()
            .to_string()
            .contains("is not hex")
    );
}

#[test]
fn every_artifact_kind_names_its_format_and_target() {
    for (kind, format, target) in [
        (
            Kind::Deb,
            Some(ArtifactFormat::Deb),
            "x86_64-unknown-linux-gnu",
        ),
        (
            Kind::Rpm,
            Some(ArtifactFormat::Rpm),
            "x86_64-unknown-linux-gnu",
        ),
        (
            Kind::Pacman,
            Some(ArtifactFormat::Pacman),
            "x86_64-unknown-linux-gnu",
        ),
        (
            Kind::Tar,
            Some(ArtifactFormat::Tar),
            "x86_64-unknown-linux-gnu",
        ),
        (
            Kind::Zip,
            Some(ArtifactFormat::Zip),
            "x86_64-pc-windows-msvc",
        ),
        (
            Kind::Msi,
            Some(ArtifactFormat::Msi),
            "x86_64-pc-windows-msvc",
        ),
        (Kind::Wxs, None, "x86_64-pc-windows-msvc"),
        (Kind::PolicyTemplates, None, "x86_64-pc-windows-msvc"),
        (Kind::Manifest, None, "x86_64-unknown-linux-gnu"),
    ] {
        assert_eq!(kind.artifact_format(), format, "{kind:?}");
        if format.is_some() {
            assert_eq!(kind.target(), target, "{kind:?}");
        }
    }
}

#[test]
fn every_installable_artifact_gets_a_manifest_naming_exactly_it_and_its_build() {
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let p256 = pair(tmp.path(), "p256", SignatureAlgorithm::EcdsaP256);
    let config = config(
        tmp.path(),
        &["ml-dsa-87", "ecdsa-p256"],
        &[("ml-dsa-87", &mldsa.public), ("ecdsa-p256", &p256.public)],
        "\"tar\", \"zip\"",
    );
    let signers = vec![
        local(&mldsa.secret, SignatureAlgorithm::MlDsa87),
        local(&p256.secret, SignatureAlgorithm::EcdsaP256),
    ];
    let artifacts = build_signed(&config, tmp.path(), "a1b2c3d4e5f6", signers).unwrap();
    let kinds: Vec<Kind> = artifacts.iter().map(|a| a.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::Zip,
            Kind::Tar,
            Kind::Manifest,
            Kind::Manifest,
            Kind::Sbom,
            Kind::Sbom
        ]
    );
    for (kind, format, target) in [
        (Kind::Zip, ArtifactFormat::Zip, "x86_64-pc-windows-msvc"),
        (Kind::Tar, ArtifactFormat::Tar, "x86_64-unknown-linux-gnu"),
    ] {
        let artifact = artifacts.iter().find(|a| a.kind == kind).unwrap();
        let path = manifest_path(&artifact.path);
        assert!(
            artifacts
                .iter()
                .any(|a| a.kind == Kind::Manifest && a.path == path)
        );
        let (manifest, signatures) =
            ReleaseManifest::decode_signed(&std::fs::read(&path).unwrap()).unwrap();
        let data = std::fs::read(&artifact.path).unwrap();
        assert_eq!(
            manifest,
            ReleaseManifest {
                product: "acme-console".into(),
                channel: Some("stable".into()),
                version: "1.4.0-rc.2".into(),
                build: "a1b2c3d4e5f6".into(),
                sequence: 812,
                target: target.into(),
                format,
                size: data.len() as u64,
                digest_algorithm: DigestAlgorithm::Sha512,
                digest: DigestAlgorithm::Sha512.hash(&data),
            }
        );
        assert_eq!(manifest.token(), "1.4.0-rc.2+a1b2c3d4e5f6");
        let statement = manifest.statement().unwrap();
        assert_eq!(signatures.len(), 2);
        for (signature, public) in signatures.iter().zip([&mldsa.public_key, &p256.public_key]) {
            let key = ReleaseKey::new(public.clone(), signature.algorithm).unwrap();
            assert_eq!(signature.key_id, key.key_id(), "the id clients compute");
            assert!(verify(
                signature.algorithm,
                public,
                &statement,
                &signature.signature
            ));
        }
    }
}

#[test]
fn a_published_manifest_must_carry_every_required_signature_and_name_exactly_its_artifact() {
    // seaworthy repo's check: what a client would accept, and more
    // (every algorithm release-signatures lists, not just one).
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let p256 = pair(tmp.path(), "p256", SignatureAlgorithm::EcdsaP256);
    let config = config(
        tmp.path(),
        &["ml-dsa-87", "ecdsa-p256"],
        &[("ml-dsa-87", &mldsa.public), ("ecdsa-p256", &p256.public)],
        "\"tar\", \"zip\"",
    );
    let signers = vec![
        local(&mldsa.secret, SignatureAlgorithm::MlDsa87),
        local(&p256.secret, SignatureAlgorithm::EcdsaP256),
    ];
    let artifacts = build_signed(&config, tmp.path(), "a1b2c3", signers).unwrap();
    let path_of = |kind| {
        artifacts
            .iter()
            .find(|a| a.kind == kind)
            .unwrap()
            .path
            .clone()
    };
    let (tar, zip) = (path_of(Kind::Tar), path_of(Kind::Zip));
    let build = BuildId {
        metadata: "a1b2c3".into(),
    };
    let expected = |format, target: &str, path: &Path| {
        manifest_for(&config, "console", &release(), &build, target, format, path).unwrap()
    };
    let tar_expected = expected(ArtifactFormat::Tar, "x86_64-unknown-linux-gnu", &tar);
    let signed = std::fs::read(manifest_path(&tar)).unwrap();
    check_manifest(&config, &signed, &tar_expected).unwrap();
    let refused = |bytes: &[u8], expected: &ReleaseManifest, mentions: &str| {
        let err = check_manifest(&config, bytes, expected)
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{mentions}: {err}");
    };
    // Another artifact's manifest, or another build's.
    refused(
        &std::fs::read(manifest_path(&zip)).unwrap(),
        &tar_expected,
        "not this artifact",
    );
    let other_build = manifest_for(
        &config,
        "console",
        &release(),
        &BuildId {
            metadata: "ffff".into(),
        },
        "x86_64-unknown-linux-gnu",
        ArtifactFormat::Tar,
        &tar,
    )
    .unwrap();
    refused(&signed, &other_build, "not this artifact");
    // One of the two required signatures dropped, or broken.
    let (manifest, signatures) = ReleaseManifest::decode_signed(&signed).unwrap();
    refused(
        &manifest.encode_signed(&signatures[..1]).unwrap(),
        &tar_expected,
        "no ecdsa-p256 signature",
    );
    let mut broken = signatures.clone();
    broken[0].signature[10] ^= 1;
    refused(
        &manifest.encode_signed(&broken).unwrap(),
        &tar_expected,
        "no ml-dsa-87 signature",
    );
    // A key the policy doesn't trust (another seaworthy.toml's).
    let other_dir = tmp.path().join("other");
    std::fs::create_dir(&other_dir).unwrap();
    let stranger = pair(&other_dir, "mldsa", SignatureAlgorithm::MlDsa87);
    let other = self::config(
        &other_dir,
        &["ml-dsa-87"],
        &[("ml-dsa-87", &stranger.public)],
        "\"tar\"",
    );
    let err = check_manifest(&other, &signed, &tar_expected)
        .unwrap_err()
        .to_string();
    assert!(err.contains("by one of defaults.release-keys"), "{err}");
    // Not a manifest at all.
    refused(
        b"seaworthy-release-manifest:1\n",
        &tar_expected,
        "doesn't parse",
    );
}

#[test]
fn an_unsigned_build_writes_no_manifests() {
    let tmp = tempfile::tempdir().unwrap();
    let config = config(tmp.path(), &["ml-dsa-87"], &[], "\"tar\"");
    let artifacts = build_signed(&config, tmp.path(), "", vec![]).unwrap();
    assert!(artifacts.iter().all(|a| a.kind != Kind::Manifest));
}

#[test]
fn a_signer_outside_the_policy_stops_the_build_before_it_starts() {
    let tmp = tempfile::tempdir().unwrap();
    let ed = pair(tmp.path(), "ed", SignatureAlgorithm::Ed25519);
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let config = config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", &mldsa.public)],
        "\"tar\"",
    );
    let err = build_signed(
        &config,
        tmp.path(),
        "",
        vec![local(&ed.secret, SignatureAlgorithm::Ed25519)],
    )
    .unwrap_err();
    assert!(err.to_string().contains("doesn't admit ed25519"), "{err}");
    assert!(
        !tmp.path().join("dist/console/packages").exists(),
        "nothing built"
    );
}

#[test]
fn an_artifact_changed_after_it_was_recorded_fails_the_build() {
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let config = config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", &mldsa.public)],
        "\"tar\"",
    );
    let out = tempfile::tempdir().unwrap();
    let packages = out.path().join("dist/console/packages");
    // A signing command that also appends to the tarball (a buggy or
    // hostile script): the manifest it signs names the old bytes.
    let mut command: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        "for f in \"$1\"/*.tar.zst; do printf x >> \"$f\"; done; shift; exec \"$@\"".into(),
        "sh".into(),
        packages.display().to_string(),
    ];
    command.extend(sign_statement(&mldsa.secret, false));
    let signer = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        mldsa.public_key.clone(),
        command,
        Output::Hex,
        Duration::from_secs(60),
    )
    .unwrap();
    let err = build_signed(&config, out.path(), "", vec![Box::new(signer)])
        .unwrap_err()
        .to_string();
    assert!(err.contains("changed after it was recorded"), "{err}");
}

fn seaworthy_bin() -> String {
    env!("CARGO_BIN_EXE_seaworthy").to_owned()
}

fn sign_statement(key: &Path, raw: bool) -> Vec<String> {
    let mut command = vec![
        seaworthy_bin(),
        "sign-statement".into(),
        "--algorithm".into(),
        "ml-dsa-87".into(),
        "--key".into(),
        key.display().to_string(),
    ];
    if raw {
        command.push("--raw".into());
    }
    command
}

#[test]
fn an_external_command_signs_and_a_wrong_key_is_caught() {
    let tmp = tempfile::tempdir().unwrap();
    let mldsa = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    let config = config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", &mldsa.public)],
        "\"tar\", \"zip\"",
    );
    for output in [Output::Hex, Output::Raw] {
        let command = sign_statement(&mldsa.secret, output == Output::Raw);
        let signer = CommandSigner::new(
            SignatureAlgorithm::MlDsa87,
            mldsa.public_key.clone(),
            command,
            output,
            Duration::from_secs(60),
        )
        .unwrap();
        let out = tempfile::tempdir().unwrap();
        let artifacts = build_signed(&config, out.path(), "", vec![Box::new(signer)]).unwrap();
        assert_eq!(
            artifacts
                .iter()
                .filter(|a| a.kind == Kind::Manifest)
                .count(),
            2,
            "{output:?}"
        );
    }
    // A command signing with another key than the configured public key.
    let other = pair(tmp.path(), "other", SignatureAlgorithm::MlDsa87);
    let wrong = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        mldsa.public_key.clone(),
        sign_statement(&other.secret, false),
        Output::Hex,
        Duration::from_secs(60),
    )
    .unwrap();
    let out = tempfile::tempdir().unwrap();
    let err = build_signed(&config, out.path(), "", vec![Box::new(wrong)]).unwrap_err();
    assert!(err.to_string().contains("doesn't verify"), "{err}");
    // A failing command, an empty one, and a hanging one.
    let failing = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![1; 2592],
        vec!["false".into()],
        Output::Hex,
        Duration::from_secs(5),
    )
    .unwrap();
    assert!(
        failing
            .sign(b"x")
            .unwrap_err()
            .to_string()
            .contains("failed")
    );
    assert!(
        CommandSigner::new(
            SignatureAlgorithm::MlDsa87,
            vec![],
            vec![],
            Output::Hex,
            Duration::from_secs(5)
        )
        .is_err()
    );
    assert!(
        CommandSigner::new(
            SignatureAlgorithm::MlDsa87,
            vec![],
            vec![String::new(), "x".into()],
            Output::Hex,
            Duration::from_secs(5)
        )
        .is_err()
    );
    // A signer printing more than any signature is cut off, not buffered.
    let flood = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![1; 2592],
        vec![
            "sh".into(),
            "-c".into(),
            "head -c 3000000 /dev/zero | tr '\\0' a".into(),
        ],
        Output::Raw,
        Duration::from_secs(30),
    )
    .unwrap();
    let err = flood.sign(b"x").unwrap_err().to_string();
    assert!(err.contains("printed more than"), "{err}");
    let hanging = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![1; 2592],
        vec!["sleep".into(), "30".into()],
        Output::Hex,
        Duration::from_secs(1),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let err = hanging.sign(b"x").unwrap_err().to_string();
    assert!(err.contains("didn't finish within 1 s"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "killed at the deadline"
    );
    // A signer that exits while its child still holds the pipes: the
    // deadline covers draining them, and the child is killed with it.
    let marker = tmp.path().join("grandchild-alive");
    let script = format!("(sleep 3; touch '{}') & echo 00", marker.display());
    let orphaning = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![1; 2592],
        vec!["sh".into(), "-c".into(), script],
        Output::Hex,
        Duration::from_secs(1),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let err = orphaning.sign(b"x").unwrap_err().to_string();
    assert!(err.contains("didn't finish within 1 s"), "{err}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    std::thread::sleep(Duration::from_secs(4));
    assert!(!marker.exists(), "the signer's process group was killed");
    // A failing signer's stderr is shown, but only so much of it.
    let noisy = CommandSigner::new(
        SignatureAlgorithm::MlDsa87,
        vec![1; 2592],
        vec![
            "sh".into(),
            "-c".into(),
            "head -c 100000 /dev/zero | tr '\\0' x >&2; exit 3".into(),
        ],
        Output::Hex,
        Duration::from_secs(10),
    )
    .unwrap();
    let err = noisy.sign(b"x").unwrap_err().to_string();
    assert!(
        err.len() < 1000 && err.ends_with('…'),
        "{} bytes",
        err.len()
    );
}

#[test]
fn signing_toml_takes_exactly_a_key_or_a_command_and_resolves_paths_beside_it() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pair(tmp.path(), "mldsa", SignatureAlgorithm::MlDsa87);
    // A signer script beside signing.toml, named relatively, run from
    // another working directory.
    let script = tmp.path().join("signer.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nexec {} \"$@\"\n",
            sign_statement(&p.secret, false).join(" ")
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let load = |text: &str| {
        let path = tmp.path().join("signing.toml");
        std::fs::write(&path, text).unwrap();
        let (signing, base) = SigningConfig::load(&path)?;
        signing.manifest_signers(&base)
    };
    let signers = load(
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"mldsa.key\"\n\n\
         [[manifest]]\nalgorithm = \"ml-dsa-87\"\npublic-key = \"mldsa.pub\"\ncommand = [\"./signer.sh\"]\ntimeout-seconds = 30\n",
    )
    .unwrap();
    assert_eq!(signers.len(), 2);
    assert_eq!(signers[1].public_key(), p.public_key.as_slice());
    let statement = common::release()
        .package_versions()
        .map(|_| ())
        .map(|()| {
            ReleaseManifest {
                product: "acme-console".into(),
                channel: None,
                version: "1.0.0".into(),
                build: String::new(),
                sequence: 1,
                target: "x86_64-unknown-linux-gnu".into(),
                format: ArtifactFormat::Tar,
                size: 1,
                digest_algorithm: DigestAlgorithm::Sha512,
                digest: DigestAlgorithm::Sha512.hash(b"x"),
            }
            .statement()
            .unwrap()
        })
        .unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(elsewhere.path()).unwrap();
    let signed = signers[1].sign(&statement);
    std::env::set_current_dir(previous).unwrap();
    assert!(verify(
        SignatureAlgorithm::MlDsa87,
        &p.public_key,
        &statement,
        &signed.unwrap()
    ));
    for bad in [
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"k\"\ncommand = [\"x\"]\npublic-key = \"mldsa.pub\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\ncommand = [\"x\"]\n",
        "[[manifest]]\nalgorithm = \"rsa\"\nkey = \"k\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"k\"\nsecret = \"inline\"\n",
        // A command's options on a local key.
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"mldsa.key\"\noutput = \"raw\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"mldsa.key\"\ntimeout-seconds = 5\n",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
}

#[test]
fn keygen_and_sign_statement_round_trip_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let (secret, public) = (tmp.path().join("k.key"), tmp.path().join("k.pub"));
    let keygen = |secret: &Path, public: &Path| {
        Command::new(seaworthy_bin())
            .args(["keygen", "--algorithm", "ed25519", "--secret"])
            .arg(secret)
            .arg("--public")
            .arg(public)
            .output()
            .unwrap()
    };
    let out = keygen(&secret, &public);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ed25519 key "));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Never over an existing file, and no orphan when only the public one exists.
    assert_eq!(keygen(&secret, &public).status.code(), Some(1));
    let orphan = tmp.path().join("orphan.key");
    assert_eq!(keygen(&orphan, &public).status.code(), Some(1));
    assert!(
        !orphan.exists(),
        "no secret written when the public file exists"
    );
    let fresh_public = tmp.path().join("fresh.pub");
    assert_eq!(keygen(&secret, &fresh_public).status.code(), Some(1));
    assert!(
        !fresh_public.exists(),
        "no public file left when the secret exists"
    );
    let public_key = hex::decode(std::fs::read_to_string(&public).unwrap().trim()).unwrap();
    let sign = |input: &[u8]| {
        let mut child = Command::new(seaworthy_bin())
            .args(["sign-statement", "--algorithm", "ed25519", "--key"])
            .arg(&secret)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        child.wait_with_output().unwrap()
    };
    let statement = ReleaseManifest {
        product: "acme-console".into(),
        channel: None,
        version: "1.0.0".into(),
        build: String::new(),
        sequence: 1,
        target: "x86_64-unknown-linux-gnu".into(),
        format: ArtifactFormat::Tar,
        size: 1,
        digest_algorithm: DigestAlgorithm::Sha512,
        digest: DigestAlgorithm::Sha512.hash(b"x"),
    }
    .statement()
    .unwrap();
    let out = sign(&statement);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let signature = hex::decode(String::from_utf8(out.stdout).unwrap().trim()).unwrap();
    assert!(verify(
        SignatureAlgorithm::Ed25519,
        &public_key,
        &statement,
        &signature
    ));
    // The reference signer signs release statements and nothing else.
    for not_a_statement in [&b"hello"[..], b"", b"seaworthy-release-manifest:1\n"] {
        let out = sign(not_a_statement);
        assert_eq!(out.status.code(), Some(1), "{not_a_statement:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("not a canonical"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let usage = Command::new(seaworthy_bin())
        .args(["keygen", "--algorithm", "rsa"])
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));
}

#[test]
fn package_signing_runs_end_to_end_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pair(tmp.path(), "release", SignatureAlgorithm::MlDsa87);
    config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", Path::new("release.pub"))],
        "\"tar\"",
    );
    common::acme_artifacts(&tmp.path().join("artifacts"));
    std::fs::write(
        tmp.path().join("signing.toml"),
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"release.key\"\n",
    )
    .unwrap();
    let run = |build: Option<&str>| {
        let mut command = Command::new(seaworthy_bin());
        command.args([
            "package",
            "--no-strip",
            "--release",
            "3.0.0",
            "--sequence",
            "9",
        ]);
        if let Some(build) = build {
            command.args(["--build", build]);
        }
        command
            .arg("--config")
            .arg(tmp.path().join("seaworthy.toml"))
            .arg("--artifacts")
            .arg(tmp.path().join("artifacts"))
            .arg("--out")
            .arg(tmp.path().join("out"))
            .arg("--signing")
            .arg(tmp.path().join("signing.toml"))
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .unwrap()
    };
    let out = run(Some("cafe12"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("no --build"));
    let manifest = tmp
        .path()
        .join("out/console/packages/acme-console-3.0.0-9-linux-x86_64.tar.zst.manifest");
    let (decoded, signatures) =
        ReleaseManifest::decode_signed(&std::fs::read(manifest).unwrap()).unwrap();
    assert_eq!(
        (decoded.token().as_str(), decoded.sequence, decoded.format),
        ("3.0.0+cafe12", 9, ArtifactFormat::Tar)
    );
    assert_eq!(
        signatures[0].key_id,
        ReleaseKey::new(p.public_key, SignatureAlgorithm::MlDsa87)
            .unwrap()
            .key_id()
    );
    // Build metadata outside SemVer's grammar is a usage error: its charset,
    // empty identifiers, more than 64 characters.
    let long = "a".repeat(65);
    for build in ["a+b", "é", "a..b", "a.", ".a", long.as_str()] {
        assert_eq!(run(Some(build)).status.code(), Some(2), "{build}");
    }
    // Signing without --build works, but says what it means.
    let out = run(None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("warning: no --build"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn signing_toml_configures_authenticode_and_openpgp() {
    let tmp = tempfile::tempdir().unwrap();
    let load = |text: &str| {
        let path = tmp.path().join("signing.toml");
        std::fs::write(&path, text).unwrap();
        let (signing, base) = SigningConfig::load(&path)?;
        signing.signing(&base)
    };
    std::fs::write(tmp.path().join("codesign.pem"), "cert").unwrap();
    std::fs::write(tmp.path().join("codesign.key"), "key").unwrap();
    let _ = pair(tmp.path(), "p", SignatureAlgorithm::Ed25519);
    assert!(load("[[manifest]]\nalgorithm = \"ed25519\"\ncommand = [\"x\"]\npublic-key = \"p.pub\"\ntimeout-seconds = 3600\n").is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            tmp.path().join("codesign.key"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let signing = load(
        "[authenticode]\ncertificate = \"codesign.pem\"\nkey = \"codesign.key\"\ntimestamp-url = \"http://ts.example\"\n\n\
         [openpgp]\nhome = \"gnupg\"\nkey = \"ABCDEF0123456789ABCDEF0123456789ABCDEF01\"\n",
    )
    .unwrap();
    assert!(signing.manifest.is_empty());
    let described = format!("{signing:?}");
    assert!(
        described.contains("osslsigncode with") && described.contains("codesign.pem"),
        "{described}"
    );
    assert!(
        described.contains("gpg key ABCDEF0123456789ABCDEF0123456789ABCDEF01 in")
            && described.contains("gnupg"),
        "{described}"
    );
    let command = load("[authenticode]\ncommand = [\"./sign.sh\", \"{file}\"]\n").unwrap();
    assert!(format!("{command:?}").contains("sign.sh"));
    for bad in [
        "[authenticode]\n",
        "[authenticode]\ncertificate = \"codesign.pem\"\n",
        "[authenticode]\ncertificate = \"codesign.pem\"\nkey = \"codesign.key\"\ncommand = [\"x\", \"{file}\"]\n",
        "[authenticode]\ncommand = [\"x\", \"{file}\"]\ntimestamp-url = \"http://ts.example\"\n",
        "[openpgp]\nhome = \"gnupg\"\n",
        "[openpgp]\nhome = \"gnupg\"\nkey = \"K\"\npassphrase = \"inline\"\n",
        // A user id, not a fingerprint (rpm expands macros in it).
        "[openpgp]\nhome = \"gnupg\"\nkey = \"%(touch x) <a@b>\"\n",
        // Timeouts out of range (a huge one overflowed the clock).
        "[authenticode]\ncommand = [\"x\", \"{file}\"]\ntimeout-seconds = 0\n",
        "[openpgp]\nhome = \"gnupg\"\nkey = \"ABCDEF0123456789ABCDEF0123456789ABCDEF01\"\ntimeout-seconds = 3601\n",
        "[[manifest]]\nalgorithm = \"ed25519\"\ncommand = [\"x\"]\npublic-key = \"p.pub\"\ntimeout-seconds = 9223372036854775807\n",
    ] {
        assert!(load(bad).is_err(), "{bad}");
    }
    // A signing key others can read is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            tmp.path().join("codesign.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let err = load("[authenticode]\ncertificate = \"codesign.pem\"\nkey = \"codesign.key\"\n")
            .unwrap_err();
        assert!(err.to_string().contains("must be 0600"), "{err}");
    }
}

/// A key a custody system hands over in the environment (`key-env`,
/// `secret-key-env`): named in signing.toml, read from the secrets the
/// binary took out of its environment, refused when missing, and never
/// combined with another source.
#[test]
fn signing_toml_takes_keys_from_the_environment() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pair(tmp.path(), "release", SignatureAlgorithm::MlDsa87);
    let hex = std::fs::read_to_string(&p.secret).unwrap();
    let load = |text: &str| {
        let path = tmp.path().join("signing.toml");
        std::fs::write(&path, text).unwrap();
        SigningConfig::load(&path)
    };
    let mut secrets = EnvSecrets::new();
    secrets.insert("RELEASE_KEY_HEX".into(), EnvSecret::new(hex));
    // Never shown by Debug.
    assert_eq!(
        format!("{:?}", secrets.get("RELEASE_KEY_HEX").unwrap()),
        "EnvSecret(..)"
    );
    let (file, base) =
        load("[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"RELEASE_KEY_HEX\"\n").unwrap();
    assert_eq!(file.secret_variables(), vec!["RELEASE_KEY_HEX"]);
    let signers = file.manifest_signers_with(&base, &secrets).unwrap();
    assert_eq!(signers[0].public_key(), p.public_key.as_slice());
    // The variable not handed over: refused, naming it.
    let err = file.manifest_signers(&base).err().unwrap().to_string();
    assert!(
        err.contains("the environment variable RELEASE_KEY_HEX isn't set"),
        "{err}"
    );
    // Exactly one source per signer; a command's options only with a command.
    for text in [
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"release.key\"\nkey-env = \"RELEASE_KEY_HEX\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"RELEASE_KEY_HEX\"\ncommand = [\"x\"]\npublic-key = \"release.pub\"\n",
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"RELEASE_KEY_HEX\"\ntimeout-seconds = 30\n",
    ] {
        let (file, base) = load(text).unwrap();
        let err = file
            .manifest_signers_with(&base, &secrets)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("give one of `key`"), "{text}: {err}");
    }
    // Variable names: [A-Z_][A-Z0-9_]*, refused at load otherwise.
    let long = "K".repeat(129);
    for bad in [
        "release_key",
        "1KEY",
        "KEY-HEX",
        "",
        "KEY HEX",
        long.as_str(),
    ] {
        let err = load(&format!(
            "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"{bad}\"\n"
        ))
        .err()
        .unwrap()
        .to_string();
        assert!(
            err.contains("isn't an environment variable name"),
            "{bad}: {err}"
        );
    }
    assert!(seaworthy::sign::is_variable_name("_A1"));
    assert!(seaworthy::sign::is_variable_name(&"K".repeat(128)));
    // [openpgp]: one of a home, a key from the environment or (the CI test
    // key) a key file, not two or none; each variable listed once.
    let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
    for text in [
        format!("[openpgp]\nhome = \"g\"\nsecret-key-env = \"REPO_KEY\"\nkey = \"{fpr}\"\n"),
        format!("[openpgp]\nkey = \"{fpr}\"\n"),
    ] {
        let (file, base) = load(&text).unwrap();
        let err = file.signing(&base).err().unwrap().to_string();
        assert!(
            err.contains("give one of `home` (a gpg home), `secret-key-env`"),
            "{text}: {err}"
        );
    }
    let (file, base) = load(&format!(
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"KEYS\"\n\n[openpgp]\nsecret-key-env = \"KEYS\"\nkey = \"{fpr}\"\n"
    ))
    .unwrap();
    assert_eq!(file.secret_variables(), vec!["KEYS"]);
    assert_eq!(file.manifest_variables(), vec!["KEYS"]);
    assert_eq!(file.openpgp_variables(), vec!["KEYS"]);
    let err = file.signing(&base).err().unwrap().to_string();
    assert!(
        err.contains("[openpgp] secret-key-env: the environment variable KEYS isn't set"),
        "{err}"
    );
}

/// `[openpgp] secret-key-env`: the armored key imported into a private
/// throwaway home, which signs, then goes (agent and key) with the signer;
/// a key that isn't the configured one, a public key, or garbage is refused.
#[test]
fn an_openpgp_key_from_the_environment_signs_from_a_private_home_that_goes_with_it() {
    if !common::have("gpg", &["--version"]) {
        return;
    }
    let keyring = common::Keyring::new();
    let tmp = tempfile::tempdir().unwrap();
    let public = tmp.path().join("repo.asc");
    keyring.export(&public);
    let import = |armored: &str, key: &str| {
        seaworthy::codesign::ImportedGpg::import(
            armored,
            key,
            PathBuf::from("gpg"),
            PathBuf::from("rpmsign"),
            Duration::from_secs(120),
        )
    };
    let armored = keyring.export_secret();
    let signer = import(&armored, &keyring.fingerprint).unwrap();
    let home = signer.home().to_path_buf();
    assert!(home.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&home).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "a private home");
    }
    let file = tmp.path().join("index");
    std::fs::write(&file, "an index\n").unwrap();
    let signature = tmp.path().join("index.sig");
    seaworthy::codesign::OpenPgpSigner::detach_sign(&signer, &file, &signature).unwrap();
    let pins = seaworthy::codesign::Pins {
        authenticode: None,
        openpgp: vec![public.clone()],
        osslsigncode: PathBuf::from("osslsigncode"),
        gpg: PathBuf::from("gpg"),
        rpmkeys: PathBuf::from("rpmkeys"),
    };
    pins.check_detached(&signature, &file).unwrap();
    assert!(seaworthy::codesign::OpenPgpSigner::describe(&signer).contains("imported"));
    drop(signer);
    assert!(
        !home.exists(),
        "the private home (and the key) goes with the signer"
    );
    assert!(
        !processes_naming(&home),
        "the home's gpg-agent is stopped with it"
    );
    // Another fingerprint than the key's.
    let other = "0123456789ABCDEF0123456789ABCDEF01234567";
    let err = import(&armored, other).err().unwrap().to_string();
    assert!(err.contains("must hold exactly one secret key"), "{err}");
    // A subkey's fingerprint isn't the key's.
    let with_subkey = common::Keyring::new();
    common::run(
        Command::new("gpg")
            .arg("--homedir")
            .arg(with_subkey.home())
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args([
                "--quick-add-key",
                &with_subkey.fingerprint,
                "rsa3072",
                "sign",
                "never",
            ]),
    );
    let listing = common::run(
        Command::new("gpg")
            .arg("--homedir")
            .arg(with_subkey.home())
            .args(["--with-colons", "--list-secret-keys"]),
    );
    let subkey = listing
        .lines()
        .skip_while(|l| !l.starts_with("ssb:"))
        .find_map(|l| l.strip_prefix("fpr:"))
        .and_then(|l| l.split(':').nth(8))
        .unwrap()
        .to_owned();
    assert_ne!(subkey, with_subkey.fingerprint);
    let sub_armored = with_subkey.export_secret();
    let err = import(&sub_armored, &subkey).err().unwrap().to_string();
    assert!(err.contains("its primary key's fingerprint"), "{err}");
    assert!(import(&sub_armored, &with_subkey.fingerprint).is_ok());
    // Two keys in one text: refused, though one is the configured key.
    let both = format!("{armored}\n{sub_armored}");
    let err = import(&both, &keyring.fingerprint)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("must hold exactly one secret key"), "{err}");
    // A protected key imports, but can't sign in a batch run: refused now.
    let protected = tempfile::tempdir().unwrap();
    let phome = protected.path().join("g");
    std::fs::create_dir(&phome).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&phome, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let gpg_with = |args: &[&str]| {
        common::run(
            Command::new("gpg")
                .arg("--homedir")
                .arg(&phome)
                .args([
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "s3cret",
                ])
                .args(args),
        )
    };
    gpg_with(&[
        "--quick-gen-key",
        "Protected <p@acme.test>",
        "rsa3072",
        "sign",
        "never",
    ]);
    let pfpr = gpg_with(&["--with-colons", "--list-keys"])
        .lines()
        .find_map(|l| l.strip_prefix("fpr:"))
        .and_then(|l| l.split(':').nth(8))
        .unwrap()
        .to_owned();
    let parmored = gpg_with(&["--armor", "--export-secret-keys", &pfpr]);
    let err = import(&parmored, &pfpr).err().unwrap().to_string();
    assert!(
        err.contains("can't sign without a passphrase or a prompt"),
        "{err}"
    );
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&phome)
        .args(["--kill", "all"])
        .output();
    // A public key only; text that isn't a key; a user id for the key.
    let public_text = std::fs::read_to_string(&public).unwrap();
    let err = import(&public_text, &keyring.fingerprint)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("must hold exactly one secret key"), "{err}");
    let err = import("not a key", &keyring.fingerprint)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("couldn't import the key"), "{err}");
    let err = import(&armored, "pkg@acme.test").err().unwrap().to_string();
    assert!(err.contains("named by its fingerprint"), "{err}");
}

/// Through the CLI: a manifest key handed over in the environment signs,
/// and no tool `seaworthy` starts sees it (the strip tool records its
/// environment here).
#[test]
fn a_key_from_the_environment_signs_and_never_reaches_a_tool() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pair(tmp.path(), "release", SignatureAlgorithm::MlDsa87);
    let hex = std::fs::read_to_string(&p.secret).unwrap();
    std::fs::remove_file(&p.secret).unwrap();
    config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", Path::new("release.pub"))],
        "\"tar\"",
    );
    common::acme_artifacts(&tmp.path().join("artifacts"));
    std::fs::write(
        tmp.path().join("signing.toml"),
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"SEAWORTHY_RELEASE_KEY_HEX\"\n",
    )
    .unwrap();
    let strip = tmp.path().join("strip.sh");
    let seen = tmp.path().join("strip-env");
    std::fs::write(
        &strip,
        format!(
            "#!/bin/sh\nenv >> '{seen}'\necho \"uid=$(id -u)\" >> '{seen}.parent'\n\
             if tr '\\0' '\\n' < /proc/$PPID/environ >> '{seen}.parent' 2>/dev/null; then :; else echo DENIED >> '{seen}.parent'; fi\n\
             exit 0\n",
            seen = seen.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&strip, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = |key: Option<&str>| {
        let mut command = Command::new(seaworthy_bin());
        command
            .args([
                "package",
                "--release",
                "3.0.0",
                "--sequence",
                "9",
                "--build",
                "cafe12",
            ])
            .arg("--config")
            .arg(tmp.path().join("seaworthy.toml"))
            .arg("--artifacts")
            .arg(tmp.path().join("artifacts"))
            .arg("--out")
            .arg(tmp.path().join("out"))
            .arg("--signing")
            .arg(tmp.path().join("signing.toml"))
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .env("STRIP", &strip)
            .env("SEAWORTHY_TEST_MARKER", "visible")
            .env_remove("SEAWORTHY_RELEASE_KEY_HEX");
        if let Some(key) = key {
            command.env("SEAWORTHY_RELEASE_KEY_HEX", key);
        }
        command.output().unwrap()
    };
    let out = run(Some(&hex));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let manifest = tmp
        .path()
        .join("out/console/packages/acme-console-3.0.0-9-linux-x86_64.tar.zst.manifest");
    let (_, signatures) =
        ReleaseManifest::decode_signed(&std::fs::read(manifest).unwrap()).unwrap();
    assert_eq!(
        signatures[0].key_id,
        ReleaseKey::new(p.public_key.clone(), SignatureAlgorithm::MlDsa87)
            .unwrap()
            .key_id()
    );
    let env = std::fs::read_to_string(&seen).unwrap();
    assert!(
        env.contains("SEAWORTHY_TEST_MARKER=visible"),
        "the tool ran: {env}"
    );
    assert!(
        !env.contains("SEAWORTHY_RELEASE_KEY_HEX"),
        "the key reached a tool"
    );
    assert!(!env.contains(hex.trim()), "the key reached a tool");
    // Nor can a tool read it back out of seaworthy (its initial
    // environment, which /proc serves, still holds the bytes): the process
    // is non-dumpable, so its environ is root's only (root reads anything).
    let parent = std::fs::read_to_string(seen.with_extension("parent")).unwrap();
    if !parent.lines().any(|l| l == "uid=0") {
        assert!(
            parent.contains("DENIED"),
            "seaworthy's environ was readable: {parent}"
        );
    }
    assert!(
        !parent.contains(hex.trim()),
        "the key was read back from seaworthy"
    );
    // Not handed over, empty, or oversized: refused before anything runs.
    let oversized = "0".repeat(seaworthy::sign::MAX_ENV_SECRET + 1);
    for key in [None, Some(""), Some(oversized.as_str())] {
        let out = run(key);
        assert_eq!(out.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(
                "names the environment variable SEAWORTHY_RELEASE_KEY_HEX, which is unset, empty"
            ),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Through the CLI: a dev build (`--authenticode-only`) takes
/// signing.toml's `[authenticode]` alone — it needs `--signing` and an
/// `[authenticode]`, and never asks for the manifest or OpenPGP keys the
/// file names (the dev secrets wrapper hands over none).
#[test]
fn a_dev_build_takes_the_authenticode_signer_alone() {
    let tmp = tempfile::tempdir().unwrap();
    pair(tmp.path(), "release", SignatureAlgorithm::MlDsa87);
    config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", Path::new("release.pub"))],
        "\"tar\"",
    );
    common::acme_artifacts(&tmp.path().join("artifacts"));
    let signing = tmp.path().join("signing.toml");
    let release = "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"SEAWORTHY_RELEASE_KEY_HEX\"\n\n\
                   [openpgp]\nkey = \"0123456789ABCDEF0123456789ABCDEF01234567\"\nsecret-key-env = \"ACME_REPOSITORY_KEY_ASC\"\n";
    let run = |command: &str, signing: Option<&Path>| {
        let mut run = Command::new(seaworthy_bin());
        run.arg(command)
            .arg("--config")
            .arg(tmp.path().join("seaworthy.toml"));
        if command == "package" {
            run.args(["--release", "3.0.0", "--sequence", "9"])
                .arg("--artifacts")
                .arg(tmp.path().join("artifacts"));
        } else {
            run.args(["--product", "console"])
                .arg("--msi")
                .arg(tmp.path().join("none.msi"));
        }
        run.arg("--out").arg(tmp.path().join("out"));
        if let Some(signing) = signing {
            run.arg("--signing").arg(signing);
        }
        run.arg("--authenticode-only")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .env_remove("SEAWORTHY_RELEASE_KEY_HEX")
            .env_remove("ACME_REPOSITORY_KEY_ASC");
        let out = run.output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for command in ["package", "adopt-msi"] {
        // Without --signing: a usage error.
        let (code, err) = run(command, None);
        assert_eq!(code, Some(2), "{command}: {err}");
        assert!(
            err.contains(
                "--authenticode-only signs with --signing's [authenticode]: it needs --signing"
            ),
            "{command}: {err}"
        );
        // Without [authenticode]: refused, and the missing keys never asked for.
        std::fs::write(&signing, release).unwrap();
        let (code, err) = run(command, Some(&signing));
        assert_eq!(code, Some(1), "{command}: {err}");
        assert!(
            err.contains("--authenticode-only: the signing configuration has no [authenticode]"),
            "{command}: {err}"
        );
        assert!(
            !err.contains("names the environment variable"),
            "{command}: {err}"
        );
        // With one: past the keys, to seaworthy.toml's pins (this one pins no
        // Authenticode identity).
        std::fs::write(
            &signing,
            format!("{release}\n[authenticode]\ncommand = [\"sign\"]\n"),
        )
        .unwrap();
        let (code, err) = run(command, Some(&signing));
        assert_eq!(code, Some(1), "{command}: {err}");
        assert!(
            err.contains("defaults.authenticode is not set"),
            "{command}: {err}"
        );
        assert!(
            !err.contains("names the environment variable"),
            "{command}: {err}"
        );
    }
    assert!(!tmp.path().join("out").exists(), "nothing packaged");
}

/// Whether any process's command line names `path` (a gpg-agent started
/// for that home).
fn processes_naming(path: &Path) -> bool {
    let needle = path.to_string_lossy().into_owned();
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            std::fs::read(entry.path().join("cmdline"))
                .is_ok_and(|bytes| String::from_utf8_lossy(&bytes).contains(&needle))
        })
}

/// `seaworthy.toml` text trusting `real` and, under `[defaults.ci-test-keys]`,
/// `test`.
fn ci_test_dist(dir: &Path, real: &Path, test: &Path) -> PathBuf {
    let path = dir.join("seaworthy.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{{ algorithm = "ml-dsa-87", public-key = "{}" }}]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[defaults.ci-test-keys]
release-keys = [{{ algorithm = "ml-dsa-87", public-key = "{}" }}]

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
sidecars.windows = ["extra_*.dll"]
outputs = ["tar"]
"#,
            real.display(),
            test.display()
        ),
    )
    .unwrap();
    path
}

/// The CI test keys replace the trusted keys for one build
/// (`use_ci_test_keys`): the real key's signer is then refused and the test
/// key's accepted, the build's listing says it was signed by the test keys
/// (not a release: `signed` false), and its manifests verify against the
/// test key alone. A test key that is also a real one is refused at load,
/// and a `seaworthy.toml` without the table has no test keys to switch to.
#[test]
fn the_ci_test_keys_sign_a_build_that_is_never_a_release() {
    let tmp = tempfile::tempdir().unwrap();
    let real = pair(tmp.path(), "real", SignatureAlgorithm::MlDsa87);
    let test = pair(tmp.path(), "test", SignatureAlgorithm::MlDsa87);
    let path = ci_test_dist(tmp.path(), &real.public, &test.public);
    let loaded = Config::load(&path).unwrap();
    assert!(!loaded.ci_test);
    let switched = loaded.clone().use_ci_test_keys().unwrap();
    assert!(switched.ci_test);
    let trusted = switched.release_keys().unwrap();
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].public_key(), test.public_key.as_slice());
    let err = check_policy(
        &switched,
        &[local(&real.secret, SignatureAlgorithm::MlDsa87)],
    )
    .unwrap_err();
    assert!(err.to_string().contains("release-keys"), "{err}");
    check_policy(
        &switched,
        &[local(&test.secret, SignatureAlgorithm::MlDsa87)],
    )
    .unwrap();

    let layouts = layouts(&switched, "console", tmp.path());
    let signing = seaworthy::package::Signing {
        manifest: vec![local(&test.secret, SignatureAlgorithm::MlDsa87)],
        ci_test: true,
        ..seaworthy::package::Signing::default()
    };
    assert!(!signing.is_release(), "a CI test build is never a release");
    let artifacts = seaworthy::package::package(
        &switched,
        "console",
        &layouts,
        &tmp.path().join("dist"),
        &options("abc123"),
        &signing,
    )
    .unwrap();
    let listing = std::fs::read_to_string(tmp.path().join("dist/console/packages.json")).unwrap();
    assert!(listing.contains("\"ci_test\": true"), "{listing}");
    assert!(listing.contains("\"signed\": false"), "{listing}");
    let manifests: Vec<_> = artifacts
        .iter()
        .filter(|a| a.kind == Kind::Manifest)
        .collect();
    assert!(!manifests.is_empty());
    for manifest in manifests {
        let signed = std::fs::read(&manifest.path).unwrap();
        let (decoded, signatures) = ReleaseManifest::decode_signed(&signed).unwrap();
        let statement = decoded.statement().unwrap();
        assert!(signatures.iter().any(|s| verify(
            SignatureAlgorithm::MlDsa87,
            &test.public_key,
            &statement,
            &s.signature
        )));
        assert!(!signatures.iter().any(|s| verify(
            SignatureAlgorithm::MlDsa87,
            &real.public_key,
            &statement,
            &s.signature
        )));
    }

    // A test key that is a real key: refused at load.
    let both = ci_test_dist(tmp.path(), &real.public, &real.public);
    let err = Config::load(&both).unwrap_err().to_string();
    assert!(
        err.contains("a test key must never be a release key"),
        "{err}"
    );
    // No table: nothing to switch to.
    let plain = config(
        tmp.path(),
        &["ml-dsa-87"],
        &[("ml-dsa-87", &real.public)],
        "\"tar\"",
    );
    let err = plain.use_ci_test_keys().unwrap_err().to_string();
    assert!(err.contains("no [defaults.ci-test-keys]"), "{err}");
}

/// `--ci-test-signing` never joins a release's `--signing` (only a
/// dev build's `--authenticode-only`), and its file names the test keys
/// as files: a key from the environment is refused before anything runs.
/// The test key's file signs a CI test build, and a build that makes no rpm
/// or pacman package never loads its `[openpgp]` (the Mac has no gpg).
#[test]
fn ci_test_signing_refuses_a_release_and_environment_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let real = pair(tmp.path(), "real", SignatureAlgorithm::MlDsa87);
    let test = pair(tmp.path(), "test", SignatureAlgorithm::MlDsa87);
    let dist = ci_test_dist(tmp.path(), &real.public, &test.public);
    common::acme_artifacts(&tmp.path().join("artifacts"));
    let release_signing = tmp.path().join("signing.toml");
    std::fs::write(
        &release_signing,
        format!(
            "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"{}\"\n",
            real.secret.display()
        ),
    )
    .unwrap();
    let ci_signing = tmp.path().join("signing.ci-test.toml");
    let run = |extra: &[&std::ffi::OsStr]| {
        let out = Command::new(seaworthy_bin())
            .arg("package")
            .arg("--config")
            .arg(&dist)
            .args(["--release", "3.0.0", "--sequence", "9"])
            // The fixture binaries are hand-written: nothing to strip (and
            // the macOS runner's strip refuses GNU's --strip-all).
            .arg("--no-strip")
            .arg("--artifacts")
            .arg(tmp.path().join("artifacts"))
            .arg("--out")
            .arg(tmp.path().join("out"))
            .args(extra)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let test_key_file = format!(
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey = \"{}\"\n",
        test.secret.display()
    );
    std::fs::write(&ci_signing, &test_key_file).unwrap();
    let (code, err) = run(&[
        "--signing".as_ref(),
        release_signing.as_os_str(),
        "--ci-test-signing".as_ref(),
        ci_signing.as_os_str(),
    ]);
    assert_eq!(code, Some(2), "{err}");
    assert!(
        err.contains("--ci-test-signing never joins a release's --signing"),
        "{err}"
    );
    std::fs::write(
        &ci_signing,
        "[[manifest]]\nalgorithm = \"ml-dsa-87\"\nkey-env = \"SEAWORTHY_RELEASE_KEY_HEX\"\n",
    )
    .unwrap();
    let (code, err) = run(&["--ci-test-signing".as_ref(), ci_signing.as_os_str()]);
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("not secrets in the environment"), "{err}");
    std::fs::write(&ci_signing, &test_key_file).unwrap();
    let (code, err) = run(&["--ci-test-signing".as_ref(), ci_signing.as_os_str()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(err.contains("--ci-test-signing: manifests"), "{err}");
    // A run that makes no rpm or pacman package (a tarball, no repository
    // package; the Mac's pkg and dmg) never loads the file's `[openpgp]`:
    // its key file may as well not exist, and no gpg runs.
    std::fs::write(
        &ci_signing,
        format!(
            "{test_key_file}\n[openpgp]\nkey = \"4996512A5F43B01A5CE106D88FEA21780AA09CA1\"\n\
             secret-key-file = \"{}\"\n",
            tmp.path().join("no-such-key.asc").display()
        ),
    )
    .unwrap();
    let (code, err) = run(&["--ci-test-signing".as_ref(), ci_signing.as_os_str()]);
    assert_eq!(code, Some(0), "{err}");
}
