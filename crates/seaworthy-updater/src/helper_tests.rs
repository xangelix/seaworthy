//! End-to-end tests of [`super::run`] against loopback HTTP stubs, with a
//! fake installer standing in for the package manager (the real ones run
//! in the repository's conformance lanes).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::tests_support::{Reply, SigningKey, Stub, signed, stub};
use crate::{DigestAlgorithm, ReleaseManifest, SignatureAlgorithm};

const VENDOR: &str = "SeaworthyHelperTest";
const PACKAGE: &str = "seaworthyhelpertest-agent";

fn product(policy: UpdatePolicy) -> Product {
    Product::new(VENDOR, "agent", "Agent", "stable")
        .unwrap()
        .with_default_policy(policy)
}

/// A fresh staging directory, private as systemd's `CacheDirectoryMode=0700`
/// makes it (tempfile's mode follows the umask).
fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn release(version: &str, sequence: u64) -> Release {
    Release::new(version, sequence).unwrap()
}

/// What a fake package of `format` starts with, then `payload`.
fn package_bytes(format: ArtifactFormat, payload: &[u8]) -> Vec<u8> {
    let mut bytes = match format {
        ArtifactFormat::Deb => {
            b"!<arch>\ndebian-binary   1700000000  0     0     100644  4         `\n2.0\n".to_vec()
        }
        ArtifactFormat::Rpm => vec![0xed, 0xab, 0xee, 0xdb, 3, 0, 0, 0],
        ArtifactFormat::Pacman => vec![0x28, 0xb5, 0x2f, 0xfd],
        ArtifactFormat::Msi => vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
        other => panic!("no fake {other} package"),
    };
    bytes.extend_from_slice(payload);
    bytes
}

fn manifest(
    version: &str,
    build: &str,
    sequence: u64,
    format: ArtifactFormat,
    artifact: &[u8],
) -> ReleaseManifest {
    ReleaseManifest {
        product: PACKAGE.into(),
        channel: Some("stable".into()),
        version: version.into(),
        build: build.into(),
        sequence,
        target: crate::TARGET_TRIPLE.into(),
        format,
        size: artifact.len() as u64,
        digest_algorithm: DigestAlgorithm::Sha512,
        digest: DigestAlgorithm::Sha512.hash(artifact),
    }
}

/// One install the fake was asked for.
#[derive(Debug, Clone)]
struct Installed {
    file: PathBuf,
    bytes: Vec<u8>,
    release: Release,
    downgrade: bool,
    signature: Option<Vec<u8>>,
}

/// The package manager, faked: it reports `installed`, records what it's
/// asked to install, and (when `takes`) then reports that release.
#[derive(Debug)]
struct FakeState {
    format: ArtifactFormat,
    installed: Mutex<Option<Release>>,
    installs: Mutex<Vec<Installed>>,
    takes: bool,
    fails: bool,
    /// Hands the install off (Windows' msiexec): nothing changes before
    /// the run ends.
    hands_off: bool,
    queries: AtomicUsize,
    /// What the second query reports, when set: someone else changed the
    /// installed release while the run downloaded.
    changes_to: Option<Option<Release>>,
    /// Whether the memo held the attempt when the install ran.
    memo_at_install: Mutex<Vec<bool>>,
    staging: Mutex<Option<PathBuf>>,
}

#[derive(Debug, Clone)]
struct Fake(Arc<FakeState>);

impl Fake {
    fn new(format: ArtifactFormat, installed: Option<Release>) -> Self {
        Self(Arc::new(FakeState {
            format,
            installed: Mutex::new(installed),
            installs: Mutex::new(Vec::new()),
            takes: true,
            fails: false,
            hands_off: false,
            queries: AtomicUsize::new(0),
            changes_to: None,
            memo_at_install: Mutex::new(Vec::new()),
            staging: Mutex::new(None),
        }))
    }

    fn changing(format: ArtifactFormat, installed: Release, to: Option<Release>) -> Self {
        let fake = Self::new(format, Some(installed));
        Self(Arc::new(FakeState {
            changes_to: Some(to),
            ..Arc::try_unwrap(fake.0).unwrap()
        }))
    }

    fn watching(self, staging: &Path) -> Self {
        *self.0.staging.lock().unwrap() = Some(staging.to_owned());
        self
    }

    fn not_taking(format: ArtifactFormat, installed: Release) -> Self {
        let fake = Self::new(format, Some(installed));
        Self(Arc::new(FakeState {
            takes: false,
            ..Arc::try_unwrap(fake.0).unwrap()
        }))
    }

    fn handing_off(format: ArtifactFormat, installed: Release) -> Self {
        let fake = Self::new(format, Some(installed));
        Self(Arc::new(FakeState {
            takes: false,
            hands_off: true,
            ..Arc::try_unwrap(fake.0).unwrap()
        }))
    }

    fn failing(format: ArtifactFormat, installed: Release) -> Self {
        let fake = Self::new(format, Some(installed));
        Self(Arc::new(FakeState {
            fails: true,
            ..Arc::try_unwrap(fake.0).unwrap()
        }))
    }

    fn installs(&self) -> Vec<Installed> {
        self.0.installs.lock().unwrap().clone()
    }
}

impl Installer for Fake {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn hands_off(&self) -> bool {
        self.0.hands_off
    }

    fn format(&self) -> ArtifactFormat {
        self.0.format
    }

    fn installed(&self, package: &str) -> Result<Option<Release>, InstallError> {
        assert_eq!(package, PACKAGE);
        let query = self.0.queries.fetch_add(1, Ordering::SeqCst);
        if query == 1
            && let Some(to) = &self.0.changes_to
        {
            return Ok(to.clone());
        }
        Ok(self.0.installed.lock().unwrap().clone())
    }

    fn install(&self, install: &Install<'_>) -> Result<(), InstallError> {
        assert_eq!(install.package, PACKAGE);
        if let Some(staging) = self.0.staging.lock().unwrap().as_ref() {
            self.0
                .memo_at_install
                .lock()
                .unwrap()
                .push(staging.join("failure-memo").exists());
        }
        let bytes = std::fs::read(install.file).unwrap();
        let signature = install.signature.map(|s| std::fs::read(s).unwrap());
        self.0.installs.lock().unwrap().push(Installed {
            file: install.file.to_owned(),
            bytes,
            release: install.release.clone(),
            downgrade: install.is_downgrade(),
            signature,
        });
        if self.0.fails {
            return Err(InstallError::Install(
                "the fake package manager failed".into(),
            ));
        }
        if self.0.takes {
            *self.0.installed.lock().unwrap() = Some(install.release.clone());
        }
        Ok(())
    }
}

/// A served release: the stub, the key that signed it, and the paths.
struct Served {
    stub: Stub,
    key: SigningKey,
    template: String,
}

fn serve(
    token_path: &str,
    format: ArtifactFormat,
    artifact: &[u8],
    manifest_bytes: Vec<u8>,
    extra: Vec<(String, Reply)>,
) -> Stub {
    // As the helper sends it: the token's `+` as `%2B`.
    let path = format!(
        "/{PACKAGE}/stable/{}/{}/{PACKAGE}.{}",
        token_path.replace('+', "%2B"),
        crate::TARGET_TRIPLE,
        format.tag()
    );
    let mut routes = vec![
        (path.clone(), Reply::Ok(artifact.to_vec())),
        (format!("{path}.manifest"), Reply::Ok(manifest_bytes)),
    ];
    for (suffix, reply) in extra {
        routes.push((format!("{path}{suffix}"), reply));
    }
    stub(routes)
}

fn served(token: &str, manifest: &ReleaseManifest, artifact: &[u8]) -> Served {
    let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
    let bytes = signed(manifest, &[&key]);
    let stub = serve(token, manifest.format, artifact, bytes, Vec::new());
    let template = format!(
        "{}/{{product}}/{{channel}}/{{version}}/{{target}}/{{product}}.{{format}}",
        stub.base
    );
    Served {
        stub,
        key,
        template,
    }
}

fn config(
    served: &Served,
    product: Product,
    server_token: &str,
    installer: Fake,
    staging: &Path,
) -> HelperConfig {
    let trust = ManifestTrust::for_product(&product, [served.key.release_key()]).unwrap();
    let token = server_token.to_owned();
    HelperConfig::new(
        product,
        trust,
        served.template.clone(),
        move || {
            let token = token.clone();
            async move { Ok::<_, String>(token) }
        },
        PackageSignatures::ManifestOnly,
    )
    .unwrap()
    .installer(installer)
    .staging_dir(staging)
    .unprivileged_for_tests()
    .min_run_interval(Duration::ZERO)
}

/// The files a run left in `staging` (the lock, the memo and the last
/// run's marker aside).
fn leftovers(staging: &Path) -> Vec<String> {
    std::fs::read_dir(staging)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !super::STAGING_KEEPS.contains(&name.as_str()))
        .collect()
}

fn memo_exists(staging: &Path) -> bool {
    staging.join("failure-memo").exists()
}

#[tokio::test]
async fn the_servers_release_is_downloaded_verified_installed_and_confirmed() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"release 1.1.0");
    let manifest = manifest("1.1.0", "abc123", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0+abc123", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "v1.1.0+abc123",
        fake.clone(),
        staging.path(),
    )
    .server_token_prefix("v");
    let outcome = run(&config).await.unwrap();
    assert_eq!(
        outcome,
        HelperOutcome::Installed {
            from: release("1.0.0", 1),
            to: release("1.1.0", 2)
        }
    );
    let installs = fake.installs();
    assert_eq!(installs.len(), 1);
    let Installed {
        file,
        bytes,
        release: to,
        downgrade,
        signature,
    } = &installs[0];
    assert_eq!(file, &staging.path().join(format!("{PACKAGE}-1.1.0-2.deb")));
    assert_eq!(bytes, &artifact);
    assert_eq!(
        (to, *downgrade, signature),
        (&release("1.1.0", 2), false, &None)
    );
    assert!(
        leftovers(staging.path()).is_empty(),
        "{:?}",
        leftovers(staging.path())
    );
    assert!(
        !memo_exists(staging.path()),
        "a confirmed install clears the memo"
    );
    assert_eq!(
        served.stub.requests().len(),
        2,
        "the manifest, then the package"
    );
}

#[tokio::test]
async fn an_install_handed_off_keeps_its_file_and_is_confirmed_by_the_next_run() {
    // Windows' msiexec: the helper exits before the install ends.
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Msi, b"release 1.1.0");
    let manifest = manifest("1.1.0", "abc123", 2, ArtifactFormat::Msi, &artifact);
    let served = served("1.1.0+abc123", &manifest, &artifact);
    let fake = Fake::handing_off(ArtifactFormat::Msi, release("1.0.0", 1));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0+abc123",
        fake.clone(),
        staging.path(),
    );
    let outcome = run(&config).await.unwrap();
    assert_eq!(
        outcome,
        HelperOutcome::HandedOff {
            from: release("1.0.0", 1),
            to: release("1.1.0", 2)
        }
    );
    assert!(succeeded(&Ok(outcome)));
    let installs = fake.installs();
    assert_eq!(installs.len(), 1);
    let staged = staging.path().join(format!("{PACKAGE}-1.1.0-2.msi"));
    assert_eq!(installs[0].file, staged);
    // The installer reads the file after the run: it stays, as does the
    // attempt (only a confirmed install clears the memo).
    assert_eq!(std::fs::read(&staged).unwrap(), artifact);
    assert!(memo_exists(staging.path()));
    // msiexec installed it; the next run sweeps the file and finds the
    // release installed.
    *fake.0.installed.lock().unwrap() = Some(release("1.1.0", 2));
    std::fs::write(staging.path().join(crate::installer::MSIEXEC_LOG), b"log").unwrap();
    let config = config.min_run_interval(Duration::ZERO);
    let memo = crate::memo::FailureMemo::new(staging.path().join("failure-memo"));
    memo.clear();
    assert_eq!(
        run(&config).await.unwrap(),
        HelperOutcome::UpToDate {
            installed: release("1.1.0", 2)
        }
    );
    assert!(!staged.exists(), "the next run sweeps the handed-off file");
    assert!(
        staging.path().join(crate::installer::MSIEXEC_LOG).exists(),
        "msiexec's last log is kept"
    );
}

#[tokio::test]
async fn the_policy_is_read_again_and_anything_but_auto_installs_nothing() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    for policy in [UpdatePolicy::Notify, UpdatePolicy::Off] {
        let config = config(
            &served,
            product(policy),
            "1.1.0",
            fake.clone(),
            staging.path(),
        );
        assert!(matches!(
            run(&config).await.unwrap(),
            HelperOutcome::PolicyNotAuto(PolicyDecision { policy: p, .. }) if p == policy
        ));
    }
    assert!(served.stub.requests().is_empty());
    assert!(fake.installs().is_empty());
    assert_eq!(
        fake.0.queries.load(Ordering::SeqCst),
        0,
        "nothing is even queried"
    );
}

#[tokio::test]
async fn the_version_floor_orders_by_version_then_sequence() {
    // (installed, offered, outcome): Some(true) installs, Some(false) is
    // up to date, None is a refused downgrade.
    let cases = [
        (("1.0.0", 7), ("1.0.0", 8), Some(true)),
        (("1.0.0", 8), ("1.0.0", 8), Some(false)),
        (("1.0.0", 9), ("1.0.0", 8), None),
        (("1.1.0", 1), ("1.0.0", 8), None),
        (("1.0.0-rc.2", 9), ("1.0.0", 3), Some(true)),
        (("1.0.0", 1), ("1.0.0-rc.2", 9), None),
    ];
    for ((iv, is), (ov, os), expected) in cases {
        let staging = private_dir();
        let artifact = package_bytes(ArtifactFormat::Deb, ov.as_bytes());
        let manifest = manifest(ov, "", os, ArtifactFormat::Deb, &artifact);
        let served = served(ov, &manifest, &artifact);
        let fake = Fake::new(ArtifactFormat::Deb, Some(release(iv, is)));
        let result = run(&config(
            &served,
            product(UpdatePolicy::Auto),
            ov,
            fake.clone(),
            staging.path(),
        ))
        .await;
        match expected {
            Some(true) => assert!(
                matches!(result, Ok(HelperOutcome::Installed { .. })),
                "{iv}/{is} → {ov}/{os}: {result:?}"
            ),
            Some(false) => {
                assert!(
                    matches!(result, Ok(HelperOutcome::UpToDate { .. })),
                    "{result:?}"
                );
                assert!(fake.installs().is_empty());
                assert!(memo_exists(staging.path()), "a no-op backs off too");
            }
            None => {
                assert!(
                    matches!(result, Err(HelperError::Downgrade { .. })),
                    "{iv}/{is} → {ov}/{os}: {result:?}"
                );
                assert!(fake.installs().is_empty());
                assert_eq!(
                    served.stub.requests().len(),
                    1,
                    "only the manifest was fetched"
                );
            }
        }
    }
}

#[tokio::test]
async fn downgrades_install_only_when_the_product_allows_them() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Rpm, b"old");
    let manifest = manifest("1.0.0", "", 3, ArtifactFormat::Rpm, &artifact);
    let served = served("1.0.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Rpm, Some(release("1.2.0", 9)));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.0.0",
        fake.clone(),
        staging.path(),
    )
    .allow_downgrades();
    assert_eq!(
        run(&config).await.unwrap(),
        HelperOutcome::Installed {
            from: release("1.2.0", 9),
            to: release("1.0.0", 3)
        }
    );
    let installs = fake.installs();
    assert!(
        installs[0].downgrade,
        "the installer is told it's a downgrade"
    );
    assert!(installs[0].file.to_string_lossy().ends_with(".rpm"));
}

#[tokio::test]
async fn a_failed_version_backs_off_before_any_network_io() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::failing(ArtifactFormat::Deb, release("1.0.0", 1));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    );
    assert!(matches!(
        run(&config).await,
        Err(HelperError::Install(InstallError::Install(_)))
    ));
    assert!(memo_exists(staging.path()));
    let requests = served.stub.requests().len();
    let error = run(&config).await.unwrap_err();
    assert!(
        matches!(error, HelperError::Backoff { ref version, .. } if version == "1.1.0"),
        "{error}"
    );
    assert!(error.is_expected());
    assert_eq!(
        served.stub.requests().len(),
        requests,
        "no network I/O while backing off"
    );
    assert_eq!(fake.installs().len(), 1);
    assert!(
        leftovers(staging.path()).is_empty(),
        "{:?}",
        leftovers(staging.path())
    );
}

#[tokio::test]
async fn tampered_wrong_format_and_wrong_magic_releases_never_reach_the_installer() {
    let good = package_bytes(ArtifactFormat::Deb, b"genuine");
    let cases: Vec<(&str, ReleaseManifest, Vec<u8>)> = vec![
        // The bytes served aren't the ones the manifest names.
        (
            "tampered",
            manifest("1.1.0", "", 2, ArtifactFormat::Deb, &good),
            package_bytes(ArtifactFormat::Deb, b"evil!!!"),
        ),
        // A correctly signed manifest for another format.
        (
            "format",
            manifest("1.1.0", "", 2, ArtifactFormat::Rpm, &good),
            good.clone(),
        ),
        // Signed and digested, but not a deb (an error page captured by CI).
        (
            "magic",
            manifest("1.1.0", "", 2, ArtifactFormat::Deb, b"<html>oops</html>"),
            b"<html>oops</html>".to_vec(),
        ),
        // Another product, another channel, another version, another target.
        (
            "product",
            ReleaseManifest {
                product: "other".into(),
                ..manifest("1.1.0", "", 2, ArtifactFormat::Deb, &good)
            },
            good.clone(),
        ),
        (
            "channel",
            ReleaseManifest {
                channel: Some("beta".into()),
                ..manifest("1.1.0", "", 2, ArtifactFormat::Deb, &good)
            },
            good.clone(),
        ),
        (
            "version",
            manifest("1.1.0", "otherbuild", 2, ArtifactFormat::Deb, &good),
            good.clone(),
        ),
        (
            "target",
            ReleaseManifest {
                target: "riscv64gc-unknown-linux-gnu".into(),
                ..manifest("1.1.0", "", 2, ArtifactFormat::Deb, &good)
            },
            good.clone(),
        ),
        // A version outside the release grammar the floor orders.
        (
            "grammar",
            manifest("1.1", "", 2, ArtifactFormat::Deb, &good),
            good.clone(),
        ),
    ];
    for (name, manifest, served_bytes) in cases {
        let staging = private_dir();
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let token = if name == "grammar" { "1.1" } else { "1.1.0" };
        let stub = serve(
            token,
            ArtifactFormat::Deb,
            &served_bytes,
            signed(&manifest, &[&key]),
            Vec::new(),
        );
        let served = Served {
            template: format!(
                "{}/{{product}}/{{channel}}/{{version}}/{{target}}/{{product}}.{{format}}",
                stub.base
            ),
            stub,
            key,
        };
        let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
        let result = run(&config(
            &served,
            product(UpdatePolicy::Auto),
            token,
            fake.clone(),
            staging.path(),
        ))
        .await;
        assert!(result.is_err(), "{name}: {result:?}");
        assert!(fake.installs().is_empty(), "{name} reached the installer");
        assert!(memo_exists(staging.path()), "{name} wasn't recorded");
        assert!(
            leftovers(staging.path()).is_empty(),
            "{name}: {:?}",
            leftovers(staging.path())
        );
    }
}

#[tokio::test]
async fn a_manifest_signed_by_an_untrusted_key_is_refused() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let mut served = served("1.1.0", &manifest, &artifact);
    served.key = SigningKey::generate(SignatureAlgorithm::Ed25519);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    let result = run(&config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    ))
    .await;
    assert!(
        matches!(
            result,
            Err(HelperError::Update(UpdateError::SignatureMismatch))
        ),
        "{result:?}"
    );
    assert_eq!(
        served.stub.requests().len(),
        1,
        "the package is never fetched"
    );
}

#[tokio::test]
async fn an_install_that_doesnt_take_is_a_failure() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Pacman, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Pacman, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::not_taking(ArtifactFormat::Pacman, release("1.0.0", 1));
    let result = run(&config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    ))
    .await;
    assert!(
        matches!(result, Err(HelperError::NotTaken { .. })),
        "{result:?}"
    );
    assert!(memo_exists(staging.path()));
    assert!(
        fake.installs()[0]
            .file
            .to_string_lossy()
            .ends_with(".pkg.tar.zst")
    );
}

#[tokio::test]
async fn one_run_at_a_time_and_only_from_a_private_staging_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    );
    {
        let _held = crate::staging::TargetLock::try_acquire(&staging.path().join(".lock")).unwrap();
        let error = run(&config).await.unwrap_err();
        assert!(
            matches!(error, HelperError::InProgress) && error.is_expected(),
            "{error}"
        );
    }
    std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(run(&config).await, Err(HelperError::Staging(_))));
    std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // A staging path through a symlink.
    let link = staging.path().join("link");
    let real = staging.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let through_link = HelperConfig {
        staging: Some(link.join("x")),
        ..config
    };
    assert!(matches!(
        run(&through_link).await,
        Err(HelperError::Staging(_))
    ));
    assert!(served.stub.requests().is_empty());
    assert!(fake.installs().is_empty());
}

#[tokio::test]
async fn probes_and_server_tokens_are_checked() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    // Without the configured prefix; with a path in it.
    for token in ["1.1.0", "v1.1.0/../x"] {
        let config = config(
            &served,
            product(UpdatePolicy::Auto),
            token,
            fake.clone(),
            staging.path(),
        )
        .server_token_prefix("v");
        assert!(
            matches!(run(&config).await, Err(HelperError::Version(_))),
            "{token}"
        );
    }
    // A probe that fails or hangs.
    let base = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    );
    let failing = HelperConfig {
        probe: Arc::new(|| Box::pin(async { Err("connection refused".to_owned()) })),
        ..base
    };
    assert!(matches!(run(&failing).await, Err(HelperError::Probe(_))));
    let hanging = HelperConfig {
        probe: Arc::new(|| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Ok(String::new())
            })
        }),
        probe_timeout: Duration::from_millis(200),
        ..failing
    };
    assert!(matches!(run(&hanging).await, Err(HelperError::Probe(_))));
    assert!(served.stub.requests().is_empty());
    assert!(
        !memo_exists(staging.path()),
        "nothing to back off from without the server's token"
    );
    // Not installed at all.
    let missing = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        Fake::new(ArtifactFormat::Deb, None),
        staging.path(),
    );
    assert!(matches!(
        run(&missing).await,
        Err(HelperError::Install(InstallError::Unsupported(_)))
    ));
}

#[test]
fn configurations_that_could_never_install_are_refused_up_front() {
    let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
    let probe = || async { Ok::<_, String>("1.0.0".to_owned()) };
    let good =
        "https://packages.example.com/{product}/{channel}/{version}/{target}/{product}.{format}";
    let trust =
        ManifestTrust::for_product(&product(UpdatePolicy::Auto), [key.release_key()]).unwrap();
    assert!(
        HelperConfig::new(
            product(UpdatePolicy::Auto),
            trust.clone(),
            good,
            probe,
            PackageSignatures::ManifestOnly
        )
        .is_ok()
    );
    let wrong_product = ManifestTrust::new("acme-agent", [key.release_key()])
        .unwrap()
        .channel("stable")
        .unwrap();
    let wrong_channel = ManifestTrust::new(PACKAGE, [key.release_key()])
        .unwrap()
        .channel("beta")
        .unwrap();
    let no_channel = ManifestTrust::new(PACKAGE, [key.release_key()]).unwrap();
    for trust in [wrong_product, wrong_channel, no_channel] {
        assert!(matches!(
            HelperConfig::new(
                product(UpdatePolicy::Auto),
                trust,
                good,
                probe,
                PackageSignatures::ManifestOnly
            ),
            Err(HelperError::Config(_))
        ));
    }
    for template in [
        "http://packages.example.com/{version}",
        "https://packages.example.com/{version}/{arch}",
        "https://packages.example.com/{version",
        "ftp://packages.example.com/{version}",
    ] {
        assert!(
            matches!(
                HelperConfig::new(
                    product(UpdatePolicy::Auto),
                    trust.clone(),
                    template,
                    probe,
                    PackageSignatures::ManifestOnly
                ),
                Err(HelperError::Config(_))
            ),
            "{template}"
        );
    }
    assert_eq!(
        expand_package_url(
            good,
            "1.4.0+abc",
            &product(UpdatePolicy::Auto),
            ArtifactFormat::Pacman
        )
        .unwrap(),
        format!(
            "https://packages.example.com/{PACKAGE}/stable/1.4.0%2Babc/{}/{PACKAGE}.pacman",
            crate::TARGET_TRIPLE
        )
    );
}

/// A throwaway gpg key for the signature layer; `None` (announced) when
/// gpg isn't installed, unless SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1.
fn gpg_key() -> Option<(tempfile::TempDir, String, Vec<u8>)> {
    let runs = std::process::Command::new("/usr/bin/gpg")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !runs {
        assert!(
            !crate::tests_support::tools_required(),
            "/usr/bin/gpg is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1)"
        );
        eprintln!("SKIPPED: /usr/bin/gpg is not installed");
        return None;
    }
    let home = tempfile::tempdir().unwrap();
    let gpg = |args: &[&str]| {
        let out = std::process::Command::new("/usr/bin/gpg")
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--pinentry-mode", "loopback", "--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    gpg(&[
        "--quick-gen-key",
        "Seaworthy Helper Test <helper@example.com>",
        "ed25519",
        "sign",
        "never",
    ]);
    let listing = String::from_utf8(gpg(&["--list-keys", "--with-colons"])).unwrap();
    let fingerprint = listing
        .lines()
        .find_map(|l| l.strip_prefix("fpr:"))
        .and_then(|l| l.split(':').nth(8))
        .unwrap()
        .to_owned();
    let public = gpg(&["--armor", "--export", &fingerprint]);
    Some((home, fingerprint, public))
}

fn gpg_detach_sign(home: &Path, fingerprint: &str, data: &[u8]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data");
    std::fs::write(&file, data).unwrap();
    let out = std::process::Command::new("/usr/bin/gpg")
        .arg("--homedir")
        .arg(home)
        .args([
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--local-user",
            fingerprint,
            "--detach-sign",
            "--output",
            "-",
        ])
        .arg(&file)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[tokio::test]
async fn pacman_packages_carry_a_signature_from_a_pinned_key() {
    let Some((home, fingerprint, public)) = gpg_key() else {
        return;
    };
    let Some((other_home, other_fingerprint, _)) = gpg_key() else {
        return;
    };
    let artifact = package_bytes(ArtifactFormat::Pacman, b"signed release");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Pacman, &artifact);
    let keys = OpenPgpKeys::new([public]).unwrap();
    for (signature, accepted) in [
        (
            Some(gpg_detach_sign(home.path(), &fingerprint, &artifact)),
            true,
        ),
        (
            Some(gpg_detach_sign(
                other_home.path(),
                &other_fingerprint,
                &artifact,
            )),
            false,
        ),
        (
            Some(gpg_detach_sign(home.path(), &fingerprint, b"other bytes")),
            false,
        ),
        (None, false),
    ] {
        let staging = private_dir();
        let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
        let extra = signature
            .clone()
            .map(|s| vec![(".sig".to_owned(), Reply::Ok(s))])
            .unwrap_or_default();
        let stub = serve(
            "1.1.0",
            ArtifactFormat::Pacman,
            &artifact,
            signed(&manifest, &[&key]),
            extra,
        );
        let served = Served {
            template: format!(
                "{}/{{product}}/{{channel}}/{{version}}/{{target}}/{{product}}.{{format}}",
                stub.base
            ),
            stub,
            key,
        };
        let fake = Fake::new(ArtifactFormat::Pacman, Some(release("1.0.0", 1)));
        let config = HelperConfig {
            signatures: PackageSignatures::Pinned(keys.clone()),
            ..config(
                &served,
                product(UpdatePolicy::Auto),
                "1.1.0",
                fake.clone(),
                staging.path(),
            )
        };
        let result = run(&config).await;
        if accepted {
            assert!(
                matches!(result, Ok(HelperOutcome::Installed { .. })),
                "{result:?}"
            );
            assert_eq!(
                fake.installs()[0].signature,
                signature,
                "the installer gets the verified signature"
            );
        } else {
            assert!(result.is_err(), "{result:?}");
            assert!(fake.installs().is_empty());
        }
        assert!(
            leftovers(staging.path()).is_empty(),
            "{:?}",
            leftovers(staging.path())
        );
    }
}

#[tokio::test]
async fn the_attempt_is_recorded_before_the_install_and_cleared_by_success() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1))).watching(staging.path());
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    );
    assert!(matches!(
        run(&config).await,
        Ok(HelperOutcome::Installed { .. })
    ));
    assert_eq!(
        *fake.0.memo_at_install.lock().unwrap(),
        [true],
        "a run killed mid-install backs off"
    );
    assert!(!memo_exists(staging.path()));
}

#[tokio::test]
async fn a_release_installed_by_someone_else_during_the_run_is_never_replaced() {
    for now in [Some(release("1.2.0", 7)), Some(release("1.0.0", 2)), None] {
        let staging = private_dir();
        let artifact = package_bytes(ArtifactFormat::Rpm, b"x");
        let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Rpm, &artifact);
        let served = served("1.1.0", &manifest, &artifact);
        let fake = Fake::changing(ArtifactFormat::Rpm, release("1.0.0", 1), now.clone());
        let result = run(&config(
            &served,
            product(UpdatePolicy::Auto),
            "1.1.0",
            fake.clone(),
            staging.path(),
        ))
        .await;
        assert!(
            matches!(result, Err(HelperError::InstalledChanged { .. })),
            "{now:?}: {result:?}"
        );
        assert!(fake.installs().is_empty());
        assert!(memo_exists(staging.path()));
    }
}

#[tokio::test]
async fn more_bytes_than_the_manifest_names_are_refused_by_size() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"genuine");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let mut longer = artifact.clone();
    longer.extend_from_slice(b" and then some");
    let key = SigningKey::generate(SignatureAlgorithm::Ed25519);
    let stub = serve(
        "1.1.0",
        ArtifactFormat::Deb,
        &longer,
        signed(&manifest, &[&key]),
        Vec::new(),
    );
    let served = Served {
        template: format!(
            "{}/{{product}}/{{channel}}/{{version}}/{{target}}/{{product}}.{{format}}",
            stub.base
        ),
        stub,
        key,
    };
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    let result = run(&config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    ))
    .await;
    assert!(
        matches!(
            result,
            Err(HelperError::Update(UpdateError::SizeMismatch { .. }))
        ),
        "{result:?}"
    );
    assert!(fake.installs().is_empty());
}

#[tokio::test]
async fn runs_too_close_together_end_before_any_network_io() {
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.1.0", 2)));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake.clone(),
        staging.path(),
    )
    .min_run_interval(Duration::from_secs(3600));
    assert!(matches!(
        run(&config).await,
        Ok(HelperOutcome::UpToDate { .. })
    ));
    let requests = served.stub.requests().len();
    let error = run(&config).await.unwrap_err();
    assert!(
        matches!(error, HelperError::Throttled { .. }) && error.is_expected(),
        "{error}"
    );
    assert_eq!(served.stub.requests().len(), requests);
    assert_eq!(
        fake.0.queries.load(Ordering::SeqCst),
        1,
        "not even the package manager is asked"
    );
    // A last run in the future (a clock set back) doesn't hold runs off.
    let marker = staging.path().join("last-run");
    let future = std::time::SystemTime::now() + Duration::from_secs(86_400);
    std::fs::File::options()
        .write(true)
        .open(&marker)
        .unwrap()
        .set_modified(future)
        .unwrap();
    assert!(!matches!(
        run(&config).await,
        Err(HelperError::Throttled { .. })
    ));
}

#[tokio::test]
async fn a_previous_runs_leftovers_are_swept_under_the_lock() {
    let staging = private_dir();
    for name in [
        ".seaworthyhelpertest-agent.abc.seaworthy-download",
        "seaworthyhelpertest-agent-1.1.0-2.deb",
        "x.download-sig",
    ] {
        std::fs::write(staging.path().join(name), b"stale").unwrap();
    }
    std::fs::create_dir(staging.path().join("sw-gpg-1-2-3")).unwrap();
    std::fs::write(staging.path().join("sw-gpg-1-2-3/pubring.kbx"), b"stale").unwrap();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.1.0", 2)));
    let config = config(
        &served,
        product(UpdatePolicy::Auto),
        "1.1.0",
        fake,
        staging.path(),
    );
    assert!(matches!(
        run(&config).await,
        Ok(HelperOutcome::UpToDate { .. })
    ));
    let mut left: Vec<String> = std::fs::read_dir(staging.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, [".lock", "failure-memo", "last-run"]);
}

#[tokio::test]
async fn the_helper_runs_only_as_root_from_a_root_owned_private_directory() {
    use std::os::unix::fs::PermissionsExt as _;
    #[allow(unsafe_code, reason = "geteuid(2)")]
    // SAFETY: geteuid takes no arguments and can't fail.
    let euid = unsafe { libc::geteuid() };
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Deb, b"x");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Deb, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Deb, Some(release("1.0.0", 1)));
    let privileged = HelperConfig {
        require_root: true,
        ..config(
            &served,
            product(UpdatePolicy::Auto),
            "1.1.0",
            fake.clone(),
            staging.path(),
        )
    };
    if euid != 0 {
        assert!(
            matches!(run(&privileged).await, Err(HelperError::NotPrivileged(uid)) if uid == euid)
        );
        // The staging directory must be root's.
        let error = prepare_staging(staging.path(), true).unwrap_err();
        assert!(error.to_string().contains("not root"), "{error}");
    }
    // Every directory above it must be closed to group and others.
    let parent = private_dir();
    let nested = parent.path().join("staging");
    std::fs::create_dir(&nested).unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(prepare_staging(&nested, false).is_ok());
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
    let error = prepare_staging(&nested, false).unwrap_err();
    assert!(error.to_string().contains("writable by group"), "{error}");
    // A missing staging directory is made private.
    let fresh = parent.path().join("fresh");
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    prepare_staging(&fresh, false).unwrap();
    assert_eq!(
        std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(prepare_staging(Path::new("relative/staging"), false).is_err());
    assert!(fake.installs().is_empty());
}

#[test]
fn the_exit_status_fails_only_on_failures() {
    let ok = |o: HelperOutcome| succeeded(&Ok(o));
    assert!(ok(HelperOutcome::UpToDate {
        installed: release("1.0.0", 1)
    }));
    assert!(ok(HelperOutcome::Installed {
        from: release("1.0.0", 1),
        to: release("1.1.0", 2)
    }));
    assert!(ok(HelperOutcome::HandedOff {
        from: release("1.0.0", 1),
        to: release("1.1.0", 2)
    }));
    assert!(ok(HelperOutcome::PolicyNotAuto(PolicyDecision {
        policy: UpdatePolicy::Off,
        source: crate::PolicySource::ProductDefault
    })));
    for expected in [
        HelperError::InProgress,
        HelperError::Backoff {
            version: "1.1.0".into(),
            retry_after: Duration::from_secs(60),
        },
        HelperError::Throttled {
            interval: Duration::from_secs(30),
            retry_after: Duration::from_secs(1),
        },
    ] {
        assert!(succeeded(&Err(expected)));
    }
    for failure in [
        HelperError::Probe("x".into()),
        HelperError::Downgrade {
            installed: Box::new(release("1.1.0", 1)),
            offered: Box::new(release("1.0.0", 1)),
        },
        HelperError::NotPrivileged(1000),
        HelperError::NotElevated("started as S-1-5-21-1-2-3-1001, not elevated".into()),
        HelperError::Signature("x".into()),
    ] {
        assert!(!succeeded(&Err(failure)));
    }
}

#[tokio::test]
async fn rpm_packages_must_carry_a_signature_from_a_pinned_key() {
    if !Path::new("/usr/bin/rpmkeys").is_file() {
        assert!(
            !crate::tests_support::tools_required(),
            "/usr/bin/rpmkeys is required (SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1)"
        );
        eprintln!("SKIPPED: /usr/bin/rpmkeys is not installed");
        return;
    }
    let Some((_home, _fingerprint, public)) = gpg_key() else {
        return;
    };
    // The fake rpm carries no signature at all: rpmkeys can't report a
    // good one, so nothing installs.
    let staging = private_dir();
    let artifact = package_bytes(ArtifactFormat::Rpm, b"unsigned");
    let manifest = manifest("1.1.0", "", 2, ArtifactFormat::Rpm, &artifact);
    let served = served("1.1.0", &manifest, &artifact);
    let fake = Fake::new(ArtifactFormat::Rpm, Some(release("1.0.0", 1)));
    let config = HelperConfig {
        signatures: PackageSignatures::Pinned(OpenPgpKeys::new([public]).unwrap()),
        ..config(
            &served,
            product(UpdatePolicy::Auto),
            "1.1.0",
            fake.clone(),
            staging.path(),
        )
    };
    let result = run(&config).await;
    assert!(
        matches!(result, Err(HelperError::Signature(_))),
        "{result:?}"
    );
    assert!(fake.installs().is_empty());
}
