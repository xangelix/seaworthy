//! Package and binary signatures (`seaworthy::codesign`), with
//! throwaway keys: Authenticode over a stamped binary, verified by
//! `osslsigncode verify` against the test certificate (and through an
//! external-command signer); OpenPGP over real rpm and pacman packages,
//! verified by `rpm -K` against the imported key and by `gpg --verify`
//! (what `pacman-key --verify` runs; `pacman-key` itself needs root, so the
//! Linux conformance lane runs it).
//!
//! A missing tool is skipped loudly, unless
//! `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1` turns the skip into a failure.

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

use common::{Keyring, Pe, have, nfpm, record, run};
use seaworthy::codesign::{
    AuthenticodeSigner, CommandAuthenticode, Gpg, OpenPgpSigner, Osslsigncode, signature_path,
    verify_authenticode,
};
use seaworthy::pe_version::{VersionInfo, stamp_version};
use seaworthy::version::Release;

/// A self-signed code-signing certificate and key (PEM).
fn test_certificate(dir: &Path) -> (PathBuf, PathBuf) {
    certificate(dir, "codesign", "/CN=Acme Test Code Signing/O=Acme")
}

/// A self-signed code-signing certificate for `subject` (OpenSSL's slash
/// form) and its key (0600), as `<name>.pem` and `<name>.key`.
fn certificate(dir: &Path, name: &str, subject: &str) -> (PathBuf, PathBuf) {
    let (cert, key) = (
        dir.join(format!("{name}.pem")),
        dir.join(format!("{name}.key")),
    );
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30", "-subj", subject,
        ])
        .args([
            "-addext",
            "extendedKeyUsage=codeSigning",
            "-addext",
            "keyUsage=digitalSignature",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    (cert, key)
}

fn stamped_core(dir: &Path) -> PathBuf {
    let pe = Pe {
        sections: vec![(
            ".cpureq".into(),
            record("x86_64-pc-windows-msvc", "x86-64-v3", common::V2),
        )],
        imports: vec!["kernel32.dll".into()],
        executable: false,
    }
    .build();
    let info = VersionInfo {
        company: "Acme",
        product: "Acme Agent",
        description: "Acme Agent core",
        file_name: "acme_core.dll",
        dll: true,
    };
    let path = dir.join("acme_core.dll");
    std::fs::write(
        &path,
        stamp_version(&pe, &Release::new("1.4.0", 7).unwrap(), &info).unwrap(),
    )
    .unwrap();
    path
}

fn osslsigncode(cert: &Path, key: &Path) -> Osslsigncode {
    Osslsigncode {
        tool: PathBuf::from("osslsigncode"),
        certificate: cert.to_path_buf(),
        key: key.to_path_buf(),
        timestamp_url: None,
        url: Some("https://acme.test".into()),
        timeout: Duration::from_secs(120),
    }
}

/// The subject `osslsigncode verify` prints for `test_certificate`'s.
const TEST_SUBJECT: &str = "O=Acme,CN=Acme Test Code Signing";

#[test]
fn authenticode_signs_a_stamped_binary_that_verifies() {
    if !have("osslsigncode", &["--version"]) || !have("openssl", &["version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (cert, key) = test_certificate(tmp.path());
    let file = stamped_core(tmp.path());
    let signer = osslsigncode(&cert, &key);
    signer.sign(&file, "Acme Agent").unwrap();
    let report = verify_authenticode(Path::new("osslsigncode"), &file, Some(&cert)).unwrap();
    assert!(report.contains("Signature verification: ok"), "{report}");
    assert!(report.contains("Acme Test Code Signing"), "{report}");
    // The record still reads, and a signed binary can't be stamped again.
    assert_eq!(
        seaworthy_levels::read_requirement(&file).unwrap().cpu,
        "x86-64-v3"
    );
    let signed = std::fs::read(&file).unwrap();
    let info = VersionInfo {
        company: "a",
        product: "b",
        description: "c",
        file_name: "d.dll",
        dll: true,
    };
    let err = stamp_version(&signed, &Release::new("1.4.1", 8).unwrap(), &info).unwrap_err();
    assert!(err.to_string().contains("Authenticode-signed"), "{err}");
    // A tampered byte fails verification.
    let mut tampered = signed;
    let at = tampered.len() / 3;
    tampered[at] ^= 0xff;
    std::fs::write(&file, tampered).unwrap();
    assert!(verify_authenticode(Path::new("osslsigncode"), &file, Some(&cert)).is_err());
    // No temporary file is left beside the signed one.
    let names: Vec<String> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.contains(".signing")), "{names:?}");
}

#[test]
fn an_external_authenticode_command_signs_in_place() {
    if !have("osslsigncode", &["--version"]) || !have("openssl", &["version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (cert, key) = test_certificate(tmp.path());
    let file = stamped_core(tmp.path());
    let script = format!(
        "osslsigncode sign -h sha256 -certs '{}' -key '{}' -n Acme -in \"$1\" -out \"$1.s\" && mv \"$1.s\" \"$1\"",
        cert.display(),
        key.display()
    );
    let signer = CommandAuthenticode {
        command: vec![
            "sh".into(),
            "-c".into(),
            script,
            "sh".into(),
            "{file}".into(),
        ],
        timeout: Duration::from_secs(120),
    };
    signer.sign(&file, "Acme Agent").unwrap();
    verify_authenticode(Path::new("osslsigncode"), &file, Some(&cert)).unwrap();
    // A command that can't know the file, and one that fails.
    let timeout = Duration::from_secs(120);
    assert!(
        CommandAuthenticode {
            command: vec!["true".into()],
            timeout
        }
        .sign(&file, "Acme")
        .is_err()
    );
    assert!(
        CommandAuthenticode {
            command: vec!["false".into(), "{file}".into()],
            timeout
        }
        .sign(&file, "Acme")
        .is_err()
    );
    // A hung signer (a stalled timestamp server, a remote signer) is killed
    // at its deadline, even when its child holds the pipes.
    let hung = CommandAuthenticode {
        command: vec![
            "sh".into(),
            "-c".into(),
            "sleep 60 & echo {file}; wait".into(),
        ],
        timeout: Duration::from_secs(1),
    };
    let started = std::time::Instant::now();
    let err = hung.sign(&file, "Acme").unwrap_err().to_string();
    assert!(err.contains("didn't finish within 1 s"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn signers_get_exactly_what_they_are_configured_with() {
    let tmp = tempfile::tempdir().unwrap();
    // `{file}` and `{description}` are replaced in one pass: a path that
    // itself contains `{description}` reaches the command unchanged.
    let file = tmp.path().join("odd {description} name.exe");
    std::fs::write(&file, b"MZ").unwrap();
    let seen = tmp.path().join("seen");
    let recorder = CommandAuthenticode {
        command: vec![
            "sh".into(),
            "-c".into(),
            "printf '%s|%s' \"$1\" \"$2\" > \"$3\"".into(),
            "sh".into(),
            "{file}".into(),
            "-n={description}".into(),
            seen.display().to_string(),
        ],
        timeout: Duration::from_secs(30),
    };
    recorder.sign(&file, "Acme Agent").unwrap();
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap(),
        format!("{}|-n=Acme Agent", file.display())
    );
    // An OpenPGP key named any way but its fingerprint is refused before
    // anything runs (rpm would expand macros in it, and a user id can
    // match another key).
    let by_name = Gpg {
        home: tmp.path().to_path_buf(),
        key: "Acme Packaging <pkg@acme.test>".into(),
        gpg: PathBuf::from("gpg"),
        rpmsign: PathBuf::from("rpmsign"),
        timeout: Duration::from_secs(30),
    };
    for err in [
        by_name.sign_rpm(&file).unwrap_err(),
        by_name
            .detach_sign(&file, &tmp.path().join("x.sig"))
            .unwrap_err(),
    ] {
        assert!(err.to_string().contains("fingerprint"), "{err}");
    }
}

#[test]
fn a_failing_authenticode_signer_leaves_the_file_unchanged() {
    if !have("osslsigncode", &["--version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let file = stamped_core(tmp.path());
    let before = std::fs::read(&file).unwrap();
    let missing = tmp.path().join("missing.pem");
    assert!(
        osslsigncode(&missing, &missing)
            .sign(&file, "Acme")
            .is_err()
    );
    assert_eq!(std::fs::read(&file).unwrap(), before);
}

/// Builds a one-file package of `packager` with nFPM.
fn package(nfpm: &Path, dir: &Path, packager: &str, target: &str) -> PathBuf {
    let file = dir.join("payload");
    std::fs::write(&file, vec![7u8; 4096]).unwrap();
    let config = dir.join("nfpm.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"name":"acme-test","arch":"amd64","version":"1.0.0","version_schema":"none","release":"1","maintainer":"Acme <pkg@acme.test>","description":"test","license":"MIT","mtime":"2023-11-14T22:13:20Z","contents":[{{"src":"{}","dst":"/opt/acme/test/payload","file_info":{{"mode":420,"mtime":"2023-11-14T22:13:20Z"}}}}]}}"#,
            file.display()
        ),
    )
    .unwrap();
    let out = dir.join(target);
    run(Command::new(nfpm)
        .arg("package")
        .arg("--config")
        .arg(&config)
        .args(["--packager", packager])
        .arg("--target")
        .arg(&out));
    out
}

#[test]
fn rpm_packages_carry_a_signature_rpm_verifies() {
    let Some(nfpm) = nfpm() else { return };
    if !have("gpg", &["--version"])
        || !have("rpmsign", &["--version"])
        || !have("rpm", &["--version"])
    {
        return;
    }
    let keyring = Keyring::new();
    let tmp = tempfile::tempdir().unwrap();
    let rpm = package(&nfpm, tmp.path(), "rpm", "acme-test-1.0.0-1.x86_64.rpm");
    keyring.signer().sign_rpm(&rpm).unwrap();
    let db = tempfile::tempdir().unwrap();
    let public = tmp.path().join("pub.asc");
    let exported = run(Command::new("gpg")
        .arg("--homedir")
        .arg(keyring.home())
        .args(["--armor", "--export"])
        .arg(&keyring.fingerprint));
    std::fs::write(&public, exported).unwrap();
    // Before the key is trusted, the signature is present but not OK.
    let untrusted = Command::new("rpm")
        .arg("--dbpath")
        .arg(db.path())
        .arg("-K")
        .arg(&rpm)
        .output()
        .unwrap();
    assert!(
        !untrusted.status.success(),
        "{}",
        String::from_utf8_lossy(&untrusted.stdout)
    );
    run(Command::new("rpm")
        .arg("--dbpath")
        .arg(db.path())
        .arg("--import")
        .arg(&public));
    let checked = run(Command::new("rpm")
        .arg("--dbpath")
        .arg(db.path())
        .arg("-K")
        .arg(&rpm));
    assert!(checked.contains("signatures OK"), "{checked}");
}

#[test]
fn pacman_packages_get_a_detached_signature_gpg_verifies() {
    let Some(nfpm) = nfpm() else { return };
    if !have("gpg", &["--version"]) {
        return;
    }
    let keyring = Keyring::new();
    let tmp = tempfile::tempdir().unwrap();
    let pkg = package(
        &nfpm,
        tmp.path(),
        "archlinux",
        "acme-test-1.0.0-1-x86_64.pkg.tar.zst",
    );
    let sig = signature_path(&pkg);
    assert!(sig.to_string_lossy().ends_with(".pkg.tar.zst.sig"));
    keyring.signer().detach_sign(&pkg, &sig).unwrap();
    let verified = Command::new("gpg")
        .arg("--homedir")
        .arg(keyring.home())
        .arg("--verify")
        .arg(&sig)
        .arg(&pkg)
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stderr).contains("Good signature"));
    // pacman expects a binary (not armored) signature.
    assert_ne!(std::fs::read(&sig).unwrap().first(), Some(&b'-'));
    // A different package doesn't verify against it.
    std::fs::write(&pkg, b"tampered").unwrap();
    let bad = Command::new("gpg")
        .arg("--homedir")
        .arg(keyring.home())
        .arg("--verify")
        .arg(&sig)
        .arg(&pkg)
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

/// Every signer at once, through `package()`: Authenticode on every Windows
/// binary (stamped first) and on the MSI, OpenPGP on the rpm and pacman
/// packages, and manifests over the final, signed bytes.
/// `VS_FIXEDFILEINFO.dwFileType` of a stamped image (found by its
/// signature, `0xFEEF04BD`).
#[test]
fn repository_indexes_get_armored_and_clear_signatures_the_pins_check() {
    // seaworthy repo's signatures: Release.gpg and repomd.xml.asc
    // armored and detached, InRelease clear-signed, each checked against
    // the pinned keys alone; a staging key, or text outside the signed
    // message, is refused.
    if !have("gpg", &["--version"]) {
        return;
    }
    let pinned = Keyring::new();
    let staging = Keyring::new();
    let tmp = tempfile::tempdir().unwrap();
    pinned.export(&tmp.path().join("pinned.asc"));
    let pins = seaworthy::codesign::Pins {
        authenticode: None,
        openpgp: vec![tmp.path().join("pinned.asc")],
        osslsigncode: PathBuf::from("osslsigncode"),
        gpg: PathBuf::from("gpg"),
        rpmkeys: PathBuf::from("rpmkeys"),
    };
    let release = tmp.path().join("Release");
    // A line starting with a dash: clear-signing escapes it, and the
    // check returns it unescaped.
    std::fs::write(&release, "Origin: acme\nSuite: stable\n-- not a marker\n").unwrap();
    let detached = tmp.path().join("Release.gpg");
    pinned
        .signer()
        .armored_detach_sign(&release, &detached)
        .unwrap();
    assert!(
        std::fs::read_to_string(&detached)
            .unwrap()
            .starts_with("-----BEGIN PGP SIGNATURE-----")
    );
    pins.check_detached(&detached, &release).unwrap();
    let inline = tmp.path().join("InRelease");
    pinned.signer().clear_sign(&release, &inline).unwrap();
    let text = std::fs::read_to_string(&inline).unwrap();
    assert!(
        text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n"),
        "{text}"
    );
    assert!(text.contains("\n- -- not a marker\n"), "{text}");
    assert_eq!(
        pins.check_clearsigned(&inline).unwrap(),
        std::fs::read(&release).unwrap()
    );
    // Text after the signature: gpg alone would verify the message and
    // ignore it; the check refuses the file.
    let trailing = tmp.path().join("trailing");
    std::fs::write(&trailing, format!("{text}Suite: unsigned\n")).unwrap();
    let err = pins.check_clearsigned(&trailing).unwrap_err().to_string();
    assert!(
        err.contains("not exactly one clear-signed message"),
        "{err}"
    );
    // A staging key's signatures.
    let staged = tmp.path().join("staged");
    staging.signer().clear_sign(&release, &staged).unwrap();
    let err = pins.check_clearsigned(&staged).unwrap_err().to_string();
    assert!(err.contains("no pinned OpenPGP key signed it"), "{err}");
    staging
        .signer()
        .armored_detach_sign(&release, &detached)
        .unwrap();
    let err = pins
        .check_detached(&detached, &release)
        .unwrap_err()
        .to_string();
    assert!(err.contains("no pinned OpenPGP key made it"), "{err}");
    // A changed text under a good signature.
    let tampered = tmp.path().join("tampered");
    std::fs::write(&tampered, text.replace("Suite: stable", "Suite: stale")).unwrap();
    assert!(pins.check_clearsigned(&tampered).is_err());
}

#[test]
fn pinned_keys_must_be_ones_every_client_accepts() {
    // gpg signs and verifies with any of these; Debian 13's apt
    // (sqv) refuses RSA below 2048, DSA and SHA-1 binding signatures, and
    // RHEL's crypto policies refuse them for rpm.
    if !have("gpg", &["--version"]) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let pins = |key: &Path| seaworthy::codesign::Pins {
        authenticode: None,
        openpgp: vec![key.to_path_buf()],
        osslsigncode: PathBuf::from("osslsigncode"),
        gpg: PathBuf::from("gpg"),
        rpmkeys: PathBuf::from("rpmkeys"),
    };
    for (name, algorithm, extra, mentions) in [
        (
            "rsa1024",
            "rsa1024",
            &[][..],
            Some("uses RSA 1024, below 2048"),
        ),
        ("dsa", "dsa2048", &[][..], Some("uses DSA")),
        (
            "sha1",
            "rsa3072",
            &["--cert-digest-algo", "SHA1"][..],
            Some("a signature on the key uses SHA-1"),
        ),
        ("rsa3072", "rsa3072", &[][..], None),
        ("ed25519", "ed25519", &[][..], None),
        ("nistp256", "nistp256", &[][..], None),
    ] {
        let ring = Keyring::with_algorithm(algorithm, extra);
        let key = tmp.path().join(format!("{name}.asc"));
        ring.export(&key);
        let checked = pins(&key).check_key_strength();
        match mentions {
            Some(mentions) => {
                let err = checked.unwrap_err().to_string();
                assert!(err.contains(mentions), "{name}: {err}");
                assert!(err.contains(&format!("{name}.asc")), "{name}: {err}");
            }
            None => checked.unwrap_or_else(|e| panic!("{name}: {e}")),
        }
    }
    // A key file that isn't there.
    assert!(
        pins(&tmp.path().join("missing.asc"))
            .check_key_strength()
            .is_err()
    );
    // `package` checks before signing anything.
    let weak = Keyring::with_algorithm("rsa1024", &[]);
    let dir = tmp.path().join("product");
    std::fs::create_dir(&dir).unwrap();
    weak.export(&dir.join("weak.asc"));
    let (config, layouts) = product(&dir, "\"rpm\"", "openpgp-keys = [\"weak.asc\"]", None);
    let signing = seaworthy::package::Signing {
        openpgp: Some(Box::new(weak.signer())),
        ..seaworthy::package::Signing::default()
    };
    let err = package_with(&config, &layouts, &dir, &signing, PathBuf::from("nfpm"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("uses RSA 1024, below 2048"), "{err}");
}

#[test]
fn weak_key_findings_read_gpgs_listings() {
    let colons = "pub:-:1024:1:C43BE6D13F7DA715:1792000944:::-:::scSC::::::::0:\n\
                  sub:-:2048:1:AAAA:1:::-:::e::::::::0:\n\
                  sub:-:255:22:BBBB:1:::-:::s:::::ed25519:::0:\n\
                  sub:-:256:19:CCCC:1:::-:::s:::::brainpoolP256r1:::0:\n\
                  sub:-:256:18:DDDD:1:::-:::e:::::cv25519:::0:\n\
                  pub:-:1024:1:EEEE:1:::-:::cSC::::::::0:\n";
    let packets = ":signature packet: algo 1, keyid C43B\n\tdigest algo 2, begin of digest 62 63\n\
                   :signature packet: algo 1, keyid C43B\n\tdigest algo 2, begin of digest 11 22\n\
                   :signature packet: algo 1, keyid C43B\n\tdigest algo 10, begin of digest 33 44\n";
    assert_eq!(
        seaworthy::codesign::weak_key_findings(colons, packets),
        [
            "pub key C43BE6D13F7DA715 uses RSA 1024, below 2048",
            "sub key CCCC uses the curve \"brainpoolp256r1\"",
            "pub key EEEE uses RSA 1024, below 2048",
            "a signature on the key uses SHA-1",
        ]
    );
    assert!(seaworthy::codesign::weak_key_findings("", "").is_empty());
}

fn file_type(pe: &[u8]) -> u32 {
    let at = pe
        .windows(4)
        .position(|w| w == 0xFEEF_04BDu32.to_le_bytes())
        .expect("a VS_FIXEDFILEINFO");
    u32::from_le_bytes(pe[at + 36..at + 40].try_into().unwrap())
}

/// The console product with `outputs`, the signing pins `pins` (TOML lines
/// for `[defaults]`, then `[defaults.authenticode]` when given), laid out
/// under `dir`.
fn product(
    dir: &Path,
    outputs: &str,
    pins: &str,
    authenticode: Option<(&str, &str)>,
) -> (seaworthy::config::Config, Vec<seaworthy::layout::Layout>) {
    std::fs::create_dir_all(dir).unwrap();
    let authenticode = authenticode.map_or_else(String::new, |(subject, trust)| {
        format!("[defaults.authenticode]\nsubject = \"{subject}\"\ntrust = \"{trust}\"\n")
    });
    std::fs::write(
        dir.join("seaworthy.toml"),
        format!(
            r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"
{pins}
{authenticode}
[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["extra_*.dll"]
outputs = [{outputs}]
"#
        ),
    )
    .unwrap();
    let config = seaworthy::config::Config::load(&dir.join("seaworthy.toml")).unwrap();
    let layouts = common::layouts(&config, "console", dir);
    (config, layouts)
}

/// The console product with a zip output, laid out under `dir`, its
/// Authenticode signer pinned to the test subject and `trust.pem`.
fn zip_product(dir: &Path) -> (seaworthy::config::Config, Vec<seaworthy::layout::Layout>) {
    std::fs::create_dir_all(dir).unwrap();
    if !dir.join("trust.pem").exists() {
        std::fs::write(dir.join("trust.pem"), "").unwrap();
    }
    product(dir, "\"zip\"", "", Some((TEST_SUBJECT, "trust.pem")))
}

fn package_zip(
    config: &seaworthy::config::Config,
    layouts: &[seaworthy::layout::Layout],
    dir: &Path,
    signing: &seaworthy::package::Signing,
) -> Result<Vec<seaworthy::package::Artifact>, seaworthy::DistError> {
    package_with(config, layouts, dir, signing, PathBuf::from("nfpm"))
}

fn package_with(
    config: &seaworthy::config::Config,
    layouts: &[seaworthy::layout::Layout],
    dir: &Path,
    signing: &seaworthy::package::Signing,
    nfpm: PathBuf,
) -> Result<Vec<seaworthy::package::Artifact>, seaworthy::DistError> {
    let options = seaworthy::package::Options {
        release: common::release(),
        mtime: 1_700_000_000,
        nfpm,
        wix: None,
        build: seaworthy::sign::BuildId::default(),
    };
    seaworthy::package::package(
        config,
        "console",
        layouts,
        &dir.join("dist"),
        &options,
        signing,
    )
}

/// A certificate issued by `ca` (`<name>.pem` and `<name>.key`), with
/// `extensions` (an OpenSSL extension file's lines).
fn issued(
    dir: &Path,
    ca: (&Path, &Path),
    name: &str,
    subject: &str,
    extensions: &str,
) -> (PathBuf, PathBuf) {
    let (cert, key, csr, ext) = (
        dir.join(format!("{name}.pem")),
        dir.join(format!("{name}.key")),
        dir.join(format!("{name}.csr")),
        dir.join(format!("{name}.ext")),
    );
    run(Command::new("openssl")
        .args(["req", "-newkey", "rsa:3072", "-nodes", "-subj", subject])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&csr));
    std::fs::write(&ext, extensions).unwrap();
    run(Command::new("openssl")
        .args(["x509", "-req", "-days", "30", "-set_serial", "2"])
        .arg("-in")
        .arg(&csr)
        .arg("-CA")
        .arg(ca.0)
        .arg("-CAkey")
        .arg(ca.1)
        .arg("-extfile")
        .arg(&ext)
        .arg("-out")
        .arg(&cert));
    (cert, key)
}

/// A self-signed CA (`<name>.pem`, `<name>.key`).
fn root(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let (cert, key) = (
        dir.join(format!("{name}.pem")),
        dir.join(format!("{name}.key")),
    );
    run(Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30",
        ])
        .args(["-subj", &format!("/CN={name}/O=Acme")])
        .args(["-addext", "basicConstraints=critical,CA:TRUE"])
        .args(["-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert));
    (cert, key)
}

#[test]
fn a_timestamped_signature_verifies_through_the_pinned_root() {
    // Real signatures are timestamped (azure-sign.sh, an osslsigncode
    // signer's timestamp-url), and osslsigncode checks the timestamp's
    // chain against its own trust file: the pinned trust anchors must reach
    // it too, or every release signature fails the pin check (found on
    // Acme's Trusted Signing collector: its chain and its
    // timestamp's both end in one Microsoft root). osslsigncode's
    // built-in timestamping authority stands in for Microsoft's.
    for (tool, probe) in [("osslsigncode", "--version"), ("openssl", "version")] {
        if !have(tool, &[probe]) {
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let (ca, ca_key) = root(&keys, "Acme Test Root");
    let (other, other_key) = root(&keys, "Other Root");
    let (cert, key) = issued(
        &keys,
        (&ca, &ca_key),
        "codesign",
        "/CN=Acme Test Code Signing/O=Acme",
        "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n",
    );
    let timestamping = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n";
    let tsa = issued(
        &keys,
        (&ca, &ca_key),
        "tsa",
        "/CN=Acme Test Timestamps/O=Acme",
        timestamping,
    );
    let foreign_tsa = issued(
        &keys,
        (&other, &other_key),
        "foreign-tsa",
        "/CN=Other Timestamps/O=Acme",
        timestamping,
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let signed = |name: &str, tsa: &(PathBuf, PathBuf)| {
        let dir = tmp.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let unsigned = stamped_core(&dir);
        let out = dir.join("signed.dll");
        run(Command::new("osslsigncode")
            .args(["sign", "-h", "sha256"])
            .arg("-certs")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .arg("-TSA-certs")
            .arg(&tsa.0)
            .arg("-TSA-key")
            .arg(&tsa.1)
            .args(["-TSA-time", &now])
            .arg("-in")
            .arg(&unsigned)
            .arg("-out")
            .arg(&out));
        out
    };
    let trust = ca.display().to_string();
    let (config, _) = product(
        &tmp.path().join("pins"),
        "\"zip\"",
        "",
        Some((TEST_SUBJECT, &trust)),
    );
    let pins = seaworthy::codesign::Pins::of(&config);
    // Signed under the pinned root, timestamped under it too: accepted.
    pins.check_authenticode(&signed("ours", &tsa)).unwrap();
    // A timestamp from an authority the pinned anchors don't reach:
    // refused, though osslsigncode itself passes it while the certificate
    // is valid.
    let err = pins
        .check_authenticode(&signed("foreign", &foreign_tsa))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("the signature's timestamp doesn't verify"),
        "{err}"
    );
}

#[test]
fn every_signature_must_come_from_the_identity_dist_toml_pins() {
    // A staging certificate or key fails the build.
    let Some(nfpm) = nfpm() else { return };
    for (tool, probe) in [
        ("osslsigncode", "--version"),
        ("openssl", "version"),
        ("gpg", "--version"),
        ("rpmsign", "--version"),
        ("rpmkeys", "--version"),
    ] {
        if !have(tool, &[probe]) {
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    let (cert, key) = test_certificate(&keys);
    let (staging_cert, staging_key) =
        certificate(&keys, "staging", "/CN=Acme Staging Code Signing/O=Acme");
    let (impostor_cert, impostor_key) =
        certificate(&keys, "impostor", "/CN=Acme Test Code Signing/O=Acme");
    let authenticode = |cert: &Path, key: &Path| seaworthy::package::Signing {
        authenticode: Some(Box::new(osslsigncode(cert, key))),
        ..seaworthy::package::Signing::default()
    };
    let trust = cert.display().to_string();
    // The pinned certificate: signs.
    let dir = tmp.path().join("ok");
    let (config, layouts) = product(&dir, "\"zip\"", "", Some((TEST_SUBJECT, &trust)));
    package_zip(&config, &layouts, &dir, &authenticode(&cert, &key)).unwrap();
    // Another subject.
    let dir = tmp.path().join("staging");
    let (config, layouts) = product(
        &dir,
        "\"zip\"",
        "",
        Some((TEST_SUBJECT, &staging_cert.display().to_string())),
    );
    let err = package_zip(
        &config,
        &layouts,
        &dir,
        &authenticode(&staging_cert, &staging_key),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("not the pinned"), "{err}");
    // The pinned subject on a certificate that doesn't chain to the pinned
    // trust anchors.
    let dir = tmp.path().join("impostor");
    let (config, layouts) = product(&dir, "\"zip\"", "", Some((TEST_SUBJECT, &trust)));
    let err = package_zip(
        &config,
        &layouts,
        &dir,
        &authenticode(&impostor_cert, &impostor_key),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("doesn't verify to"), "{err}");
    // The MSI is checked too: a signer that signs the binaries as pinned
    // but the MSI with another certificate stops the build at the MSI.
    if let Some(wix) = std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from) {
        let script = format!(
            "case \"$1\" in *.msi) c='{}' k='{}';; *) c='{}' k='{}';; esac; \
             osslsigncode sign -h sha256 -certs \"$c\" -key \"$k\" -in \"$1\" -out \"$1.s\" && mv \"$1.s\" \"$1\"",
            staging_cert.display(),
            staging_key.display(),
            cert.display(),
            key.display()
        );
        let split = seaworthy::package::Signing {
            authenticode: Some(Box::new(CommandAuthenticode {
                command: vec![
                    "sh".into(),
                    "-c".into(),
                    script,
                    "sh".into(),
                    "{file}".into(),
                ],
                timeout: Duration::from_secs(120),
            })),
            ..seaworthy::package::Signing::default()
        };
        let dir = tmp.path().join("msi");
        let (config, layouts) = product(&dir, "\"msi\"", "", Some((TEST_SUBJECT, &trust)));
        let options = seaworthy::package::Options {
            release: common::release(),
            mtime: 1_700_000_000,
            nfpm: nfpm.clone(),
            wix: Some(wix),
            build: seaworthy::sign::BuildId::default(),
        };
        let err = seaworthy::package::package(
            &config,
            "console",
            &layouts,
            &dir.join("dist"),
            &options,
            &split,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(".msi: the Authenticode signature doesn't verify to"),
            "{err}"
        );
    }
    // No pins at all: nothing signs.
    let dir = tmp.path().join("unpinned");
    let (config, layouts) = product(&dir, "\"zip\"", "", None);
    let err = package_zip(&config, &layouts, &dir, &authenticode(&cert, &key))
        .unwrap_err()
        .to_string();
    assert!(err.contains("defaults.authenticode is not set"), "{err}");
    // OpenPGP: rpm and pacman signatures must verify against the pinned
    // keys alone.
    let pinned = Keyring::new();
    let staging = Keyring::new();
    pinned.export(&keys.join("pinned.asc"));
    let pins = format!("openpgp-keys = [\"{}\"]", keys.join("pinned.asc").display());
    let openpgp = |ring: &Keyring| seaworthy::package::Signing {
        openpgp: Some(Box::new(ring.signer())),
        ..seaworthy::package::Signing::default()
    };
    for output in ["\"rpm\"", "\"pacman\""] {
        let dir = tmp
            .path()
            .join(format!("pgp-ok-{}", output.trim_matches('"')));
        let (config, layouts) = product(&dir, output, &pins, None);
        package_with(&config, &layouts, &dir, &openpgp(&pinned), nfpm.clone()).unwrap();
        let dir = tmp
            .path()
            .join(format!("pgp-staging-{}", output.trim_matches('"')));
        let (config, layouts) = product(&dir, output, &pins, None);
        let err = package_with(&config, &layouts, &dir, &openpgp(&staging), nfpm.clone())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no pinned OpenPGP key"), "{output}: {err}");
    }
    let dir = tmp.path().join("pgp-unpinned");
    let (config, layouts) = product(&dir, "\"rpm\"", "", None);
    let err = package_with(&config, &layouts, &dir, &openpgp(&pinned), nfpm.clone())
        .unwrap_err()
        .to_string();
    assert!(err.contains("openpgp-keys is empty"), "{err}");
    // A signing failure (a key the home doesn't hold) stops the build.
    let dir = tmp.path().join("pgp-missing");
    let (config, layouts) = product(&dir, "\"rpm\"", &pins, None);
    let mut missing = pinned.signer();
    missing.key = "0123456789ABCDEF0123456789ABCDEF01234567".into();
    let signing = seaworthy::package::Signing {
        openpgp: Some(Box::new(missing)),
        ..seaworthy::package::Signing::default()
    };
    assert!(package_with(&config, &layouts, &dir, &signing, nfpm).is_err());
}

#[test]
fn a_signer_that_breaks_a_binarys_record_fails_the_build() {
    let tmp = tempfile::tempdir().unwrap();
    let (config, layouts) = zip_product(tmp.path());
    // A "signer" that leaves a PE without its records.
    let breaking = CommandAuthenticode {
        command: vec![
            "sh".into(),
            "-c".into(),
            "printf 'MZ' > \"$1\"".into(),
            "sh".into(),
            "{file}".into(),
        ],
        timeout: Duration::from_secs(60),
    };
    let signing = seaworthy::package::Signing {
        authenticode: Some(Box::new(breaking)),
        ..seaworthy::package::Signing::default()
    };
    // A previous, successful run's listing...
    package_zip(
        &config,
        &layouts,
        tmp.path(),
        &seaworthy::package::Signing::default(),
    )
    .unwrap();
    let listing = tmp.path().join("dist/console/packages.json");
    assert!(listing.is_file());
    let err = package_zip(&config, &layouts, tmp.path(), &signing)
        .unwrap_err()
        .to_string();
    assert!(err.contains("lost its record when signed"), "{err}");
    // ...never survives a failed one beside its partial output.
    assert!(!listing.exists(), "the stale packages.json is gone");
}

#[test]
fn a_core_whose_record_section_holds_its_resources_keeps_its_record() {
    // A linker that merged `.rsrc` into `.cpureq`: only a section named
    // `.rsrc` is ever rewritten in place, so the tree goes into
    // a new section and the record stays (the re-check after stamping
    // would catch the loss).
    let tmp = tempfile::tempdir().unwrap();
    let (config, layouts) = zip_product(tmp.path());
    let windows = layouts
        .iter()
        .find(|l| l.triple == "x86_64-pc-windows-msvc")
        .unwrap();
    let core = windows
        .files
        .iter()
        .find(|f| matches!(f.role, seaworthy::layout::Role::Core { .. }))
        .unwrap();
    let seaworthy::layout::Role::Core { cpu } = &core.role else {
        unreachable!()
    };
    let (cpu, staged) = (cpu.clone(), core.staged.clone());
    let mut data = record("x86_64-pc-windows-msvc", &cpu, common::V2);
    data.resize(data.len().next_multiple_of(8), 0);
    let tree_at = data.len() as u32;
    data.extend_from_slice(&[0; 16]); // an empty resource directory (and NULs a record tolerates)
    let mut merged = Pe {
        sections: vec![(".cpureq".into(), data)],
        imports: vec![],
        executable: false,
    }
    .build();
    let header = u32::from_le_bytes(merged[0x3c..0x40].try_into().unwrap()) as usize;
    let section_va = u32::from_le_bytes(
        merged[header + 24 + 240 + 12..header + 24 + 240 + 16]
            .try_into()
            .unwrap(),
    );
    let resource = header + 24 + 112 + 2 * 8;
    merged[resource..resource + 4].copy_from_slice(&(section_va + tree_at).to_le_bytes());
    merged[resource + 4..resource + 8].copy_from_slice(&16u32.to_le_bytes());
    std::fs::write(&staged, &merged).unwrap();
    package_zip(
        &config,
        &layouts,
        tmp.path(),
        &seaworthy::package::Signing::default(),
    )
    .unwrap();
    assert_eq!(
        seaworthy_levels::read_requirement(&staged).unwrap().cpu,
        cpu
    );
    let stamped = std::fs::read(&staged).unwrap();
    assert!(stamped.len() > merged.len(), "a new section");
    assert_eq!(file_type(&stamped), 2, "and the version resource");
}

#[test]
fn a_fully_signed_build_verifies_everywhere() {
    let Some(nfpm) = nfpm() else { return };
    for (tool, probe) in [
        ("osslsigncode", "--version"),
        ("openssl", "version"),
        ("gpg", "--version"),
        ("rpmsign", "--version"),
        ("rpm", "--version"),
        ("unzip", "-v"),
        ("llvm-readobj", "--version"),
    ] {
        if !have(tool, &[probe]) {
            return;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let (cert, key) = test_certificate(tmp.path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let keyring = Keyring::new();
    let release_key =
        seaworthy::sign::generate_key(seaworthy_updater::SignatureAlgorithm::MlDsa87).unwrap();
    let secret = tmp.path().join("release.key");
    std::fs::write(&secret, format!("{}\n", *release_key.secret_hex)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(
        tmp.path().join("release.pub"),
        hex::encode(&release_key.public_key),
    )
    .unwrap();
    keyring.export(&tmp.path().join("pgp.asc"));
    let wix = std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from);
    let outputs = if wix.is_some() {
        "\"msi\", \"zip\", \"rpm\", \"pacman\""
    } else {
        "\"zip\", \"rpm\", \"pacman\""
    };
    std::fs::write(
        tmp.path().join("seaworthy.toml"),
        format!(
            r#"
[defaults]
vendor = "Acme"
targets = ["x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{{ algorithm = "ml-dsa-87", public-key = "release.pub" }}]
openpgp-keys = ["pgp.asc"]
maintainer = "Acme <pkg@acme.test>"
license = "MIT"

[defaults.authenticode]
subject = "{TEST_SUBJECT}"
trust = "codesign.pem"

[product.console]
display-name = "Acme Console"
description = "The Acme console."
executable = "AcmeTool"
core = "acme_core"
helper = "AcmeToolUpdate"
kind = "desktop"
windows-directory = "Console"
sidecars.windows = ["extra_*.dll"]
outputs = [{outputs}]
"#
        ),
    )
    .unwrap();
    let config = seaworthy::config::Config::load(&tmp.path().join("seaworthy.toml")).unwrap();
    let signing = seaworthy::package::Signing {
        manifest: vec![Box::new(
            seaworthy::sign::LocalKey::from_file(
                seaworthy_updater::SignatureAlgorithm::MlDsa87,
                &secret,
            )
            .unwrap(),
        )],
        authenticode: Some(Box::new(osslsigncode(&cert, &key))),
        openpgp: Some(Box::new(keyring.signer())),
        ..seaworthy::package::Signing::default()
    };
    let options = seaworthy::package::Options {
        release: common::release(),
        mtime: 1_700_000_000,
        nfpm,
        wix: wix.clone(),
        build: seaworthy::sign::BuildId {
            metadata: "cafe12".into(),
        },
    };
    let sidecar_of = |layouts: &[seaworthy::layout::Layout]| {
        layouts
            .iter()
            .find(|l| l.triple == "x86_64-pc-windows-msvc")
            .and_then(|l| l.files.iter().find(|f| f.staged.ends_with("extra_1.dll")))
            .unwrap()
            .staged
            .clone()
    };
    // A sidecar arriving signed by anyone but the product's pinned identity
    // (a vendor's redistributable, any certificate at all): refused, as a
    // signed release vouches for every binary it ships.
    let layouts = common::layouts(&config, "console", tmp.path());
    let publisher = tmp.path().join("publisher");
    std::fs::create_dir(&publisher).unwrap();
    let (publisher_cert, publisher_key) = test_certificate(&publisher);
    osslsigncode(&publisher_cert, &publisher_key)
        .sign(&sidecar_of(&layouts), "Publisher")
        .unwrap();
    let err = seaworthy::package::package(
        &config,
        "console",
        &layouts,
        &tmp.path().join("dist-refused"),
        &options,
        &signing,
    )
    .expect_err("refused")
    .to_string();
    assert!(
        err.contains("sidecar extra_1.dll arrives Authenticode-signed, but not by the product's pinned identity (defaults.authenticode): ship it unsigned and seaworthy signs it"),
        "{err}"
    );
    // One the product's own identity signed already keeps that signature.
    let layouts = common::layouts(&config, "console", tmp.path());
    osslsigncode(&cert, &key)
        .sign(&sidecar_of(&layouts), "Acme Console")
        .unwrap();
    let artifacts = seaworthy::package::package(
        &config,
        "console",
        &layouts,
        &tmp.path().join("dist"),
        &options,
        &signing,
    )
    .unwrap();
    let path_of = |kind| common::artifact(&artifacts, kind);
    use seaworthy::package::Kind;
    // Every Windows binary in the zip: signed; the product's own also stamped.
    let unpacked = tmp.path().join("unzipped");
    run(Command::new("unzip")
        .arg("-q")
        .arg(path_of(Kind::Zip))
        .arg("-d")
        .arg(&unpacked));
    let top = unpacked.join("acme-console-1.4.0-rc.2-812");
    for name in [
        "AcmeTool.exe",
        "AcmeToolUpdate.exe",
        "acme_core_x86-64-v3.dll",
        "acme_core_x86-64-v2.dll",
        "extra_1.dll",
    ] {
        let file = top.join(name);
        verify_authenticode(Path::new("osslsigncode"), &file, Some(&cert))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let resources = run(Command::new("llvm-readobj")
            .arg("--coff-resources")
            .arg(&file));
        assert_eq!(
            resources.contains("VERSIONINFO"),
            name != "extra_1.dll",
            "{name}: {resources}"
        );
        if name != "extra_1.dll" {
            assert_eq!(
                file_type(&std::fs::read(&file).unwrap()),
                if name.ends_with(".dll") { 2 } else { 1 },
                "{name}: VFT_DLL for cores, VFT_APP otherwise"
            );
        }
    }
    if wix.is_some() {
        verify_authenticode(Path::new("osslsigncode"), &path_of(Kind::Msi), Some(&cert)).unwrap();
    }
    // rpm: an embedded signature rpm verifies once the key is imported.
    let db = tempfile::tempdir().unwrap();
    let public = tmp.path().join("pgp.asc");
    std::fs::write(
        &public,
        run(Command::new("gpg")
            .arg("--homedir")
            .arg(keyring.home())
            .args(["--armor", "--export"])
            .arg(&keyring.fingerprint)),
    )
    .unwrap();
    run(Command::new("rpm")
        .arg("--dbpath")
        .arg(db.path())
        .arg("--import")
        .arg(&public));
    let checked = run(Command::new("rpm")
        .arg("--dbpath")
        .arg(db.path())
        .arg("-K")
        .arg(path_of(Kind::Rpm)));
    assert!(checked.contains("signatures OK"), "{checked}");
    // pacman: the detached signature is listed and verifies.
    let sig = path_of(Kind::Signature);
    assert_eq!(sig, signature_path(&path_of(Kind::Pacman)));
    let verified = Command::new("gpg")
        .arg("--homedir")
        .arg(keyring.home())
        .arg("--verify")
        .arg(&sig)
        .arg(path_of(Kind::Pacman))
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    // The zip's SBOM names every file by its final (stamped, signed) bytes.
    let sbom: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(seaworthy::sbom::sbom_path(&path_of(Kind::Zip))).unwrap(),
    )
    .unwrap();
    let files: Vec<&serde_json::Value> = sbom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["type"] == "file")
        .collect();
    assert!(files.len() >= 5, "{files:?}");
    for file in files {
        let name = file["name"]
            .as_str()
            .unwrap()
            .rsplit(['\\', '/'])
            .next()
            .unwrap();
        let bytes = std::fs::read(top.join(name)).unwrap();
        assert_eq!(
            file["hashes"][0]["content"],
            seaworthy_crypto::digest::sha256_hex(&bytes),
            "{name}"
        );
    }
    // The Windows layout.json describes the shipped (stamped, signed) bytes.
    let windows = layouts
        .iter()
        .find(|l| l.triple == "x86_64-pc-windows-msvc")
        .unwrap();
    let listing: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(windows.tree.parent().unwrap().join("layout.json")).unwrap(),
    )
    .unwrap();
    for file in listing["files"].as_array().unwrap() {
        let path = windows.tree.join(file["path"].as_str().unwrap());
        assert_eq!(
            file["sha256"],
            seaworthy_crypto::digest::sha256_hex(&std::fs::read(&path).unwrap()),
            "{}",
            path.display()
        );
    }
    // Every manifest names its artifact's final (signed) bytes and the build.
    let mut manifested = vec![Kind::Zip, Kind::Rpm, Kind::Pacman];
    if wix.is_some() {
        manifested.push(Kind::Msi);
    }
    for kind in manifested {
        let artifact = path_of(kind);
        let manifest = seaworthy::sign::manifest_path(&artifact);
        let (decoded, _) =
            seaworthy_updater::ReleaseManifest::decode_signed(&std::fs::read(&manifest).unwrap())
                .unwrap();
        let data = std::fs::read(&artifact).unwrap();
        assert_eq!(
            decoded.digest,
            decoded.digest_algorithm.hash(&data),
            "{kind:?}"
        );
        assert_eq!(decoded.token(), "1.4.0-rc.2+cafe12");
    }
}
