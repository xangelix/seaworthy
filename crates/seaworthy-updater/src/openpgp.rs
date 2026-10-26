//! OpenPGP package signatures checked against pinned keys alone: an rpm's
//! embedded signature with `rpmkeys --checksig`, and a pacman package's
//! detached `.sig` with `gpg --verify`, each in a throwaway database or
//! keyring that holds only the keys the caller pins. (The seaworthy CLI
//! checks its repository signatures the same way: detached ones over
//! pacman databases and `repomd.xml`, and APT's clear-signed `InRelease`.)
//!
//! The update helper checks a downloaded rpm or pacman package this way
//! as a second layer behind the signed release manifest, with the
//! product's keys compiled in. The seaworthy CLI checks every signature it
//! makes the same way, so a package that leaves the release pipeline is one
//! the helper accepts.
//!
//! Neither check consults the machine's own trust (the rpm database's
//! imported keys, pacman's keyring): those are the package manager's
//! layer, which still applies when it installs.
//!
//! Nor the caller's environment: gpg, gpgconf and rpmkeys start with an
//! allowlisted one ([`process::command`]: `PATH`, `TZ`, `LC_ALL=C`, plus
//! [`Tools::env`]), with `HOME` (and for gpg `GNUPGHOME`) set to the
//! throwaway directory, so no credential the caller holds reaches them and
//! no configuration in the caller's home (`~/.rpmmacros`, `~/.gnupg`)
//! changes how they check.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::process::{self, ProcessError, TempDir};

/// How long one check (or key import) may take.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest public key accepted, armored.
const MAX_KEY_BYTES: usize = 64 * 1024;

/// Why a package signature was refused.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// No pinned key made a good signature (a foreign key, an unsigned or
    /// tampered package, an expired or revoked key).
    #[error("{0}")]
    Refused(String),
    /// A tool couldn't run, or a scratch directory couldn't be made.
    #[error("{0}")]
    Tool(String),
}

impl From<ProcessError> for SignatureError {
    fn from(error: ProcessError) -> Self {
        Self::Tool(error.to_string())
    }
}

/// The OpenPGP public keys a package signature must come from.
#[derive(Clone)]
pub struct OpenPgpKeys(Vec<Vec<u8>>);

impl std::fmt::Debug for OpenPgpKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenPgpKeys({} keys)", self.0.len())
    }
}

impl OpenPgpKeys {
    /// The pinned keys: each an ASCII-armored public key block
    /// (`-----BEGIN PGP PUBLIC KEY BLOCK-----`), at most 64 KiB, at least
    /// one. Binary keys are refused (export with `gpg --armor --export`):
    /// one spelling, which every tool here imports alike.
    ///
    /// # Errors
    /// [`SignatureError::Refused`] for an empty set, or a key that isn't an
    /// armored public key block of that size (a private key is refused
    /// here, before any tool sees it).
    pub fn new<I, K>(keys: I) -> Result<Self, SignatureError>
    where
        I: IntoIterator<Item = K>,
        K: Into<Vec<u8>>,
    {
        let keys: Vec<Vec<u8>> = keys.into_iter().map(Into::into).collect();
        if keys.is_empty() {
            return Err(SignatureError::Refused(
                "no OpenPGP public keys are pinned".to_owned(),
            ));
        }
        for (index, key) in keys.iter().enumerate() {
            let text = std::str::from_utf8(key).unwrap_or_default();
            if key.len() > MAX_KEY_BYTES
                || !text
                    .trim_start()
                    .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                || !text
                    .trim_end()
                    .ends_with("-----END PGP PUBLIC KEY BLOCK-----")
            {
                return Err(SignatureError::Refused(format!(
                    "pinned OpenPGP key {index} is not an ASCII-armored public key block of at most {MAX_KEY_BYTES} bytes"
                )));
            }
        }
        Ok(Self(keys))
    }

    /// How many keys are pinned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Never: [`new`](Self::new) refuses an empty set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Writes each key into `dir` (`key-<n>.asc`, 0600 under the 0700
    /// scratch directory), returning the paths.
    fn write_into(&self, dir: &Path) -> Result<Vec<PathBuf>, SignatureError> {
        self.0
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let path = dir.join(format!("key-{index}.asc"));
                std::fs::write(&path, key)
                    .map_err(|e| SignatureError::Tool(format!("{}: {e}", path.display())))?;
                Ok(path)
            })
            .collect()
    }
}

/// The programs the checks run.
#[derive(Debug, Clone)]
pub struct Tools {
    /// `gpg`.
    pub gpg: PathBuf,
    /// `gpgconf` (stops the throwaway home's agent and keyboxd).
    pub gpgconf: PathBuf,
    /// `rpmkeys`.
    pub rpmkeys: PathBuf,
    /// More variables the programs keep from the environment beside
    /// [`process::PROGRAM_ENV`]: a site's own settings, never a credential
    /// (the seaworthy CLI passes the names `SEAWORTHY_TOOL_ENV` lists).
    pub env: Vec<String>,
}

impl Tools {
    /// The tools by name, found on `PATH` (build machines).
    #[must_use]
    pub fn from_path() -> Self {
        Self {
            gpg: PathBuf::from("gpg"),
            gpgconf: PathBuf::from("gpgconf"),
            rpmkeys: PathBuf::from("rpmkeys"),
            env: Vec::new(),
        }
    }

    /// The distribution's own tools, by absolute path (`/usr/bin`): what
    /// the update helper runs, never whatever `PATH` names.
    #[must_use]
    pub fn system() -> Self {
        Self {
            gpg: PathBuf::from("/usr/bin/gpg"),
            gpgconf: PathBuf::from("/usr/bin/gpgconf"),
            rpmkeys: PathBuf::from("/usr/bin/rpmkeys"),
            env: Vec::new(),
        }
    }

    /// `program`'s command with the allowlisted environment
    /// ([`process::command`] with [`env`](Self::env)) and `HOME` set to
    /// `home`, a throwaway directory: nothing the caller's environment or
    /// home holds reaches the check.
    fn command(&self, program: &Path, home: &Path) -> Command {
        let extra: Vec<&str> = self.env.iter().map(String::as_str).collect();
        let mut command = process::command(program, &extra);
        command.env("HOME", home);
        command
    }

    /// [`command`](Self::command) for gpg or gpgconf, `GNUPGHOME` set to
    /// the throwaway home too.
    fn gpg_command(&self, program: &Path, home: &Path) -> Command {
        let mut command = self.command(program, home);
        command.env("GNUPGHOME", home);
        command
    }
}

/// Checks `rpm`'s signature against `keys` alone, in a throwaway rpm
/// database under `scratch` (removed afterwards).
///
/// The check requires both a zero exit and `signatures OK` in the report:
/// rpm 4 reports only `digests OK` for an unsigned package and exits 0;
/// rpm 6 reports `digests SIGNATURES NOT OK` and exits 1.
///
/// # Errors
/// [`SignatureError::Refused`] for a package no pinned key signed, or an
/// unsigned one; [`SignatureError::Tool`] when rpmkeys can't run.
pub fn check_rpm(
    keys: &OpenPgpKeys,
    rpm: &Path,
    scratch: &Path,
    tools: &Tools,
) -> Result<(), SignatureError> {
    let dir = TempDir::new_in(scratch, "rpmdb").map_err(|e| SignatureError::Tool(e.to_string()))?;
    let db = dir.path().join("db");
    std::fs::create_dir(&db).map_err(|e| SignatureError::Tool(format!("{}: {e}", db.display())))?;
    for key in keys.write_into(dir.path())? {
        let mut import = tools.command(&tools.rpmkeys, dir.path());
        import.arg("--dbpath").arg(&db).arg("--import").arg(key);
        process::run_ok(&mut import, "rpm key import", CHECK_TIMEOUT)?;
    }
    let mut check = tools.command(&tools.rpmkeys, dir.path());
    check.arg("--dbpath").arg(&db).arg("--checksig").arg(rpm);
    let finished = process::run(
        &mut check,
        "rpm signature check",
        None,
        CHECK_TIMEOUT,
        1 << 16,
    )?;
    let report = String::from_utf8_lossy(&finished.stdout);
    if !finished.status.success() || !report.contains("signatures OK") {
        return Err(SignatureError::Refused(format!(
            "{}: no pinned OpenPGP key signed it: {}",
            rpm.display(),
            finished.shown()
        )));
    }
    Ok(())
}

/// Checks `signature`, a detached signature of `file`, against `keys`
/// alone, in a throwaway gpg home under `scratch` (its agent stopped and
/// the home removed afterwards).
///
/// # Errors
/// [`SignatureError::Refused`] for a signature no pinned key made (gpg's
/// status must report `GOODSIG`: an expired or revoked key reports
/// `EXPKEYSIG`/`REVKEYSIG` instead); [`SignatureError::Tool`] when gpg
/// can't run.
pub fn check_detached(
    keys: &OpenPgpKeys,
    signature: &Path,
    file: &Path,
    scratch: &Path,
    tools: &Tools,
) -> Result<(), SignatureError> {
    with_pinned_home(keys, scratch, tools, |home| {
        let mut verify = tools.gpg_command(&tools.gpg, home);
        verify
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--status-fd", "1", "--verify"])
            .arg(signature)
            .arg(file);
        let finished = process::run(
            &mut verify,
            "OpenPGP signature check",
            None,
            CHECK_TIMEOUT,
            1 << 16,
        )?;
        let status = String::from_utf8_lossy(&finished.stdout);
        let good = status.lines().any(|l| l.starts_with("[GNUPG:] GOODSIG "));
        if !finished.status.success() || !good {
            return Err(SignatureError::Refused(format!(
                "{}: no pinned OpenPGP key made it: {}",
                signature.display(),
                finished.shown()
            )));
        }
        Ok(())
    })
}

/// The longest clear-signed text [`check_clearsigned`] returns.
const MAX_CLEARSIGNED_BYTES: u64 = 16 * 1024 * 1024;

/// Checks `signed`, a clear-signed text (an APT repository's `InRelease`),
/// against `keys` alone, in a throwaway gpg home under `scratch`, and
/// returns the text it signs.
///
/// The file must be one signed message and nothing else: its first line
/// `-----BEGIN PGP SIGNED MESSAGE-----`, one signature block, nothing after
/// the block's end line, and gpg must report exactly one good signature
/// over exactly one plaintext. (APT reads `InRelease` as strictly; gpg
/// alone would verify a message with unsigned text around it.)
///
/// # Errors
/// [`SignatureError::Refused`] for a text no pinned key signed, or a file
/// that is more or less than one signed message; [`SignatureError::Tool`]
/// when gpg can't run.
pub fn check_clearsigned(
    keys: &OpenPgpKeys,
    signed: &Path,
    scratch: &Path,
    tools: &Tools,
) -> Result<Vec<u8>, SignatureError> {
    let refused = |why: &str| SignatureError::Refused(format!("{}: {why}", signed.display()));
    let bytes = std::fs::read(signed)
        .map_err(|e| SignatureError::Tool(format!("{}: {e}", signed.display())))?;
    if !is_one_clearsigned_message(&bytes) {
        return Err(refused(
            "not exactly one clear-signed message (text before or after it, or two)",
        ));
    }
    with_pinned_home(keys, scratch, tools, |home| {
        let text = home.join("text");
        let mut verify = tools.gpg_command(&tools.gpg, home);
        verify
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--status-fd", "1", "--output"])
            .arg(&text)
            .arg("--decrypt")
            .arg(signed);
        let finished = process::run(
            &mut verify,
            "OpenPGP clear-signed text check",
            None,
            CHECK_TIMEOUT,
            1 << 16,
        )?;
        let status = String::from_utf8_lossy(&finished.stdout);
        let count = |prefix: &str| status.lines().filter(|l| l.starts_with(prefix)).count();
        if !finished.status.success() || count("[GNUPG:] GOODSIG ") != 1 {
            return Err(refused(&format!(
                "no pinned OpenPGP key signed it: {}",
                finished.shown()
            )));
        }
        if count("[GNUPG:] PLAINTEXT ") != 1 || count("[GNUPG:] NEWSIG") > 1 {
            return Err(refused("more than one signed message"));
        }
        let size = std::fs::metadata(&text)
            .map_err(|e| SignatureError::Tool(format!("{}: {e}", text.display())))?
            .len();
        if size > MAX_CLEARSIGNED_BYTES {
            return Err(refused("the signed text is too long"));
        }
        std::fs::read(&text).map_err(|e| SignatureError::Tool(format!("{}: {e}", text.display())))
    })
}

/// The framing of exactly one clear-signed message: its header line
/// first, one signature block, and nothing after the block's end line.
/// (Dash-escaping keeps these lines out of the signed text itself.) gpg
/// alone accepts text around a message and verifies only the message.
fn is_one_clearsigned_message(bytes: &[u8]) -> bool {
    const HEADER: &[u8] = b"-----BEGIN PGP SIGNED MESSAGE-----";
    const BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
    const END: &[u8] = b"-----END PGP SIGNATURE-----";
    let lines: Vec<&[u8]> = bytes
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    let count = |marker: &[u8]| lines.iter().filter(|l| **l == marker).count();
    lines.first() == Some(&HEADER)
        && count(HEADER) == 1
        && count(BEGIN) == 1
        && count(END) == 1
        && lines.iter().rfind(|l| !l.is_empty()) == Some(&END)
}

/// Runs `check` with a throwaway gpg home under `scratch` that holds
/// `keys` alone, then stops the home's agent; the home is removed on
/// return.
fn with_pinned_home<T>(
    keys: &OpenPgpKeys,
    scratch: &Path,
    tools: &Tools,
    check: impl FnOnce(&Path) -> Result<T, SignatureError>,
) -> Result<T, SignatureError> {
    let home = TempDir::new_in(scratch, "gpg").map_err(|e| SignatureError::Tool(e.to_string()))?;
    let key_files = keys.write_into(home.path())?;
    let result = (|| {
        let mut import = tools.gpg_command(&tools.gpg, home.path());
        import
            .arg("--homedir")
            .arg(home.path())
            .args(["--batch", "--quiet", "--import"])
            .args(&key_files);
        process::run_ok(&mut import, "OpenPGP key import", CHECK_TIMEOUT)?;
        check(home.path())
    })();
    let mut kill = tools.gpg_command(&tools.gpgconf, home.path());
    kill.arg("--homedir")
        .arg(home.path())
        .args(["--kill", "all"]);
    let _ = process::run_ok(&mut kill, "gpg agent shutdown", CHECK_TIMEOUT);
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_armored_public_keys_are_pinned() {
        let public =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(OpenPgpKeys::new([public]).unwrap().len(), 1);
        assert!(OpenPgpKeys::new(Vec::<Vec<u8>>::new()).is_err());
        for bad in [
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQ\n-----END PGP PRIVATE KEY BLOCK-----\n",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQ\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "mQINBF…",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n",
        ] {
            assert!(OpenPgpKeys::new([bad]).is_err(), "{bad}");
        }
        let huge = format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n{}\n-----END PGP PUBLIC KEY BLOCK-----\n",
            "A".repeat(MAX_KEY_BYTES)
        );
        assert!(OpenPgpKeys::new([huge]).is_err());
        assert_eq!(
            format!("{:?}", OpenPgpKeys::new([public]).unwrap()),
            "OpenPgpKeys(1 keys)"
        );
    }

    /// A fake tool printing `stdout` and exiting with `code`.
    #[cfg(unix)]
    fn fake(dir: &Path, name: &str, stdout: &str, code: i32) -> PathBuf {
        let path = dir.join(name);
        crate::tests_support::write_script(
            &path,
            &format!("#!/bin/sh\nprintf '%s\\n' '{stdout}'\nexit {code}\n"),
        );
        path
    }

    #[cfg(unix)]
    #[test]
    fn only_a_reported_good_signature_passes() {
        let dir = tempfile::tempdir().unwrap();
        let keys = OpenPgpKeys::new([
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ])
        .unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, b"x").unwrap();
        let tools = |rpmkeys: PathBuf, gpg: PathBuf| Tools {
            gpg,
            gpgconf: fake(dir.path(), "gpgconf", "", 0),
            rpmkeys,
            env: Vec::new(),
        };
        // rpm 4 on an unsigned package: digests only, exit 0.
        let rpm_digests = tools(
            fake(dir.path(), "rpmkeys", "x: digests OK", 0),
            PathBuf::new(),
        );
        assert!(matches!(
            check_rpm(&keys, &file, dir.path(), &rpm_digests),
            Err(SignatureError::Refused(_))
        ));
        let rpm_good = tools(
            fake(dir.path(), "rpmkeys2", "x: digests signatures OK", 0),
            PathBuf::new(),
        );
        assert!(check_rpm(&keys, &file, dir.path(), &rpm_good).is_ok());
        let rpm_failed = tools(
            fake(dir.path(), "rpmkeys3", "x: digests signatures OK", 1),
            PathBuf::new(),
        );
        assert!(check_rpm(&keys, &file, dir.path(), &rpm_failed).is_err());
        // gpg: an expired or revoked key, or no signature status, exit 0
        //.
        for (name, status) in [
            ("gpg-exp", "[GNUPG:] EXPKEYSIG 0123 Acme"),
            ("gpg-rev", "[GNUPG:] REVKEYSIG 0123 Acme"),
            ("gpg-none", "[GNUPG:] NEWSIG"),
        ] {
            let t = tools(PathBuf::new(), fake(dir.path(), name, status, 0));
            assert!(
                matches!(
                    check_detached(&keys, &file, &file, dir.path(), &t),
                    Err(SignatureError::Refused(_))
                ),
                "{name}"
            );
        }
        let good = tools(
            PathBuf::new(),
            fake(dir.path(), "gpg-good", "[GNUPG:] GOODSIG 0123 Acme", 0),
        );
        assert!(check_detached(&keys, &file, &file, dir.path(), &good).is_ok());
        let failed = tools(
            PathBuf::new(),
            fake(dir.path(), "gpg-bad", "[GNUPG:] GOODSIG 0123 Acme", 2),
        );
        assert!(check_detached(&keys, &file, &file, dir.path(), &failed).is_err());
        // Scratch databases and homes are removed.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("sw-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The variable a re-run of this test binary carries in its own
    /// environment, as a release machine's credential would be.
    #[cfg(unix)]
    const PLANTED: &str = "ACME_PLANTED_SECRET";

    #[cfg(unix)]
    #[test]
    fn the_checks_programs_never_see_the_caller_s_environment_or_home() {
        if std::env::var_os(PLANTED).is_none() {
            // Re-run exactly this test with a secret, a home and a gpg home
            // in the child's own environment (std::env::set_var would race
            // the other tests).
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "openpgp::tests::the_checks_programs_never_see_the_caller_s_environment_or_home",
                    "--test-threads=1",
                    "--quiet",
                ])
                .env(PLANTED, "hunter2")
                .env("HOME", "/home/acme")
                .env("GNUPGHOME", "/home/acme/.gnupg")
                .env("ACME_SITE_SETTING", "kept")
                .status()
                .unwrap();
            assert!(status.success(), "the re-run failed: {status}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let keys = OpenPgpKeys::new([
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ])
        .unwrap();
        let file = dir.path().join("x");
        std::fs::write(&file, b"x").unwrap();
        // Each fake records the environment it was given next to itself.
        let dumping = |name: &str, stdout: &str| {
            let path = dir.path().join(name);
            crate::tests_support::write_script(
                &path,
                &format!("#!/bin/sh\nenv > \"$0.env\"\nprintf '%s\\n' '{stdout}'\nexit 0\n"),
            );
            path
        };
        let tools = Tools {
            gpg: dumping("gpg", "[GNUPG:] GOODSIG 0123 Acme"),
            gpgconf: dumping("gpgconf", ""),
            rpmkeys: dumping("rpmkeys", "x: digests signatures OK"),
            env: vec!["ACME_SITE_SETTING".to_owned()],
        };
        check_detached(&keys, &file, &file, dir.path(), &tools).unwrap();
        check_rpm(&keys, &file, dir.path(), &tools).unwrap();
        let scratch = dir.path().to_str().unwrap();
        for name in ["gpg", "gpgconf", "rpmkeys"] {
            let env = std::fs::read_to_string(dir.path().join(format!("{name}.env"))).unwrap();
            assert!(!env.contains(PLANTED), "{name}: {env}");
            assert!(!env.contains("hunter2"), "{name}: {env}");
            assert!(!env.contains("/home/acme"), "{name}: {env}");
            let value = |key: &str| {
                env.lines()
                    .find_map(|line| line.strip_prefix(&format!("{key}=")))
                    .map(str::to_owned)
            };
            let home = value("HOME").unwrap();
            assert!(home.starts_with(&format!("{scratch}/sw-")), "{name}: {env}");
            if name != "rpmkeys" {
                assert_eq!(value("GNUPGHOME").as_deref(), Some(home.as_str()), "{name}");
            }
            assert_eq!(value("LC_ALL").as_deref(), Some("C"), "{name}");
            assert_eq!(
                value("ACME_SITE_SETTING").as_deref(),
                Some("kept"),
                "{name}"
            );
            assert!(value("PATH").is_some(), "{name}: {env}");
        }
    }

    /// A fake gpg for [`check_clearsigned`]: a key import succeeds
    /// silently; the check prints `status`, writes `text` to the
    /// `--output` file and exits with `code`.
    #[cfg(unix)]
    fn fake_decrypt(dir: &Path, name: &str, status: &str, text: &str, code: i32) -> PathBuf {
        let path = dir.join(name);
        crate::tests_support::write_script(
            &path,
            &format!(
                "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do [ \"$1\" = --output ] && out=$2; shift; done\n\
                 [ -n \"$out\" ] || exit 0\nprintf '%s' '{text}' > \"$out\"\nprintf '%s\\n' '{status}'\nexit {code}\n"
            ),
        );
        path
    }

    #[cfg(unix)]
    #[test]
    fn a_clearsigned_text_needs_one_good_signature_over_one_message() {
        let dir = tempfile::tempdir().unwrap();
        let keys = OpenPgpKeys::new([
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ])
        .unwrap();
        let signed = dir.path().join("InRelease");
        let message = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSuite: stable\n\
                       -----BEGIN PGP SIGNATURE-----\n\nwsB\n-----END PGP SIGNATURE-----\n";
        std::fs::write(&signed, message).unwrap();
        let tools = |gpg: PathBuf| Tools {
            gpg,
            gpgconf: fake(dir.path(), "gpgconf", "", 0),
            rpmkeys: PathBuf::new(),
            env: Vec::new(),
        };
        let one = "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0123 Acme\n[GNUPG:] PLAINTEXT 74 0";
        let good = tools(fake_decrypt(
            dir.path(),
            "gpg-good",
            one,
            "Suite: stable\n",
            0,
        ));
        assert_eq!(
            check_clearsigned(&keys, &signed, dir.path(), &good).unwrap(),
            b"Suite: stable\n"
        );
        for (name, status, code) in [
            (
                "gpg-exp",
                "[GNUPG:] EXPKEYSIG 0123 Acme\n[GNUPG:] PLAINTEXT 74 0",
                0,
            ),
            ("gpg-fail", one, 2),
            (
                "gpg-two-texts",
                "[GNUPG:] GOODSIG 0123 Acme\n[GNUPG:] PLAINTEXT 74 0\n[GNUPG:] PLAINTEXT 74 0",
                0,
            ),
            (
                "gpg-two-sigs",
                "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0123 Acme\n[GNUPG:] NEWSIG\n[GNUPG:] PLAINTEXT 74 0",
                0,
            ),
            (
                "gpg-two-good",
                "[GNUPG:] GOODSIG 0123 Acme\n[GNUPG:] GOODSIG 0123 Acme\n[GNUPG:] PLAINTEXT 74 0",
                0,
            ),
            ("gpg-no-text", "[GNUPG:] GOODSIG 0123 Acme", 0),
        ] {
            let t = tools(fake_decrypt(dir.path(), name, status, "x", code));
            assert!(
                matches!(
                    check_clearsigned(&keys, &signed, dir.path(), &t),
                    Err(SignatureError::Refused(_))
                ),
                "{name}"
            );
        }
        // Not exactly one clear-signed message: refused before gpg runs,
        // whatever gpg would say.
        for (name, text) in [
            (
                "detached",
                "-----BEGIN PGP SIGNATURE-----\n\nwsB\n-----END PGP SIGNATURE-----\n".to_owned(),
            ),
            ("leading", format!("Suite: before\n{message}")),
            ("trailing", format!("{message}Suite: unsigned\n")),
            ("two", format!("{message}{message}")),
            (
                "unterminated",
                message.replace("-----END PGP SIGNATURE-----\n", ""),
            ),
        ] {
            let file = dir.path().join(name);
            std::fs::write(&file, text).unwrap();
            assert!(
                matches!(
                    check_clearsigned(&keys, &file, dir.path(), &good),
                    Err(SignatureError::Refused(_))
                ),
                "{name}"
            );
        }
        // CRLF line ends and blank lines after the block are the same
        // framing.
        let crlf = dir.path().join("crlf");
        std::fs::write(
            &crlf,
            format!("{}\r\n\n", message.trim_end().replace('\n', "\r\n")),
        )
        .unwrap();
        assert!(check_clearsigned(&keys, &crlf, dir.path(), &good).is_ok());
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("sw-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
