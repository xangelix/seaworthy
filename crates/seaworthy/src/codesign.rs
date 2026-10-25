//! Package and binary signatures (steps 2 and 5 of the pipeline), each
//! behind a signer interface so the key-custody decisions never change
//! code:
//!
//! - **Authenticode** ([`AuthenticodeSigner`]): every Windows binary in the
//!   tree (the launcher, each core, the helper, the FIPS DLL pair) before
//!   the zip and the MSI are built, then the MSI itself.
//!   [`Osslsigncode`] signs with a local certificate and key (tests,
//!   throwaway CI certificates); [`CommandAuthenticode`] runs any program
//!   with the file in place of `{file}` (jsign with Azure Trusted Signing,
//!   signtool on the Windows runner).
//! - **OpenPGP** ([`OpenPgpSigner`]): rpm packages get an embedded header
//!   signature (`rpmsign --addsign`), pacman packages a detached `.sig`
//!   beside them, as `pacman` and `repo-add` expect. [`Gpg`] drives `gpg`
//!   with a key named by its fingerprint in a given home: a local test key,
//!   or a production key behind gpg-agent (a smartcard, or a KMS through a
//!   PKCS#11 bridge). deb packages carry no signature: apt verifies the
//!   repository's signed index instead.
//!
//! Every signature is then checked against the identity `seaworthy.toml` pins
//! ([`Pins`]): an Authenticode signature must verify to the pinned
//! trust anchors and name the pinned subject (`osslsigncode verify`); an
//! rpm or pacman signature must verify against the pinned OpenPGP keys
//! alone, in a throwaway keyring (`rpmkeys --checksig`, `gpg --verify`). A
//! staging certificate or key fails the build, not the customer's install.
//!
//! Every program runs through [`crate::process`]: no shell, a deadline
//! (default [`DEFAULT_TOOL_TIMEOUT`]; a timestamping service or a remote
//! signer can be slow), bounded output.
//!
//! A signature makes a package depend on its signing time, so signed
//! builds aren't byte-reproducible; the unsigned bytes are, and
//! `rpm --delsign` or dropping the certificate table recovers them.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::DistError;
use seaworthy_updater::openpgp::{self, OpenPgpKeys, SignatureError};

use crate::process::run_ok;

/// A signing program's default deadline.
pub const DEFAULT_TOOL_TIMEOUT: Duration = Duration::from_secs(600);

/// A verifying program's deadline (local work only).
const VERIFY_TIMEOUT: Duration = Duration::from_secs(120);

/// Signs Windows binaries and MSIs with Authenticode, in place.
pub trait AuthenticodeSigner {
    /// Signs `file` (a PE image or an MSI) in place, with `description`
    /// (the product's name) as the program name Windows shows.
    ///
    /// # Errors
    /// [`DistError::Tool`] when signing fails.
    fn sign(&self, file: &Path, description: &str) -> Result<(), DistError>;
    /// What this signer is, for messages.
    fn describe(&self) -> String;
}

/// osslsigncode with a local PEM certificate chain and key.
#[derive(Debug, Clone)]
pub struct Osslsigncode {
    /// The osslsigncode binary.
    pub tool: PathBuf,
    /// The PEM certificate (leaf first, then intermediates).
    pub certificate: PathBuf,
    /// The PEM private key.
    pub key: PathBuf,
    /// An RFC 3161 timestamping service, so signatures outlive the
    /// certificate.
    pub timestamp_url: Option<String>,
    /// The vendor's URL signed in (`-i`).
    pub url: Option<String>,
    /// The deadline for one signature.
    pub timeout: Duration,
}

impl Osslsigncode {
    /// Refuses a private key other users can touch, or a path that isn't a
    /// regular file (Unix), as a release key file is refused. Advisory:
    /// osslsigncode opens the path again itself.
    ///
    /// # Errors
    /// [`DistError::Io`], [`DistError::Sign`].
    pub fn check_key(&self) -> Result<(), DistError> {
        crate::sign::open_private(&self.key, 1 << 20, "a signing key file").map(|_| ())
    }
}

impl AuthenticodeSigner for Osslsigncode {
    fn sign(&self, file: &Path, description: &str) -> Result<(), DistError> {
        let signed = file.with_extension(format!(
            "{}.signing",
            file.extension()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let mut command = Command::new(&self.tool);
        command
            .arg("sign")
            .args(["-h", "sha256"])
            .arg("-certs")
            .arg(&self.certificate)
            .arg("-key")
            .arg(&self.key)
            .arg("-n")
            .arg(description);
        if let Some(url) = &self.url {
            command.arg("-i").arg(url);
        }
        if let Some(ts) = &self.timestamp_url {
            command.arg("-ts").arg(ts);
        }
        command.arg("-in").arg(file).arg("-out").arg(&signed);
        let result = run_ok(&mut command, "Authenticode", self.timeout);
        if result.is_err() {
            let _ = std::fs::remove_file(&signed);
        }
        result?;
        std::fs::rename(&signed, file).map_err(|e| DistError::io(file, e))
    }

    fn describe(&self) -> String {
        format!("osslsigncode with {}", self.certificate.display())
    }
}

/// Any signing program, run with `{file}` in its arguments replaced by the
/// file's path (and `{description}` by the product's name); it must sign
/// the file in place.
#[derive(Debug, Clone)]
pub struct CommandAuthenticode {
    /// The program and its arguments.
    pub command: Vec<String>,
    /// The deadline for one signature.
    pub timeout: Duration,
}

/// `arg` with `{file}` and `{description}` replaced in one pass, so a
/// path containing `{description}` stays as it is.
fn substitute(arg: &str, file: &str, description: &str) -> String {
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(at) = rest.find('{') {
        out.push_str(rest.get(..at).unwrap_or_default());
        let tail = rest.get(at..).unwrap_or_default();
        if let Some(after) = tail.strip_prefix("{file}") {
            out.push_str(file);
            rest = after;
        } else if let Some(after) = tail.strip_prefix("{description}") {
            out.push_str(description);
            rest = after;
        } else {
            out.push('{');
            rest = tail.get(1..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    out
}

impl AuthenticodeSigner for CommandAuthenticode {
    fn sign(&self, file: &Path, description: &str) -> Result<(), DistError> {
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| DistError::Sign("an Authenticode command needs a program".to_owned()))?;
        if !args.iter().any(|a| a.contains("{file}")) {
            return Err(DistError::Sign(
                "an Authenticode command must name {file}".to_owned(),
            ));
        }
        let path = file.to_string_lossy();
        let mut command = Command::new(program);
        command.args(args.iter().map(|a| substitute(a, &path, description)));
        run_ok(&mut command, "Authenticode", self.timeout).map(|_| ())
    }

    fn describe(&self) -> String {
        format!(
            "command {}",
            self.command.first().map_or("", String::as_str)
        )
    }
}

/// `osslsigncode verify` on `file`, trusting `ca` (PEM) when given, for
/// the signer's chain and for its timestamp's (`-TSA-CAfile`: osslsigncode
/// checks a timestamp against its own trust file, and without a valid
/// timestamp a short-lived certificate, such as Azure Trusted Signing's,
/// fails as expired); the tool's report.
///
/// # Errors
/// [`DistError::Tool`] when the signature doesn't verify.
pub fn verify_authenticode(
    tool: &Path,
    file: &Path,
    ca: Option<&Path>,
) -> Result<String, DistError> {
    let mut command = Command::new(tool);
    command.arg("verify");
    if let Some(ca) = ca {
        command.arg("-CAfile").arg(ca).arg("-TSA-CAfile").arg(ca);
    }
    command.arg("-in").arg(file);
    run_ok(&mut command, "Authenticode verification", VERIFY_TIMEOUT)
}

/// Whether an `osslsigncode verify` report says a timestamp failed to
/// verify (a signature without a timestamp reports none).
#[must_use]
pub fn timestamp_failed(report: &str) -> bool {
    report
        .lines()
        .any(|line| line.trim() == "Timestamp Server Signature verification: failed")
}

/// The primary signer's subject in an `osslsigncode verify` report: the
/// first `Subject:` under "Signer's certificate:".
#[must_use]
pub fn signer_subject(report: &str) -> Option<&str> {
    let section = report.split_once("Signer's certificate:")?.1;
    section
        .lines()
        .find_map(|line| line.trim().strip_prefix("Subject:"))
        .map(str::trim)
}

/// Signs Linux packages with OpenPGP.
pub trait OpenPgpSigner {
    /// Adds an embedded signature to an rpm package.
    ///
    /// # Errors
    /// [`DistError::Tool`] when signing fails.
    fn sign_rpm(&self, rpm: &Path) -> Result<(), DistError>;
    /// Writes a detached binary signature of `file` to `signature`.
    ///
    /// # Errors
    /// [`DistError::Tool`] when signing fails.
    fn detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError>;
    /// Writes an ASCII-armored detached signature of `file` to `signature`
    /// (a DNF repository's `repomd.xml.asc`).
    ///
    /// # Errors
    /// [`DistError::Tool`] when signing fails.
    fn armored_detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError>;
    /// Writes `file` clear-signed to `signed` (an APT repository's
    /// `InRelease`).
    ///
    /// # Errors
    /// [`DistError::Tool`] when signing fails.
    fn clear_sign(&self, file: &Path, signed: &Path) -> Result<(), DistError>;
    /// What this signer is, for messages.
    fn describe(&self) -> String;
}

/// gpg (and rpmsign, which runs gpg) with a key in a gpg home.
#[derive(Debug, Clone)]
pub struct Gpg {
    /// The gpg home holding (or reaching, through gpg-agent) the key.
    pub home: PathBuf,
    /// The key's fingerprint (40 or 64 hex characters): never a user id,
    /// which could match a different key and reaches rpm's macro expander.
    pub key: String,
    /// The gpg binary.
    pub gpg: PathBuf,
    /// The rpmsign binary.
    pub rpmsign: PathBuf,
    /// The deadline for one signature.
    pub timeout: Duration,
}

impl Gpg {
    /// One gpg signing operation with the key, SHA-512 digests (RHEL's
    /// FIPS mode refuses SHA-1 ones).
    fn gpg_sign(
        &self,
        mode: &[&str],
        file: &Path,
        out: &Path,
        what: &str,
    ) -> Result<(), DistError> {
        self.check()?;
        let mut command = Command::new(&self.gpg);
        command
            .arg("--homedir")
            .arg(&self.home)
            .args(["--batch", "--yes", "--digest-algo", "SHA512"])
            .args(mode)
            .arg("--local-user")
            .arg(&self.key)
            .arg("--output")
            .arg(out)
            .arg(file);
        run_ok(&mut command, what, self.timeout).map(|_| ())
    }
}

/// Whether `key` is an OpenPGP fingerprint: v4 (40 hex) or v5/v6 (64 hex).
#[must_use]
pub fn is_fingerprint(key: &str) -> bool {
    matches!(key.len(), 40 | 64) && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `program` as an absolute path: as given when it names a path, else the
/// first match on `PATH` (rpmsign executes its `__gpg` without a lookup).
fn absolute(program: &Path) -> Result<PathBuf, DistError> {
    if program.components().count() > 1 || program.is_absolute() {
        return Ok(program.to_path_buf());
    }
    // allow-std-env: PATH, to resolve a bare tool name as a shell would
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| DistError::Tool(format!("{} is not on PATH", program.display())))
}

/// `value` as the body of an rpm macro definition: `%` doubled, so rpm
/// expands nothing in it (`%(…)` would run a shell command).
fn macro_literal(value: &str) -> String {
    value.replace('%', "%%")
}

impl Gpg {
    fn check(&self) -> Result<(), DistError> {
        if !is_fingerprint(&self.key) {
            return Err(DistError::Sign(format!(
                "the OpenPGP key must be named by its fingerprint (40 or 64 hex characters), not {:?}",
                self.key
            )));
        }
        Ok(())
    }
}

impl OpenPgpSigner for Gpg {
    fn sign_rpm(&self, rpm: &Path) -> Result<(), DistError> {
        self.check()?;
        let gpg = absolute(&self.gpg)?;
        let mut command = Command::new(&self.rpmsign);
        command
            .arg("--addsign")
            // rpm 6 signs through `%_openpgp_sign`; pin gpg, so a host
            // configured for another signer can't ignore the home below.
            .arg("--define")
            .arg("_openpgp_sign gpg")
            .arg("--define")
            .arg(format!("_gpg_name {}", self.key))
            .arg("--define")
            .arg(format!(
                "_gpg_path {}",
                macro_literal(&self.home.to_string_lossy())
            ))
            .arg("--define")
            .arg(format!("__gpg {}", macro_literal(&gpg.to_string_lossy())))
            .arg(rpm);
        run_ok(&mut command, "rpm signature", self.timeout).map(|_| ())
    }

    fn detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError> {
        self.gpg_sign(
            &["--no-armor", "--detach-sign"],
            file,
            signature,
            "detached signature",
        )
    }

    fn armored_detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError> {
        self.gpg_sign(
            &["--armor", "--detach-sign"],
            file,
            signature,
            "armored detached signature",
        )
    }

    fn clear_sign(&self, file: &Path, signed: &Path) -> Result<(), DistError> {
        self.gpg_sign(&["--clearsign"], file, signed, "clear signature")
    }

    fn describe(&self) -> String {
        format!("gpg key {} in {}", self.key, self.home.display())
    }
}

/// [`Gpg`] with a key given as armored text (a custody system's key,
/// handed over in the environment: `signing.toml`'s
/// `[openpgp] secret-key-env`), imported into a private throwaway gpg home
/// (0700, under the system's temporary directory) for the run. Dropping it
/// stops the home's gpg-agent and deletes the home, the key with it; so
/// does SIGTERM, SIGINT or SIGHUP meanwhile (Unix), and a later import
/// sweeps away the homes of runs that were killed outright.
#[derive(Debug)]
pub struct ImportedGpg {
    signer: Gpg,
    gpgconf: PathBuf,
    home: Option<seaworthy_updater::process::TempDir>,
}

/// The longest path a Unix socket can be bound at (`sun_path` holds 108
/// bytes, the terminating NUL included).
const MAX_SOCKET_PATH: usize = 107;

/// gpg's longest socket name in a home, where it puts its sockets when
/// `/run/user/<uid>` is missing.
const LONGEST_SOCKET: &str = "S.gpg-agent.browser";

/// The longest name [`seaworthy_updater::process::TempDir`] gives an
/// `openpgp` home (`sw-openpgp-<pid>-<n>-<nanos>`).
const LONGEST_HOME_NAME: usize = 56;

/// The homes of imported keys alive in this process, each with the
/// gpgconf that stops its agent: what the interrupt cleanup removes.
static LIVE_HOMES: std::sync::Mutex<Vec<(PathBuf, PathBuf)>> = std::sync::Mutex::new(Vec::new());

/// gpgconf beside `gpg` when `gpg` names a path (a configured gpg with no
/// gpgconf on `PATH` would otherwise leave its agent running), else
/// `gpgconf` from `PATH`.
fn gpgconf_beside(gpg: &Path) -> PathBuf {
    match gpg.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) if dir.join("gpgconf").is_file() => dir.join("gpgconf"),
        _ => PathBuf::from("gpgconf"),
    }
}

/// Where a throwaway gpg home goes (an imported key's, the signature
/// checks'): the temporary directory, or `/tmp` when a home there would put
/// gpg-agent's sockets past what a socket path holds (gpg would fail to
/// start its agent, and the import or check with it).
fn home_parent() -> PathBuf {
    let tmp = std::env::temp_dir();
    let socket = tmp.as_os_str().len() + 1 + LONGEST_HOME_NAME + 1 + LONGEST_SOCKET.len();
    if socket <= MAX_SOCKET_PATH {
        tmp
    } else {
        PathBuf::from("/tmp")
    }
}

/// Stops `home`'s gpg-agent and deletes the home.
fn remove_home(home: &Path, gpgconf: &Path) {
    let mut kill = Command::new(gpgconf);
    kill.arg("--homedir").arg(home).args(["--kill", "all"]);
    let _ = run_ok(&mut kill, "gpg agent shutdown", DEFAULT_TOOL_TIMEOUT);
    let _ = std::fs::remove_dir_all(home);
}

/// Every live home's agent stopped and the home deleted (the Unix signal
/// handler's).
#[cfg(unix)]
fn remove_live_homes() {
    let homes = std::mem::take(
        &mut *LIVE_HOMES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    for (home, gpgconf) in homes {
        remove_home(&home, &gpgconf);
    }
}

/// Registers a live home, and once per process (Unix) a thread that, on
/// SIGTERM, SIGINT or SIGHUP, removes every live home and then ends the
/// process as the signal would have.
fn register_home(home: &Path, gpgconf: &Path) {
    #[cfg(unix)]
    {
        static CLEANUP: std::sync::Once = std::sync::Once::new();
        CLEANUP.call_once(|| {
            use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
            let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP])
            else {
                return;
            };
            let _ = std::thread::Builder::new()
                .name("seaworthy key cleanup".to_owned())
                .spawn(move || {
                    if let Some(signal) = signals.forever().next() {
                        remove_live_homes();
                        let _ = signal_hook::low_level::emulate_default_handler(signal);
                    }
                });
        });
    }
    LIVE_HOMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((home.to_path_buf(), gpgconf.to_path_buf()));
}

fn unregister_home(home: &Path) {
    LIVE_HOMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|(h, _)| h != home);
}

/// Removes the homes earlier runs left under `parent` when they were
/// killed before they could clean up (Linux): `sw-openpgp-<pid>-…`
/// directories owned by the owner of `ours` (this process's own new home)
/// whose process is gone, each agent stopped first.
fn sweep_stale_homes(parent: &Path, ours: &Path, gpgconf: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        let Ok(owner) = std::fs::symlink_metadata(ours).map(|m| m.uid()) else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(parent) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name
                .to_str()
                .and_then(|n| n.strip_prefix("sw-openpgp-"))
                .and_then(|rest| rest.split('-').next())
                .and_then(|pid| pid.parse::<u32>().ok())
            else {
                continue;
            };
            let path = entry.path();
            let stale = pid != std::process::id()
                && !Path::new("/proc").join(pid.to_string()).exists()
                && std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && m.uid() == owner);
            if stale {
                remove_home(&path, gpgconf);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (parent, ours, gpgconf);
}

impl ImportedGpg {
    /// Imports `armored` (an ASCII-armored secret key: unprotected, as a
    /// batch signer needs) into a new private home, and checks it: exactly
    /// one primary secret key, whose fingerprint is `key` (a subkey's
    /// doesn't count), and a test signature made with prompts refused (a
    /// protected key fails here, before any work).
    ///
    /// # Errors
    /// [`DistError::Sign`] for a fingerprint that isn't one, text that
    /// doesn't import, anything but exactly that one key, or a key that
    /// can't sign without a prompt; [`DistError::Tool`] when gpg can't run
    /// or the home can't be made.
    pub fn import(
        armored: &str,
        key: &str,
        gpg: PathBuf,
        rpmsign: PathBuf,
        timeout: Duration,
    ) -> Result<Self, DistError> {
        if !is_fingerprint(key) {
            return Err(DistError::Sign(format!(
                "the OpenPGP key must be named by its fingerprint (40 or 64 hex characters), not {key:?}"
            )));
        }
        let gpgconf = gpgconf_beside(&gpg);
        let parent = home_parent();
        let home = seaworthy_updater::process::TempDir::new_in(&parent, "openpgp")
            .map_err(|e| DistError::Tool(format!("a private gpg home: {e}")))?;
        register_home(home.path(), &gpgconf);
        sweep_stale_homes(&parent, home.path(), &gpgconf);
        let mut imported = Self {
            signer: Gpg {
                home: home.path().to_path_buf(),
                key: key.to_owned(),
                gpg,
                rpmsign,
                timeout,
            },
            gpgconf,
            home: Some(home),
        };
        imported.load(armored)?;
        Ok(imported)
    }

    /// The import and its checks (on failure, `self` is dropped: the home
    /// goes with it).
    fn load(&mut self, armored: &str) -> Result<(), DistError> {
        let gpg = &self.signer;
        let home = gpg.home.as_path();
        // The key goes in on stdin: never an argument or a file.
        let mut import = Command::new(&gpg.gpg);
        import
            .arg("--homedir")
            .arg(home)
            .args(["--batch", "--no-auto-check-trustdb", "--import"]);
        let finished = crate::process::run(
            &mut import,
            "importing the OpenPGP secret key",
            Some(armored.as_bytes().to_vec()),
            gpg.timeout,
            crate::process::MAX_OUTPUT_SHOWN,
        )?;
        if !finished.status.success() {
            return Err(DistError::Sign(format!(
                "[openpgp] secret-key-env: gpg couldn't import the key (an ASCII-armored secret key?): {}",
                finished.shown()
            )));
        }
        let mut list = Command::new(&gpg.gpg);
        list.arg("--homedir").arg(home).args([
            "--batch",
            "--no-auto-check-trustdb",
            "--with-colons",
            "--list-secret-keys",
        ]);
        let listing = run_ok(&mut list, "listing the imported secret key", gpg.timeout)?;
        let primaries = primary_fingerprints(&listing);
        if primaries.len() != 1 || !primaries[0].eq_ignore_ascii_case(&gpg.key) {
            return Err(DistError::Sign(format!(
                "[openpgp] secret-key-env must hold exactly one secret key, the configured `key` {} (its primary key's fingerprint; it holds {})",
                gpg.key,
                if primaries.is_empty() {
                    "none".to_owned()
                } else {
                    primaries.join(", ")
                }
            )));
        }
        // A test signature, prompts refused: a protected key (which a batch
        // run can never use) fails now, not midway through the packaging.
        let probe = home.join("probe");
        std::fs::write(&probe, b"seaworthy: the imported key signs\n")
            .map_err(|e| DistError::io(&probe, e))?;
        let mut sign = Command::new(&gpg.gpg);
        sign.arg("--homedir")
            .arg(home)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "error",
                "--local-user",
            ])
            .arg(&gpg.key)
            .arg("--output")
            .arg(home.join("probe.sig"))
            .args(["--detach-sign", "--"])
            .arg(&probe);
        run_ok(&mut sign, "a test signature with the imported key", gpg.timeout).map_err(|e| {
            DistError::Sign(format!(
                "[openpgp] secret-key-env: the key can't sign without a passphrase or a prompt (a batch signer needs an unprotected key): {e}"
            ))
        })?;
        Ok(())
    }

    /// The private home the key was imported into (while it exists).
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.signer.home
    }
}

/// The fingerprints of the primary secret keys in gpg's `--with-colons
/// --list-secret-keys` output: each `fpr` record right after a `sec` one
/// (a subkey's follows `ssb`).
#[must_use]
pub fn primary_fingerprints(listing: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut after_primary = false;
    for line in listing.lines() {
        let mut fields = line.split(':');
        match fields.next() {
            Some("sec") => after_primary = true,
            Some("fpr") if after_primary => {
                if let Some(fpr) = fields.nth(8) {
                    found.push(fpr.to_owned());
                }
                after_primary = false;
            }
            Some("ssb" | "pub" | "sub") => after_primary = false,
            _ => {}
        }
    }
    found
}

impl Drop for ImportedGpg {
    fn drop(&mut self) {
        if let Some(home) = self.home.take() {
            unregister_home(home.path());
            remove_home(home.path(), &self.gpgconf);
            drop(home);
        }
    }
}

impl OpenPgpSigner for ImportedGpg {
    fn sign_rpm(&self, rpm: &Path) -> Result<(), DistError> {
        self.signer.sign_rpm(rpm)
    }

    fn detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError> {
        self.signer.detach_sign(file, signature)
    }

    fn armored_detach_sign(&self, file: &Path, signature: &Path) -> Result<(), DistError> {
        self.signer.armored_detach_sign(file, signature)
    }

    fn clear_sign(&self, file: &Path, signed: &Path) -> Result<(), DistError> {
        self.signer.clear_sign(file, signed)
    }

    fn describe(&self) -> String {
        format!(
            "gpg key {} (imported from the environment into a private home)",
            self.signer.key
        )
    }
}

/// The detached signature of a pacman package: `<package>.sig`.
#[must_use]
pub fn signature_path(package: &Path) -> PathBuf {
    let mut name = package.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// The signing identities `seaworthy.toml` pins, and the tools that
/// check them.
#[derive(Debug, Clone)]
pub struct Pins {
    /// The Authenticode subject and trust anchors (an absolute path).
    pub authenticode: Option<(String, PathBuf)>,
    /// The OpenPGP public key files (absolute paths).
    pub openpgp: Vec<PathBuf>,
    /// The osslsigncode that verifies Authenticode signatures.
    pub osslsigncode: PathBuf,
    /// gpg, for detached signatures.
    pub gpg: PathBuf,
    /// rpmkeys, for rpm signatures.
    pub rpmkeys: PathBuf,
}

impl Pins {
    /// The pins of `config`, with the default tools.
    #[must_use]
    pub fn of(config: &crate::config::Config) -> Self {
        Self {
            authenticode: config
                .defaults
                .authenticode
                .as_ref()
                .map(|a| (a.subject.clone(), config.dir.join(&a.trust))),
            openpgp: config
                .defaults
                .openpgp_keys
                .iter()
                .map(|k| config.dir.join(k))
                .collect(),
            osslsigncode: PathBuf::from("osslsigncode"),
            gpg: PathBuf::from("gpg"),
            rpmkeys: PathBuf::from("rpmkeys"),
        }
    }

    /// Refuses signers `seaworthy.toml` pins no identity for: Authenticode
    /// without `defaults.authenticode`, OpenPGP without
    /// `defaults.openpgp-keys`.
    ///
    /// # Errors
    /// [`DistError::Sign`] naming the missing setting.
    pub fn require(&self, authenticode: bool, openpgp: bool) -> Result<(), DistError> {
        if authenticode && self.authenticode.is_none() {
            return Err(DistError::Sign(
                "defaults.authenticode is not set: name the signing certificate's subject and its trust anchors, and sign only as them".to_owned(),
            ));
        }
        if openpgp && self.openpgp.is_empty() {
            return Err(DistError::Sign(
                "defaults.openpgp-keys is empty: list the OpenPGP public keys package managers trust, and sign only with one of them".to_owned(),
            ));
        }
        Ok(())
    }

    /// Checks `file`'s Authenticode signature: it verifies to the pinned
    /// trust anchors and its signer is the pinned subject.
    ///
    /// # Errors
    /// [`DistError::Sign`] for a signature that doesn't verify or names
    /// another signer; [`DistError::Tool`] when osslsigncode can't run.
    pub fn check_authenticode(&self, file: &Path) -> Result<(), DistError> {
        let Some((subject, trust)) = &self.authenticode else {
            return Err(DistError::Sign(
                "no Authenticode identity is pinned".to_owned(),
            ));
        };
        let report = verify_authenticode(&self.osslsigncode, file, Some(trust)).map_err(|e| {
            DistError::Sign(format!(
                "{}: the Authenticode signature doesn't verify to {} ({e})",
                file.display(),
                trust.display()
            ))
        })?;
        // osslsigncode reports a timestamp that doesn't verify but still
        // exits 0 while the signer's certificate is valid: a short-lived
        // one (Azure Trusted Signing's lasts three days) would then stop
        // verifying days after the release.
        if timestamp_failed(&report) {
            return Err(DistError::Sign(format!(
                "{}: the signature's timestamp doesn't verify to {} (osslsigncode: \"Timestamp Server Signature verification: failed\")",
                file.display(),
                trust.display()
            )));
        }
        match signer_subject(&report) {
            Some(found) if found == subject => Ok(()),
            found => Err(DistError::Sign(format!(
                "{}: signed by {:?}, not the pinned {subject:?} (defaults.authenticode.subject)",
                file.display(),
                found.unwrap_or("nobody")
            ))),
        }
    }

    /// The pinned OpenPGP keys, read from their files.
    fn openpgp_keys(&self) -> Result<OpenPgpKeys, DistError> {
        let keys = self
            .openpgp
            .iter()
            .map(|path| std::fs::read(path).map_err(|e| DistError::io(path, e)))
            .collect::<Result<Vec<_>, _>>()?;
        OpenPgpKeys::new(keys).map_err(|e| DistError::Sign(format!("defaults.openpgp-keys: {e}")))
    }

    fn openpgp_tools(&self) -> openpgp::Tools {
        openpgp::Tools {
            gpg: self.gpg.clone(),
            gpgconf: PathBuf::from("gpgconf"),
            rpmkeys: self.rpmkeys.clone(),
        }
    }

    /// Checks an rpm's signature against the pinned keys alone, in a
    /// throwaway rpm database ([`seaworthy_updater::openpgp::check_rpm`], the
    /// update helper's own check).
    ///
    /// # Errors
    /// [`DistError::Sign`] for a package no pinned key signed;
    /// [`DistError::Tool`] when rpmkeys can't run.
    pub fn check_rpm(&self, rpm: &Path) -> Result<(), DistError> {
        let keys = self.openpgp_keys()?;
        openpgp::check_rpm(&keys, rpm, &home_parent(), &self.openpgp_tools())
            .map_err(signature_error)
    }

    /// Checks a detached signature of `file` against the pinned keys
    /// alone, in a throwaway gpg home
    /// ([`seaworthy_updater::openpgp::check_detached`], the update helper's own
    /// check).
    ///
    /// # Errors
    /// [`DistError::Sign`] for a signature no pinned key made;
    /// [`DistError::Tool`] when gpg can't run.
    pub fn check_detached(&self, signature: &Path, file: &Path) -> Result<(), DistError> {
        let keys = self.openpgp_keys()?;
        openpgp::check_detached(
            &keys,
            signature,
            file,
            &home_parent(),
            &self.openpgp_tools(),
        )
        .map_err(signature_error)
    }

    /// Refuses a pinned OpenPGP key a client would refuse: a signing or
    /// certifying key outside apt's default `Assert-Pubkey-Algo`
    /// (`>=rsa2048`, `ed25519`, `ed448`, `nistp256`, `nistp384`,
    /// `nistp521`; DSA never), or any signature on the key made with MD5,
    /// SHA-1 or RIPEMD-160. Debian 13's apt verifies with sqv, which
    /// refuses both, and RHEL's crypto policies refuse them for rpm: gpg
    /// alone would sign and verify happily.
    ///
    /// # Errors
    /// [`DistError::Sign`] naming each weak key; [`DistError::Tool`] when
    /// gpg can't run; [`DistError::Io`] for an unreadable key file.
    pub fn check_key_strength(&self) -> Result<(), DistError> {
        let home = seaworthy_updater::process::TempDir::new_in(&home_parent(), "keys")
            .map_err(|e| DistError::Tool(format!("a scratch gpg home: {e}")))?;
        let mut findings = Vec::new();
        for key in &self.openpgp {
            std::fs::metadata(key).map_err(|e| DistError::io(key, e))?;
            let gpg = |args: &[&str], what: &str| {
                let mut command = Command::new(&self.gpg);
                command
                    .arg("--homedir")
                    .arg(home.path())
                    .args(["--batch", "--no-auto-check-trustdb"])
                    .args(args)
                    .arg(key);
                run_ok(&mut command, what, DEFAULT_TOOL_TIMEOUT)
            };
            let colons = gpg(&["--with-colons", "--show-keys"], "reading a pinned key")?;
            let packets = gpg(&["--list-packets"], "reading a pinned key's packets")?;
            findings.extend(
                weak_key_findings(&colons, &packets)
                    .into_iter()
                    .map(|f| format!("{}: {f}", key.display())),
            );
        }
        let mut kill = Command::new("gpgconf");
        kill.arg("--homedir")
            .arg(home.path())
            .args(["--kill", "all"]);
        let _ = run_ok(&mut kill, "gpg agent shutdown", DEFAULT_TOOL_TIMEOUT);
        if findings.is_empty() {
            Ok(())
        } else {
            Err(DistError::Sign(format!(
                "defaults.openpgp-keys: {} (apt, dnf and pacman clients would refuse these signatures)",
                findings.join("; ")
            )))
        }
    }

    /// Checks a clear-signed text (an APT repository's `InRelease`)
    /// against the pinned keys alone and returns the text it signs
    /// ([`seaworthy_updater::openpgp::check_clearsigned`]).
    ///
    /// # Errors
    /// [`DistError::Sign`] for a text no pinned key signed, or a file that
    /// isn't exactly one signed message; [`DistError::Tool`] when gpg
    /// can't run.
    pub fn check_clearsigned(&self, signed: &Path) -> Result<Vec<u8>, DistError> {
        let keys = self.openpgp_keys()?;
        openpgp::check_clearsigned(&keys, signed, &home_parent(), &self.openpgp_tools())
            .map_err(signature_error)
    }
}

/// What makes a key weak to its clients, read from gpg's `--with-colons
/// --show-keys` (`colons`) and `--list-packets` (`packets`) output.
#[must_use]
pub fn weak_key_findings(colons: &str, packets: &str) -> Vec<String> {
    let mut findings = Vec::new();
    for line in colons.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let Some(kind) = fields.first().filter(|k| matches!(**k, "pub" | "sub")) else {
            continue;
        };
        let field = |i: usize| fields.get(i).copied().unwrap_or("");
        let (bits, algo, id, caps, curve) = (field(2), field(3), field(4), field(11), field(16));
        // Lowercase: the key's own capabilities; only signing and
        // certifying keys verify anything.
        if !caps.contains(['s', 'c']) {
            continue;
        }
        let bits: u32 = bits.parse().unwrap_or(0);
        let curve = curve.to_ascii_lowercase();
        let weak = match algo {
            "1" | "3" if bits < 2048 => Some(format!("RSA {bits}, below 2048")),
            "1" | "3" | "27" | "28" => None,
            "17" => Some("DSA".to_owned()),
            "19" if matches!(curve.as_str(), "nistp256" | "nistp384" | "nistp521") => None,
            "22" if matches!(curve.as_str(), "ed25519" | "ed448") => None,
            "19" | "22" => Some(format!("the curve {curve:?}")),
            other => Some(format!("public-key algorithm {other}")),
        };
        if let Some(why) = weak {
            findings.push(format!("{kind} key {id} uses {why}"));
        }
    }
    for line in packets.lines() {
        let digest = line
            .trim()
            .strip_prefix("digest algo ")
            .and_then(|rest| rest.split(',').next());
        let name = match digest {
            Some("1") => "MD5",
            Some("2") => "SHA-1",
            Some("3") => "RIPEMD-160",
            _ => continue,
        };
        let finding = format!("a signature on the key uses {name}");
        if !findings.contains(&finding) {
            findings.push(finding);
        }
    }
    findings
}

fn signature_error(error: SignatureError) -> DistError {
    match error {
        SignatureError::Refused(why) => {
            DistError::Sign(format!("{why} (the pinned keys are defaults.openpgp-keys)"))
        }
        SignatureError::Tool(why) => DistError::Tool(why),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_replaced_in_one_pass() {
        assert_eq!(
            substitute("{file}", "/a/{description}.exe", "Acme"),
            "/a/{description}.exe"
        );
        assert_eq!(
            substitute("-n={description};f={file}", "x", "Acme"),
            "-n=Acme;f=x"
        );
        assert_eq!(substitute("{other}{", "x", "y"), "{other}{");
    }

    #[test]
    fn only_fingerprints_name_an_openpgp_key() {
        assert!(is_fingerprint(&"a".repeat(40)));
        assert!(is_fingerprint(&"F".repeat(64)));
        for bad in [
            "Acme <pkg@acme.test>",
            "%(touch x)",
            &"a".repeat(41),
            &"g".repeat(40),
        ] {
            assert!(!is_fingerprint(bad), "{bad}");
        }
        assert_eq!(macro_literal("/home/%(id)"), "/home/%%(id)");
    }

    #[test]
    fn the_signer_subject_is_read_from_the_signers_section() {
        let report = "Signer's certificate:\n\t------------------\n\tSigner #0:\n\t\tSubject: CN=Acme,O=Acme\n\t\tIssuer : CN=Root\n\
                      Signing certificate chain verified using:\n\t\tSubject: CN=Root\n";
        assert_eq!(signer_subject(report), Some("CN=Acme,O=Acme"));
        assert_eq!(signer_subject("no signature"), None);
    }
}
