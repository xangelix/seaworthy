//! The helper's side of first-paint probation (`updates.probation`; the app's
//! side and the shared formats are [`crate::first_paint`]).
//!
//! **Starting one.** Before the helper installs a newer release, it keeps
//! the release that release replaces: it reads the installed release record
//! from the install root ([`crate::InstalledRelease`]), fetches that
//! release's manifest by its token and verifies it as it verifies an update
//! (same keys, product, channel, target and format; it must name exactly
//! the installed version and sequence), downloads and verifies its package
//! into the staging directory (`probation-previous.<ext>`), writes its own
//! record ([`ProbationRecord`], `seaworthy-update-probation:1`, private)
//! and publishes the notice the app reads. Only then does it install. A
//! release on probation replaced by a newer one keeps the release kept
//! before it (the last one that painted, or was never on probation). When
//! the previous release can't be kept, the new one installs without
//! probation, and the log and the status record say why.
//!
//! **Each run** (before it asks the server anything) evaluates a probation:
//! the installed release isn't the pending one → the probation is void; the
//! administrator's switch is off → it ends, nothing reverted; the markers
//! for the pending release are read, counted and removed; a paint commits
//! the release; `launches` launches without one, or `window` since the
//! first, revert it: exactly the kept release is installed again (its file
//! re-hashed against the digest kept from its manifest, the installer's
//! downgrade path for that release only), and the pending token is
//! remembered as rejected (`seaworthy-update-rejected:1`), so the helper
//! never installs it again; a newer one installs as usual. Windows hands
//! the revert to msiexec as it hands an install; the next run confirms it.
//! Markers past [`crate::first_paint::MAX_MARKER_ENTRIES`] decide nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{HelperConfig, HelperError, HelperOutcome};
use crate::first_paint::{Ingested, Locations, Notice};
use crate::installer::{Install, Installer};
use crate::policy::ProbationSwitch;
use crate::release::{Release, Version};
use crate::status::UpdateStage;
use crate::{ArtifactFormat, DigestAlgorithm};

/// The record's file name in the staging directory.
pub(crate) const RECORD_FILE: &str = "probation";

/// The rejected tokens' file name in the staging directory.
pub(crate) const REJECTED_FILE: &str = "probation-rejected";

/// The kept package's file stem in the staging directory (its extension is
/// its format's; a pacman signature beside it ends in `.sig`).
pub(crate) const PREVIOUS_STEM: &str = "probation-previous";

/// The record's tag.
pub(crate) const RECORD_TAG: &str = "seaworthy-update-probation:1";

/// The rejected tokens' tag.
pub(crate) const REJECTED_TAG: &str = "seaworthy-update-rejected:1";

/// The largest record read.
pub(crate) const MAX_RECORD_BYTES: usize = 2048;

/// How many rejected tokens are remembered (the newest).
pub(crate) const MAX_REJECTED: usize = 8;

/// Where a probation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// The pending release is installed and watched.
    Watching,
    /// The revert was handed to an installer that finishes after the run.
    Reverting,
}

/// The helper's private record of a probation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbationRecord {
    pub(crate) pending: Release,
    pub(crate) pending_token: String,
    pub(crate) previous: Release,
    pub(crate) previous_token: String,
    pub(crate) format: ArtifactFormat,
    pub(crate) size: u64,
    pub(crate) digest_algorithm: DigestAlgorithm,
    pub(crate) digest: String,
    pub(crate) started: u64,
    pub(crate) launches: u32,
    pub(crate) first_launch: Option<u64>,
    pub(crate) state: State,
}

fn spell(release: &Release) -> String {
    format!("{} {}", release.version, release.sequence)
}

fn release_of(text: &str) -> Option<Release> {
    let (version, sequence) = text.split_once(' ')?;
    let number = canonical_number(sequence)?;
    let parsed = Version::parse(version).ok()?;
    (parsed.to_string() == version)
        .then(|| Release::new(version, number).ok())
        .flatten()
}

/// A decimal number without a leading zero (or `0`).
fn canonical_number(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

fn token_ok(token: &str) -> bool {
    crate::validate_version(token).is_ok()
}

impl ProbationRecord {
    /// The record's text.
    pub(crate) fn encode(&self) -> String {
        format!(
            "{RECORD_TAG}\npending {}\npending-token {}\nprevious {}\nprevious-token {}\n\
             previous-format {}\nprevious-size {}\nprevious-digest {}:{}\nstarted {}\n\
             launches {}\nfirst-launch {}\nstate {}\n",
            spell(&self.pending),
            self.pending_token,
            spell(&self.previous),
            self.previous_token,
            self.format.tag(),
            self.size,
            self.digest_algorithm.name(),
            self.digest,
            self.started,
            self.launches,
            self.first_launch
                .map_or_else(|| "-".to_owned(), |at| at.to_string()),
            match self.state {
                State::Watching => "watching",
                State::Reverting => "reverting",
            }
        )
    }

    /// A record from its text: exactly its own encoding.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_RECORD_BYTES {
            return None;
        }
        let mut lines = text.split_terminator('\n');
        if lines.next()? != RECORD_TAG {
            return None;
        }
        let mut field = |key: &str| {
            lines
                .next()
                .and_then(|line| line.strip_prefix(key))
                .and_then(|rest| rest.strip_prefix(' '))
        };
        let pending = release_of(field("pending")?)?;
        let pending_token = field("pending-token")?.to_owned();
        let previous = release_of(field("previous")?)?;
        let previous_token = field("previous-token")?.to_owned();
        let format = ArtifactFormat::from_tag(field("previous-format")?)?;
        let size = canonical_number(field("previous-size")?)?;
        let (algorithm, digest) = field("previous-digest")?.split_once(':')?;
        let digest_algorithm = [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512]
            .into_iter()
            .find(|a| a.name() == algorithm)?;
        let started = canonical_number(field("started")?)?;
        let launches = u32::try_from(canonical_number(field("launches")?)?).ok()?;
        let first_launch = match field("first-launch")? {
            "-" => None,
            at => Some(canonical_number(at)?),
        };
        let state = match field("state")? {
            "watching" => State::Watching,
            "reverting" => State::Reverting,
            _ => return None,
        };
        if lines.next().is_some() {
            return None;
        }
        let hex_len = match digest_algorithm {
            DigestAlgorithm::Sha256 => 64,
            DigestAlgorithm::Sha512 => 128,
        };
        if digest.len() != hex_len
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !token_ok(&pending_token)
            || !token_ok(&previous_token)
            || size == 0
        {
            return None;
        }
        let record = Self {
            pending,
            pending_token,
            previous,
            previous_token,
            format,
            size,
            digest_algorithm,
            digest: digest.to_owned(),
            started,
            launches,
            first_launch,
            state,
        };
        (record.encode() == text).then_some(record)
    }

    /// The kept package's file name in the staging directory.
    pub(crate) fn previous_file(&self) -> String {
        previous_file(self.format)
    }
}

fn previous_file(format: ArtifactFormat) -> String {
    let extension = match format {
        ArtifactFormat::Deb => "deb",
        ArtifactFormat::Rpm => "rpm",
        ArtifactFormat::Pacman => "pkg.tar.zst",
        ArtifactFormat::Msi => "msi",
        ArtifactFormat::Zip => "zip",
        ArtifactFormat::Tar => "tar.zst",
        ArtifactFormat::Pkg => "pkg",
    };
    format!("{PREVIOUS_STEM}.{extension}")
}

/// The rejected tokens' text.
pub(crate) fn encode_rejected(tokens: &[String]) -> String {
    let mut text = format!("{REJECTED_TAG}\n");
    for token in tokens {
        text.push_str("token ");
        text.push_str(token);
        text.push('\n');
    }
    text
}

/// The rejected tokens from their text: exactly its own encoding, at most
/// [`MAX_REJECTED`] tokens, each passing the version gate.
pub(crate) fn parse_rejected(text: &str) -> Option<Vec<String>> {
    if text.len() > MAX_RECORD_BYTES {
        return None;
    }
    let mut lines = text.split_terminator('\n');
    if lines.next()? != REJECTED_TAG {
        return None;
    }
    let mut tokens = Vec::new();
    for line in lines {
        let token = line.strip_prefix("token ")?;
        if !token_ok(token) || tokens.len() >= MAX_REJECTED {
            return None;
        }
        tokens.push(token.to_owned());
    }
    (encode_rejected(&tokens) == text).then_some(tokens)
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Reads a small private file in the staging directory (never through a
/// link).
fn read_private(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// The record, if one exists; a record that doesn't parse is removed (with
/// a warning) and reads as none.
pub(crate) fn load(staging: &Path) -> Option<ProbationRecord> {
    let path = staging.join(RECORD_FILE);
    let text = read_private(&path)?;
    let record = ProbationRecord::parse(&text);
    if record.is_none() {
        tracing::warn!(
            "first-paint probation: {} doesn't parse; ending the probation, nothing reverted",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
    }
    record
}

fn save(staging: &Path, record: &ProbationRecord) -> Result<(), HelperError> {
    super::write_private(&staging.join(RECORD_FILE), record.encode().as_bytes())
}

/// The rejected tokens (none when the file is missing or doesn't parse).
pub(crate) fn rejected(staging: &Path) -> Vec<String> {
    read_private(&staging.join(REJECTED_FILE))
        .and_then(|text| parse_rejected(&text))
        .unwrap_or_default()
}

/// Remembers `token` as rejected (the newest [`MAX_REJECTED`] are kept).
fn reject(staging: &Path, token: &str) {
    let mut tokens = rejected(staging);
    tokens.retain(|t| t != token);
    tokens.insert(0, token.to_owned());
    tokens.truncate(MAX_REJECTED);
    if let Err(e) = super::write_private(
        &staging.join(REJECTED_FILE),
        encode_rejected(&tokens).as_bytes(),
    ) {
        tracing::warn!("first-paint probation: couldn't remember {token} as rejected: {e}");
    }
}

/// Ends a probation: the record, the kept package and the notice go.
fn clear(config: &HelperConfig, staging: &Path) {
    for name in [RECORD_FILE.to_owned()]
        .into_iter()
        .chain(previous_names().iter().map(|n| (*n).to_owned()))
    {
        match std::fs::remove_file(staging.join(&name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!("first-paint probation: couldn't remove {name}: {e}");
            }
            _ => {}
        }
    }
    withdraw(config);
}

/// Every name a kept package (and its signature) may have.
fn previous_names() -> [&'static str; 8] {
    [
        "probation-previous.deb",
        "probation-previous.rpm",
        "probation-previous.pkg.tar.zst",
        "probation-previous.msi",
        "probation-previous.zip",
        "probation-previous.tar.zst",
        "probation-previous.pkg",
        "probation-previous.sig",
    ]
}

/// Whether the sweep keeps `name`: a probation's own files.
pub(crate) fn keeps(name: &str) -> bool {
    name == RECORD_FILE || name == REJECTED_FILE || previous_names().contains(&name)
}

fn locations(config: &HelperConfig) -> Result<Locations, String> {
    if let Some(at) = &config.probation_at {
        return Ok(at.clone());
    }
    Ok(Locations {
        install_root: Some(install_root(config)?),
        public: config.product.probation_directory(),
        top: PathBuf::from("/var"),
        require_root: config.require_root,
        request: false,
    })
}

/// The product's install root: `/opt/<vendor>/<id>` (lowercase) on Linux,
/// `%ProgramFiles%\<Vendor>\<Directory>` on Windows.
fn install_root(config: &HelperConfig) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let program_files = seaworthy_fsguard::windows::known_folder(
            seaworthy_fsguard::windows::KnownFolder::ProgramFiles,
        )
        .map_err(|e| e.to_string())?;
        Ok(program_files
            .join(config.product.vendor())
            .join(config.product.windows_directory()))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from("/opt")
            .join(config.product.vendor().to_ascii_lowercase())
            .join(config.product.id()))
    }
}

fn switch(config: &HelperConfig) -> ProbationSwitch {
    config
        .probation_switch
        .unwrap_or_else(|| crate::policy::read_probation_switch(&config.product))
}

fn publish(config: &HelperConfig, notice: &Notice) -> Result<(), String> {
    #[cfg(windows)]
    {
        if config.probation_at.is_none() {
            return crate::first_paint::windows::publish(&config.product, notice);
        }
    }
    let at = locations(config)?;
    #[cfg(not(windows))]
    {
        crate::first_paint::unix::publish(&at, notice)
    }
    #[cfg(windows)]
    {
        let _ = (at, notice);
        Err("a test's locations on Windows".to_owned())
    }
}

fn withdraw(config: &HelperConfig) {
    #[cfg(windows)]
    {
        if config.probation_at.is_none() {
            crate::first_paint::windows::withdraw(&config.product);
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(at) = locations(config) {
            crate::first_paint::unix::withdraw(&at);
        }
    }
}

fn ingest(config: &HelperConfig, pending: &Release) -> Result<Ingested, String> {
    #[cfg(windows)]
    {
        let _ = locations;
        crate::first_paint::windows::ingest(&config.product, pending)
    }
    #[cfg(not(windows))]
    {
        crate::first_paint::unix::ingest(&locations(config)?, pending)
    }
}

/// Re-hashes the kept package against its record.
fn check_kept(staging: &Path, record: &ProbationRecord) -> Result<PathBuf, String> {
    use std::io::Read as _;
    let path = staging.join(record.previous_file());
    let mut file = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() != record.size {
        return Err(format!(
            "{} isn't the {}-byte package kept",
            path.display(),
            record.size
        ));
    }
    let mut digest = crate::DigestStream::new(record.digest_algorithm);
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        digest.update(buffer.get(..n).unwrap_or_default());
    }
    let actual = digest.finish_hex();
    if !seaworthy_crypto::ct_eq(actual.as_bytes(), record.digest.as_bytes()) {
        return Err(format!(
            "{} no longer has the kept digest {}",
            path.display(),
            record.digest
        ));
    }
    Ok(path)
}

/// Step 0 of a run: evaluates a probation (see the module docs).
/// `Ok(Some(outcome))` when it reverted (the run ends there); `Ok(None)` to
/// go on to the update check.
pub(crate) async fn evaluate(
    config: &HelperConfig,
    staging: &Path,
    installer: &Arc<dyn Installer>,
    installed: &Release,
) -> Result<Option<HelperOutcome>, HelperError> {
    let Some(mut record) = load(staging) else {
        // Kept packages without a record: a previous run's.
        for name in previous_names() {
            let _ = std::fs::remove_file(staging.join(name));
        }
        return Ok(None);
    };
    let package = config.product.package();
    if record.state == State::Reverting {
        if *installed == record.previous {
            tracing::info!(
                "first-paint probation: {package} {} is installed again (the revert from {} took)",
                record.previous,
                record.pending
            );
        } else {
            tracing::error!(
                "first-paint probation: the revert of {package} to {} didn't take ({installed} is installed); keeping it",
                record.previous
            );
        }
        clear(config, staging);
        return Ok(None);
    }
    if *installed != record.pending {
        tracing::info!(
            "first-paint probation: {package} {} was on probation, but {installed} is installed: the probation ends",
            record.pending
        );
        clear(config, staging);
        return Ok(None);
    }
    if switch(config) == ProbationSwitch::Off {
        tracing::info!(
            "first-paint probation is off on this machine: keeping {package} {} without watching it",
            record.pending
        );
        clear(config, staging);
        return Ok(None);
    }
    let Some(probation) = config.product.probation() else {
        clear(config, staging);
        return Ok(None);
    };
    let found = match ingest(config, &record.pending) {
        Ok(found) => found,
        Err(why) => {
            tracing::warn!(
                "first-paint probation: the markers can't be read ({}); deciding nothing this run",
                crate::log::line_safe(&why)
            );
            return Ok(None);
        }
    };
    if found.overflow {
        tracing::warn!(
            "first-paint probation: more than {} markers are waiting; deciding nothing this run",
            crate::first_paint::MAX_MARKER_ENTRIES
        );
        return Ok(None);
    }
    let now = now_ms();
    record.launches = record.launches.saturating_add(found.launches);
    if found.launches > 0 && record.first_launch.is_none() {
        record.first_launch = Some(now);
    }
    if found.painted {
        tracing::info!(
            "first-paint probation: {package} {} painted; it stays",
            record.pending
        );
        clear(config, staging);
        return Ok(None);
    }
    let window_ms = u64::try_from(probation.window.as_millis()).unwrap_or(u64::MAX);
    let overdue = record
        .first_launch
        .is_some_and(|first| now.saturating_sub(first) >= window_ms);
    if record.launches < probation.launches && !overdue {
        save(staging, &record)?;
        return Ok(None);
    }
    tracing::warn!(
        "first-paint probation: {package} {} never painted ({} launches since {}): reinstalling {}",
        record.pending,
        record.launches,
        record.first_launch.map_or_else(
            || "-".to_owned(),
            |at| format!("{} s ago", now.saturating_sub(at) / 1000)
        ),
        record.previous
    );
    revert(config, staging, installer, record).await.map(Some)
}

/// Installs exactly the kept release over the pending one.
async fn revert(
    config: &HelperConfig,
    staging: &Path,
    installer: &Arc<dyn Installer>,
    mut record: ProbationRecord,
) -> Result<HelperOutcome, HelperError> {
    let version = record.previous.version.to_string();
    super::report(staging, UpdateStage::Installing, Some(&version), "");
    reject(staging, &record.pending_token);
    let kept = match check_kept(staging, &record) {
        Ok(path) => path,
        Err(why) => {
            clear(config, staging);
            return Err(HelperError::Probation(format!(
                "the release kept to revert to can't be used ({why}); keeping {}",
                record.pending
            )));
        }
    };
    let signature = (record.format == ArtifactFormat::Pacman)
        .then(|| staging.join(format!("{PREVIOUS_STEM}.sig")))
        .filter(|path| path.exists());
    let package = config.product.package();
    let (install_installer, install_package, file, previous, pending) = (
        Arc::clone(installer),
        package.clone(),
        kept.clone(),
        record.previous.clone(),
        record.pending.clone(),
    );
    let installed = super::blocking(move || {
        install_installer.install(&Install {
            package: &install_package,
            file: &file,
            signature: signature.as_deref(),
            release: &previous,
            replaces: &pending,
        })
    })
    .await?;
    if let Err(error) = installed {
        clear(config, staging);
        return Err(HelperError::Probation(format!(
            "reinstalling {} failed ({error}); keeping {}",
            record.previous, record.pending
        )));
    }
    let outcome = |handed_off| HelperOutcome::Reverted {
        from: record.pending.clone(),
        to: record.previous.clone(),
        handed_off,
    };
    if installer.hands_off() {
        record.state = State::Reverting;
        save(staging, &record)?;
        withdraw(config);
        return Ok(outcome(true));
    }
    let confirm = Arc::clone(installer);
    let now = super::blocking(move || confirm.installed(&package)).await??;
    clear(config, staging);
    if now.as_ref() != Some(&record.previous) {
        return Err(HelperError::NotTaken {
            expected: Box::new(record.previous.clone()),
            found: now.map_or_else(|| "it not installed".to_owned(), |r| r.to_string()),
        });
    }
    Ok(outcome(false))
}

/// What starting a probation left behind, for [`abandon`] when the install
/// then fails.
pub(crate) struct Started {
    prior: Option<ProbationRecord>,
}

/// Before the install of `offered` over `installed`: starts a probation
/// (see the module docs). `Ok(None)` when none applies or starts (the
/// reason logged and returned for the status record's detail).
pub(crate) async fn begin(
    config: &HelperConfig,
    staging: &Path,
    format: ArtifactFormat,
    installed: &Release,
    offered: &Release,
    offered_token: &str,
) -> (Option<Started>, Option<String>) {
    if config.product.probation().is_none() || offered <= installed {
        return (None, None);
    }
    if switch(config) == ProbationSwitch::Off {
        return (
            None,
            Some("first-paint probation is off on this machine".to_owned()),
        );
    }
    let prior = load(staging);
    let kept = match &prior {
        // A newer release over one still on probation: the release kept
        // before it stays the one to go back to.
        Some(record)
            if record.state == State::Watching
                && record.pending == *installed
                && record.format == format
                && check_kept(staging, record).is_ok() =>
        {
            Ok(record.clone())
        }
        _ => keep_installed(config, staging, format, installed).await,
    };
    let kept = match kept {
        Ok(kept) => kept,
        Err(why) => {
            tracing::warn!(
                "first-paint probation: {} installs without probation: {}",
                offered,
                crate::log::line_safe(&why)
            );
            if prior.is_some() {
                clear(config, staging);
            }
            return (None, Some(format!("without first-paint probation: {why}")));
        }
    };
    let record = ProbationRecord {
        pending: offered.clone(),
        pending_token: offered_token.to_owned(),
        started: now_ms(),
        launches: 0,
        first_launch: None,
        state: State::Watching,
        ..kept
    };
    let published = save(staging, &record)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            publish(
                config,
                &Notice {
                    pending: offered.clone(),
                },
            )
        });
    if let Err(why) = published {
        tracing::warn!(
            "first-paint probation: {} installs without probation: {}",
            offered,
            crate::log::line_safe(&why)
        );
        clear(config, staging);
        return (None, Some(format!("without first-paint probation: {why}")));
    }
    tracing::info!(
        "first-paint probation: {} goes on probation; {} is kept to go back to",
        offered,
        record.previous
    );
    (Some(Started { prior }), None)
}

/// The install after [`begin`] failed: the probation it started is undone
/// (a prior one comes back).
pub(crate) fn abandon(config: &HelperConfig, staging: &Path, started: Started) {
    match started.prior {
        Some(prior) => {
            if save(staging, &prior).is_err()
                || publish(
                    config,
                    &Notice {
                        pending: prior.pending.clone(),
                    },
                )
                .is_err()
            {
                clear(config, staging);
            }
        }
        None => clear(config, staging),
    }
}

/// Fetches, verifies and keeps the installed release's package: the facts
/// of a record whose `previous` is `installed`.
async fn keep_installed(
    config: &HelperConfig,
    staging: &Path,
    format: ArtifactFormat,
    installed: &Release,
) -> Result<ProbationRecord, String> {
    let at = locations(config)?;
    let root = at
        .install_root
        .ok_or_else(|| "no install root".to_owned())?;
    let record = crate::first_paint::read_installed_release(&root).ok_or_else(|| {
        format!(
            "{} has no readable installed release record",
            root.join(crate::INSTALLED_RELEASE_FILE).display()
        )
    })?;
    if record.release != *installed {
        return Err(format!(
            "the install tree says {}, the package manager {installed}",
            record.release
        ));
    }
    let token = record.token();
    let path = staging.join(previous_file(format));
    let signature_path = staging.join(format!("{PREVIOUS_STEM}.sig"));
    let manifest = super::fetch_and_keep(
        config,
        staging,
        &token,
        format,
        installed,
        &path,
        &signature_path,
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(ProbationRecord {
        pending: installed.clone(),
        pending_token: token.clone(),
        previous: installed.clone(),
        previous_token: token,
        format,
        size: manifest.size,
        digest_algorithm: manifest.digest_algorithm,
        digest: hex::encode(&manifest.digest),
        started: 0,
        launches: 0,
        first_launch: None,
        state: State::Watching,
    })
}

/// Whether the server's `token` failed its probation here.
pub(crate) fn is_rejected(staging: &Path, token: &str) -> bool {
    rejected(staging).iter().any(|t| t == token)
}

/// Writes `record` as the staging directory's (this crate's tests).
#[cfg(all(test, unix))]
pub(crate) fn tests_save(staging: &Path, record: &ProbationRecord) {
    let _ = save(staging, record);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn record() -> ProbationRecord {
        ProbationRecord {
            pending: Release::new("1.1.0-rc.1", 9).unwrap(),
            pending_token: "1.1.0-rc.1+bbb".to_owned(),
            previous: Release::new("1.0.0", 8).unwrap(),
            previous_token: "1.0.0".to_owned(),
            format: ArtifactFormat::Rpm,
            size: 4096,
            digest_algorithm: DigestAlgorithm::Sha512,
            digest: "ab".repeat(64),
            started: 1_700_000_000_000,
            launches: 2,
            first_launch: Some(1_700_000_100_000),
            state: State::Watching,
        }
    }

    #[test]
    fn the_record_round_trips_canonically() {
        for r in [
            record(),
            ProbationRecord {
                first_launch: None,
                state: State::Reverting,
                digest_algorithm: DigestAlgorithm::Sha256,
                digest: "0f".repeat(32),
                ..record()
            },
        ] {
            let text = r.encode();
            assert_eq!(ProbationRecord::parse(&text), Some(r));
        }
        assert!(record().encode().contains("previous-digest sha512:abab"));
        assert_eq!(record().previous_file(), "probation-previous.rpm");
        let good = record().encode();
        for bad in [
            String::new(),
            good.replace(RECORD_TAG, "seaworthy-update-probation:2"),
            good.replace("launches 2", "launches 02"),
            good.replace("launches 2", "launches -2"),
            good.replace("previous-size 4096", "previous-size 0"),
            good.replace("previous-format rpm", "previous-format exe"),
            good.replace("sha512:", "md5:"),
            good.replace(&"ab".repeat(64), &"AB".repeat(64)),
            good.replace(&"ab".repeat(64), &"ab".repeat(32)),
            good.replace("state watching", "state committed"),
            good.replace("first-launch 1700000100000", "first-launch soon"),
            good.replace("pending-token 1.1.0-rc.1+bbb", "pending-token a..b"),
            good.replace("pending 1.1.0-rc.1 9", "pending v1.1.0-rc.1 9"),
            good.trim_end().to_owned(),
            format!("{good}extra\n"),
            good.replace("\nlaunches 2", ""),
            "x".repeat(MAX_RECORD_BYTES + 1),
        ] {
            assert_eq!(ProbationRecord::parse(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rejected_tokens_round_trip_and_are_bounded() {
        let tokens: Vec<String> = (0..MAX_REJECTED).map(|n| format!("1.{n}.0+x")).collect();
        let text = encode_rejected(&tokens);
        assert_eq!(parse_rejected(&text), Some(tokens.clone()));
        assert_eq!(parse_rejected(&encode_rejected(&[])), Some(Vec::new()));
        let mut more = tokens;
        more.push("9.9.9".to_owned());
        assert_eq!(parse_rejected(&encode_rejected(&more)), None);
        for bad in [
            "seaworthy-update-rejected:2\n",
            "seaworthy-update-rejected:1\ntoken a..b\n",
            "seaworthy-update-rejected:1\ntoken \n",
            "seaworthy-update-rejected:1\ntokens 1.0.0\n",
            "seaworthy-update-rejected:1\ntoken 1.0.0",
        ] {
            assert_eq!(parse_rejected(bad), None, "{bad:?}");
        }
        assert!(keeps(RECORD_FILE) && keeps(REJECTED_FILE) && keeps("probation-previous.deb"));
        assert!(!keeps("probation-previous.exe") && !keeps("failure-memo"));
    }
}
