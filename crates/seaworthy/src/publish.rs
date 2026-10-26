//! Publishing: the repositories `seaworthy repo` built, uploaded to any
//! S3-compatible store by their publish plan, through [`crate::s3`]'s
//! SigV4 client.
//!
//! ```text
//! <prefix>/apt/…  rpm/…  pacman/…  releases/…  keys/…  setup/…   the plan's files
//! <prefix>/plans/<date>-<sha256[..16]>.json              every plan that went (or may have gone) live
//! <prefix>/publish-plan.json                             the current plan (the next `--previous`)
//! ```
//!
//! **Before anything is uploaded**, everything that could refuse the
//! publication is checked: every file in the repository directory is the
//! plan's (its SHA-256 and size; nothing unplanned beside them; every path
//! a key under the repository's own directories); the repository package's
//! URL (the plan's `url`) is the target's `public-url`; the published plans —
//! the current one and the history in `plans/` — are this repository's,
//! and the newest of them is older than this one (an identical current plan
//! means already published); and every immutable path is looked up in the
//! bucket — present with the same SHA-256, it's skipped; present with other
//! bytes, the publication is refused naming it. The SHA-256 is the one
//! `publish` stored as the object's `x-amz-meta-sha256` (every
//! S3-compatible store keeps user metadata), else the store's own stored
//! checksum, else the object's bytes, read and hashed. The bucket is the
//! truth, not only the last plan: an immutable path is published once.
//!
//! **Then, in order**: the missing
//! immutable files, create-only (`If-None-Match: *`: a concurrent writer
//! can't be overwritten either) with `Cache-Control: public,
//! max-age=31536000, immutable`; the plan into `plans/` (from here on it
//! may be live, so pruning must count it); the indexes, in the plan's
//! order, with a short `max-age` (default 60 s); and last
//! `publish-plan.json`, after checking no other publication moved it
//! meanwhile. Every upload carries the body's SHA-256, which the store
//! verifies, and is read back at once: its size, SHA-256, type and cache
//! rule must be what was sent. A re-run of the published plan uploads its
//! indexes again (a later publication may have stopped midway).
//!
//! **Afterwards**, given the public URL clients use, every index, every
//! release manifest and the plan are fetched back through it (a
//! cache-busting query, so the answer comes from the bucket through the
//! CDN's routing) and compared byte for byte: a wrong domain or rule, or a
//! store decoding a key differently, shows here, not on customers'
//! machines. (The query bypasses the edge cache, so it doesn't prove how
//! long the CDN keeps an index.)
//!
//! **Pruning**: a file the current plan doesn't list is deleted
//! once the retention period (default 30 days) has passed since the plan
//! after the last one listing it went live — `plans/` keeps each plan with
//! the time it was written there — or, for a file no plan ever listed (a
//! publication that failed before its plan went into `plans/`), since it
//! was written. Only keys under the repository's own directories (`apt/`,
//! `rpm/`, `pacman/`, `releases/`, `keys/`, `setup/`) are ever deleted; a key there
//! that can't be a store path isn't ours and is left; `plans/` is kept. A
//! pruning failure doesn't undo a publication: it's reported apart.
//!
//! Credentials come from the environment (`SEAWORTHY_S3_ACCESS_KEY_ID`,
//! `SEAWORTHY_S3_SECRET_ACCESS_KEY`, optionally
//! `SEAWORTHY_S3_SESSION_TOKEN`; in CI, from the secret store's wrapper),
//! never from a file, and are never printed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::s3::{
    ObjectDetail, PutOptions, PutOutcome, S3Backend, S3Config, StorageError, StoragePath,
};
use bytes::Bytes;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::DistError;
use crate::repo::{Class, PLAN_FILE, Plan, PlanEntry};

/// The current plan's key, under the prefix.
pub const CURRENT_PLAN: &str = "publish-plan.json";
/// The plans history's directory, under the prefix.
pub const PLANS_DIR: &str = "plans";
/// The repository's own directories: every planned file is under one, and
/// they're the only ones pruning touches.
pub const OWN_DIRS: [&str; 6] = ["apt", "rpm", "pacman", "releases", "keys", "setup"];
/// An immutable file's `Cache-Control`.
pub const IMMUTABLE_CACHE: &str = "public, max-age=31536000, immutable";
/// The user metadata name `publish` stores each object's SHA-256 (hex)
/// under.
pub const SHA256_METADATA: &str = "sha256";
/// The largest file published (and fetched back): the update helper's
/// artifact limit, which `repo` already enforces on releases.
pub const MAX_FILE_BYTES: u64 = seaworthy_updater::MAX_ARTIFACT_BYTES;
/// The longest key a store accepts (S3's limit), prefix included.
const MAX_KEY_BYTES: usize = 1024;
/// The largest plan read back from the bucket.
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;
/// How many times a request that may succeed on retry is tried.
const ATTEMPTS: u32 = 4;
/// The slowest transfer a put, a read of an object's bytes or a fetch-back
/// waits for (bytes per second), on top of a fixed allowance
/// ([`transfer_deadline`]): a 1 GiB file gets about 70 minutes.
const MIN_TRANSFER_RATE: u64 = 256 * 1024;
/// The fixed allowance of every transfer's deadline (seconds).
const TRANSFER_BASE_SECONDS: u64 = 120;

/// The most `ListObjectsV2` pages one listing follows (at the default
/// 1000 keys a page, a million keys): a store answering truncated pages
/// forever can't keep a publication waiting.
pub const MAX_LIST_PAGES: usize = 1000;

/// `publish.toml`: where a repository is published. Environment specific
/// (CI), never part of `seaworthy.toml`.
///
/// ```toml
/// endpoint = "https://s3.example.com"                     # the S3 API (https; http only to loopback)
/// bucket = "files"
/// region = "auto"                                          # the store's SigV4 region
/// prefix = "packages"                                      # every key under it
/// public-url = "https://files.example.com/packages"        # what clients fetch: checked after publishing
/// index-max-age-seconds = 60                               # the default
/// retention-days = 30                                      # the default
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Target {
    /// The S3 API endpoint (no path).
    pub endpoint: String,
    /// The bucket.
    pub bucket: String,
    /// The SigV4 region (`us-east-1`, or `auto` for stores that take it).
    pub region: String,
    /// The key prefix every published file is under (`packages`):
    /// `[a-z0-9._-]` segments joined by `/`, never empty, none of them a
    /// name the repository uses inside it (`apt`, `plans`, …) — another
    /// target's pruning would treat a nested one as its own.
    pub prefix: String,
    /// The URL clients fetch the prefix through, when the publication is
    /// to be checked from their side.
    #[serde(default)]
    pub public_url: Option<String>,
    /// The indexes' `max-age` (1 to 3600 s; default 60).
    #[serde(default = "default_index_max_age")]
    pub index_max_age_seconds: u64,
    /// How long a file no plan references any more is kept (1 to 3650
    /// days; default 30).
    #[serde(default = "default_retention_days")]
    pub retention_days: u64,
}

const fn default_index_max_age() -> u64 {
    60
}

const fn default_retention_days() -> u64 {
    30
}

impl Target {
    /// Reads and checks `publish.toml`.
    ///
    /// # Errors
    /// [`DistError::Io`] for an unreadable file, [`DistError::Config`] for
    /// an invalid one.
    pub fn load(path: &Path) -> Result<Self, DistError> {
        let text = std::fs::read_to_string(path).map_err(|e| DistError::io(path, e))?;
        let target: Self = toml::from_str(&text)
            .map_err(|e| DistError::Config(format!("{}: {e}", path.display())))?;
        target.check()?;
        Ok(target)
    }

    /// The rules beyond the schema.
    ///
    /// # Errors
    /// [`DistError::Config`] naming the key.
    pub fn check(&self) -> Result<(), DistError> {
        let bad =
            |key: &str, why: &str| Err(DistError::Config(format!("publish.toml: {key} {why}")));
        let segment = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !OWN_DIRS.contains(&s)
                && s != PLANS_DIR
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        };
        if !self.prefix.split('/').all(segment) {
            return bad(
                "prefix",
                "must be [a-z0-9._-] segments joined by /, never empty, none of them apt, rpm, pacman, releases, keys, setup or plans: pruning deletes under it",
            );
        }
        if !(1..=3600).contains(&self.index_max_age_seconds) {
            return bad("index-max-age-seconds", "must be 1 to 3600");
        }
        if !(1..=3650).contains(&self.retention_days) {
            return bad("retention-days", "must be 1 to 3650");
        }
        if let Some(url) = &self.public_url
            && !public_url_ok(url)
        {
            return bad(
                "public-url",
                "must be an https URL (http only to a loopback address), written as a URL parser writes it (lowercase host, no default port), without credentials, a query, a fragment or a trailing slash, of ASCII letters, digits and -._~:/[] only",
            );
        }
        Ok(())
    }
}

/// The repository package points machines at the URL this target
/// publishes to (`publish.toml`'s `public-url` is `seaworthy.toml`'s
/// `[defaults.repository]` url): a package pointing elsewhere would set
/// every machine up for repositories this publication never reaches.
fn check_url(plan: &Plan, target: &Target) -> Result<(), DistError> {
    match (&plan.url, &target.public_url) {
        (Some(url), Some(public)) if url == public => Ok(()),
        (Some(url), Some(public)) => Err(DistError::Config(format!(
            "the repository package points machines at {url}, but publish.toml's public-url is {public}: publish to where the package points (or rebuild it with seaworthy.toml's [defaults.repository] url set to the public URL)"
        ))),
        (Some(url), None) => Err(DistError::Config(format!(
            "the repository package points machines at {url}: publish.toml must name it as public-url, so the publication is checked from there"
        ))),
        (None, _) => Ok(()),
    }
}

/// [`crate::config::client_url_ok`]: the rule `[defaults.repository]`'s
/// URL follows, so [`check_url`] compares the two as text.
fn public_url_ok(text: &str) -> bool {
    crate::config::client_url_ok(text)
}

/// The store's credentials, from the environment.
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// The credentials given.
    #[must_use]
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: session_token.map(Zeroizing::new),
        }
    }

    /// `SEAWORTHY_S3_ACCESS_KEY_ID`, `SEAWORTHY_S3_SECRET_ACCESS_KEY` and
    /// optionally `SEAWORTHY_S3_SESSION_TOKEN`.
    ///
    /// # Errors
    /// [`DistError::Config`] naming a missing or empty variable (never a
    /// value).
    pub fn from_env() -> Result<Self, DistError> {
        let var = |name: &str| {
            // allow-std-env: the publisher's store credentials (the secret
            // store's wrapper hands them over in CI)
            std::env::var(name).ok().filter(|v| !v.is_empty())
        };
        let required = |name: &str| {
            var(name).ok_or_else(|| {
                DistError::Config(format!(
                    "{name} is not set: the store's credentials come from the environment"
                ))
            })
        };
        Ok(Self::new(
            required("SEAWORTHY_S3_ACCESS_KEY_ID")?,
            required("SEAWORTHY_S3_SECRET_ACCESS_KEY")?,
            var("SEAWORTHY_S3_SESSION_TOKEN"),
        ))
    }
}

/// How a publication runs.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Check everything, upload nothing, delete nothing (the report says
    /// what would be uploaded and pruned).
    pub dry_run: bool,
    /// Prune after publishing.
    pub prune: bool,
    /// The time pruning measures retention against (seconds since the
    /// epoch): now.
    pub now: u64,
}

/// What a publication did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// The plan was already the published one: its indexes went up again,
    /// nothing else.
    pub already_published: bool,
    /// Keys uploaded (or, in a dry run, to be), in order, relative to the
    /// prefix.
    pub uploaded: Vec<String>,
    /// Immutable keys already published with the same bytes.
    pub skipped: Vec<String>,
    /// Keys pruning deleted (or, in a dry run, would delete).
    pub deleted: Vec<String>,
    /// Keys under the repository's directories that can't be store paths:
    /// not ours, left alone.
    pub foreign: Vec<String>,
    /// Why pruning was refused, when it was (the publication stands).
    pub prune_error: Option<String>,
    /// Files fetched back through the public URL and found identical.
    pub verified: usize,
}

/// Publishes the repository built in `repo` (its `publish-plan.json`) to
/// `target`. A pruning failure is reported in [`Report::prune_error`]: the
/// publication stands.
///
/// # Errors
/// [`DistError::Layout`] for a repository directory that isn't its plan's,
/// published plans this one can't follow, or an immutable path published
/// with other bytes (nothing uploaded in any of these); [`DistError::Tool`]
/// for a store or network failure, an upload the store didn't keep as sent,
/// a public URL serving other bytes, or another publication moving the
/// current plan meanwhile; [`DistError::Config`] for an unusable target.
pub fn publish(
    repo: &Path,
    target: &Target,
    credentials: &Credentials,
    options: &Options,
) -> Result<Report, DistError> {
    target.check()?;
    let plan = Plan::read(&repo.join(PLAN_FILE))?;
    check_directory(repo, &plan, &target.prefix)?;
    check_url(&plan, target)?;
    let plan_bytes = plan_bytes(&plan)?;
    let history_key = history_key(&plan, &plan_bytes);
    runtime()?.block_on(async {
        let store = Store::new(target, credentials)?;
        let mut report = Report::default();
        let current = store.current_plan().await?;
        let history = store.history().await?;
        report.already_published = current
            .as_ref()
            .is_some_and(|(bytes, _)| *bytes == plan_bytes);
        check_follows(
            &plan,
            &plan_bytes,
            current.as_ref(),
            &history,
            report.already_published,
        )?;
        let mut upload = Vec::new();
        if !report.already_published {
            let mut conflicts = Vec::new();
            for entry in plan.files.iter().filter(|f| f.class == Class::Immutable) {
                match store.compare(&entry.path, &entry.sha256, entry.size).await? {
                    Compared::Missing => upload.push(entry),
                    Compared::Same => report.skipped.push(entry.path.clone()),
                    Compared::Other(why) => conflicts.push(format!("{} ({why})", entry.path)),
                }
            }
            if !conflicts.is_empty() {
                return Err(DistError::Layout(format!(
                    "{} immutable file(s) already published with other bytes: {} — nothing was uploaded; a path is published once",
                    conflicts.len(),
                    conflicts.join(", ")
                )));
            }
        }
        let indexes: Vec<&PlanEntry> = plan
            .files
            .iter()
            .filter(|f| f.class == Class::Index)
            .collect();
        if options.dry_run {
            report
                .uploaded
                .extend(upload.iter().map(|e| e.path.clone()));
            if !report.already_published {
                report.uploaded.push(history_key.clone());
            }
            report
                .uploaded
                .extend(indexes.iter().map(|e| e.path.clone()));
            if !report.already_published {
                report.uploaded.push(CURRENT_PLAN.to_owned());
            }
            if options.prune {
                match store
                    .prune_plan(&plan, &history, target.retention_days, options.now)
                    .await
                {
                    Ok((doomed, foreign)) => {
                        report.deleted = doomed;
                        report.foreign = foreign;
                    }
                    Err(e) => report.prune_error = Some(e.to_string()),
                }
            }
            return Ok(report);
        }
        let index_cache = format!("public, max-age={}", target.index_max_age_seconds);
        if !report.already_published {
            for entry in upload {
                let bytes = read_planned(repo, entry)?;
                store
                    .put_immutable(&entry.path, bytes, &entry.sha256)
                    .await?;
                report.uploaded.push(entry.path.clone());
            }
            // From here on the plan may be live: into the history first,
            // so pruning counts it even if this run stops midway.
            let digest = seaworthy_crypto::digest::sha256_hex(&plan_bytes);
            store
                .put_immutable(&history_key, Bytes::from(plan_bytes.clone()), &digest)
                .await?;
            report.uploaded.push(history_key.clone());
        }
        // The indexes always (a re-run of the published plan restores them
        // after a later publication that stopped midway).
        for entry in &indexes {
            let bytes = read_planned(repo, entry)?;
            store
                .put(&entry.path, bytes, &entry.sha256, &index_cache, false)
                .await?;
            report.uploaded.push(entry.path.clone());
        }
        if !report.already_published {
            // Nobody else moved the current plan meanwhile (one publication
            // at a time is the rule — a CI resource group — this catches a
            // breach of it before the pointer is overwritten).
            let now_current = store.current_plan().await?.map(|(bytes, _)| bytes);
            if now_current != current.as_ref().map(|(bytes, _)| bytes.clone()) {
                return Err(DistError::Tool(format!(
                    "another publication replaced {CURRENT_PLAN} while this one ran: this plan's indexes are up, the pointer isn't, nothing was pruned — publish one at a time, then re-run"
                )));
            }
            let digest = seaworthy_crypto::digest::sha256_hex(&plan_bytes);
            store
                .put(
                    CURRENT_PLAN,
                    Bytes::from(plan_bytes.clone()),
                    &digest,
                    &index_cache,
                    false,
                )
                .await?;
            report.uploaded.push(CURRENT_PLAN.to_owned());
        }
        if let Some(url) = &target.public_url {
            report.verified = verify_public(&store, url, &plan, &plan_bytes).await?;
        }
        if options.prune {
            let planned = match store.history().await {
                Ok(history) => {
                    store
                        .prune_plan(&plan, &history, target.retention_days, options.now)
                        .await
                }
                Err(e) => Err(e),
            };
            match planned {
                Ok((doomed, foreign)) => {
                    report.foreign = foreign;
                    match store.delete(&doomed).await {
                        Ok(()) => report.deleted = doomed,
                        Err(e) => report.prune_error = Some(e.to_string()),
                    }
                }
                Err(e) => report.prune_error = Some(e.to_string()),
            }
        }
        Ok(report)
    })
}

/// Prunes `target` alone, against its current plan: what [`publish`] runs
/// last. Returns the keys deleted.
///
/// # Errors
/// A store failure, a plan in the history that doesn't parse, or no
/// current plan.
pub fn prune(
    target: &Target,
    credentials: &Credentials,
    now: u64,
) -> Result<Vec<String>, DistError> {
    target.check()?;
    runtime()?.block_on(async {
        let store = Store::new(target, credentials)?;
        let Some((_, plan)) = store.current_plan().await? else {
            return Err(DistError::Layout(
                "nothing is published here: no publish-plan.json to prune against".to_owned(),
            ));
        };
        Ok(store.prune(&plan, target.retention_days, now).await?.0)
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, DistError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| DistError::Tool(format!("an async runtime: {e}")))
}

/// The plan as published: the bytes `repo` wrote are re-serialized the
/// same way, so equal plans are equal bytes.
fn plan_bytes(plan: &Plan) -> Result<Vec<u8>, DistError> {
    let json = serde_json::to_string_pretty(plan).map_err(|e| DistError::Layout(e.to_string()))?;
    Ok(format!("{json}\n").into_bytes())
}

/// `plans/<date>-<sha256[..16]>.json`.
fn history_key(plan: &Plan, bytes: &[u8]) -> String {
    let digest = seaworthy_crypto::digest::sha256_hex(bytes);
    format!(
        "{PLANS_DIR}/{}-{}.json",
        plan.date,
        digest.get(..16).unwrap_or(&digest)
    )
}

/// Every file under `repo` is the plan's, every planned file is there with
/// its size and SHA-256, and every planned path is a store key under the
/// repository's own directories (never `plans/` or the plan itself).
fn check_directory(repo: &Path, plan: &Plan, prefix: &str) -> Result<(), DistError> {
    let planned: BTreeMap<&str, &PlanEntry> =
        plan.files.iter().map(|f| (f.path.as_str(), f)).collect();
    if planned.len() != plan.files.len() {
        return Err(DistError::Layout("the plan names a file twice".to_owned()));
    }
    for path in planned.keys() {
        let own = path
            .split_once('/')
            .is_some_and(|(top, _)| OWN_DIRS.contains(&top));
        if !own || StoragePath::new(path).is_err() || prefix.len() + 1 + path.len() > MAX_KEY_BYTES
        {
            return Err(DistError::Layout(format!(
                "the plan names {path:?}: every published file is a store key (at most {MAX_KEY_BYTES} bytes with the prefix) under apt/, rpm/, pacman/, releases/, keys/ or setup/"
            )));
        }
    }
    let mut found = Vec::new();
    walk(repo, repo, &mut found)?;
    let unplanned: Vec<&str> = found
        .iter()
        .map(String::as_str)
        .filter(|p| *p != PLAN_FILE && !planned.contains_key(p))
        .collect();
    if !unplanned.is_empty() {
        return Err(DistError::Layout(format!(
            "{} holds files its plan doesn't list: {}",
            repo.display(),
            unplanned.join(", ")
        )));
    }
    for entry in &plan.files {
        read_planned(repo, entry)?;
    }
    Ok(())
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), DistError> {
    for entry in std::fs::read_dir(dir).map_err(|e| DistError::io(dir, e))? {
        let entry = entry.map_err(|e| DistError::io(dir, e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| DistError::io(&path, e))?;
        if kind.is_dir() {
            walk(root, &path, out)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| DistError::Layout(format!("{} is outside", path.display())))?;
            out.push(
                relative
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        } else {
            return Err(DistError::Layout(format!(
                "{} is neither a file nor a directory",
                path.display()
            )));
        }
    }
    Ok(())
}

/// A planned file's bytes, which must be the plan's (read at upload time:
/// what's uploaded is what was checked).
fn read_planned(repo: &Path, entry: &PlanEntry) -> Result<Bytes, DistError> {
    let path: PathBuf = entry
        .path
        .split('/')
        .fold(repo.to_path_buf(), |p, s| p.join(s));
    let meta = std::fs::symlink_metadata(&path).map_err(|e| DistError::io(&path, e))?;
    if !meta.is_file() || meta.len() != entry.size || entry.size > MAX_FILE_BYTES {
        return Err(DistError::Layout(format!(
            "{} isn't the plan's file ({} bytes planned, at most {MAX_FILE_BYTES})",
            path.display(),
            entry.size
        )));
    }
    let bytes = std::fs::read(&path).map_err(|e| DistError::io(&path, e))?;
    if seaworthy_crypto::digest::sha256_hex(&bytes) != entry.sha256
        || bytes.len() as u64 != entry.size
    {
        return Err(DistError::Layout(format!(
            "{} changed since its plan was written",
            path.display()
        )));
    }
    Ok(Bytes::from(bytes))
}

/// The published plans this one follows: each is the same repository and
/// channel, and the newest of the current one and the history is older
/// (or is this very plan: a run that stopped midway, resumed). A re-run of
/// the current plan is refused when a newer one went into the history.
fn check_follows(
    plan: &Plan,
    plan_bytes: &[u8],
    current: Option<&(Vec<u8>, Plan)>,
    history: &[Published],
    already_published: bool,
) -> Result<(), DistError> {
    let published = current
        .map(|(_, p)| p)
        .into_iter()
        .chain(history.iter().map(|h| &h.plan));
    for other in published {
        if other.repository != plan.repository || other.channel != plan.channel {
            return Err(DistError::Layout(format!(
                "the target publishes {}'s {} channel, not {}'s {}",
                other.repository, other.channel, plan.repository, plan.channel
            )));
        }
    }
    let ours = seaworthy_crypto::digest::sha256_hex(plan_bytes);
    let newest_plan = history
        .iter()
        .filter(|h| h.digest != ours)
        .map(|h| &h.plan)
        .chain(
            current
                .filter(|(bytes, _)| seaworthy_crypto::digest::sha256_hex(bytes) != ours)
                .map(|(_, p)| p),
        )
        .max_by_key(|p| p.date);
    if !already_published
        && !plan.rollback
        && let Some(newest) = newest_plan
    {
        // A pipeline running out of order must not roll the repositories
        // back; a deliberate rollback says so (repo --allow-older).
        for release in &plan.releases {
            if let Some(published) = newest
                .releases
                .iter()
                .find(|r| r.product == release.product && r.sequence > release.sequence)
            {
                return Err(DistError::Layout(format!(
                    "the plan publishes {} {} (sequence {}), older than the published {} (sequence {}): a pipeline ran out of order (to roll back on purpose, repo --allow-older)",
                    release.package,
                    release.token,
                    release.sequence,
                    published.token,
                    published.sequence
                )));
            }
        }
    }
    let newest = newest_plan.map(|p| p.date);
    match newest {
        Some(date) if already_published && date > plan.date => Err(DistError::Layout(format!(
            "a newer plan (dated {date}) went into {PLANS_DIR}/ after this one was published: publish that plan again instead"
        ))),
        Some(date) if !already_published && plan.date <= date => Err(DistError::Layout(format!(
            "the plan's date {} isn't after the published plan's ({date}): build the repositories again (apt keeps the Release it holds when a new one is older)",
            plan.date
        ))),
        _ => Ok(()),
    }
}

/// The `Content-Type` a published file is stored with.
#[must_use]
pub fn content_type(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ends = |suffix: &str| name.ends_with(suffix);
    if path.starts_with("keys/") && ends(".asc") {
        "application/pgp-keys"
    } else if ends(".asc") || ends(".sig") || name == "Release.gpg" {
        "application/pgp-signature"
    } else if ends(".deb") {
        "application/vnd.debian.binary-package"
    } else if ends(".rpm") {
        "application/x-rpm"
    } else if ends(".msi") {
        "application/x-msi"
    } else if ends(".zip") {
        "application/zip"
    } else if ends(".cdx.json") {
        "application/vnd.cyclonedx+json"
    } else if ends(".json") {
        "application/json"
    } else if ends(".gz") {
        "application/gzip"
    } else if ends(".zst") || ends(".pacman") || ends(".tar") || ends(".db") || ends(".files") {
        // pacman packages and databases (and their alias names), the
        // release tree's pacman package and tarball: zstd streams.
        "application/zstd"
    } else if ends(".xml") {
        "application/xml"
    } else if ends(".manifest") || matches!(name, "Release" | "InRelease" | "Packages") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// What the bucket holds at an immutable path.
enum Compared {
    Missing,
    Same,
    Other(String),
}

/// An object's bytes, read back and hashed ([`Store::hash_object`]).
#[derive(Debug, PartialEq, Eq)]
enum Hashed {
    /// Exactly the size expected: their SHA-256.
    Digest(Vec<u8>),
    /// Fewer bytes than expected: how many.
    Short(u64),
    /// More than expected: reading stopped at the first chunk past them.
    Long,
}

/// A plan in the history, when it was written there, and its digest.
#[derive(Debug, Clone)]
pub struct Published {
    /// The plan.
    pub plan: Plan,
    /// When its history entry was written (seconds since the epoch), when
    /// the store says.
    pub written: Option<u64>,
    /// The SHA-256 (hex) of its bytes.
    pub digest: String,
}

/// The bucket, under the target's prefix.
struct Store {
    backend: S3Backend,
}

impl Store {
    fn new(target: &Target, credentials: &Credentials) -> Result<Self, DistError> {
        let mut config = S3Config::new(
            target.bucket.clone(),
            target.region.clone(),
            credentials.access_key_id.clone(),
            credentials.secret_access_key.to_string(),
        )
        .with_endpoint(target.endpoint.clone())
        .with_key_prefix(target.prefix.clone());
        if let Some(token) = &credentials.session_token {
            config = config.with_session_token(token.as_str());
        }
        let backend =
            S3Backend::new(config).map_err(|e| DistError::Config(format!("publish.toml: {e}")))?;
        Ok(Self { backend })
    }

    fn path(key: &str) -> Result<StoragePath, DistError> {
        StoragePath::new(key)
            .map_err(|e| DistError::Layout(format!("{key} can't be a key in the store: {e}")))
    }

    /// `op`, retried while the store answers something a retry may fix.
    async fn retried<T, F, Fut>(what: &str, mut op: F) -> Result<T, DistError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, StorageError>>,
    {
        let mut attempt = 1;
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(e) if e.is_retryable() && attempt < ATTEMPTS => {
                    tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
                    attempt += 1;
                }
                Err(e) => return Err(DistError::Tool(format!("{what}: {e}"))),
            }
        }
    }

    async fn get_plan(&self, key: &str) -> Result<Option<(Vec<u8>, Plan)>, DistError> {
        let path = Self::path(key)?;
        let fetched = Self::retried(&format!("reading {key}"), || {
            self.backend.get_object(&path, MAX_PLAN_BYTES)
        })
        .await?;
        let Some(fetched) = fetched else {
            return Ok(None);
        };
        let plan: Plan = serde_json::from_slice(&fetched.body).map_err(|e| {
            DistError::Layout(format!(
                "the published {key} isn't a plan this seaworthy reads ({e}): nothing was done"
            ))
        })?;
        Ok(Some((fetched.body.to_vec(), plan)))
    }

    /// The published plan: its bytes and itself.
    async fn current_plan(&self) -> Result<Option<(Vec<u8>, Plan)>, DistError> {
        self.get_plan(CURRENT_PLAN).await
    }

    /// Every plan in `plans/`, with when it was written there.
    async fn history(&self) -> Result<Vec<Published>, DistError> {
        let mut history = Vec::new();
        for (key, modified) in self.list(PLANS_DIR).await? {
            let (bytes, plan) = self
                .get_plan(&key)
                .await?
                .ok_or_else(|| DistError::Tool(format!("{key} vanished while being read")))?;
            history.push(Published {
                plan,
                written: modified.as_deref().and_then(parse_iso8601),
                digest: seaworthy_crypto::digest::sha256_hex(&bytes),
            });
        }
        Ok(history)
    }

    /// The bucket's object at `key` against the planned SHA-256 and size:
    /// by the SHA-256 `publish` stored in its metadata, else the store's
    /// stored checksum, else its bytes, hashed.
    async fn compare(&self, key: &str, sha256: &str, size: u64) -> Result<Compared, DistError> {
        let path = Self::path(key)?;
        let detail = Self::retried(&format!("looking up {key}"), || {
            self.backend.head_object_detail(&path)
        })
        .await?;
        let Some(detail) = detail else {
            return Ok(Compared::Missing);
        };
        if detail.size != size {
            return Ok(Compared::Other(format!("{} bytes", detail.size)));
        }
        let expected = hex::decode(sha256)
            .map_err(|_| DistError::Layout(format!("{sha256:?} isn't a hex SHA-256")))?;
        let found = match stored_sha256(&detail) {
            Some(found) => found,
            None => match self.hash_object(key, size, transfer_deadline(size)).await? {
                Hashed::Digest(digest) => digest,
                Hashed::Short(read) => {
                    return Ok(Compared::Other(format!(
                        "{read} of its {size} bytes when read"
                    )));
                }
                Hashed::Long => {
                    return Ok(Compared::Other(format!(
                        "more than its {size} bytes when read"
                    )));
                }
            },
        };
        Ok(if found == expected {
            Compared::Same
        } else {
            Compared::Other("other bytes".to_owned())
        })
    }

    /// The object's bytes, streamed and hashed: the request and the whole
    /// body within `deadline` ([`transfer_deadline`] of the size), so a
    /// store trickling bytes can't hold the publication past it. The
    /// store's stream is unbounded in size: reading stops at the first
    /// chunk past `size`.
    async fn hash_object(
        &self,
        key: &str,
        size: u64,
        deadline: Duration,
    ) -> Result<Hashed, DistError> {
        use futures_util::StreamExt as _;
        let path = Self::path(key)?;
        let mut stream = Self::retried(&format!("reading {key}"), || {
            self.backend.get_stream(&path, deadline)
        })
        .await?;
        let mut hasher = seaworthy_crypto::digest::Sha256::new();
        let mut read = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| match e {
                StorageError::Timeout => DistError::Tool(format!(
                    "reading {key}: not all of its {size} bytes within {} s",
                    deadline.as_secs_f64().ceil()
                )),
                e => DistError::Tool(format!("reading {key}: {e}")),
            })?;
            read = read.saturating_add(chunk.len() as u64);
            if read > size {
                return Ok(Hashed::Long);
            }
            hasher.update(&chunk);
        }
        if read != size {
            return Ok(Hashed::Short(read));
        }
        Ok(Hashed::Digest(hasher.finish().to_vec()))
    }

    /// Uploads `body`, then reads the object back: its size, SHA-256, type
    /// and cache rule must be what was sent.
    async fn put(
        &self,
        key: &str,
        body: Bytes,
        sha256: &str,
        cache_control: &str,
        create_only: bool,
    ) -> Result<PutOutcome, DistError> {
        let path = Self::path(key)?;
        let size = body.len() as u64;
        let mut options = PutOptions::create_only()
            .with_content_type(content_type(key))
            .with_cache_control(cache_control)
            .with_metadata(SHA256_METADATA, sha256)
            .with_max_body_bytes(MAX_FILE_BYTES)
            .with_timeout(transfer_deadline(size));
        options.create_only = create_only;
        let outcome = Self::retried(&format!("uploading {key}"), || {
            self.backend.put_object(&path, body.clone(), &options)
        })
        .await?;
        if matches!(outcome, PutOutcome::Created { .. }) {
            let detail = Self::retried(&format!("reading {key} back"), || {
                self.backend.head_object_detail(&path)
            })
            .await?
            .ok_or_else(|| DistError::Tool(format!("{key} is missing right after its upload")))?;
            let kept = detail.size == size
                && stored_sha256(&detail).is_some_and(|s| hex::encode(s) == sha256)
                && detail.content_type.as_deref() == Some(content_type(key))
                && detail.cache_control.as_deref() == Some(cache_control);
            if !kept {
                return Err(DistError::Tool(format!(
                    "the store didn't keep {key} as sent (size, SHA-256 metadata, type or cache rule): {detail:?}"
                )));
            }
        }
        Ok(outcome)
    }

    /// An immutable file, create-only: if another writer got there first
    /// (a concurrent publication), its bytes must be these.
    async fn put_immutable(&self, key: &str, body: Bytes, sha256: &str) -> Result<(), DistError> {
        let size = body.len() as u64;
        match self.put(key, body, sha256, IMMUTABLE_CACHE, true).await? {
            PutOutcome::Created { .. } => Ok(()),
            PutOutcome::AlreadyExists => match self.compare(key, sha256, size).await? {
                Compared::Same => Ok(()),
                Compared::Missing | Compared::Other(_) => Err(DistError::Layout(format!(
                    "{key} was published with other bytes while this publication ran"
                ))),
            },
        }
    }

    /// Every key under `dir` (relative to the prefix), with its
    /// modification time, over at most [`MAX_LIST_PAGES`] pages.
    ///
    /// # Errors
    /// [`DistError::Tool`] for a listing longer than that: a store that
    /// never stops paging can't keep a publication waiting.
    async fn list(&self, dir: &str) -> Result<Vec<(String, Option<String>)>, DistError> {
        let prefix = Self::path(dir)?;
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        for _ in 0..MAX_LIST_PAGES {
            let page = Self::retried(&format!("listing {dir}/"), || {
                self.backend
                    .list_objects_v2(&prefix, None, continuation.as_deref())
            })
            .await?;
            keys.extend(page.objects.into_iter().map(|o| (o.path, o.last_modified)));
            match page.continuation {
                Some(next) => continuation = Some(next),
                None => return Ok(keys),
            }
        }
        Err(DistError::Tool(format!(
            "listing {dir}/: more than {MAX_LIST_PAGES} pages; refusing to follow further"
        )))
    }

    /// What pruning against `plan` would delete, and the keys under the
    /// repository's directories that aren't ours.
    async fn prune_plan(
        &self,
        plan: &Plan,
        history: &[Published],
        retention_days: u64,
        now: u64,
    ) -> Result<(Vec<String>, Vec<String>), DistError> {
        let mut listed = Vec::new();
        let mut foreign = Vec::new();
        for dir in OWN_DIRS {
            for (key, modified) in self.list(dir).await? {
                if StoragePath::new(&key).is_ok() {
                    listed.push((key, modified));
                } else {
                    foreign.push(key);
                }
            }
        }
        Ok((doomed(plan, history, &listed, retention_days, now), foreign))
    }

    /// Prunes against `plan`: everything checked first, then the deletes.
    async fn prune(
        &self,
        plan: &Plan,
        retention_days: u64,
        now: u64,
    ) -> Result<(Vec<String>, Vec<String>), DistError> {
        let history = self.history().await?;
        let (doomed, foreign) = self.prune_plan(plan, &history, retention_days, now).await?;
        self.delete(&doomed).await?;
        Ok((doomed, foreign))
    }

    /// Deletes `keys`, every one a valid key first.
    async fn delete(&self, keys: &[String]) -> Result<(), DistError> {
        let paths = keys
            .iter()
            .map(|key| Self::path(key))
            .collect::<Result<Vec<_>, _>>()?;
        for (key, path) in keys.iter().zip(&paths) {
            Self::retried(&format!("deleting {key}"), || {
                self.backend.delete_object(path)
            })
            .await?;
        }
        Ok(())
    }
}

/// The SHA-256 an object carries: `publish`'s metadata, else the store's
/// stored checksum (base64).
fn stored_sha256(detail: &ObjectDetail) -> Option<Vec<u8>> {
    use base64::Engine as _;
    detail
        .metadata
        .get(SHA256_METADATA)
        .and_then(|hex_digest| hex::decode(hex_digest).ok())
        .or_else(|| {
            detail
                .sha256
                .as_deref()
                .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        })
        .filter(|digest| digest.len() == 32)
}

/// The deadline of a transfer of `size` bytes, whichever way (a put, a
/// read of an object's bytes, a fetch-back through the public URL): two
/// minutes, plus the body at [`MIN_TRANSFER_RATE`], at most
/// [`crate::s3::MAX_PUT_TIMEOUT`].
fn transfer_deadline(size: u64) -> Duration {
    Duration::from_secs(TRANSFER_BASE_SECONDS.saturating_add(size / MIN_TRANSFER_RATE))
        .min(crate::s3::MAX_PUT_TIMEOUT)
}

/// What pruning deletes: of the `listed` keys (each with its modification
/// time), those `current` doesn't list whose retention is over. A key is
/// unreferenced since the plan after the last one listing it went live —
/// a plan's time is the later of its date and when its history entry was
/// written (`history`; `current` too, by its date, when it isn't there) —
/// or, for a key no plan ever listed, since it was written. Keys outside
/// the repository's own directories are never chosen, nor any key whose
/// time can't be told.
#[must_use]
pub fn doomed(
    current: &Plan,
    history: &[Published],
    listed: &[(String, Option<String>)],
    retention_days: u64,
    now: u64,
) -> Vec<String> {
    let keep: BTreeSet<&str> = current.files.iter().map(|f| f.path.as_str()).collect();
    let mut plans: Vec<(u64, &Plan)> = history
        .iter()
        .map(|h| (h.plan.date.max(h.written.unwrap_or(h.plan.date)), &h.plan))
        .collect();
    if !history.iter().any(|h| h.plan == *current) {
        plans.push((current.date, current));
    }
    plans.sort_by_key(|(time, _)| *time);
    let retention = retention_days.saturating_mul(86_400);
    let mut doomed = Vec::new();
    for (key, modified) in listed {
        let own = OWN_DIRS.iter().any(|d| {
            key.strip_prefix(d)
                .is_some_and(|rest| rest.starts_with('/'))
        });
        if !own || keep.contains(key.as_str()) {
            continue;
        }
        let last = plans
            .iter()
            .rposition(|(_, p)| p.files.iter().any(|f| &f.path == key));
        let since = match last {
            Some(i) => plans.get(i + 1).map(|(time, _)| *time),
            None => modified.as_deref().and_then(parse_iso8601),
        };
        if since.is_some_and(|since| since.saturating_add(retention) <= now) {
            doomed.push(key.clone());
        }
    }
    doomed
}

/// `2026-10-14T12:00:00.000Z` (ListObjectsV2's `LastModified`) as seconds
/// since the epoch; `None` for anything else.
#[must_use]
pub fn parse_iso8601(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-').map(|p| p.parse::<u64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    let time = time.split('.').next()?;
    let mut time = time.split(':').map(|p| p.parse::<u64>().ok());
    let (hour, minute, second) = (time.next()??, time.next()??, time.next()??);
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Fetches every index, every release manifest and the plan back through
/// `public_url`, each with a cache-busting query, and compares them with
/// what was published. Returns how many were checked.
async fn verify_public(
    store: &Store,
    public_url: &str,
    plan: &Plan,
    plan_bytes: &[u8],
) -> Result<usize, DistError> {
    let client = store.backend.http_client();
    let plan_digest = seaworthy_crypto::digest::sha256_hex(plan_bytes);
    let mut checks: Vec<(&str, &str, u64)> = plan
        .files
        .iter()
        .filter(|f| f.class == Class::Index || f.path.ends_with(".manifest"))
        .map(|f| (f.path.as_str(), f.sha256.as_str(), f.size))
        .collect();
    checks.push((CURRENT_PLAN, &plan_digest, plan_bytes.len() as u64));
    for (key, sha256, size) in &checks {
        let url = public_file_url(public_url, key, sha256);
        let deadline = transfer_deadline(*size);
        let fetched = tokio::time::timeout(deadline, fetch(client, &url, *size))
            .await
            .map_err(|_| {
                DistError::Tool(format!(
                    "published, but {url} doesn't serve it: no full answer within {} s",
                    deadline.as_secs()
                ))
            })?
            .map_err(|why| {
                DistError::Tool(format!("published, but {url} doesn't serve it: {why}"))
            })?;
        if seaworthy_crypto::digest::sha256_hex(&fetched) != *sha256 {
            return Err(DistError::Tool(format!(
                "published, but {url} serves other bytes (a CDN rule or domain, or a store decoding the key differently)"
            )));
        }
    }
    Ok(checks.len())
}

/// `<public>/<key>?seaworthy-verify=<sha256>`, the key percent-encoded as the
/// update helper encodes it (a `+` as `%2B`).
#[must_use]
pub fn public_file_url(public_url: &str, key: &str, sha256: &str) -> String {
    format!(
        "{public_url}/{}?seaworthy-verify={sha256}",
        crate::s3::sigv4::uri_encode(key, true)
    )
}

/// One GET, its body at most `size` bytes: reading stops at the first
/// chunk past them (the caller bounds the time).
async fn fetch(client: &reqwest::Client, url: &str, size: u64) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status.as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| e.without_url().to_string())?
    {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > size {
            return Err(format!("more than the {size} bytes published"));
        }
    }
    Ok(body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn plan(date: u64, files: &[&str]) -> Plan {
        Plan {
            repository: "acme".into(),
            channel: "stable".into(),
            url: None,
            rollback: false,
            date,
            releases: Vec::new(),
            tools: BTreeMap::new(),
            files: files
                .iter()
                .map(|p| PlanEntry {
                    path: (*p).to_owned(),
                    sha256: "00".repeat(32),
                    size: 1,
                    class: Class::Immutable,
                })
                .collect(),
        }
    }

    fn published(plan: &Plan, written: Option<u64>) -> Published {
        Published {
            plan: plan.clone(),
            written,
            digest: seaworthy_crypto::digest::sha256_hex(&plan_bytes(plan).unwrap()),
        }
    }

    #[test]
    fn iso8601_times_read_as_seconds() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601("2026-10-14T12:00:00.000Z"),
            Some(1_791_979_200)
        );
        assert_eq!(parse_iso8601("2000-02-29T00:00:00Z"), Some(951_782_400));
        for bad in [
            "",
            "2026-10-14 12:00:00Z",
            "2026-10-14T12:00:00",
            "2026-13-01T00:00:00Z",
            "2026-10-14T24:00:00Z",
            "1969-12-31T23:59:59Z",
            "x-10-14T12:00:00Z",
        ] {
            assert_eq!(parse_iso8601(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn pruning_waits_for_retention_after_the_next_plan_went_live() {
        let day = 86_400;
        let a = plan(10 * day, &["apt/a.deb", "keys/k.asc", "releases/x/1/a"]);
        let b = plan(20 * day, &["apt/b.deb", "keys/k.asc"]);
        let c = plan(25 * day, &["apt/c.deb", "keys/k.asc"]);
        let listed: Vec<(String, Option<String>)> = [
            "apt/a.deb",
            "apt/b.deb",
            "apt/c.deb",
            "keys/k.asc",
            "releases/x/1/a",
            "apt/stray.deb",
            "notes/readme.txt",
            "plans/1.json",
            "aptly/x",
        ]
        .iter()
        .map(|k| ((*k).to_owned(), Some("1970-01-11T00:00:00.000Z".to_owned())))
        .collect();
        let history = [
            published(&a, Some(10 * day)),
            published(&b, Some(20 * day)),
            published(&c, Some(25 * day)),
        ];
        // a's files stopped being referenced when b went live (day 20), b's
        // when c did (day 25); the stray was written on day 10; c's are
        // current.
        let at = |now_days: u64| doomed(&c, &history, &listed, 30, now_days * day);
        assert_eq!(at(39), Vec::<String>::new());
        assert_eq!(at(40), ["apt/stray.deb"]);
        assert_eq!(at(49), ["apt/stray.deb"]);
        assert_eq!(at(50), ["apt/a.deb", "releases/x/1/a", "apt/stray.deb"]);
        assert_eq!(at(54), ["apt/a.deb", "releases/x/1/a", "apt/stray.deb"]);
        assert_eq!(
            at(55),
            ["apt/a.deb", "apt/b.deb", "releases/x/1/a", "apt/stray.deb"]
        );
        // The history in any order (as a listing returns it).
        let shuffled = [history[1].clone(), history[0].clone(), history[2].clone()];
        assert_eq!(
            doomed(&c, &shuffled, &listed, 30, 50 * day),
            ["apt/a.deb", "releases/x/1/a", "apt/stray.deb"]
        );
        // A plan built long ago but published late: its
        // predecessor's files are kept for the retention after it went
        // live, not after its date.
        let late = [published(&a, Some(10 * day)), published(&b, Some(45 * day))];
        assert_eq!(
            doomed(&b, &late, &listed[..2], 30, 50 * day),
            Vec::<String>::new()
        );
        assert_eq!(doomed(&b, &late, &listed[..2], 30, 75 * day), ["apt/a.deb"]);
        // The current plan not yet in the history counts by its date: it
        // is a's successor here.
        assert_eq!(
            doomed(&c, &history[..1], &listed[..1], 30, 54 * day),
            Vec::<String>::new()
        );
        assert_eq!(
            doomed(&c, &history[..1], &listed[..1], 30, 55 * day),
            ["apt/a.deb"]
        );
        // A key with no time and no plan is kept; outside the repository's
        // directories, never touched.
        let unknown = vec![
            ("apt/when.deb".to_owned(), None),
            ("aptly/x".to_owned(), None),
        ];
        assert!(doomed(&c, &history, &unknown, 1, u64::MAX).is_empty());
    }

    #[test]
    fn an_older_release_than_the_published_one_is_a_deliberate_rollback_or_refused() {
        let release = |sequence: u64| crate::repo::PlanRelease {
            product: "agent".into(),
            package: "acme-agent".into(),
            token: format!("1.{sequence}.0"),
            sequence,
        };
        let mut newer = plan(10, &["apt/a"]);
        newer.releases = vec![release(20)];
        let mut older = plan(20, &["apt/b"]);
        older.releases = vec![release(19)];
        let newer_bytes = plan_bytes(&newer).unwrap();
        let older_bytes = plan_bytes(&older).unwrap();
        // A later pipeline of an older release: refused, though its plan is
        // newer by date.
        let err = check_follows(
            &older,
            &older_bytes,
            Some(&(newer_bytes.clone(), newer.clone())),
            &[published(&newer, None)],
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(
                "acme-agent 1.19.0 (sequence 19), older than the published 1.20.0 (sequence 20)"
            ),
            "{err}"
        );
        // A deliberate rollback says so.
        older.rollback = true;
        let older_bytes = plan_bytes(&older).unwrap();
        assert!(
            check_follows(
                &older,
                &older_bytes,
                Some(&(newer_bytes.clone(), newer.clone())),
                &[],
                false
            )
            .is_ok()
        );
        // The same release again (another product moved on): no rollback.
        let mut same = plan(25, &["apt/d"]);
        same.releases = vec![release(20)];
        let same_bytes = plan_bytes(&same).unwrap();
        assert!(
            check_follows(
                &same,
                &same_bytes,
                Some(&(newer_bytes.clone(), newer.clone())),
                &[],
                false
            )
            .is_ok()
        );
        // Another product's release doesn't count.
        let mut other = plan(30, &["apt/c"]);
        other.releases = vec![crate::repo::PlanRelease {
            product: "console".into(),
            ..release(1)
        }];
        let other_bytes = plan_bytes(&other).unwrap();
        assert!(
            check_follows(
                &other,
                &other_bytes,
                Some(&(newer_bytes, newer)),
                &[],
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn a_plan_follows_the_newest_published_one() {
        let a = plan(10, &["apt/a"]);
        let b = plan(20, &["apt/b"]);
        let a_bytes = plan_bytes(&a).unwrap();
        let b_bytes = plan_bytes(&b).unwrap();
        let current = (a_bytes.clone(), a.clone());
        // B after A: fine; A after B: refused.
        assert!(check_follows(&b, &b_bytes, Some(&current), &[published(&a, None)], false).is_ok());
        let err = check_follows(
            &a,
            &a_bytes,
            Some(&(b_bytes.clone(), b.clone())),
            &[],
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("isn't after"), "{err}");
        // B stopped midway (in the history, pointer still A): a re-run of A
        // is refused; B's own re-run resumes.
        let history = [published(&a, None), published(&b, None)];
        let err = check_follows(&a, &a_bytes, Some(&current), &history, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("a newer plan (dated 20)"), "{err}");
        assert!(check_follows(&b, &b_bytes, Some(&current), &history, false).is_ok());
        // No pointer, but a history: still compared.
        let err = check_follows(&a, &a_bytes, None, &[published(&b, None)], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("isn't after"), "{err}");
        // Another repository.
        let mut other = b.clone();
        other.repository = "globex".into();
        let err = check_follows(&plan(30, &[]), &[], None, &[published(&other, None)], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("globex's stable"), "{err}");
    }

    #[test]
    fn content_types_by_file() {
        for (path, expected) in [
            (
                "apt/pool/main/acme-agent/acme-agent_1-1_amd64.deb",
                "application/vnd.debian.binary-package",
            ),
            ("apt/dists/stable/InRelease", "text/plain; charset=utf-8"),
            ("apt/dists/stable/Release.gpg", "application/pgp-signature"),
            (
                "apt/dists/stable/main/binary-amd64/Packages.gz",
                "application/gzip",
            ),
            (
                "apt/dists/stable/main/binary-amd64/by-hash/SHA256/ab",
                "application/octet-stream",
            ),
            ("rpm/stable/x86_64/repodata/repomd.xml", "application/xml"),
            (
                "rpm/stable/x86_64/repodata/repomd.xml.asc",
                "application/pgp-signature",
            ),
            ("pacman/stable/x86_64/acme.db", "application/zstd"),
            (
                "pacman/stable/x86_64/acme.db.sig",
                "application/pgp-signature",
            ),
            (
                "releases/acme-agent/stable/1+b/x/acme-agent.pacman",
                "application/zstd",
            ),
            (
                "releases/acme-agent/stable/1+b/x/acme-agent.deb.manifest",
                "text/plain; charset=utf-8",
            ),
            (
                "releases/acme-agent/stable/1+b/x/acme-agent.msi.cdx.json",
                "application/vnd.cyclonedx+json",
            ),
            ("keys/acme.asc", "application/pgp-keys"),
            ("plans/1-ab.json", "application/json"),
        ] {
            assert_eq!(content_type(path), expected, "{path}");
        }
    }

    #[test]
    fn public_urls_encode_the_token_as_the_helper_does() {
        assert_eq!(
            public_file_url(
                "https://files.example.com/packages",
                "releases/a/stable/1.4.0+abc/t/a.deb",
                "ff"
            ),
            "https://files.example.com/packages/releases/a/stable/1.4.0%2Babc/t/a.deb?seaworthy-verify=ff"
        );
    }

    /// A store answering every request with a 200 declaring `length`
    /// bytes, then writing `chunk` every `every` until the client hangs up.
    async fn store_writing(length: u64, chunk: &'static [u8], every: Duration) -> Store {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buffer = [0_u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n");
                    if socket.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                    while socket.write_all(chunk).await.is_ok() {
                        tokio::time::sleep(every).await;
                    }
                });
            }
        });
        let target = Target {
            endpoint,
            bucket: "files".into(),
            region: "auto".into(),
            prefix: "packages".into(),
            public_url: None,
            index_max_age_seconds: 60,
            retention_days: 30,
        };
        let credentials = Credentials::new("AKIDEXAMPLE".into(), "secret".into(), None);
        Store::new(&target, &credentials).unwrap()
    }

    #[tokio::test]
    async fn reading_an_object_is_bounded_by_its_deadline() {
        // A byte every 100 ms of a 1000-byte object: well inside the
        // client's per-read timeout, never done within the deadline.
        let store = store_writing(1000, b"x", Duration::from_millis(100)).await;
        let start = std::time::Instant::now();
        let err = store
            .hash_object("apt/a.deb", 1000, Duration::from_millis(500))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("reading apt/a.deb: not all of its 1000 bytes within 1 s"),
            "{err}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn reading_an_object_stops_at_the_first_chunk_past_its_size() {
        // An endless body claiming 1 GiB, as fast as it goes: refused at
        // once, not read to the deadline.
        static CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];
        let store = store_writing(1 << 30, &CHUNK, Duration::ZERO).await;
        let start = std::time::Instant::now();
        let hashed = store
            .hash_object("apt/a.deb", 6, Duration::from_secs(600))
            .await
            .unwrap();
        assert_eq!(hashed, Hashed::Long);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn transfer_deadlines_scale_with_the_body() {
        assert_eq!(transfer_deadline(0), Duration::from_secs(120));
        assert_eq!(
            transfer_deadline(MAX_FILE_BYTES),
            Duration::from_secs(120 + 4096)
        );
        assert_eq!(transfer_deadline(u64::MAX), crate::s3::MAX_PUT_TIMEOUT);
    }

    #[test]
    fn targets_are_checked() {
        let target = |extra: &str| {
            toml::from_str::<Target>(&format!(
                "endpoint = \"https://s3.example.com\"\nbucket = \"files\"\nregion = \"auto\"\nprefix = \"packages\"\n{extra}"
            ))
            .map_err(|e| e.to_string())
            .and_then(|t| t.check().map(|()| t).map_err(|e| e.to_string()))
        };
        let ok = target("").unwrap();
        assert_eq!((ok.index_max_age_seconds, ok.retention_days), (60, 30));
        for good in [
            "https://files.example.com/packages",
            "http://127.0.0.1:9000/b/packages",
            "http://localhost:9000/packages",
            "http://[::1]:9000/packages",
        ] {
            assert!(
                target(&format!("public-url = \"{good}\"")).is_ok(),
                "{good}"
            );
        }
        for bad in [
            "public-url = \"http://files.example.com/packages\"",
            "public-url = \"http://localhost.attacker.example/packages\"",
            "public-url = \"http://127.0.0.1.nip.io/packages\"",
            "public-url = \"https://user:pass@files.example.com/packages\"",
            "public-url = \"https://user@files.example.com/packages\"",
            "public-url = \"https://files.example.com/packages/\"",
            "public-url = \"https://files.example.com/p?x=1\"",
            "public-url = \"https://files.example.com/p#x\"",
            "public-url = \"not a url\"",
            "public-url = \"https:files.example.com/packages\"",
            "public-url = \"https://Files.example.com/packages\"",
            "public-url = \"https://files.example.com:443/packages\"",
            "public-url = \"https://files.example.com/a,b\"",
            "retention-days = 0",
            "index-max-age-seconds = 0",
            "index-max-age-seconds = 3601",
            "unknown = 1",
        ] {
            assert!(target(bad).is_err(), "{bad}");
        }
        for prefix in [
            "",
            "/",
            "a//b",
            "A",
            "a/..",
            "a b",
            "../x",
            "apt",
            "packages/apt",
            "x/plans",
            "keys",
            "setup",
            "packages/setup",
        ] {
            let t = toml::from_str::<Target>(&format!(
                "endpoint = \"https://x\"\nbucket = \"b\"\nregion = \"auto\"\nprefix = \"{prefix}\""
            ))
            .unwrap();
            assert!(t.check().is_err(), "{prefix:?}");
        }
    }

    #[test]
    fn stored_digests_prefer_the_metadata_and_decode_the_checksum() {
        use base64::Engine as _;
        let digest = [7_u8; 32];
        let detail = |metadata: Option<&str>, sha256: Option<String>| ObjectDetail {
            size: 1,
            etag: None,
            last_modified: None,
            content_type: None,
            cache_control: None,
            sha256,
            metadata: metadata
                .map(|m| [(SHA256_METADATA.to_owned(), m.to_owned())].into())
                .unwrap_or_default(),
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        assert_eq!(
            stored_sha256(&detail(Some(&hex::encode(digest)), None)),
            Some(digest.to_vec())
        );
        assert_eq!(
            stored_sha256(&detail(None, Some(b64.clone()))),
            Some(digest.to_vec())
        );
        assert_eq!(
            stored_sha256(&detail(Some(&hex::encode([1_u8; 32])), Some(b64))),
            Some(vec![1_u8; 32]),
            "the metadata first"
        );
        assert_eq!(stored_sha256(&detail(Some("zz"), None)), None);
        assert_eq!(
            stored_sha256(&detail(Some("00ff"), None)),
            None,
            "not 32 bytes"
        );
        assert_eq!(stored_sha256(&detail(None, None)), None);
    }
}
