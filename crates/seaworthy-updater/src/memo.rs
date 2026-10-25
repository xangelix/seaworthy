//! The update helper's persisted per-version failure memo.
//!
//! Without it, a failing release repeats on every request: a CDN serving
//! stale bytes, a release signed with the wrong key, a truncated upload,
//! each request another full transfer, and across a fleet one mis-published
//! file becomes sustained origin egress. The memo remembers the most
//! recently attempted version and when it may next be tried; a run inside
//! that window ends with `HelperError::Backoff` WITHOUT fetching anything.
//! The helper records each attempt before it fetches anything
//! ([`FailureMemo::record_attempt`]), so a run that dies midway backs off
//! too, and only a confirmed install clears it.
//!
//! - **Backoff:** jittered exponential, 1 min doubling to a 6 h ceiling
//!   (each delay drawn from the top quarter of its step, floored at 1 min:
//!   the fleet does not retry in lockstep).
//! - **Per version:** only the recorded version is paced; a DIFFERENT
//!   version is never blocked (it replaces the record when attempted in
//!   turn: the memo holds one record, bounded by construction).
//! - **Persisted:** a small text file written atomically (0600 staged file
//!   → fsync → rename → directory fsync), so restarts don't reset the
//!   pacing. When the file cannot be written (a read-only directory) the
//!   record is kept in memory for the process's life, loudly.
//! - **Availability over tidiness:** an unreadable or corrupt memo reads as
//!   "no memo" with a warning: the memo is a pacing aid, never a security
//!   control, and must never park a fleet. A remaining delay beyond the
//!   ceiling (a clock stepped backwards) is clamped to the ceiling.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The first backoff step.
pub(crate) const MIN_BACKOFF: Duration = Duration::from_secs(60);
/// The backoff ceiling.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(6 * 60 * 60);
/// The memo file's format header.
const MEMO_HEADER: &str = "seaworthy-update-memo:1";
/// Read cap: a real memo is well under 200 bytes.
const MAX_MEMO_BYTES: u64 = 4096;

/// One failed version and when it may be retried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MemoRecord {
    pub(crate) version: String,
    pub(crate) attempts: u32,
    /// Unix epoch milliseconds (wall clock: the record survives restarts).
    pub(crate) next_allowed_ms: u64,
}

impl MemoRecord {
    fn encode(&self) -> String {
        format!(
            "{MEMO_HEADER}\nversion={}\nattempts={}\nnext_allowed_unix_ms={}\n",
            self.version, self.attempts, self.next_allowed_ms
        )
    }

    fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != MEMO_HEADER {
            return None;
        }
        let version = lines.next()?.strip_prefix("version=")?.to_string();
        seaworthy_formats::validate_version(&version).ok()?;
        let attempts = lines.next()?.strip_prefix("attempts=")?.parse().ok()?;
        let next_allowed_ms = lines
            .next()?
            .strip_prefix("next_allowed_unix_ms=")?
            .parse()
            .ok()?;
        if lines.next().is_some() {
            return None;
        }
        Some(Self {
            version,
            attempts,
            next_allowed_ms,
        })
    }
}

/// The jittered delay after the `attempts`-th consecutive failure:
/// `c = min(1 min × 2^(attempts−1), 6 h)`, drawn uniformly from
/// `[¾·c, c]` by `jitter` (a uniform `u64`), floored at 1 min.
pub(crate) fn backoff_delay(attempts: u32, jitter: u64) -> Duration {
    let exponent = attempts.saturating_sub(1).min(20);
    let step = MIN_BACKOFF
        .saturating_mul(1u32 << exponent)
        .min(MAX_BACKOFF);
    let step_ms = step.as_millis() as u64;
    let spread = step_ms / 4;
    let delay_ms = step_ms - spread
        + if spread == 0 {
            0
        } else {
            jitter % (spread + 1)
        };
    Duration::from_millis(delay_ms).max(MIN_BACKOFF)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // A CSPRNG failure degrades to no jitter, never a failed update.
    let _ = seaworthy_crypto::rand::fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

/// In-memory fallback for memos whose file could not be written, keyed by
/// memo path. `persisted == false` entries win over the (stale or absent)
/// file.
fn unpersisted() -> &'static Mutex<HashMap<PathBuf, MemoRecord>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<PathBuf, MemoRecord>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The memo at one path.
#[derive(Clone, Debug)]
pub(crate) struct FailureMemo {
    path: PathBuf,
}

impl FailureMemo {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Option<MemoRecord> {
        if let Some(record) = unpersisted()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&self.path)
        {
            return Some(record.clone());
        }
        match read_memo_file(&self.path) {
            Ok(Some(text)) => {
                let record = MemoRecord::decode(&text);
                if record.is_none() {
                    tracing::warn!(
                        path = %self.path.display(),
                        "ignoring a malformed update failure memo"
                    );
                }
                record
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "cannot read the update failure memo; treating it as absent"
                );
                None
            }
        }
    }

    /// `Some(retry_after)` when `version` must not be tried yet.
    pub(crate) fn backoff_for(&self, version: &str) -> Option<Duration> {
        self.backoff_for_at(version, now_ms())
    }

    fn backoff_for_at(&self, version: &str, now: u64) -> Option<Duration> {
        let record = self.load()?;
        if record.version != version || now >= record.next_allowed_ms {
            return None;
        }
        Some(Duration::from_millis(record.next_allowed_ms - now).min(MAX_BACKOFF))
    }

    /// Record an attempt at `version` before making it: a run that dies
    /// midway still backs off, and only a confirmed success
    /// [`clear`](Self::clear)s it. Answers the new record.
    pub(crate) fn record_attempt(&self, version: &str) -> MemoRecord {
        let record = self.record_at(version, now_ms(), random_u64());
        tracing::debug!(
            version = %crate::log::line_safe(version),
            attempts = record.attempts,
            "update attempt recorded; another waits for its backoff unless this one succeeds"
        );
        record
    }

    fn record_at(&self, version: &str, now: u64, jitter: u64) -> MemoRecord {
        let attempts = match self.load() {
            Some(previous) if previous.version == version => previous.attempts.saturating_add(1),
            _ => 1,
        };
        let delay = backoff_delay(attempts, jitter);
        let record = MemoRecord {
            version: version.to_string(),
            attempts,
            next_allowed_ms: now.saturating_add(delay.as_millis() as u64),
        };
        let mut cache = unpersisted()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match write_memo_file(&self.path, &record.encode()) {
            Ok(()) => {
                cache.remove(&self.path);
            }
            Err(error) => {
                tracing::warn!(
                    path = %self.path.display(),
                    %error,
                    "cannot persist the update failure memo; pacing retries in memory for \
                     this process only"
                );
                cache.insert(self.path.clone(), record.clone());
            }
        }
        record
    }

    /// Forget every recorded failure (a successful update).
    pub(crate) fn clear(&self) {
        unpersisted()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.path);
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "cannot remove the update failure memo after a successful update"
            ),
        }
    }
}

/// Read the memo file without following a symlink at its final component,
/// bounded. `Ok(None)` when it does not exist.
fn read_memo_file(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("the memo path is not a regular file"));
    }
    let mut text = String::new();
    file.take(MAX_MEMO_BYTES).read_to_string(&mut text)?;
    Ok(Some(text))
}

/// Write the memo atomically: a 0600 staged file beside it (created
/// exclusively — never through a planted symlink), fsync, rename, then a
/// best-effort directory fsync.
fn write_memo_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("the memo path has no file name"))?;
    let mut staged = crate::staging::StagedFile::create(dir, file_name, "memo")?;
    staged.file_mut()?.write_all(contents.as_bytes())?;
    staged.file_mut()?.sync_all()?;
    staged.persist_over(path)?;
    if let Err(error) = crate::staging::sync_dir(dir) {
        tracing::debug!(%error, "memo directory fsync failed (the memo is a pacing aid)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_at_one_minute_and_caps_at_six_hours() {
        for jitter in [0, 1, u64::MAX / 3, u64::MAX] {
            assert_eq!(backoff_delay(1, jitter), MIN_BACKOFF);
            let second = backoff_delay(2, jitter);
            assert!(second >= Duration::from_secs(90) && second <= Duration::from_secs(120));
            let ceiling = backoff_delay(40, jitter);
            assert!(
                ceiling <= MAX_BACKOFF && ceiling >= MAX_BACKOFF * 3 / 4,
                "{ceiling:?}"
            );
        }
        // Monotone envelope: the step doubles until the ceiling.
        assert!(backoff_delay(5, 0) > backoff_delay(4, u64::MAX));
    }

    #[test]
    fn memo_paces_only_the_failed_version_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let memo = FailureMemo::new(dir.path().join(".app.memo"));
        assert_eq!(memo.backoff_for_at("2.0.0", 1_000), None);

        let record = memo.record_at("2.0.0", 1_000, 0);
        assert_eq!(record.attempts, 1);
        assert_eq!(record.next_allowed_ms, 61_000);
        assert_eq!(
            memo.backoff_for_at("2.0.0", 1_000),
            Some(Duration::from_secs(60))
        );
        // A different version is never blocked.
        assert_eq!(memo.backoff_for_at("2.0.1", 1_000), None);
        // The window passes.
        assert_eq!(memo.backoff_for_at("2.0.0", 61_000), None);

        // A second failure of the same version doubles the step.
        let record = memo.record_at("2.0.0", 61_000, 0);
        assert_eq!(record.attempts, 2);
        // A different version's failure replaces the record.
        let record = memo.record_at("3.0.0", 61_000, 0);
        assert_eq!(record.attempts, 1);
        assert_eq!(memo.backoff_for_at("2.0.0", 61_001), None);

        memo.clear();
        assert_eq!(memo.backoff_for_at("3.0.0", 61_001), None);
        assert!(!dir.path().join(".app.memo").exists());
    }

    #[test]
    fn memo_persists_across_instances_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".app.memo");
        FailureMemo::new(path.clone()).record_at("2.0.0", 5, 0);
        // A fresh instance (a restarted process) reads it back.
        assert!(
            FailureMemo::new(path.clone())
                .backoff_for_at("2.0.0", 6)
                .is_some()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Only the memo remains (the staged file was renamed over it).
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_memo_reads_as_absent_and_clock_rewind_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".app.memo");
        std::fs::write(&path, "garbage").unwrap();
        let memo = FailureMemo::new(path.clone());
        assert_eq!(memo.backoff_for_at("2.0.0", 0), None);
        // A record far in the future (the clock stepped back) is clamped.
        std::fs::write(
            &path,
            MemoRecord {
                version: "2.0.0".into(),
                attempts: 3,
                next_allowed_ms: u64::MAX,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(memo.backoff_for_at("2.0.0", 0), Some(MAX_BACKOFF));
        // An unsafe version in a planted memo is ignored.
        std::fs::write(
            &path,
            "seaworthy-update-memo:1\nversion=../x\nattempts=1\nnext_allowed_unix_ms=99999999999999\n",
        )
        .unwrap();
        assert_eq!(memo.backoff_for_at("../x", 0), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_memo_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "precious").unwrap();
        let path = dir.path().join(".app.memo");
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        let memo = FailureMemo::new(path.clone());
        assert_eq!(memo.backoff_for_at("2.0.0", 0), None);
        memo.record_at("2.0.0", 0, 0);
        // The rename replaced the symlink itself; the victim is untouched.
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn an_unwritable_memo_paces_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        // A path whose parent does not exist cannot be written.
        let memo = FailureMemo::new(dir.path().join("missing-dir").join(".app.memo"));
        memo.record_at("2.0.0", 0, 0);
        assert!(memo.backoff_for_at("2.0.0", 1).is_some());
        memo.clear();
        assert_eq!(memo.backoff_for_at("2.0.0", 1), None);
    }
}
