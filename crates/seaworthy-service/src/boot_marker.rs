//! A boot marker: proof that a start died in a step that leaves nothing
//! else behind.
//!
//! Some failures end a process before it can say anything: a cryptographic
//! module's power-on self-test that aborts, a library that calls `abort()`
//! on missing entropy. A service [`arm`](BootMarker::arm)s the marker
//! before such a step and [`disarm`](ArmedBootMarker::disarm)s it after;
//! a marker still standing well after the start began
//! ([`BootMarker::stale_since`]) says the step never returned. A GUI or a
//! health check reads it while the service isn't running.
//!
//! The marker is an empty-ish file in a directory only the service may
//! write: its CONTENT is never parsed (a tag line for people reading the
//! directory), only its existence and modification time count. A failure
//! the service can report itself (an error, not an abort) is the service's
//! to record elsewhere; it disarms the marker either way.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The marker file's first line (for people; never parsed).
pub const TAG: &str = "seaworthy-boot-marker:1";

/// A boot marker at a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootMarker {
    path: PathBuf,
}

/// An armed marker: [`disarm`](Self::disarm) it once the guarded step
/// returned. Dropping it without disarming leaves the marker standing
/// (deliberately: an unwinding panic in the step is a failed start too).
#[derive(Debug)]
#[must_use = "disarm the marker once the guarded step returned"]
pub struct ArmedBootMarker {
    path: PathBuf,
}

impl BootMarker {
    /// The marker at `path` (in a directory only the service may write).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Where it is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Arm it: (re)write the file now, naming this process.
    ///
    /// # Errors
    /// The file couldn't be written (the step may still run; nothing will
    /// be known if it dies).
    pub fn arm(&self) -> std::io::Result<ArmedBootMarker> {
        // An earlier start's marker (or anything else in its place: a link
        // is removed, never followed) goes first; `create_new` then never
        // follows a link that appears meanwhile (O_CREAT | O_EXCL).
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&self.path)?;
        writeln!(file, "{TAG}\npid {}", std::process::id())?;
        file.sync_all()?;
        Ok(ArmedBootMarker {
            path: self.path.clone(),
        })
    }

    /// When the marker was armed, if it still stands and was armed at least
    /// `grace` before `now` (the guarded step takes less than that): the
    /// start died in the step. `None` when there is no marker, or it is
    /// younger than `grace` (a start may be in the step right now).
    ///
    /// # Errors
    /// The marker exists but can't be read.
    pub fn stale_since(
        &self,
        now: SystemTime,
        grace: Duration,
    ) -> std::io::Result<Option<SystemTime>> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Ok(None);
        }
        let armed = metadata.modified()?;
        let age = now.duration_since(armed).unwrap_or(Duration::ZERO);
        Ok((age >= grace).then_some(armed))
    }
}

impl ArmedBootMarker {
    /// The guarded step returned: remove the marker.
    ///
    /// # Errors
    /// The marker couldn't be removed (it stays, and reads as a failed
    /// start once stale).
    pub fn disarm(self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "seaworthy-boot-marker-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An armed marker reads as a failed start only once it is older than
    /// the grace; a disarmed one never does; a directory in its place
    /// isn't a marker.
    #[test]
    fn a_marker_left_standing_past_the_grace_means_the_start_died() {
        let dir = scratch("stale");
        let marker = BootMarker::new(dir.join("booting"));
        let now = SystemTime::now();
        assert_eq!(marker.stale_since(now, Duration::ZERO).unwrap(), None);
        let armed = marker.arm().unwrap();
        let text = std::fs::read_to_string(marker.path()).unwrap();
        assert!(text.starts_with(TAG), "{text}");
        assert_eq!(
            marker
                .stale_since(SystemTime::now(), Duration::from_secs(30))
                .unwrap(),
            None,
            "a start may be in the step"
        );
        let later = SystemTime::now() + Duration::from_secs(60);
        assert!(
            marker
                .stale_since(later, Duration::from_secs(30))
                .unwrap()
                .is_some()
        );
        armed.disarm().unwrap();
        assert_eq!(marker.stale_since(later, Duration::ZERO).unwrap(), None);
        // Re-arming after a died start replaces the old marker.
        let again = marker.arm().unwrap();
        again.disarm().unwrap();
        std::fs::create_dir(marker.path()).unwrap();
        assert_eq!(marker.stale_since(later, Duration::ZERO).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A link in the marker's place is never followed.
    #[cfg(unix)]
    #[test]
    fn arming_never_follows_a_link() {
        let dir = scratch("link");
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("booting")).unwrap();
        let armed = BootMarker::new(dir.join("booting")).arm().unwrap();
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"keep",
            "the target untouched"
        );
        assert!(
            std::fs::symlink_metadata(dir.join("booting"))
                .unwrap()
                .is_file(),
            "the link replaced by the marker"
        );
        armed.disarm().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
