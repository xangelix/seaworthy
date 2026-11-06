//! What the update helper is doing, for the app to show (the helper's
//! STATUS FILE).
//!
//! The helper runs as root (LocalSystem) on its own; an app that asked it
//! for an update, or a GUI watching the app's service, wants to say
//! "installing 2.4.0" rather than nothing. At each stage the helper writes
//! one small record ([`UpdateStatus`]) into its staging directory
//! ([`UPDATE_STATUS_FILE`]); the app (root or LocalSystem too: the
//! directory is private) reads the latest ([`read_status`]).
//!
//! **The format** (`seaworthy-update-status:1`) is five lines of text, one
//! `key value` each after the tag; the reader refuses anything else and
//! bounds what it reads ([`MAX_STATUS_BYTES`]). It carries no secret: a
//! stage, a version, a time and a sanitized line of detail.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The record's file name in the helper's staging directory.
pub const UPDATE_STATUS_FILE: &str = "update-status";

/// The format's tag (its first line).
pub const UPDATE_STATUS_TAG: &str = "seaworthy-update-status:1";

/// The largest record the reader accepts.
pub const MAX_STATUS_BYTES: usize = 2048;

/// The longest detail line, in bytes.
pub const MAX_DETAIL_BYTES: usize = 512;

/// Where an update run stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpdateStage {
    /// The run started: the policy, the installed release, the server's.
    Checking,
    /// Downloading the release.
    Downloading,
    /// Checking the download's digest, format and signature.
    Verifying,
    /// The OS installer runs.
    Installing,
    /// Installed and confirmed.
    Installed,
    /// Handed to an installer that finishes after the helper (msiexec).
    HandedOff,
    /// The server's release is the installed one.
    UpToDate,
    /// The machine's update policy isn't `auto`: nothing was done.
    PolicyNotAuto,
    /// The run installed nothing (the detail says why).
    Failed,
}

impl UpdateStage {
    /// Every stage.
    pub const ALL: [Self; 9] = [
        Self::Checking,
        Self::Downloading,
        Self::Verifying,
        Self::Installing,
        Self::Installed,
        Self::HandedOff,
        Self::UpToDate,
        Self::PolicyNotAuto,
        Self::Failed,
    ];

    /// The stage's spelling in the record.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::Downloading => "downloading",
            Self::Verifying => "verifying",
            Self::Installing => "installing",
            Self::Installed => "installed",
            Self::HandedOff => "handed-off",
            Self::UpToDate => "up-to-date",
            Self::PolicyNotAuto => "policy-not-auto",
            Self::Failed => "failed",
        }
    }

    /// The stage spelled `text`, if any.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|stage| stage.as_str() == text)
    }

    /// Whether a run is under way at this stage (not a final word).
    #[must_use]
    pub const fn in_progress(self) -> bool {
        matches!(
            self,
            Self::Checking | Self::Downloading | Self::Verifying | Self::Installing
        )
    }
}

/// One record of the helper's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateStatus {
    /// Where the run stands.
    pub stage: UpdateStage,
    /// The release it works on, when known.
    pub version: Option<String>,
    /// When it said so.
    pub at: SystemTime,
    /// A line of detail (an error's words): no control characters, at most
    /// [`MAX_DETAIL_BYTES`].
    pub detail: String,
}

/// Why a record was refused.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// It couldn't be read.
    #[error("reading the update status: {0}")]
    Io(#[from] std::io::Error),
    /// It isn't a record of this format.
    #[error("not an update status record: {0}")]
    Malformed(&'static str),
}

impl UpdateStatus {
    /// A record of `stage` now.
    #[must_use]
    pub fn now(stage: UpdateStage, version: Option<&str>, detail: &str) -> Self {
        Self {
            stage,
            version: version.and_then(clean_version),
            at: SystemTime::now(),
            detail: clean_detail(detail),
        }
    }

    /// The record's text.
    #[must_use]
    pub fn encode(&self) -> String {
        let millis = self
            .at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis());
        format!(
            "{UPDATE_STATUS_TAG}\nstage {}\nversion {}\nat {millis}\ndetail {}\n",
            self.stage.as_str(),
            self.version.as_deref().unwrap_or("-"),
            clean_detail(&self.detail)
        )
    }

    /// A record from its text.
    ///
    /// # Errors
    /// [`StatusError::Malformed`]: too large, another tag, a missing,
    /// repeated or unknown line, a bad value.
    pub fn parse(text: &str) -> Result<Self, StatusError> {
        if text.len() > MAX_STATUS_BYTES {
            return Err(StatusError::Malformed("too large"));
        }
        let mut lines = text.lines();
        if lines.next() != Some(UPDATE_STATUS_TAG) {
            return Err(StatusError::Malformed("another format"));
        }
        let (mut stage, mut version, mut at, mut detail) = (None, None, None, None);
        for line in lines {
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            let slot_taken = match key {
                "stage" => stage
                    .replace(UpdateStage::parse(value).ok_or(StatusError::Malformed("a stage"))?)
                    .is_some(),
                "version" => version
                    .replace(if value == "-" {
                        None
                    } else {
                        Some(clean_version(value).ok_or(StatusError::Malformed("a version"))?)
                    })
                    .is_some(),
                "at" => at
                    .replace(
                        value
                            .parse::<u64>()
                            .map_err(|_| StatusError::Malformed("a time"))?,
                    )
                    .is_some(),
                "detail" => detail.replace(clean_detail(value)).is_some(),
                _ => return Err(StatusError::Malformed("an unknown line")),
            };
            if slot_taken {
                return Err(StatusError::Malformed("a repeated line"));
            }
        }
        Ok(Self {
            stage: stage.ok_or(StatusError::Malformed("no stage"))?,
            version: version.ok_or(StatusError::Malformed("no version"))?,
            at: UNIX_EPOCH
                .checked_add(Duration::from_millis(
                    at.ok_or(StatusError::Malformed("no time"))?,
                ))
                .ok_or(StatusError::Malformed("a time"))?,
            detail: detail.ok_or(StatusError::Malformed("no detail"))?,
        })
    }
}

/// A version as the record carries it: one token, validated (never `-`,
/// which the record spells for "none").
fn clean_version(version: &str) -> Option<String> {
    (version != "-" && seaworthy_formats::validate_version(version).is_ok())
        .then(|| version.to_owned())
}

/// A detail line: control characters dropped (a hostile value can't forge
/// a line), cut to [`MAX_DETAIL_BYTES`] on a character boundary.
fn clean_detail(detail: &str) -> String {
    let mut out = String::new();
    for c in crate::log::line_safe(detail).chars() {
        if out.len().saturating_add(c.len_utf8()) > MAX_DETAIL_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// Write `status` into `dir` (the helper's staging directory): a temporary
/// file beside it, renamed over the record, so a reader never sees half of
/// one.
///
/// # Errors
/// The I/O error.
pub fn write_status(dir: &Path, status: &UpdateStatus) -> std::io::Result<()> {
    use std::io::Write as _;
    let path = dir.join(UPDATE_STATUS_FILE);
    let temp = dir.join(format!(".{UPDATE_STATUS_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options.open(&temp).and_then(|mut file| {
        file.write_all(status.encode().as_bytes())?;
        file.sync_all()
    });
    match written.and_then(|()| std::fs::rename(&temp, &path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(error)
        }
    }
}

/// The latest record in `dir` (the helper's staging directory); `None`
/// when the helper never wrote one.
///
/// # Errors
/// [`StatusError`]: unreadable, a link, or malformed.
pub fn read_status(dir: &Path) -> Result<Option<UpdateStatus>, StatusError> {
    use std::io::Read as _;
    let path = dir.join(UPDATE_STATUS_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) if !metadata.is_file() => {
            return Err(StatusError::Malformed("not a regular file"));
        }
        Ok(_) => {}
    }
    let mut text = String::new();
    std::fs::File::open(&path)?
        .take(
            u64::try_from(MAX_STATUS_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_string(&mut text)
        .map_err(|_| StatusError::Malformed("not text"))?;
    UpdateStatus::parse(&text).map(Some)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A record round-trips; its detail can't forge a line; the reader
    /// refuses other formats, unknown or repeated lines and oversized text.
    #[test]
    fn a_record_round_trips_and_the_reader_refuses_anything_else() {
        for stage in UpdateStage::ALL {
            assert_eq!(UpdateStage::parse(stage.as_str()), Some(stage));
        }
        let status = UpdateStatus::now(
            UpdateStage::Installing,
            Some("2.4.0"),
            "msiexec started\nstage installed",
        );
        assert_eq!(status.detail, "msiexec startedstage installed");
        let parsed = UpdateStatus::parse(&status.encode()).unwrap();
        assert_eq!(parsed.stage, UpdateStage::Installing);
        assert_eq!(parsed.version.as_deref(), Some("2.4.0"));
        assert_eq!(parsed.detail, status.detail);
        assert!(parsed.stage.in_progress());
        let unknown = UpdateStatus::now(UpdateStage::Failed, None, "");
        assert_eq!(
            UpdateStatus::parse(&unknown.encode()).unwrap().version,
            None
        );

        for bad in [
            String::new(),
            "seaworthy-update-status:2\n".to_owned(),
            format!("{UPDATE_STATUS_TAG}\nstage installed\n"),
            format!(
                "{UPDATE_STATUS_TAG}\nstage installed\nstage failed\nversion -\nat 1\ndetail\n"
            ),
            format!("{UPDATE_STATUS_TAG}\nstage exploded\nversion -\nat 1\ndetail\n"),
            format!("{UPDATE_STATUS_TAG}\nstage installed\nversion -\nat x\ndetail\n"),
            format!("{UPDATE_STATUS_TAG}\nstage installed\nversion -\nat 1\ndetail\nowner root\n"),
            format!("{UPDATE_STATUS_TAG}\n{}", "x".repeat(MAX_STATUS_BYTES)),
        ] {
            assert!(UpdateStatus::parse(&bad).is_err(), "{bad:?}");
        }
    }

    /// The helper writes, the app reads; nothing yet reads as none; a link
    /// in the record's place is refused.
    #[test]
    fn the_helper_writes_and_the_app_reads() {
        let dir = std::env::temp_dir().join(format!("seaworthy-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_status(&dir).unwrap().is_none());
        let status = UpdateStatus::now(UpdateStage::Downloading, Some("2.4.0"), "");
        write_status(&dir, &status).unwrap();
        let read = read_status(&dir).unwrap().unwrap();
        assert_eq!(read.stage, UpdateStage::Downloading);
        write_status(
            &dir,
            &UpdateStatus::now(UpdateStage::Installed, Some("2.4.0"), ""),
        )
        .unwrap();
        assert_eq!(
            read_status(&dir).unwrap().unwrap().stage,
            UpdateStage::Installed
        );
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.join(UPDATE_STATUS_FILE)).unwrap();
            std::os::unix::fs::symlink("/etc/hostname", dir.join(UPDATE_STATUS_FILE)).unwrap();
            assert!(read_status(&dir).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
