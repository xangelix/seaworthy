//! Where a service's daily log is now: the newest of its rotated files.
//!
//! A daily rotating log (`<prefix>.2026-11-06.log`, the next day's file
//! from midnight UTC) leaves a reader that opened yesterday's file reading
//! a file nothing writes any more. [`current_log_file`] names the file in
//! use: a reader asks again from time to time and reopens when the answer
//! changes. The directory is the product's
//! (`seaworthy_formats::Product::service_log_directory`).

use std::path::{Path, PathBuf};

/// The newest regular file in `dir` whose name starts with `prefix`: by
/// modification time, then by name (a rotated name sorts by its date).
/// Links are never followed or returned. `None` when there is none.
///
/// # Errors
/// `dir` can't be listed.
pub fn current_log_file(dir: &Path, prefix: &str) -> std::io::Result<Option<PathBuf>> {
    let mut newest: Option<(std::time::SystemTime, String, PathBuf)> = None;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_file() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|metadata| metadata.modified()) else {
            continue;
        };
        let candidate = (modified, name, entry.path());
        let newer = newest
            .as_ref()
            .is_none_or(|(at, held, _)| (candidate.0, candidate.1.as_str()) > (*at, held.as_str()));
        if newer {
            newest = Some(candidate);
        }
    }
    Ok(newest.map(|(_, _, path)| path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::{Duration, SystemTime};

    use super::*;

    /// The newest of the rotated files, by time then name; other files,
    /// directories and links are ignored.
    #[test]
    fn the_newest_rotated_file_is_the_current_one() {
        let dir = std::env::temp_dir().join(format!("seaworthy-logs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(current_log_file(&dir, "acme").unwrap(), None);
        let older = dir.join("acme-agent.2026-11-05.log");
        let newer = dir.join("acme-agent.2026-11-06.log");
        std::fs::write(&older, b"a").unwrap();
        std::fs::write(&newer, b"b").unwrap();
        std::fs::write(dir.join("other.2026-11-07.log"), b"c").unwrap();
        std::fs::create_dir(dir.join("acme-agent.zz")).unwrap();
        let day = Duration::from_secs(86_400);
        let now = SystemTime::now();
        std::fs::File::options()
            .write(true)
            .open(&older)
            .unwrap()
            .set_modified(now - day)
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&newer)
            .unwrap()
            .set_modified(now)
            .unwrap();
        assert_eq!(
            current_log_file(&dir, "acme-agent").unwrap(),
            Some(newer.clone())
        );
        // Same time: the later name (date) wins.
        std::fs::File::options()
            .write(true)
            .open(&older)
            .unwrap()
            .set_modified(now)
            .unwrap();
        assert_eq!(current_log_file(&dir, "acme-agent").unwrap(), Some(newer));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&older, dir.join("acme-agent.9999-01-01.log")).unwrap();
            assert_ne!(
                current_log_file(&dir, "acme-agent").unwrap(),
                Some(dir.join("acme-agent.9999-01-01.log")),
                "never a link"
            );
        }
        assert!(current_log_file(&dir.join("missing"), "acme").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
