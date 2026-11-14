//! First-paint probation's files on Linux (and other Unix systems): the
//! notice and the drop box in the probation directory,
//! `/var/lib/<vendor>/<id>`.
//!
//! The helper (root) makes the directory (0755) and the drop box (01733),
//! and writes the notice (0644) through a temporary file renamed over it.
//! The app writes each marker as a temporary `.<name>` it creates
//! exclusively (0600), then renames to `<uid>.<pid>.<16 hex>`. The helper
//! reads only names of that shape, opens each without following a link and
//! without blocking, and counts it only when it is a regular file with one
//! link, owned by the uid its name says, of at most
//! [`super::MAX_RECORD_BYTES`]; it removes every marker it reads, valid or
//! not, and a temporary file left for ten minutes.

use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
#[cfg(feature = "helper")]
use std::path::Path;

use super::{DROP_BOX, DROP_BOX_MODE, Locations, MAX_RECORD_BYTES, Marker, NOTICE_FILE, Notice};

/// The process's effective uid, which owns the files it creates.
fn euid() -> u32 {
    #[allow(unsafe_code, reason = "geteuid(2)")]
    // SAFETY: geteuid takes no arguments and can't fail.
    unsafe {
        libc::geteuid()
    }
}

/// Reads at most [`MAX_RECORD_BYTES`] of an open file.
fn read_small(file: std::fs::File) -> Option<String> {
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() <= MAX_RECORD_BYTES).then_some(text)
}

/// The notice, when the probation directory and the file are root's and no
/// one else may write them (up to `top`), and it parses.
pub(crate) fn read_notice(at: &Locations) -> Option<Notice> {
    let path = at.public.join(NOTICE_FILE);
    crate::policy::unix::trusted(&path, &at.top, at.require_root).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    Notice::parse(&read_small(file)?).ok()
}

/// Checks the drop box: a directory (no link), mode 01733, root's when
/// required, under a trusted probation directory.
fn check_drop_box(at: &Locations) -> Result<std::path::PathBuf, String> {
    crate::policy::unix::trusted(&at.public, &at.top, at.require_root)?;
    let dir = at.public.join(DROP_BOX);
    let metadata =
        std::fs::symlink_metadata(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if metadata.mode() & 0o7777 != DROP_BOX_MODE {
        return Err(format!(
            "{} has mode {:o}, not {DROP_BOX_MODE:o}",
            dir.display(),
            metadata.mode() & 0o7777
        ));
    }
    if at.require_root && metadata.uid() != 0 {
        return Err(format!("{} is not root's", dir.display()));
    }
    Ok(dir)
}

/// Leaves `marker` in the drop box (see the module docs).
pub(crate) fn write_marker(at: &Locations, marker: &Marker) -> Result<(), String> {
    use std::io::Write as _;
    let dir = check_drop_box(at)?;
    let name = format!("{}.{}.{}", euid(), std::process::id(), super::nonce());
    let temp = dir.join(format!(".{name}"));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .and_then(|mut file| file.write_all(marker.encode().as_bytes()))
        .and_then(|()| std::fs::rename(&temp, dir.join(&name)));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("{}: {e}", dir.display())
    })
}

/// A marker's name: `<uid>.<pid>.<16 hex>`, each number without a leading
/// zero; the uid it claims.
#[cfg(feature = "helper")]
pub(crate) fn marker_uid(name: &str) -> Option<u32> {
    let mut parts = name.split('.');
    let (uid, pid, nonce) = (parts.next()?, parts.next()?, parts.next()?);
    let number = |text: &str| {
        !text.is_empty()
            && text.len() <= 10
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|b| b.is_ascii_digit())
    };
    if parts.next().is_some()
        || !number(uid)
        || !number(pid)
        || nonce.len() != 16
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    uid.parse().ok()
}

/// How old a temporary marker may get before the helper removes it.
#[cfg(feature = "helper")]
const STALE_TEMPORARY: std::time::Duration = std::time::Duration::from_secs(600);

/// Reads, counts and removes the markers for `pending` (see the module
/// docs). No drop box, nothing found.
///
/// # Errors
/// The drop box or the probation directory isn't trusted, or can't be
/// listed.
#[cfg(feature = "helper")]
pub(crate) fn ingest(
    at: &Locations,
    pending: &crate::release::Release,
) -> Result<super::Ingested, String> {
    let mut found = super::Ingested::default();
    let dir = at.public.join(DROP_BOX);
    if !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir() || m.is_symlink()) {
        return Ok(found);
    }
    let dir = check_drop_box(at)?;
    let names: Vec<std::ffi::OsString> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .take(super::MAX_MARKER_ENTRIES.saturating_add(1))
        .filter_map(|entry| entry.ok().map(|e| e.file_name()))
        .collect();
    if names.len() > super::MAX_MARKER_ENTRIES {
        found.overflow = true;
        return Ok(found);
    }
    for name in names {
        let path = dir.join(&name);
        let Some(text) = name.to_str() else {
            remove(&path);
            continue;
        };
        if text.starts_with('.') {
            // The app's file before its rename: removed once stale.
            let stale = std::fs::symlink_metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= STALE_TEMPORARY);
            if stale {
                remove(&path);
            }
            continue;
        }
        if let Some(uid) = marker_uid(text)
            && let Some(marker) = read_marker(&path, uid)
            && &marker.release == pending
        {
            match marker.state {
                super::MarkerState::Launched => {
                    found.launches = found.launches.saturating_add(1);
                }
                super::MarkerState::Painted => found.painted = true,
            }
        }
        remove(&path);
    }
    Ok(found)
}

/// A marker file owned by `uid`: opened without following a link or
/// blocking (a FIFO), a regular file with one link and that owner, small,
/// and a marker.
#[cfg(feature = "helper")]
fn read_marker(path: &Path, uid: u32) -> Option<Marker> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != uid {
        return None;
    }
    if metadata.len() > MAX_RECORD_BYTES as u64 {
        return None;
    }
    Marker::parse(&read_small(file)?).ok()
}

#[cfg(feature = "helper")]
fn remove(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            "first-paint probation: couldn't remove {}: {e}",
            path.display()
        );
    }
}

/// Makes `dir` (mode `mode`) if it's missing; an existing one must be a
/// directory, not a link.
#[cfg(feature = "helper")]
fn make_directory(dir: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(format!("{} is not a directory", dir.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(mode)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            // Past the umask, and the sticky bit, which mkdir's mode may drop.
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
                .map_err(|e| format!("{}: {e}", dir.display()))
        }
        Err(e) => Err(format!("{}: {e}", dir.display())),
    }
}

/// The helper publishes a probation: the probation directory (and its
/// vendor directory) made root's 0755 when missing and checked trusted, the
/// drop box made 01733 and checked, then the notice written (0644, through
/// a temporary file renamed over it).
///
/// # Errors
/// A directory that can't be made, isn't trusted, or a notice that can't be
/// written.
#[cfg(feature = "helper")]
pub(crate) fn publish(at: &Locations, notice: &Notice) -> Result<(), String> {
    use std::io::Write as _;
    if let Some(vendor) = at.public.parent()
        && vendor != at.top
    {
        make_directory(vendor, 0o755)?;
    }
    make_directory(&at.public, 0o755)?;
    make_directory(&at.public.join(DROP_BOX), DROP_BOX_MODE)?;
    check_drop_box(at)?;
    let path = at.public.join(NOTICE_FILE);
    let temp = at
        .public
        .join(format!(".{NOTICE_FILE}.{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .and_then(|mut file| {
            use std::os::unix::fs::PermissionsExt as _;
            file.write_all(notice.encode().as_bytes())?;
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temp, &path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("{}: {e}", path.display())
    })?;
    crate::policy::unix::trusted(&path, &at.top, at.require_root)
}

/// The helper withdraws the notice (the drop box stays, empty).
#[cfg(feature = "helper")]
pub(crate) fn withdraw(at: &Locations) {
    remove(&at.public.join(NOTICE_FILE));
}
