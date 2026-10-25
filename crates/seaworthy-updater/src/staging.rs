//! The helper's staging primitives: files created exclusively in a
//! directory (0600, never through a symlink, removed unless persisted), a
//! cross-process lock, and the streamed digest of a staged file.
//!
//! The update helper downloads into its root-only staging directory
//! through a [`StagedFile`], hashes that same open file, and renames it to
//! the name the installer needs; the failure memo writes through one too.
//! Runs of one product are serialized across processes by a
//! [`TargetLock`] in the same directory.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::{DigestAlgorithm, UpdateError};

/// Random lowercase suffix for staged names (CSPRNG: unique across
/// processes, so concurrent attempts never share a staged path).
fn random_suffix() -> std::io::Result<String> {
    let mut bytes = [0_u8; 24];
    seaworthy_crypto::rand::fill(&mut bytes).map_err(std::io::Error::other)?;
    Ok(bytes.iter().map(|b| char::from(b'a' + b % 26)).collect())
}

/// A file created exclusively in a directory, removed on drop unless
/// persisted. Unix: `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600. Windows:
/// `CREATE_NEW`, shared for read/delete only (so the rename works while the
/// handle is open, and nobody else can write it).
pub(crate) struct StagedFile {
    file: Option<File>,
    path: PathBuf,
    armed: bool,
}

impl StagedFile {
    /// Create `.{base}.{random}.seaworthy-{purpose}` in `dir`.
    pub(crate) fn create(dir: &Path, base: &OsStr, purpose: &str) -> std::io::Result<Self> {
        let mut name = OsString::from(".");
        name.push(base);
        name.push(format!(".{}.seaworthy-{purpose}", random_suffix()?));
        let path = dir.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
        }
        let file = options.open(&path)?;
        Ok(Self {
            file: Some(file),
            path,
            armed: true,
        })
    }

    /// The open handle; an `io::Error` (never a panic) once persisted.
    pub(crate) fn file_mut(&mut self) -> std::io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the staged file was already closed"))
    }

    /// Its path.
    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Close the handle and rename over `dest`; on failure the staged file
    /// is removed.
    pub(crate) fn persist_over(mut self, dest: &Path) -> std::io::Result<()> {
        self.file = None;
        std::fs::rename(&self.path, dest)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        self.file = None;
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// A held cross-process lock: an advisory `flock`/`LockFileEx` on a
/// lockfile, held for a whole helper run. The lockfile itself is left in
/// place (deleting a lockfile races its next opener); it is empty, 0600, and
/// opened without following a symlink.
pub(crate) struct TargetLock {
    _file: File,
}

impl TargetLock {
    /// Takes the lock at `path`.
    ///
    /// # Errors
    /// [`UpdateError::UpdateInProgress`] when another holder has it;
    /// [`UpdateError::Io`] otherwise (a symlink, a directory, an
    /// unwritable directory).
    pub(crate) fn try_acquire(path: &Path) -> Result<Self, UpdateError> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(UpdateError::Io(std::io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            ))));
        }
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(UpdateError::UpdateInProgress),
            Err(std::fs::TryLockError::Error(error)) => Err(UpdateError::Io(error)),
        }
    }
}

/// What the staged bytes must hash to.
#[derive(Clone, Debug)]
pub(crate) struct Expected {
    pub(crate) algorithm: DigestAlgorithm,
    /// Lowercase hex.
    pub(crate) hex: String,
}

/// Read buffer for the streamed hash: a staged package is never held whole
/// in memory.
const VERIFY_CHUNK_BYTES: usize = 1024 * 1024;

/// Hash the staged file THROUGH ITS OWN DESCRIPTOR (rewound), collecting
/// the header the format check reads from the same pass.
pub(crate) fn hash_staged(
    file: &mut File,
    algorithm: DigestAlgorithm,
) -> std::io::Result<(String, Vec<u8>)> {
    use std::io::{Read as _, Seek as _};
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut hasher = crate::DigestStream::new(algorithm);
    let mut header = Vec::with_capacity(crate::format_check::HEADER_BYTES);
    let mut chunk = vec![0_u8; VERIFY_CHUNK_BYTES];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        // `read` never exceeds the buffer (the `Read` contract); `get`
        // keeps a broken reader from turning into a panic.
        let read = chunk.get(..read).unwrap_or_default();
        let room = crate::format_check::HEADER_BYTES.saturating_sub(header.len());
        header.extend_from_slice(read.get(..room).unwrap_or(read));
        hasher.update(read);
    }
    Ok((hasher.finish_hex(), header))
}

/// fsync a directory so a rename inside it is durable.
#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// See the unix copy. A directory handle on Windows needs
/// `FILE_FLAG_BACKUP_SEMANTICS`, and FlushFileBuffers refuses read-only
/// handles, so it is opened for writing.
#[cfg(windows)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)?
        .sync_all()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn staged_with(dir: &Path, bytes: &[u8]) -> StagedFile {
        use std::io::Write as _;
        let mut staged = StagedFile::create(dir, OsStr::new("app"), "download").unwrap();
        staged.file_mut().unwrap().write_all(bytes).unwrap();
        staged
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".seaworthy-download"))
            .collect()
    }

    #[test]
    fn staged_files_are_exclusive_unique_and_removed_unless_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let first = staged_with(dir.path(), b"a");
        let second = staged_with(dir.path(), b"b");
        assert_ne!(first.path(), second.path());
        assert_eq!(first.path().parent(), Some(dir.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(first.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(first);
        let dest = dir.path().join("kept");
        second.persist_over(&dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"b");
        assert!(leftovers(dir.path()).is_empty());
    }

    #[test]
    fn the_staged_file_is_hashed_through_its_own_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let mut staged = staged_with(dir.path(), b"payload");
        let (hex, header) =
            hash_staged(staged.file_mut().unwrap(), DigestAlgorithm::Sha512).unwrap();
        assert_eq!(hex, DigestAlgorithm::Sha512.hash_hex(b"payload"));
        assert_eq!(header, b"payload");
    }

    /// The header is the first `HEADER_BYTES` however many read chunks the
    /// file spans, while the digest covers every byte.
    #[test]
    fn the_header_is_capped_across_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let bytes: Vec<u8> = (0..VERIFY_CHUNK_BYTES * 2 + 4321)
            .map(|i| (i % 251) as u8)
            .collect();
        let mut staged = staged_with(dir.path(), &bytes);
        let (hex, header) =
            hash_staged(staged.file_mut().unwrap(), DigestAlgorithm::Sha512).unwrap();
        assert_eq!(hex, DigestAlgorithm::Sha512.hash_hex(&bytes));
        assert_eq!(header, &bytes[..crate::format_check::HEADER_BYTES]);
    }

    /// The cross-process lock is exclusive (flock locks are per
    /// open file description, so a second open in THIS process contends
    /// exactly like another process would).
    #[test]
    fn the_target_lock_is_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(".lock");
        let held = TargetLock::try_acquire(&lock_path).unwrap();
        assert!(matches!(
            TargetLock::try_acquire(&lock_path),
            Err(UpdateError::UpdateInProgress)
        ));
        drop(held);
        TargetLock::try_acquire(&lock_path).unwrap();
        // A directory where the lockfile should be is refused.
        assert!(TargetLock::try_acquire(dir.path()).is_err());
    }

    /// Only a regular file locks: a FIFO (which opens read-write without
    /// blocking, and takes a lock) is refused.
    #[cfg(unix)]
    #[test]
    fn a_lockfile_that_is_not_a_regular_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".lock");
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let refused = TargetLock::try_acquire(&fifo);
        assert!(
            matches!(&refused, Err(UpdateError::Io(e)) if e.to_string().contains("not a regular file")),
            "{:?}",
            refused.err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_lockfile_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let lock_path = dir.path().join(".lock");
        std::os::unix::fs::symlink(&victim, &lock_path).unwrap();
        assert!(TargetLock::try_acquire(&lock_path).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious".as_slice());
    }
}
