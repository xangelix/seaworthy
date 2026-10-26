//! The Unix audit: a directory and everything below it (bounded), each
//! object judged by [`crate::mode::untrusted`].

#![forbid(unsafe_code)]

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

pub use crate::ffi::unix::effective_uid;
use crate::mode::{Owners, untrusted};
use crate::{Error, MAX_DEPTH, MAX_ENTRIES};

/// Audits the directory at `path` and everything below it: the path must be
/// absolute and its own canonical form (no symlink on the way); it must be a
/// directory; it and every object below it (at most [`MAX_ENTRIES`],
/// [`MAX_DEPTH`] levels deep: a larger tree fails too) must be no symlink,
/// owned as `owners` allows and not writable by group or others.
///
/// # Errors
/// The first object that fails and why; an object that can't be read
/// fails.
pub fn audit_directory(path: &Path, owners: Owners<'_>) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::new(format!("{} is not absolute", path.display())));
    }
    let real = std::fs::canonicalize(path)
        .map_err(|e| Error::new(format!("can't resolve {}: {e}", path.display())))?;
    if real != path {
        return Err(Error::new(format!(
            "{} is reached through a symlink (it is {})",
            path.display(),
            real.display()
        )));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| Error::new(format!("can't inspect {}: {e}", path.display())))?;
    if !metadata.is_dir() {
        return Err(Error::new(format!("{} is not a directory", path.display())));
    }
    let what = path.display().to_string();
    if let Some(why) = untrusted(&what, metadata.uid(), metadata.mode(), false, owners) {
        return Err(Error::new(why));
    }
    let mut visited = 0usize;
    walk(path, owners, 1, &mut visited)
}

fn walk(dir: &Path, owners: Owners<'_>, depth: usize, visited: &mut usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::new(format!(
            "{} is nested deeper than {MAX_DEPTH} levels",
            dir.display()
        )));
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::new(format!("can't list {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::new(format!("can't list {}: {e}", dir.display())))?;
        *visited = visited.saturating_add(1);
        if *visited > MAX_ENTRIES {
            return Err(Error::new(format!(
                "more than {MAX_ENTRIES} objects to audit"
            )));
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| Error::new(format!("can't inspect {}: {e}", path.display())))?;
        let what = path.display().to_string();
        if let Some(why) = untrusted(
            &what,
            metadata.uid(),
            metadata.mode(),
            metadata.file_type().is_symlink(),
            owners,
        ) {
            return Err(Error::new(why));
        }
        if metadata.is_dir() {
            walk(&path, owners, depth.saturating_add(1), visited)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn a_tree_is_audited_whole() {
        let scratch =
            std::env::temp_dir().join(format!("seaworthy-fsguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("tree/sub")).unwrap();
        let tree = std::fs::canonicalize(scratch.join("tree")).unwrap();
        for dir in [&tree, &tree.join("sub")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::write(tree.join("sub/file"), b"x").unwrap();
        std::fs::set_permissions(
            tree.join("sub/file"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let me = Owners::RootOr {
            uid: effective_uid(),
            named: "this user",
        };
        assert_eq!(audit_directory(&tree, me), Ok(()));
        // Owned by someone the policy doesn't name (unless the test runs
        // as root, which owns everything here).
        if effective_uid() != 0 {
            let err = audit_directory(&tree, Owners::Root).unwrap_err();
            assert!(err.message().contains("not root"), "{err}");
        }
        // A symlink on the way, a symlink inside, a group-writable file.
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&tree, &link).unwrap();
        let err = audit_directory(&link, me).unwrap_err();
        assert!(err.message().contains("through a symlink"), "{err}");
        std::os::unix::fs::symlink("/etc/passwd", tree.join("sub/planted")).unwrap();
        let err = audit_directory(&tree, me).unwrap_err();
        assert!(err.message().contains("is a symlink"), "{err}");
        std::fs::remove_file(tree.join("sub/planted")).unwrap();
        std::fs::set_permissions(
            tree.join("sub/file"),
            std::fs::Permissions::from_mode(0o660),
        )
        .unwrap();
        let err = audit_directory(&tree, me).unwrap_err();
        assert!(
            err.message().contains("writable by group or others"),
            "{err}"
        );
        // Not absolute, not a directory.
        assert!(audit_directory(Path::new("relative/tree"), me).is_err());
        let err = audit_directory(&tree.join("sub/file"), me).unwrap_err();
        assert!(err.message().contains("is not a directory"), "{err}");
        std::fs::remove_dir_all(&scratch).unwrap();
    }
}
