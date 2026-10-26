//! The Windows audits: one object, a tree below a directory, and a
//! directory with everything below it, each object opened without
//! following a reparse point and judged by [`crate::acl::untrusted`] under
//! the caller's [`WriterPolicy`]; and the primitives they are built from,
//! for a caller's own walk (the reads, making a folder with its
//! descriptor, taking one back, propagating a descriptor).

#![forbid(unsafe_code)]

use std::os::windows::io::AsHandle as _;
use std::path::Path;

use crate::acl::{WriterPolicy, untrusted};
pub use crate::ffi::windows::{
    Access, Attributes, Entry, FileAccess, KnownFolder, ObjectSecurity, SecurityDescriptor,
    attributes, create_directory, descriptor_security, enable_privileges, final_path, is_protected,
    known_folder, link_count, list, named_security, open, open_file, process_elevated,
    process_user, propagate, security, take_back,
};
use crate::{Error, MAX_DEPTH, MAX_ENTRIES};

/// One object at `path`, opened without following a reparse point: refused
/// when it is one, or when `policy` doesn't trust its owner or DACL; its
/// attributes otherwise.
///
/// # Errors
/// Why it is refused, or why it can't be read.
pub fn audit_object(path: &Path, policy: &WriterPolicy<'_>) -> Result<Attributes, Error> {
    let handle = open(path, Access::ReadSecurity, false)?;
    let attributes = attributes(handle.as_handle(), path)?;
    if attributes.is_reparse_point() {
        return Err(Error::new(format!(
            "{} is a reparse point (a junction or a link)",
            path.display()
        )));
    }
    let what = path.display().to_string();
    let object = security(handle.as_handle(), &what)?;
    if let Some(why) = untrusted(
        &what,
        object.owner.as_deref(),
        object.dacl.as_deref(),
        policy,
    ) {
        return Err(Error::new(why));
    }
    Ok(attributes)
}

/// Everything below `dir` (`depth` levels below where the caller's audit
/// started, from 1): each entry counted in `visited` (more than
/// [`MAX_ENTRIES`] in all is refused), refused when listed as a reparse
/// point, audited with [`audit_object`], and descended into when a
/// directory (deeper than [`MAX_DEPTH`] is refused).
///
/// # Errors
/// The first object refused and why.
pub fn audit_tree(
    dir: &Path,
    policy: &WriterPolicy<'_>,
    depth: usize,
    visited: &mut usize,
) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::new(format!(
            "{} is nested deeper than {MAX_DEPTH} levels",
            dir.display()
        )));
    }
    for entry in list(dir)? {
        *visited = visited.saturating_add(1);
        if *visited > MAX_ENTRIES {
            return Err(Error::new(format!(
                "more than {MAX_ENTRIES} objects to audit"
            )));
        }
        let path = dir.join(entry.name());
        if entry.attributes().is_reparse_point() {
            return Err(Error::new(format!(
                "{} is a reparse point (a junction or a link)",
                path.display()
            )));
        }
        if audit_object(&path, policy)?.is_directory() {
            audit_tree(&path, policy, depth.saturating_add(1), visited)?;
        }
    }
    Ok(())
}

/// What `path`'s final path must be: under `%ProgramData%`, that folder's
/// own final path (its administrator may have redirected it) and the rest;
/// elsewhere, `\\?\` and the path.
fn wanted_final(path: &Path) -> Result<String, Error> {
    let program_data = known_folder(KnownFolder::ProgramData)?;
    let text = path.display().to_string().replace('/', "\\");
    let root = program_data.display().to_string();
    let below = text
        .get(..root.len())
        .filter(|head| head.eq_ignore_ascii_case(&root))
        .and_then(|_| text.get(root.len()..))
        .filter(|rest| rest.starts_with('\\'));
    match below {
        Some(rest) => {
            let handle = open(&program_data, Access::ReadSecurity, true)?;
            let root_final = final_path(handle.as_handle(), &program_data)?;
            Ok(format!("{}{rest}", root_final.trim_end_matches('\\')))
        }
        None => Ok(format!("\\\\?\\{}", text.trim_end_matches('\\'))),
    }
}

/// The directory at `path` and everything below it: `path` must be
/// absolute; the directory, opened without following a reparse point, must
/// be no reparse point and a directory whose final path is the one asked
/// for (so no folder above it is a junction or a link either;
/// `%ProgramData%` itself may be redirected by its administrator); it and
/// everything below it ([`audit_tree`], bounded) must pass `policy`.
///
/// # Errors
/// The first object refused and why.
pub fn audit_directory(path: &Path, policy: &WriterPolicy<'_>) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::new(format!("{} is not absolute", path.display())));
    }
    let handle = open(path, Access::ReadSecurity, false)?;
    let attributes = attributes(handle.as_handle(), path)?;
    if attributes.is_reparse_point() {
        return Err(Error::new(format!(
            "{} is a reparse point (a junction or a link)",
            path.display()
        )));
    }
    if !attributes.is_directory() {
        return Err(Error::new(format!("{} is not a directory", path.display())));
    }
    let found = final_path(handle.as_handle(), path)?;
    let wanted = wanted_final(path)?;
    if !found.eq_ignore_ascii_case(&wanted) {
        return Err(Error::new(format!(
            "{} leads to {found}: a folder on its way is a junction or a link",
            path.display()
        )));
    }
    let what = path.display().to_string();
    let object = security(handle.as_handle(), &what)?;
    if let Some(why) = untrusted(
        &what,
        object.owner.as_deref(),
        object.dacl.as_deref(),
        policy,
    ) {
        return Err(Error::new(why));
    }
    drop(handle);
    let mut visited = 0usize;
    audit_tree(path, policy, 1, &mut visited)
}
