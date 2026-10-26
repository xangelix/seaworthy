//! `seaworthy-fsguard`: the ownership and permission audits the seaworthy
//! crates run before they trust an administrator-owned folder or file.
//!
//! An installer, a service and a privileged update helper each depend on
//! folders that only administrators (and sometimes one service account)
//! may change: the update helper's staging directory and log, a service's
//! state directory, a product's `%ProgramData%` folders. Anything a less
//! privileged user could have created, written or redirected there must be
//! refused, not trusted. This crate holds that decision once:
//!
//! - [`acl`]: the Windows rule. An object's owner must be SYSTEM,
//!   Administrators, TrustedInstaller or one of the caller's accounts, and
//!   no ACE may grant anyone else a write right. Which rights count as a
//!   write and which accounts are trusted are the caller's
//!   [`acl::WriterPolicy`].
//! - [`mode`]: the Unix rule. No symlink, an owner the caller names, no
//!   group or world write.
//! - `windows` (Windows only): the audits, each object opened by handle
//!   without following a reparse point, so what is judged is what was
//!   opened; and the primitives a caller's own walk needs (attributes,
//!   final paths, security descriptors, folders created with a descriptor
//!   or taken back, descriptors propagated, known folders, the process
//!   token).
//! - `unix` (Unix only): a directory and everything below it.
//!
//! The rules are pure and tested on every platform; the audits fail closed
//! (an object that can't be read is refused) and are bounded
//! ([`MAX_ENTRIES`] objects, [`MAX_DEPTH`] levels).
//!
//! It is a support crate of the seaworthy family: its API follows what the
//! family's crates need and is versioned with them.

// The rules, the audits and the error forbid unsafe code (each module
// says so); the private `ffi` module alone allows it, per block, with its
// `// SAFETY:` invariant (the workspace denies unsafe code).
//
// The security baseline beyond the workspace lints: no panicking index or
// slice, no unchecked arithmetic and no `unreachable!` in library code (the
// FFI walks buffers the system filled; tests may index).
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

pub mod acl;
mod error;
mod ffi;
pub mod mode;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub use error::Error;

/// The most objects one audit visits below the directory it starts from.
pub const MAX_ENTRIES: usize = 100_000;
/// The deepest one audit descends below the directory it starts from.
pub const MAX_DEPTH: usize = 32;
