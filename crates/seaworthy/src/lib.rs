//! # seaworthy
//!
//! The seaworthy command-line tool: build plans for per-CPU cores,
//! verification, packaging, signing, SBOMs and publishing of releases.
//! **Under construction:** the crate currently carries only the pieces
//! ported so far, each behind its own feature:
//!
//! - `publish-s3` (off by default): the `s3` module, the S3 publish client. AWS
//!   Signature Version 4 over `seaworthy-crypto`, and the bounded
//!   management calls a publication needs: create-only checksummed puts,
//!   head, bounded get, list, delete.

#![forbid(unsafe_code)]

#[cfg(feature = "publish-s3")]
pub mod s3;
