//! # seaworthy-lab: the test harness of seaworthy's lab lanes
//!
//! The lab lanes test the contract between what the seaworthy CLI packages
//! and what the update helper installs, end to end, on real operating
//! systems: Linux distributions in containers running systemd, macOS,
//! Windows. This crate is what they share. Unpublished: a lane runs its
//! binary (`seaworthy-lab`) or links it as a fixture; no product ever
//! depends on it.
//!
//! - [`server`] (feature `server`): the **lab server**. It serves a release
//!   tree from a directory (`GET` and `HEAD`, as a static store serves the
//!   published repositories and the helper's release tree) and the
//!   product's **required-version endpoint**, `GET /_lab/required-version`,
//!   which answers the version token the lane names. A fixture's update
//!   helper takes its version from a caller closure; the fixture's closure
//!   asks this endpoint ([`client`]). Plain HTTP on loopback, or TLS on
//!   seaworthy-crypto's provider with a certificate from [`ca`]. The
//!   endpoint can hold a request until a file appears, so a lane can change
//!   the machine while a helper run waits on its version source.
//! - [`ca`] (feature `ca`): a **throwaway CA** for the TLS lanes: a root
//!   whose name constraints permit only the lab's host names, and one leaf
//!   for them. Every key and signature is seaworthy-crypto's; the root's
//!   private key never leaves memory, so after generation nothing can
//!   issue another certificate under the root a lane installs.
//! - [`client`] (feature `client`): the required-version client, over TLS
//!   with the operating system's trust store (the update helper's own TLS
//!   construction) or plain HTTP to loopback, bounded in time and size.
//! - [`manifest`]: a signed release manifest's statement re-signed by a
//!   throwaway key no build trusts (the lanes' "another key" case).
//! - [`request`]: the server's request-head parser, pure and fuzzed.
//!
//! The command-line interface, which PowerShell lanes drive as well as
//! bash ones, is documented in the crate's `README.md`.

#![forbid(unsafe_code)]

#[cfg(feature = "ca")]
pub mod ca;
#[cfg(feature = "server")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
mod error;
pub mod manifest;
pub mod request;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
mod tls;

pub use error::LabError;

/// The path of the required-version endpoint the lab server answers.
pub const REQUIRED_VERSION_PATH: &str = "/_lab/required-version";

/// The longest required-version answer the client reads (and the longest
/// token file the server reads): a version token is at most 128 bytes.
pub const MAX_TOKEN_BYTES: usize = 256;
