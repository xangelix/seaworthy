//! `seaworthy` — turns already-built artifacts and a product config into
//! every deliverable: verified inputs, install trees, signed packages,
//! release manifests and SBOMs.
//!
//! It never compiles product code, so a cargo or rustc change can't break
//! it. Its only toolchain contact is reading the records the compiler
//! already wrote into each core (`seaworthy_levels`).
//!
//! The pipeline:
//!
//! 1. **[`verify`]**: every target has a core whose record names the right
//!    triple and CPU and only known features; the launcher's CPU list
//!    matches; Windows sidecars are identical across builds; FIPS cores
//!    link only the pinned module; runtime dependencies are the base
//!    system's.
//! 2. **Prepare the Windows tree** ([`package`]): a version resource
//!    stamped into every product binary ([`pe_version`]), then every PE
//!    file Authenticode-signed ([`codesign`]), each signature checked
//!    against the identity `seaworthy.toml` pins.
//! 3. **[`layout`]**: the install tree per platform, stripped, with a
//!    manifest. Stripping, the version stamp and signing are each checked
//!    to leave what the loader maps unchanged ([`post_link`]).
//! 4. **[`package`]**: every output `seaworthy.toml` names, reproducibly: deb,
//!    rpm and pacman through nFPM ([`nfpm`], from [`linux`]'s contents and
//!    [`scripts`]' lifecycle), the tarball and zip ([`archive`]), the MSI's
//!    WiX source ([`wix`]) and the Group Policy templates ([`admx`]), with
//!    a listing of every artifact's SHA-256. An MSI WiX builds on Windows
//!    from that source is adopted only when its payload is the signed tree
//!    and its security-relevant tables are the source's ([`msi_check`]).
//! 5. **Sign the packages** ([`codesign`]): Authenticode on the MSI,
//!    OpenPGP on rpm (embedded) and pacman (`.sig`), each checked against
//!    the pinned identities. Every signing program runs through
//!    [`process`]: no shell, a deadline, bounded output.
//! 6. **[`sign`]**: a signed `seaworthy-release-manifest:1` beside every
//!    installable artifact, from signers checked against
//!    `release-signatures` and `release-keys`.
//! 7. **[`sbom`]**: a CycloneDX SBOM per artifact.
//! 8. **[`repo`]**: every product's release published as signed APT, DNF
//!    and pacman repositories plus the update helper's release tree, each
//!    release first checked as a client would (its manifests, its package
//!    signatures), with a publish plan that orders the upload; with them
//!    the [`repository_package`], which sets apt and dnf up to use them.
//! 9. **`publish`** (feature `publish-s3`): the plan uploaded to any
//!    S3-compatible store, immutable files first and the indexes last,
//!    checked back through the public URL, old files pruned.
//!
//! For the CI templates (`ci/gitlab/seaworthy.yml`): [`build_plan`],
//! the build each target triple needs, from `seaworthy.toml`; and [`ci_order`],
//! the release-ordering lint (every server deploy job needs every client
//! publication).
//!
//! [`config`] is the `seaworthy.toml` schema, [`inputs`] the artifact-directory
//! contract, and [`version`] the release version every package format
//! spells.
//!
//! ```no_run
//! use std::path::Path;
//!
//! let config = seaworthy::config::Config::load(Path::new("seaworthy.toml"))?;
//! let verified = seaworthy::verify::verify(&config, "collector", Path::new("target/artifacts"))?;
//! let trees = seaworthy::layout::layout(
//!     &config,
//!     "collector",
//!     &verified,
//!     Path::new("target/dist"),
//!     seaworthy::layout::Options::default(),
//! )?;
//! for tree in &trees {
//!     println!("{}: {} files under {}", tree.triple, tree.files.len(), tree.install_root);
//! }
//! # Ok::<(), seaworthy::DistError>(())
//! ```
//!
//! ## Features
//!
//! - `publish-s3` (default): the `s3` module, the S3 publish client (AWS
//!   Signature Version 4 over `seaworthy-crypto`, and the bounded
//!   management calls a publication needs: create-only checksummed puts,
//!   head, bounded get, list, delete), and `publish` on top of it. Without
//!   it the crate opens no network connection, and the binary's `publish`
//!   command refuses.

#![forbid(unsafe_code)]

pub mod admx;
pub mod archive;
pub mod build_plan;
pub mod ci_order;
pub mod codesign;
pub mod config;
mod error;
pub mod inputs;
pub mod layout;
pub mod linux;
pub mod macos;
pub mod msi_check;
pub mod nfpm;
pub mod package;
pub mod pe_version;
pub mod post_link;
pub mod process;
#[cfg(feature = "publish-s3")]
pub mod publish;
pub mod repo;
pub mod repository_package;
#[cfg(feature = "publish-s3")]
pub mod s3;
pub mod sbom;
pub mod scripts;
pub mod sign;
pub mod verify;
pub mod version;
pub mod wix;

pub use error::DistError;
