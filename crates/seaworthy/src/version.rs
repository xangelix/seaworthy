//! The release version and how every package format spells it.
//!
//! Defined in [`seaworthy_updater::release`] and re-exported here: the update
//! helper's version floor reads installed versions back with the same code
//! that spells them into packages, so the two can never disagree. The
//! proof that dpkg, rpm and pacman order the spellings as the floor does
//! is `tests/version_order.rs`, which runs the real tools.

pub use seaworthy_updater::release::*;
