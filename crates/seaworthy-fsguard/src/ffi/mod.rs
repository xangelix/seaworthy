//! The crate's only foreign calls, and the only modules that allow `unsafe`
//! (each block on its own, with the invariant it relies on in a `// SAFETY:`
//! comment). Everything here is a safe wrapper that the rest of the crate,
//! which forbids unsafe code, builds on.

#[cfg(unix)]
pub(crate) mod unix;
#[cfg(windows)]
pub(crate) mod windows;
