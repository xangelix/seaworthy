//! `seaworthy-crypto`: the seaworthy crate family's **minimal cryptography
//! facade**. Every cryptographic operation the distribution stack performs
//! goes through here: digests ([`digest`]), secure randomness ([`rand`]),
//! signatures ([`ed25519`], [`ecdsa`] P-256, [`mldsa`] ML-DSA-87),
//! constant-time compare ([`ct_eq`]) and the TLS client configuration
//! ([`tls`]).
//!
//! **The module.** Under the `fips` feature every operation runs in the
//! AWS-LC FIPS 4.2.0 module (CMVP: in process, Comment Resolution; its
//! validated predecessor is AWS-LC 3, certificate #5314), built from source
//! by `aws-lc-fips-sys` 0.14.2 behind `aws-lc-rs` 1.18.1, both pinned with
//! `=` and asserted at runtime ([`module`]).
//!
//! FIPS status of the three signature schemes (sourced from the CMVP record,
//! see [`fips_policy`]): the linked 4.2.0 module's service indicator
//! approves all three. **Ed25519 (EdDSA) and ECDSA P-256/SHA-256 are also
//! listed on the validated AWS-LC 3 certificate** (#5314/#5298: EdDSA
//! KeyGen/SigGen/SigVer on Ed25519 in its approved-algorithm and
//! approved-service tables); **ML-DSA-87 is not** (the 3.x certificates lack
//! ML-DSA). [`fips_policy::Posture`] keeps the two facts apart; see the
//! [`ecdsa`], [`ed25519`] and [`mldsa`] module docs.
//!
//! **What `fips` means here: only approved services are reachable through
//! the facade.** The feature links the FIPS module and restricts the TLS
//! provider to approved suites and groups ([`tls_provider`]). Intake points
//! consult [`fips_policy`], so a non-approved algorithm is refused where it
//! enters, with a typed error naming it, and the deployment's installed
//! [`fips_policy::AlgorithmPolicy`] can narrow it further (for example
//! [`fips_policy::AlgorithmPolicy::ML_DSA_87_ONLY`]). [`is_fips`] is the
//! runtime answer about the module and the TLS provider (what it does and
//! does not attest: [`module`]).
//!
//! **No cryptographic primitives are implemented in this crate.** Everything
//! delegates to [AWS-LC](https://github.com/aws/aws-lc) via `aws-lc-rs`;
//! with the `fips` feature, the AWS-LC FIPS 4.2.0 module
//! (`aws-lc-fips-sys`). That has three payoffs:
//!
//! - **One switch.** The `fips` feature lives here and only here.
//!   Applications enable it (`seaworthy-crypto = { features = ["fips"] }`);
//!   libraries never set it. It forwards to `aws-lc-rs/fips` AND
//!   `rustls/fips`, so feature unification carries the same backend, and
//!   the approved-only TLS suite/group filter, to every rustls provider in
//!   the graph; seaworthy's TLS clients all take the one canonical
//!   [`tls_provider`].
//! - **One review target.** Compliance reads this crate, not every call
//!   site.
//! - **No silent non-FIPS builds.** The build script refuses a `fips` build
//!   whose environment would swap in a pre-installed AWS-LC or alter the
//!   module build (see `build/knobs.rs`), and [`module::ensure_expected_module`]
//!   refuses, at runtime, anything but the pinned module.

#![forbid(unsafe_code)]
// The security baseline beyond the workspace lints: no panicking index or
// slice and no `unreachable!` in library code (tests may index).
#![deny(clippy::indexing_slicing, clippy::unreachable)]

pub mod digest;
pub mod ecdsa;
pub mod ed25519;
pub mod fips_policy;
pub mod mldsa;
pub mod module;
pub mod rand;
pub mod tls;

/// Errors of the facade's fallible operations.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key material was malformed (e.g. not a valid PKCS#8 Ed25519 key).
    #[error("invalid key material")]
    InvalidKey,
    /// The signature did not verify against the public key.
    #[error("invalid signature")]
    InvalidSignature,
    /// The random number generator failed.
    #[error("system RNG failed")]
    Rng,
    /// A configuration refused at runtime, such as a FIPS build linking a
    /// module other than the pinned one ([`module::ensure_expected_module`]).
    /// The message names what was found and what was expected, never a
    /// secret value.
    #[error("{0}")]
    Config(String),
    /// The requested service is not an approved service of the
    /// AWS-LC FIPS module and this build enables the `fips` feature, which
    /// means ONLY approved services are reachable (see [`fips_policy`]).
    /// Names the service.
    #[error("{0} is not a FIPS-approved service (refused under the `fips` feature)")]
    NotApproved(&'static str),
    /// The deployment's installed [`fips_policy::AlgorithmPolicy`] refuses
    /// the service: a signature algorithm outside its allowed set, or a
    /// service no validated certificate lists under the certified-only
    /// posture. Names the service and the reason.
    #[error("{service} is refused by the deployment's algorithm policy: {reason}")]
    NotAllowed {
        /// The refused service's name ([`fips_policy::Service::name`]).
        service: &'static str,
        /// Which policy axis refused it.
        reason: &'static str,
    },
}

/// The ONE rustls crypto provider every seaworthy TLS configuration is built
/// from: rustls's AWS-LC provider shaped by the process-wide
/// [`tls::TlsPolicy`]: the policy's key-exchange groups in ITS order
/// (hybrids first: `X25519MLKEM768`, `SECP256R1MLKEM768`), its minimum
/// protocol version and its suite profile. Under this crate's `fips` feature
/// (it enables `rustls/fips`) only FIPS-approved suites and groups exist: no
/// ChaCha20-Poly1305, no plain X25519. TLS clients and test harnesses take it
/// from here instead of calling `rustls::crypto::aws_lc_rs::default_provider()`
/// themselves, so [`is_fips`] describes the TLS the process actually
/// negotiates. Built once, at the first call, from the installed policy
/// ([`tls::install_policy`]) or the defaults; every call clones the `Arc`.
#[must_use]
pub fn tls_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    tls::provider()
}

/// Install [`tls_provider`] as the rustls process-default provider (for
/// code paths, such as third-party clients, that consult
/// `CryptoProvider::get_default()`). Idempotent: an already-installed
/// default is left alone (`false`), since swapping providers under live
/// connections is rustls's own refusal. Returns whether this call
/// installed it.
pub fn install_default_tls_provider() -> bool {
    rustls::crypto::CryptoProvider::install_default((*tls_provider()).clone()).is_ok()
}

/// Runtime answer to "is the FIPS module linked and the TLS stack
/// FIPS-filtered?": `true` only when
///
/// 1. our own backend is the AWS-LC FIPS module in FIPS mode (queried at
///    runtime, not compile time: its power-on self-tests and integrity
///    check passed before `main`), **and**
/// 2. the canonical [`tls_provider`], the one every seaworthy TLS client
///    builds its configuration from, reports FIPS (approved suites and
///    groups only), **and**
/// 3. the rustls process-default provider, IF one is installed, reports
///    FIPS too (a third-party client in the process takes that one).
///
/// Every half matters: a build that flips one but not the others is a
/// finding, not a posture.
///
/// **What it does NOT attest:** that only approved services run. The
/// module's per-call service indicator is not consulted, and some
/// in-module operations are non-approved by it, such as the X25519 half of
/// the hybrid key exchange. It also does not pin the module VERSION: that is
/// [`module::ensure_expected_module`] (run by [`module::startup_self_check`]).
#[must_use]
pub fn is_fips() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
        && tls_provider().fips()
        && rustls::crypto::CryptoProvider::get_default().is_none_or(|provider| provider.fips())
}

/// Constant-time byte equality (timing-safe comparisons for digests,
/// tickets and pins). Slices of different lengths compare unequal; the
/// length itself is not secret.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    subtle::ConstantTimeEq::ct_eq(a, b).into()
}

// ---------------------------------------------------------------------------
// README doctests: the crate README's Rust examples compile as doctests
// (`cargo test --doc`), so the crates.io front page can never drift from
// the API.
// ---------------------------------------------------------------------------

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
