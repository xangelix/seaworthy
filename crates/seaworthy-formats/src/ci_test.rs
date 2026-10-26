//! The CI test-key switch: a build that can trust a product's public CI
//! test keys, and the marker that makes such a build recognizable.
//!
//! CI test keys are key pairs whose private halves are NOT secret (a
//! product commits them so every CI job can sign with them), so a helper
//! that trusts one installs an update ANYONE signed. Trusting them is
//! therefore a build-time decision, off by default:
//!
//! - **The switch.** seaworthy-formats' build script sets
//!   `cfg(seaworthy_ci_test_keys)` only when the build runs with
//!   [`CI_TEST_KEYS_VAR`]`=1` (any value other than `1`, `0` or empty
//!   fails the build). Without it, [`ManifestTrust::with_ci_test_keys`](crate::ManifestTrust::with_ci_test_keys)
//!   refuses every key and [`ci_test_keys!`](crate::ci_test_keys) drops
//!   its argument unexpanded, so a release build carries no test-key bytes.
//! - **The marker.** A build that trusts test keys carries the byte string
//!   [`ci_test_keys_marker`] (`seaworthy-ci-test-keys` then
//!   `:trusted:1`, as one ASCII string with nothing between): it opens
//!   the notice [`ManifestTrust::ci_test_keys_notice`](crate::ManifestTrust::ci_test_keys_notice)
//!   returns, which the update helper logs at every run, and both
//!   `with_ci_test_keys` (given keys) and `ci_test_keys!` (handing out
//!   text) pin it into the binary. `seaworthy verify`
//!   refuses a binary carrying it unless the build is a `--ci-test-signing`
//!   one, and a release pipeline can refuse it with
//!   `grep -qaF 'seaworthy-ci-test-keys:trusted:1' <file>`.
//! - **The release guard** belongs to CI: a release job fails when the
//!   switch is set in its environment (`docs/threat-model.md`, the CI
//!   test-key mechanism).
//!
//! A product's helper trusts its test keys like this, unchanged between
//! builds:
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use seaworthy_formats::{ManifestTrust, ReleaseKey, SignatureAlgorithm};
//! # let release = seaworthy_crypto::mldsa::SigningKey::generate()?.public_key();
//! # let test = seaworthy_crypto::mldsa::SigningKey::generate()?.public_key();
//! # let test_keys_file: &'static str = Box::leak(hex::encode(test).into_boxed_str());
//! let release_keys = [ReleaseKey::new(release.to_vec(), SignatureAlgorithm::MlDsa87)?];
//! // `Some(text)` only in a build made with SEAWORTHY_ALLOW_CI_TEST_KEYS=1;
//! // otherwise `None`, and the argument (a product writes
//! // `include_str!("../keys/ci-test.pub")`) is never compiled in.
//! let test_keys = seaworthy_formats::ci_test_keys!(test_keys_file)
//!     .unwrap_or_default()
//!     .lines()
//!     .filter(|line| !line.trim().is_empty())
//!     .map(|line| {
//!         let bytes = hex::decode(line.trim()).unwrap_or_default();
//!         ReleaseKey::new(bytes, SignatureAlgorithm::MlDsa87)
//!     })
//!     .collect::<Result<Vec<_>, _>>()?;
//! let trust = ManifestTrust::new("acme-agent", release_keys)?.with_ci_test_keys(test_keys)?;
//! assert_eq!(
//!     trust.ci_test_keys().len(),
//!     usize::from(seaworthy_formats::ci_test::CI_TEST_KEYS_ALLOWED)
//! );
//! # Ok(()) }
//! ```

/// The build-time switch: the environment variable that, set to `1` when
/// seaworthy-formats is compiled, lets the build trust CI test keys.
pub const CI_TEST_KEYS_VAR: &str = "SEAWORTHY_ALLOW_CI_TEST_KEYS";

/// Whether this build was made with [`CI_TEST_KEYS_VAR`]`=1`.
pub const CI_TEST_KEYS_ALLOWED: bool = cfg!(seaworthy_ci_test_keys);

/// The marker, each byte XOR [`MARKER_MASK`], unmasked only at run time
/// ([`ci_test_keys_marker`]) so that a binary which merely scans for the
/// marker never carries it. (Two plain halves are not enough: a compiler
/// lays string constants out back to back, and the halves met again in
/// the binary.)
const MASKED_MARKER: [u8; 32] = [
    0xd6, 0xc0, 0xc4, 0xd2, 0xca, 0xd7, 0xd1, 0xcd, 0xdc, 0x88, 0xc6, 0xcc, 0x88, 0xd1, 0xc0, 0xd6,
    0xd1, 0x88, 0xce, 0xc0, 0xdc, 0xd6, 0x9f, 0xd1, 0xd7, 0xd0, 0xd6, 0xd1, 0xc0, 0xc1, 0x9f, 0x94,
];
/// See [`MASKED_MARKER`].
const MARKER_MASK: u8 = 0xa5;

/// The notice a build that trusts CI test keys logs; it starts with the
/// marker, as one literal. Public only for [`ci_test_keys!`](crate::ci_test_keys),
/// which pins it into every binary it hands test-key text to.
#[cfg(seaworthy_ci_test_keys)]
#[doc(hidden)]
pub const CI_TEST_KEYS_NOTICE: &str = concat!(
    "seaworthy-ci-test-keys",
    ":trusted:1",
    " - this build trusts public CI test keys (built with SEAWORTHY_ALLOW_CI_TEST_KEYS=1): ",
    "anyone can sign an update it installs; never distribute it"
);

/// The marker a build that trusts CI test keys carries, as bytes: the
/// ASCII string made of `seaworthy-ci-test-keys` and `:trusted:1`. Built
/// at run time, so calling this does not put the marker into a binary.
#[must_use]
pub fn ci_test_keys_marker() -> Vec<u8> {
    let mask = std::hint::black_box(MARKER_MASK);
    MASKED_MARKER.iter().map(|byte| byte ^ mask).collect()
}

/// Whether `image` (a binary, any file) carries [`ci_test_keys_marker`].
#[must_use]
pub fn carries_ci_test_keys_marker(image: &[u8]) -> bool {
    let marker = ci_test_keys_marker();
    image.windows(marker.len()).any(|window| window == marker)
}

/// `Some(text)` in a build made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1`,
/// `None` in any other, where `text` is dropped UNEXPANDED: an
/// `include_str!` of a test-key file is never read, so a release binary
/// holds no test-key bytes. `text` is a `&'static str` (`include_str!`,
/// `env!`, `concat!`), typically the product's CI test public keys, one
/// hex key per line. See the [module docs](crate::ci_test) for the
/// pattern.
#[cfg(seaworthy_ci_test_keys)]
#[macro_export]
macro_rules! ci_test_keys {
    ($text:expr $(,)?) => {{
        // Test-key text compiled in: the binary carries the marker too.
        let _ = ::core::hint::black_box($crate::ci_test::CI_TEST_KEYS_NOTICE);
        ::core::option::Option::<&'static str>::Some($text)
    }};
}

/// `Some(text)` in a build made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1`,
/// `None` in any other, where `text` is dropped UNEXPANDED: an
/// `include_str!` of a test-key file is never read, so a release binary
/// holds no test-key bytes. `text` is a `&'static str` (`include_str!`,
/// `env!`, `concat!`), typically the product's CI test public keys, one
/// hex key per line. See the [module docs](crate::ci_test) for the
/// pattern.
#[cfg(not(seaworthy_ci_test_keys))]
#[macro_export]
macro_rules! ci_test_keys {
    ($text:expr $(,)?) => {
        ::core::option::Option::<&'static str>::None
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_its_documented_string_and_is_found() {
        assert_eq!(ci_test_keys_marker(), b"seaworthy-ci-test-keys:trusted:1");
        assert!(carries_ci_test_keys_marker(
            b"\x7fELF\0\0seaworthy-ci-test-keys:trusted:1\0more"
        ));
        assert!(!carries_ci_test_keys_marker(b"seaworthy-ci-test-keys"));
        assert!(!carries_ci_test_keys_marker(
            b"seaworthy-ci-test-keys:trusted:2"
        ));
        assert!(!carries_ci_test_keys_marker(b""));
    }

    #[test]
    fn the_switch_is_this_builds() {
        assert_eq!(CI_TEST_KEYS_ALLOWED, cfg!(seaworthy_ci_test_keys));
        assert_eq!(CI_TEST_KEYS_VAR, "SEAWORTHY_ALLOW_CI_TEST_KEYS");
        // The macro: the text only with the switch, and without it the
        // argument is never expanded (this file does not exist).
        let text = crate::ci_test_keys!("00ff\n");
        assert_eq!(text.is_some(), CI_TEST_KEYS_ALLOWED);
        #[cfg(not(seaworthy_ci_test_keys))]
        assert!(crate::ci_test_keys!(include_str!("no/such/file.pub")).is_none());
    }

    #[cfg(seaworthy_ci_test_keys)]
    #[test]
    fn the_notice_opens_with_the_marker() {
        assert!(
            CI_TEST_KEYS_NOTICE
                .as_bytes()
                .starts_with(&ci_test_keys_marker())
        );
        assert!(carries_ci_test_keys_marker(CI_TEST_KEYS_NOTICE.as_bytes()));
    }
}
