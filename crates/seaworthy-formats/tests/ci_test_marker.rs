//! The CI test-key marker is in a binary exactly when the binary can trust
//! CI test keys: this test executable trusts one through the public API,
//! then scans itself. Run it in both builds (the default, and with
//! `SEAWORTHY_ALLOW_CI_TEST_KEYS=1`).

#![allow(clippy::expect_used, reason = "a test: a failed setup step fails it")]

use seaworthy_formats::ci_test::{CI_TEST_KEYS_ALLOWED, carries_ci_test_keys_marker};
use seaworthy_formats::{ManifestTrust, ReleaseKey, SignatureAlgorithm};

fn key() -> ReleaseKey {
    let public_key = seaworthy_crypto::mldsa::SigningKey::generate()
        .expect("keygen")
        .public_key();
    ReleaseKey::new(public_key.to_vec(), SignatureAlgorithm::MlDsa87).expect("a generated key")
}

#[test]
fn the_marker_is_in_the_binary_exactly_when_test_keys_can_be_trusted() {
    let trust = ManifestTrust::new("acme-agent", [key()])
        .expect("trust")
        .with_ci_test_keys([key()]);
    assert_eq!(trust.is_ok(), CI_TEST_KEYS_ALLOWED);
    if let Ok(trust) = &trust {
        assert!(trust.ci_test_keys_notice().is_some());
    }
    let image = std::fs::read(std::env::current_exe().expect("this test's path")).expect("read");
    assert_eq!(
        carries_ci_test_keys_marker(&image),
        CI_TEST_KEYS_ALLOWED,
        "the marker's presence must follow the switch"
    );
}

#[test]
fn a_test_key_file_is_compiled_in_only_with_the_switch() {
    // Without the switch the argument is never expanded: this file does
    // not exist, and the build still succeeds.
    #[cfg(not(seaworthy_ci_test_keys))]
    assert!(seaworthy_formats::ci_test_keys!(include_str!("no/such/ci-test.pub")).is_none());
    assert_eq!(
        seaworthy_formats::ci_test_keys!(concat!("00", "ff")).is_some(),
        CI_TEST_KEYS_ALLOWED
    );
}
