//! Tests of the crate-level pieces: the contract's re-exports and the
//! README's fixture, and (with the helper) the streamed digest. The
//! helper's flow is tested end to end in `helper_tests.rs`; each module
//! tests its own parts.

use std::path::PathBuf;

use super::*;

#[test]
fn the_readme_helpers_fixture_names_a_product() {
    let fixture = include_str!("../tests/fixtures/helper-seaworthy.toml");
    let product = Product::from_config(fixture, "agent").unwrap();
    assert_eq!(product.package(), "acme-agent");
    assert_eq!(
        product.request_file(),
        Some(PathBuf::from("/var/lib/acme/agent/update-request"))
    );
    assert_eq!(
        product.helper_service().as_deref(),
        Some("AcmeAgent-update")
    );
}

#[test]
fn the_request_file_is_the_one_the_service_renderer_watches() {
    // seaworthy-service's systemd renderer watches this name in the
    // service's state directory.
    assert_eq!(UPDATE_REQUEST_FILE, "update-request");
}

#[cfg(feature = "helper")]
#[test]
fn the_streamed_digest_is_the_one_shot_digest() {
    let data: Vec<u8> = (0..100_003u32).map(|i| (i * 31 % 251) as u8).collect();
    for algorithm in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
        let mut stream = DigestStream::new(algorithm);
        for chunk in data.chunks(4097) {
            stream.update(chunk);
        }
        assert_eq!(stream.finish_hex(), algorithm.hash_hex(&data));
    }
}

#[cfg(feature = "helper")]
#[test]
fn every_contract_refusal_keeps_its_variant() {
    let mapped = [
        UpdateError::from(FormatError::Resolve("x".into())),
        UpdateError::from(FormatError::ArtifactTooLarge { limit: 7 }),
        UpdateError::from(FormatError::SignatureMismatch),
        UpdateError::from(FormatError::ManifestMismatch {
            field: "version",
            expected: "1".into(),
            actual: "2".into(),
        }),
        UpdateError::from(FormatError::InvalidReleaseKey {
            algorithm: SignatureAlgorithm::Ed25519,
            reason: "x".into(),
        }),
        UpdateError::from(FormatError::InvalidConfig("x".into())),
        UpdateError::from(FormatError::WrongFormat { reason: "x".into() }),
    ];
    assert!(matches!(mapped[0], UpdateError::Resolve(_)));
    assert!(matches!(
        mapped[1],
        UpdateError::ArtifactTooLarge { limit: 7 }
    ));
    assert!(matches!(mapped[2], UpdateError::SignatureMismatch));
    assert!(matches!(
        mapped[3],
        UpdateError::ManifestMismatch {
            field: "version",
            ..
        }
    ));
    assert!(matches!(mapped[4], UpdateError::InvalidReleaseKey { .. }));
    assert!(matches!(mapped[5], UpdateError::InvalidConfig(_)));
    assert!(matches!(mapped[6], UpdateError::WrongFormat { .. }));
    // The same words either way.
    assert_eq!(
        UpdateError::from(FormatError::SignatureMismatch).to_string(),
        FormatError::SignatureMismatch.to_string()
    );
}
