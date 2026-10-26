//! Tests of the crate-level validators and algorithms; each module tests
//! its own parts.

use super::*;

#[test]
fn versions_from_the_network_are_validated() {
    for bad in [
        "",
        "..",
        "1..2",
        "1/2",
        "1?x",
        "1%2f",
        "a@b",
        "v2\r\nX",
        "1 2",
        &"9".repeat(MAX_VERSION_LEN + 1),
    ] {
        assert!(validate_version(bad).is_err(), "{bad:?}");
    }
    for good in ["2.0.0", "v2.0.0-rc.1+build_7", &"9".repeat(MAX_VERSION_LEN)] {
        validate_version(good).unwrap();
    }
    // The error text never carries raw control characters.
    let error = validate_version("v2\r\nFORGED").unwrap_err().to_string();
    assert!(!error.contains('\r') && !error.contains('\n'));
}

#[test]
fn digest_known_answers() {
    assert_eq!(
        DigestAlgorithm::Sha256.hash_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(
        DigestAlgorithm::Sha512
            .hash_hex(b"abc")
            .starts_with("ddaf35a193617aba")
    );
    assert_eq!(DigestAlgorithm::default(), DigestAlgorithm::Sha512);
    assert_eq!(DigestAlgorithm::Sha256.to_string(), "sha256");
    assert_eq!(DigestAlgorithm::Sha512.name(), "sha512");
    for algorithm in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha512] {
        assert_eq!(algorithm.hash(b"abc").len(), algorithm.digest_len());
        assert_eq!(
            hex::encode(algorithm.hash(b"abc")),
            algorithm.hash_hex(b"abc")
        );
    }
}

#[test]
fn signature_keys_are_validated_at_construction() {
    let mut identity = vec![0u8; 32];
    identity[0] = 1;
    let mut off_curve = vec![0x04u8];
    off_curve.extend_from_slice(&[0x01; 64]);
    // A non-zero rho with an all-zero t1: the keyless-forgery shape.
    let mut zero_t1 = vec![0u8; 2592];
    zero_t1[..32].fill(0x5a);
    // One non-zero t1 coefficient, and every coefficient 512: forgeable
    // too (seaworthy-crypto's intake test).
    let mut one_coefficient = zero_t1.clone();
    one_coefficient[32] = 1;
    let mut all_512 = zero_t1.clone();
    for group in all_512[32..].chunks_mut(5) {
        group.copy_from_slice(&[0x00, 0x02, 0x08, 0x20, 0x80]);
    }
    for (key, algorithm) in [
        (vec![0u8; 2592], SignatureAlgorithm::MlDsa87),
        (zero_t1, SignatureAlgorithm::MlDsa87),
        (one_coefficient, SignatureAlgorithm::MlDsa87),
        (all_512, SignatureAlgorithm::MlDsa87),
        (identity, SignatureAlgorithm::Ed25519),
        (off_curve, SignatureAlgorithm::EcdsaP256),
        (vec![1, 2, 3], SignatureAlgorithm::Ed25519),
    ] {
        assert!(
            matches!(
                ReleaseKey::new(key, algorithm),
                Err(FormatError::InvalidReleaseKey { .. })
            ),
            "{algorithm:?}"
        );
    }
}

#[test]
fn the_target_triple_is_this_builds() {
    // A real triple: an architecture first, at least three parts.
    assert!(TARGET_TRIPLE.split('-').count() >= 3, "{TARGET_TRIPLE}");
    assert!(TARGET_TRIPLE.starts_with(std::env::consts::ARCH) || cfg!(target_arch = "x86"));
}
