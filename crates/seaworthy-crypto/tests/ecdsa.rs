//! Integration tests for the ECDSA P-256/SHA-256 half of the
//! `seaworthy-crypto` facade. Complements the in-module unit test (roundtrip)
//! with the release-key contract: wrong-key/wrong-message rejection and
//! adversarial key/signature shapes (no panics, typed errors).

use seaworthy_crypto::CryptoError;
use seaworthy_crypto::ecdsa::{SigningKey, verify};

#[test]
fn generated_key_signs_and_verifies_with_the_spki_export() {
    let (key, pkcs8) = SigningKey::generate_pkcs8().expect("key generation failed");
    assert!(!pkcs8.is_empty(), "pkcs8 document must not be empty");

    // The SPKI DER export is the form applications embed for the updater.
    let public_key = key.public_key_der();
    assert_eq!(public_key[0], 0x30, "SPKI export must be a DER SEQUENCE");

    let message = b"seaworthy release artifact digest";
    let signature = key.sign(message).expect("sign");
    assert_eq!(signature[0], 0x30, "ECDSA signature must be ASN.1 DER");

    verify(&public_key, message, &signature).expect("a fresh signature must verify");
}

#[test]
fn verify_fails_with_a_different_public_key() {
    let (signing_key, _) = SigningKey::generate_pkcs8().expect("keygen");
    let (other_key, _) = SigningKey::generate_pkcs8().expect("keygen");

    let signature = signing_key.sign(b"seaworthy").expect("sign");
    let err = verify(&other_key.public_key_der(), b"seaworthy", &signature)
        .expect_err("a signature must not verify under a different key");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn verify_fails_on_a_tampered_signature_and_message() {
    let (key, _) = SigningKey::generate_pkcs8().expect("keygen");
    let message = b"release sha256 digest";
    let signature = key.sign(message).expect("sign");

    // Flip a bit in the trailing integer bytes (never the DER header).
    let mut tampered_sig = signature.clone();
    let last = tampered_sig.len() - 1;
    tampered_sig[last] ^= 0x80;
    assert!(verify(&key.public_key_der(), message, &tampered_sig).is_err());

    let err = verify(&key.public_key_der(), b"other message", &signature)
        .expect_err("a tampered message must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn from_pkcs8_roundtrip_preserves_the_public_key() {
    let (original, pkcs8) = SigningKey::generate_pkcs8().expect("keygen");
    let reloaded = SigningKey::from_pkcs8(&pkcs8).expect("a valid pkcs8 document must parse");
    assert_eq!(
        original.public_key_der(),
        reloaded.public_key_der(),
        "serialize -> reload must yield the identical keypair"
    );
}

#[test]
fn from_pkcs8_rejects_invalid_inputs_without_panicking() {
    let (_, pkcs8) = SigningKey::generate_pkcs8().expect("keygen");

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("single byte", pkcs8[..1].to_vec()),
        ("truncated to half", pkcs8[..pkcs8.len() / 2].to_vec()),
        ("truncated by one byte", pkcs8[..pkcs8.len() - 1].to_vec()),
        ("garbage bytes", vec![0xDE; 48]),
        ("zeroed at valid length", vec![0u8; pkcs8.len()]),
    ];
    for (name, bytes) in cases {
        let err = SigningKey::from_pkcs8(&bytes)
            .err()
            .expect("{name} input must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidKey),
            "{name} input must surface as InvalidKey"
        );
    }
}

#[test]
fn verify_rejects_malformed_keys_and_signatures_without_panicking() {
    let (key, _) = SigningKey::generate_pkcs8().expect("keygen");
    let message = b"seaworthy";
    let signature = key.sign(message).expect("sign");
    let public_key = key.public_key_der();

    // Garbage or truncated key material: a typed error, never a panic.
    for bad_key in [
        &b""[..],
        &public_key[..1],
        &public_key[..public_key.len() / 2],
        &[0xDEu8; 65][..],
        &[0u8; 91][..],
    ] {
        assert!(
            verify(bad_key, message, &signature).is_err(),
            "malformed key ({} bytes) must not verify",
            bad_key.len()
        );
    }

    // Empty, truncated, and garbage signatures: a typed error, never a panic.
    for bad_sig in [
        &b""[..],
        &signature[..1],
        &signature[..signature.len() - 1],
        &[0xDEu8; 71][..],
    ] {
        assert!(
            verify(&public_key, message, bad_sig).is_err(),
            "malformed signature ({} bytes) must not verify",
            bad_sig.len()
        );
    }
}

// ---------- AWS-LC already refuses invalid ECDSA points ----------

/// ECDSA needs no facade-side key check: AWS-LC validates the
/// public point (on-curve, not the point at infinity, coordinates < p)
/// before verification. Pinned here so a backend change can't silently
/// open the degenerate-key hole the review found in ML-DSA and Ed25519.
#[test]
fn verify_refuses_invalid_public_points() {
    let (key, _) = SigningKey::generate_pkcs8().expect("keygen");
    let message = b"seaworthy";
    let signature = key.sign(message).expect("sign");

    // P-256's field prime p, big-endian.
    let p: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];
    let uncompressed = |x: [u8; 32], y: [u8; 32]| {
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        point
    };
    let mut one = [0u8; 32];
    one[31] = 1;
    let invalid_points = [
        // The point at infinity's SEC1 encoding.
        vec![0x00],
        // (0, 0) and (1, 1): off the curve.
        uncompressed([0u8; 32], [0u8; 32]),
        uncompressed(one, one),
        // Coordinates ≥ p (non-reduced).
        uncompressed(p, one),
        uncompressed(one, p),
        uncompressed([0xff; 32], [0xff; 32]),
    ];
    for point in invalid_points {
        assert!(
            matches!(
                seaworthy_crypto::ecdsa::validate_public_key(&point),
                Err(CryptoError::InvalidKey)
            ),
            "intake refuses invalid point {point:02x?}"
        );
        assert!(
            matches!(
                verify(&point, message, &signature),
                Err(CryptoError::InvalidSignature)
            ),
            "invalid point {point:02x?} must never verify"
        );
    }
}

#[test]
fn validate_public_key_admits_real_keys_in_both_encodings() {
    let (key, _) = SigningKey::generate_pkcs8().expect("keygen");
    seaworthy_crypto::ecdsa::validate_public_key(&key.public_key_der()).expect("SPKI DER");
    // The raw X9.62 point is the SPKI's trailing 65 bytes.
    let der = key.public_key_der();
    seaworthy_crypto::ecdsa::validate_public_key(&der[der.len() - 65..]).expect("raw point");
}
