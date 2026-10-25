//! Integration tests for the Ed25519 half of the `seaworthy-crypto` facade.
//! Complements the in-module unit test (roundtrip + a swapped message + a
//! truncated public key) with adversarial/boundary coverage: wrong keys,
//! bit-flipped signatures and messages, PKCS#8 corruption, and every
//! wrong-length boundary of `verify`.

use seaworthy_crypto::CryptoError;
use seaworthy_crypto::ed25519::{PUBLIC_KEY_LEN, SIGNATURE_LEN, SigningKey, verify};

#[test]
fn generated_key_signs_and_verifies_with_documented_lengths() {
    let (key, pkcs8) = SigningKey::generate_pkcs8().expect("key generation failed");
    assert!(!pkcs8.is_empty(), "pkcs8 document must not be empty");

    let public_key = key.public_key();
    assert_eq!(public_key.len(), PUBLIC_KEY_LEN);

    let message = b"seaworthy release statement";
    let signature = key.sign(message);
    assert_eq!(signature.len(), SIGNATURE_LEN);

    verify(&public_key, message, &signature).expect("a fresh signature must verify");
}

#[test]
fn verify_fails_with_a_different_public_key() {
    let (signing_key, _) = SigningKey::generate_pkcs8().expect("key generation failed");
    let (other_key, _) = SigningKey::generate_pkcs8().expect("key generation failed");

    let signature = signing_key.sign(b"seaworthy");
    let err = verify(&other_key.public_key(), b"seaworthy", &signature)
        .expect_err("a signature must not verify under a different key");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn verify_fails_on_a_tampered_signature() {
    let (key, _) = SigningKey::generate_pkcs8().expect("key generation failed");
    let message = b"seaworthy";

    // Flip one bit in R (the first half of the signature)...
    let mut tampered_r = key.sign(message);
    tampered_r[0] ^= 0x01;
    let err = verify(&key.public_key(), message, &tampered_r)
        .expect_err("a bit-flipped R must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));

    // ...and one bit in S (the second half), independently.
    let mut tampered_s = key.sign(message);
    tampered_s[SIGNATURE_LEN - 1] ^= 0x80;
    let err = verify(&key.public_key(), message, &tampered_s)
        .expect_err("a bit-flipped S must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn verify_fails_on_a_tampered_message() {
    let (key, _) = SigningKey::generate_pkcs8().expect("key generation failed");
    let message = b"transfer 100 credits to account 42";
    let signature = key.sign(message);

    let mut tampered = *message;
    tampered[9] = b'9'; // "100" -> "900"; a single-byte edit
    let err = verify(&key.public_key(), &tampered, &signature)
        .expect_err("a tampered message must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn from_pkcs8_roundtrip_preserves_the_public_key() {
    let (original, pkcs8) = SigningKey::generate_pkcs8().expect("key generation failed");
    let reloaded = SigningKey::from_pkcs8(&pkcs8).expect("a valid pkcs8 document must parse");
    assert_eq!(
        original.public_key(),
        reloaded.public_key(),
        "serialize -> reload must yield the identical keypair"
    );
}

#[test]
fn from_pkcs8_rejects_invalid_inputs_without_panicking() {
    let (_, pkcs8) = SigningKey::generate_pkcs8().expect("key generation failed");

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
fn verify_rejects_wrong_length_public_keys_without_panicking() {
    let (key, _) = SigningKey::generate_pkcs8().expect("key generation failed");
    let message = b"seaworthy";
    let signature = key.sign(message);

    // Scratch buffer so both sides of the 32-byte boundary are sliceable.
    let mut scratch = [0x5Au8; PUBLIC_KEY_LEN + 1];
    scratch[..PUBLIC_KEY_LEN].copy_from_slice(&key.public_key());
    for len in [0usize, PUBLIC_KEY_LEN - 1, PUBLIC_KEY_LEN + 1] {
        let err = verify(&scratch[..len], message, &signature)
            .expect_err("a wrong-length public key must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidKey),
            "public-key length {len} must surface as InvalidKey"
        );
    }

    // Valid length but not the signer's key material: still an error.
    let garbage = [0x5Au8; PUBLIC_KEY_LEN];
    assert!(verify(&garbage, message, &signature).is_err());
}

#[test]
fn verify_rejects_wrong_length_signatures_without_panicking() {
    let (key, _) = SigningKey::generate_pkcs8().expect("key generation failed");
    let message = b"seaworthy";
    let signature = key.sign(message);

    let mut scratch = [0u8; SIGNATURE_LEN + 1];
    scratch[..SIGNATURE_LEN].copy_from_slice(&signature);
    for len in [0usize, SIGNATURE_LEN - 1, SIGNATURE_LEN + 1] {
        let err = verify(&key.public_key(), message, &scratch[..len])
            .expect_err("a wrong-length signature must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidKey),
            "signature length {len} must surface as InvalidKey"
        );
    }
}

// ---------- keyless-forgery public keys ----------

/// The identity point `A = 01 00…00` with `R = identity`, `S = 0` satisfies
/// `[S]B = R + [k]A` for EVERY challenge `k`: a signature over any message
/// with no secret.
fn identity_forgery() -> ([u8; PUBLIC_KEY_LEN], [u8; SIGNATURE_LEN]) {
    let mut key = [0u8; PUBLIC_KEY_LEN];
    key[0] = 1;
    let mut signature = [0u8; SIGNATURE_LEN];
    signature[0] = 1;
    (key, signature)
}

#[test]
fn verify_refuses_the_identity_key_keyless_forgery() {
    let (key, signature) = identity_forgery();
    for message in [b"hello".as_slice(), b"anything at all", b""] {
        let err = verify(&key, message, &signature)
            .expect_err("the identity public key must never verify anything");
        assert!(matches!(err, CryptoError::InvalidKey), "got {err:?}");
    }
}

/// The small-order `y` encodings (libsodium's blocklist), each also with
/// the x-sign (high) bit set.
#[allow(
    clippy::expect_used,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn small_order_encodings() -> Vec<[u8; PUBLIC_KEY_LEN]> {
    let hex = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let mut out = Vec::new();
    for text in hex {
        let mut key = [0u8; PUBLIC_KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex");
        }
        out.push(key);
        key[31] |= 0x80;
        out.push(key);
    }
    out
}

#[test]
fn validate_public_key_refuses_every_small_order_and_non_canonical_encoding() {
    use seaworthy_crypto::ed25519::validate_public_key;

    for key in small_order_encodings() {
        assert!(
            matches!(validate_public_key(&key), Err(CryptoError::InvalidKey)),
            "small-order key {key:02x?}"
        );
    }
    // Non-canonical y ≥ p = 2^255 − 19: p itself, p + 1 (aliases of 0 and
    // 1), and the largest 255-bit value — sign-bit variants included.
    for low in [0xedu8, 0xee, 0xff] {
        let mut key = [0xffu8; PUBLIC_KEY_LEN];
        key[0] = low;
        key[31] = 0x7f;
        assert!(validate_public_key(&key).is_err(), "y = {low:#x}… ≥ p");
        key[31] = 0xff;
        assert!(
            validate_public_key(&key).is_err(),
            "signed y = {low:#x}… ≥ p"
        );
    }
    // Real keys pass.
    let (key, _) = SigningKey::generate_pkcs8().expect("keygen");
    validate_public_key(&key.public_key()).expect("a generated key is valid");
    assert!(validate_public_key(&[1u8; 31]).is_err(), "wrong length");
}

#[test]
fn verify_refuses_every_small_order_key() {
    let (_, signature) = identity_forgery();
    for key in small_order_encodings() {
        assert!(matches!(
            verify(&key, b"hello", &signature),
            Err(CryptoError::InvalidKey)
        ));
    }
}
