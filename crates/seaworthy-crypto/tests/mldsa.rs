//! Integration tests for the ML-DSA-87 half of the `seaworthy-crypto` facade.
//! Complements the in-module unit test (roundtrip) with the release-key
//! contract: seed determinism, wrong-key/wrong-message rejection, and
//! adversarial key/signature shapes (no panics, typed errors).

use seaworthy_crypto::CryptoError;
use seaworthy_crypto::mldsa::{PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN, SigningKey, verify};

#[test]
fn generated_key_signs_and_verifies_with_documented_lengths() {
    let key = SigningKey::generate().expect("key generation failed");

    let public_key = key.public_key();
    assert_eq!(public_key.len(), PUBLIC_KEY_LEN);

    let message = b"seaworthy release artifact digest";
    let signature = key.sign(message);
    assert_eq!(signature.len(), SIGNATURE_LEN);

    verify(&public_key, message, &signature).expect("a fresh signature must verify");
}

#[test]
fn from_seed_is_deterministic() {
    // The release-key story: one seed in custody reproduces the same
    // keypair on every release host, forever.
    let seed = [0x42u8; SEED_LEN];
    let a = SigningKey::from_seed(&seed).expect("from_seed");
    let b = SigningKey::from_seed(&seed).expect("from_seed");
    assert_eq!(
        a.public_key(),
        b.public_key(),
        "the same seed must reproduce the same ML-DSA-87 keypair"
    );

    // Signatures made by either expansion verify under the shared key.
    let signature_a = a.sign(b"seaworthy");
    let signature_b = b.sign(b"seaworthy");
    verify(&a.public_key(), b"seaworthy", &signature_a).expect("a's signature");
    verify(&a.public_key(), b"seaworthy", &signature_b).expect("b's signature");

    let other = SigningKey::from_seed(&[0x43u8; SEED_LEN]).expect("from_seed");
    assert_ne!(
        a.public_key(),
        other.public_key(),
        "a different seed must give a different key"
    );
}

#[test]
fn from_seed_rejects_wrong_lengths_without_panicking() {
    for len in [0usize, SEED_LEN - 1, SEED_LEN + 1, 64] {
        let err = SigningKey::from_seed(&vec![0x5Au8; len])
            .err()
            .expect("a non-32-byte seed must be rejected");
        assert!(
            matches!(err, CryptoError::InvalidKey),
            "seed length {len} must surface as InvalidKey"
        );
    }
}

#[test]
fn verify_fails_with_a_different_public_key() {
    let signing_key = SigningKey::generate().expect("keygen");
    let other_key = SigningKey::generate().expect("keygen");

    let signature = signing_key.sign(b"seaworthy");
    let err = verify(&other_key.public_key(), b"seaworthy", &signature)
        .expect_err("a signature must not verify under a different key");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn verify_fails_on_a_tampered_signature_and_message() {
    let key = SigningKey::generate().expect("keygen");
    let message = b"release sha256 digest";
    let signature = key.sign(message);

    let mut tampered_sig = signature;
    tampered_sig[0] ^= 0x01;
    let err = verify(&key.public_key(), message, &tampered_sig)
        .expect_err("a bit-flipped signature must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));

    let mut tampered_sig = signature;
    tampered_sig[SIGNATURE_LEN - 1] ^= 0x80;
    assert!(verify(&key.public_key(), message, &tampered_sig).is_err());

    let err = verify(&key.public_key(), b"other message", &signature)
        .expect_err("a tampered message must fail verification");
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn verify_rejects_wrong_length_public_keys_without_panicking() {
    let key = SigningKey::generate().expect("keygen");
    let message = b"seaworthy";
    let signature = key.sign(message);

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
    let key = SigningKey::generate().expect("keygen");
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

#[test]
fn pkcs8_roundtrip_preserves_the_key() {
    let original = SigningKey::generate().expect("keygen");
    let pkcs8 = original.to_pkcs8v1().expect("serialize");
    let reloaded = SigningKey::from_pkcs8(&pkcs8).expect("a valid pkcs8 document must parse");
    assert_eq!(
        original.public_key(),
        reloaded.public_key(),
        "serialize -> reload must yield the identical keypair"
    );

    // The serialized form is the 32-byte seed plus framing (FIPS 204 seed
    // custody), nowhere near the ~4.9 KB expanded key.
    assert!(
        pkcs8.len() < 128,
        "pkcs8 should be the compact seed form, got {} bytes",
        pkcs8.len()
    );

    // Malformed documents are typed errors, never panics.
    for bytes in [&pkcs8[..1], &pkcs8[..pkcs8.len() - 1], &[0xDEu8; 48][..]] {
        let err = SigningKey::from_pkcs8(bytes)
            .err()
            .expect("malformed pkcs8 must be rejected");
        assert!(matches!(err, CryptoError::InvalidKey));
    }
}

// ---------- keyless-forgery public keys ----------

/// The `t1 = 0` forgery, as a pinned vector: under the public key
/// `ρ ‖ zeros(2560)` (ρ = 0 here), ML-DSA verification computes
/// `w1' = UseHint(h, A·z − c·t1·2^d) = UseHint(h, A·z)` — the challenge
/// drops out, so `z = 0`, `h = 0` gives `w1' = 0` and
/// the forger only has to compute `c̃ = H(μ ‖ w1Encode(0))` from PUBLIC
/// data. `FORGED_CTILDE` is that `c̃` for [`FORGED_MESSAGE`] (SHAKE-256,
/// FIPS 204 pure/empty context — reproducible with Python's hashlib:
/// `tr = shake_256(pk).digest(64)`, `mu = shake_256(tr + b"\0\0" +
/// msg).digest(64)`, `c̃ = shake_256(mu + bytes(1024)).digest(64)`).
const FORGED_MESSAGE: &[u8] = b"seaworthy keyless forgery";
const FORGED_CTILDE: &str = "ed5c0d69f20979ee7a3ce8d5d788bc43c6631a643abf0e3a97d93751cc1da39362cb7db2f0e3e0aaf5e4f3d6429f6911125a49d59ed61d5da140e10f919af014";

/// `c̃ (64 B) ‖ BitPack(z = 0) (7 × 640 B) ‖ HintBitPack(h = 0) (83 B)`:
/// every `z` coefficient packs as `γ1 − 0 = 2^19` in 20 bits, i.e. the
/// repeating 5-byte group `00 00 08 00 80` (two coefficients per group).
fn forged_signature() -> Vec<u8> {
    let mut signature = hex_decode(FORGED_CTILDE);
    for _ in 0..(7 * 640 / 5) {
        signature.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x80]);
    }
    signature.extend_from_slice(&[0u8; 83]);
    assert_eq!(signature.len(), SIGNATURE_LEN);
    signature
}

#[allow(
    clippy::expect_used,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn zero_t1_key() -> [u8; PUBLIC_KEY_LEN] {
    [0u8; PUBLIC_KEY_LEN]
}

#[test]
fn verify_refuses_the_zero_t1_keyless_forgery() {
    // Pre-fix this verified: anyone could "sign" any message under a
    // `t1 = 0` key without a secret. The facade now refuses the key itself.
    let err = verify(&zero_t1_key(), FORGED_MESSAGE, &forged_signature())
        .expect_err("a t1 = 0 public key must never verify anything");
    assert!(matches!(err, CryptoError::InvalidKey), "got {err:?}");

    // Any ρ with t1 = 0 is the same degenerate key.
    let mut key = zero_t1_key();
    key[..32].copy_from_slice(&[0x5a; 32]);
    assert!(matches!(
        verify(&key, FORGED_MESSAGE, &forged_signature()),
        Err(CryptoError::InvalidKey)
    ));
}

#[test]
fn validate_public_key_refuses_zero_t1_and_admits_real_keys() {
    use seaworthy_crypto::mldsa::validate_public_key;

    assert!(matches!(
        validate_public_key(&zero_t1_key()),
        Err(CryptoError::InvalidKey)
    ));
    // Wrong lengths are refused too.
    assert!(validate_public_key(&[1u8; PUBLIC_KEY_LEN - 1]).is_err());
    assert!(validate_public_key(&[]).is_err());
    // A single non-zero t1 byte anywhere is still a forgeable key.
    for at in [32, 33, PUBLIC_KEY_LEN / 2, PUBLIC_KEY_LEN - 1] {
        let mut key = zero_t1_key();
        key[at] = 1;
        assert!(validate_public_key(&key).is_err(), "byte {at}");
    }
    // Real keys pass, and the forged signature never verifies under one.
    let real = SigningKey::generate().expect("keygen").public_key();
    validate_public_key(&real).expect("a generated key is valid");
    assert!(matches!(
        verify(&real, FORGED_MESSAGE, &forged_signature()),
        Err(CryptoError::InvalidSignature)
    ));
}

// ---------- the intake test against real forgeries ----------

#[allow(
    dead_code,
    reason = "shared with the fuzz crate, which uses all of it; these tests use most"
)]
mod support {
    pub(crate) mod keyless_forgery;
}

use support::keyless_forgery::{keyless_forgery, pack_public_key, shake256};

/// Verification by AWS-LC alone, without seaworthy's key validation: what
/// a verifier that skipped the intake test would accept.
fn raw_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ML_DSA_87, public_key)
        .verify(message, signature)
        .is_ok()
}

#[test]
fn the_test_shake_matches_known_answers() {
    // FIPS 202 SHAKE256("").
    assert_eq!(
        hex_decode("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
        shake256(&[], 32)
    );
    // Multi-block input and output.
    let long = vec![0xa3u8; 200];
    assert_eq!(shake256(&[&long], 500).len(), 500);
    assert_eq!(
        shake256(&[&long[..100], &long[100..]], 300),
        shake256(&[&long], 300)
    );
    // The forgery helper reproduces the Python-pinned zero-t1 vector.
    assert_eq!(
        keyless_forgery(&zero_t1_key(), FORGED_MESSAGE),
        forged_signature()
    );
}

fn t1_from(f: impl Fn(usize, usize) -> u16) -> [[u16; 256]; 8] {
    std::array::from_fn(|row| std::array::from_fn(|i| f(row, i)))
}

/// The reviewer's key: ρ = `5a 00 …`, `t1` all zero but its first
/// coefficient, 1.
fn reviewer_key() -> Vec<u8> {
    let mut key = zero_t1_key();
    key[0] = 0x5a;
    key[32] = 0x01;
    key.to_vec()
}

/// Forgeable public keys, each verified against AWS-LC itself: the
/// keyless forgery verifies under it (for every message, or for some, as
/// noted), and seaworthy refuses the key at intake and in `verify`.
#[test]
fn forgeable_key_classes_verify_keyless_forgeries_and_are_refused() {
    let rho = {
        let mut rho = [0u8; 32];
        rho[0] = 0x5a;
        rho
    };
    // (name, key, forges every message)
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        (
            "t1 = 0, ρ ≠ 0",
            pack_public_key(rho, &t1_from(|_, _| 0)),
            true,
        ),
        (
            "one coefficient 1 (the reviewer's key)",
            reviewer_key(),
            true,
        ),
        (
            "one coefficient 1023 in each polynomial",
            pack_public_key(rho, &t1_from(|_, i| if i == 9 { 1023 } else { 0 })),
            true,
        ),
        // 512·2^d = (q + 8191)/2, so a challenge's 60 terms (an even
        // count) sum to 8191·m/2 modulo q with |m| ≤ 60: below γ2 for
        // EVERY challenge, though no coefficient is small.
        (
            "every coefficient 512",
            pack_public_key(rho, &t1_from(|_, _| 512)),
            true,
        ),
        (
            "every coefficient 511",
            pack_public_key(rho, &t1_from(|_, _| 511)),
            true,
        ),
        // 1023·2^d = q − 1: every term is ±1.
        (
            "every coefficient 1023",
            pack_public_key(rho, &t1_from(|_, _| 1023)),
            true,
        ),
        (
            "every coefficient 1",
            pack_public_key(rho, &t1_from(|_, _| 1)),
            false,
        ),
        // (X + 1)^254 over GF(2), times 512: the forgery works whenever the
        // challenge is divisible by (X + 1)^2 over GF(2), about half of
        // them (a forger tries messages).
        (
            "512 on even positions",
            pack_public_key(rho, &t1_from(|_, i| if i % 2 == 0 { 512 } else { 0 })),
            false,
        ),
    ];
    for (name, key, every_message) in cases {
        let mut forged = 0;
        for n in 0..16u8 {
            let message = [b"seaworthy forged release ".as_slice(), &[n]].concat();
            let signature = keyless_forgery(&key, &message);
            if raw_verify(&key, &message, &signature) {
                forged += 1;
            }
            // seaworthy never verifies it: the key itself is refused.
            assert!(
                matches!(
                    verify(&key, &message, &signature),
                    Err(CryptoError::InvalidKey)
                ),
                "{name}"
            );
        }
        if every_message {
            assert_eq!(forged, 16, "{name}: AWS-LC accepts every forgery");
        } else {
            assert!(
                forged >= 1,
                "{name}: AWS-LC accepts some forgeries ({forged}/16)"
            );
        }
        assert!(
            matches!(
                seaworthy_crypto::mldsa::validate_public_key(&key),
                Err(CryptoError::InvalidKey)
            ),
            "{name}"
        );
    }
}

#[test]
fn keys_from_key_generation_pass_the_intake_test() {
    use seaworthy_crypto::mldsa::validate_public_key;
    for n in 0..48u8 {
        let mut seed = [0u8; SEED_LEN];
        seed[0] = n;
        seed[1..9].copy_from_slice(b"genuine!");
        let key = SigningKey::from_seed(&seed)
            .expect("from_seed")
            .public_key();
        validate_public_key(&key).expect("a generated key passes");
        // And the keyless forgery never verifies under one, even raw.
        assert!(!raw_verify(&key, b"m", &keyless_forgery(&key, b"m")));
    }
    for _ in 0..16 {
        let key = SigningKey::generate().expect("keygen").public_key();
        validate_public_key(&key).expect("a generated key passes");
    }
}

/// The statement `seaworthy-formats`' forged-manifest regression signs
/// (`manifest.rs`, `a_forgeable_release_key_never_verifies_a_forged_manifest`).
const MANIFEST_STATEMENT: &str = "seaworthy-release-manifest:1\nproduct=10:acme-agent\nchannel=0:\n\
    version=5:2.0.0\nbuild=0:\nsequence=1\ntarget=24:x86_64-unknown-linux-gnu\nformat=deb\n\
    size=42\ndigest=sha256:abababababababababababababababababababababababababababababababab\n";

/// `c̃` of the keyless forgery of [`MANIFEST_STATEMENT`] under
/// [`reviewer_key`], as `seaworthy-formats` pins it (Python's hashlib
/// reproduces it as the zero-t1 vector above describes).
const MANIFEST_CTILDE: &str = "6f15478fdefe55ed4b1fc87ead42df0cc5d475fce152c6a843e33f77ad5a73e769de9789f14faeb787109997a0408f6fec8fc468ab70c1d7db6a3ff8af6b9f5c";

#[test]
fn the_formats_regression_vector_is_a_real_forgery() {
    let key = reviewer_key();
    let statement = MANIFEST_STATEMENT.as_bytes();
    let signature = keyless_forgery(&key, statement);
    assert_eq!(hex::encode(&signature[..64]), MANIFEST_CTILDE);
    assert!(raw_verify(&key, statement, &signature), "AWS-LC accepts it");
    assert!(matches!(
        verify(&key, statement, &signature),
        Err(CryptoError::InvalidKey)
    ));
}
