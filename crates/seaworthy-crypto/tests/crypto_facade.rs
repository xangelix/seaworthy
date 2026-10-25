//! Integration tests for the non-signature half of the `seaworthy-crypto`
//! facade: digests, secure randomness, constant-time compare, and the
//! `is_fips()` posture probe. These complement the in-module unit tests
//! (which cover the empty/"abc" `sha256_hex` vectors and the signature
//! roundtrips) rather than repeating them.

use seaworthy_crypto::{ct_eq, digest, rand};

/// Decode a 64-char lowercase hex string into the 32-byte digest it
/// represents (test-vector helper; panics on malformed input on purpose).
#[allow(
    clippy::panic,
    reason = "a malformed test vector is a bug in the test; failing loudly is the point"
)]
fn decode_hex_32(s: &str) -> [u8; 32] {
    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("test vectors are lowercase hex"),
        }
    }

    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 64, "a SHA-256 test vector is 64 hex chars");
    let mut out = [0u8; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    out
}

// ---------- digest ----------

#[test]
fn sha256_empty_input_matches_nist_vector() {
    // FIPS 180-4: SHA-256(""). The unit test covers sha256_hex; this pins
    // the raw 32-byte return value of `sha256`.
    assert_eq!(
        digest::sha256(b""),
        decode_hex_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

#[test]
fn sha256_abc_matches_nist_vector() {
    // FIPS 180-4: SHA-256("abc"), raw bytes.
    assert_eq!(
        digest::sha256(b"abc"),
        decode_hex_32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn sha256_hex_is_64_lowercase_hex_chars_matching_vector() {
    // The 56-byte NIST vector ("abcdbcde..."), so this asserts more than a
    // re-encode of the unit tests' empty/"abc" vectors.
    let hexed = digest::sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(hexed.len(), 64);
    assert!(
        hexed
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "sha256_hex must be lowercase hex, got {hexed}"
    );
    assert_eq!(
        hexed,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_one_mib_input_hashes_and_differs_from_empty() {
    let big = vec![0xA5u8; 1024 * 1024];
    let raw = digest::sha256(&big);
    assert_ne!(raw, digest::sha256(b""));
    // The hex and raw forms must agree on the same large input.
    assert_eq!(decode_hex_32(&digest::sha256_hex(&big)), raw);
}

// ---------- rand::fill ----------

#[test]
fn fill_produces_a_nonzero_buffer() {
    let mut buf = [0u8; 64];
    rand::fill(&mut buf).expect("system RNG failed");
    assert!(
        buf.iter().any(|&b| b != 0),
        "64 freshly random bytes are all zero (p = 2^-512: the RNG is broken)"
    );
}

#[test]
fn fill_consecutive_fills_differ() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    rand::fill(&mut a).expect("system RNG failed");
    rand::fill(&mut b).expect("system RNG failed");
    assert_ne!(a, b, "two independent 64-byte fills collided");
}

// ---------- ct_eq ----------

#[test]
fn ct_eq_reports_equal_slices_equal() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(&[0xABu8; 32], &[0xABu8; 32]));
    assert!(ct_eq(b"release-digest-hex", b"release-digest-hex"));
}

#[test]
fn ct_eq_reports_different_same_length_slices_unequal() {
    let a = [0u8; 32];
    let mut b = [0u8; 32];
    b[31] = 1; // differ only in the final byte
    assert!(!ct_eq(&a, &b));
    assert!(!ct_eq(&b, &a));
}

#[test]
fn ct_eq_reports_different_length_slices_unequal_without_panicking() {
    assert!(!ct_eq(b"", b"x"));
    assert!(!ct_eq(b"x", b""));
    assert!(!ct_eq(&[0u8; 31], &[0u8; 32]));
    assert!(!ct_eq(&[0u8; 32], &[0u8; 64]));
}

// ---------- is_fips ----------

#[test]
fn is_fips_is_stable_across_calls() {
    assert_eq!(seaworthy_crypto::is_fips(), seaworthy_crypto::is_fips());
}

#[test]
fn is_fips_matches_its_documented_primitives() {
    // lib.rs defines is_fips() as: the AWS-LC backend is in FIPS mode AND
    // the canonical tls_provider() reports FIPS AND the installed rustls
    // default provider (if any) reports FIPS. Recompute every half
    // independently and require agreement, whatever the feature set.
    let backend_fips = aws_lc_rs::try_fips_mode().is_ok();
    let canonical_fips = seaworthy_crypto::tls_provider().fips();
    let default_fips =
        rustls::crypto::CryptoProvider::get_default().is_none_or(|provider| provider.fips());
    assert_eq!(
        seaworthy_crypto::is_fips(),
        backend_fips && canonical_fips && default_fips
    );
    // Without `fips` nothing is FIPS; with it, the canonical provider is
    // restricted, so no installed default is needed for a true answer.
    assert_eq!(seaworthy_crypto::is_fips(), cfg!(feature = "fips"));
}

// ---------- the canonical TLS provider ----------

#[test]
fn tls_provider_is_one_shared_provider() {
    let a = seaworthy_crypto::tls_provider();
    let b = seaworthy_crypto::tls_provider();
    assert!(std::sync::Arc::ptr_eq(&a, &b), "built once, shared");
    assert!(!a.cipher_suites.is_empty() && !a.kx_groups.is_empty());
}

/// Without `fips` the provider keeps rustls's full default set (and so
/// honestly reports non-FIPS); under `fips` (`rustls/fips` via
/// seaworthy-crypto's feature) ChaCha20-Poly1305 and plain X25519 are gone:
/// the half `is_fips()` checks.
#[test]
fn tls_provider_suites_follow_the_fips_feature() {
    let provider = seaworthy_crypto::tls_provider();
    let has_chacha = provider
        .cipher_suites
        .iter()
        .any(|suite| format!("{:?}", suite.suite()).contains("CHACHA20"));
    let has_x25519 = provider
        .kx_groups
        .iter()
        .any(|group| group.name() == rustls::NamedGroup::X25519);
    if cfg!(feature = "fips") {
        assert!(!has_chacha, "no ChaCha20-Poly1305 under fips");
        assert!(!has_x25519, "no plain X25519 under fips");
        assert!(provider.fips(), "the restricted provider reports FIPS");
    } else {
        assert!(has_chacha && has_x25519, "the unrestricted default set");
        assert!(!provider.fips());
    }
}
