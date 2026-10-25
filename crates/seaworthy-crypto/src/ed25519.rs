//! Ed25519 signing and verification. **FIPS status:** Ed25519 (EdDSA,
//! FIPS 186-5) IS an approved service of the AWS-LC FIPS module: the
//! validated AWS-LC 3 module (CMVP #5314/#5298) lists EdDSA
//! KeyGen/SigGen/SigVer on Ed25519 in its approved-algorithm and
//! approved-service tables, and the linked 4.2.0 module's service indicator
//! marks it approved (see [`crate::fips_policy`] for the sources). Ed25519
//! is the fast/compact classical option next to ECDSA P-256
//! ([`crate::ecdsa`]) and post-quantum ML-DSA-87 ([`crate::mldsa`]).
//!
//! Public keys are validated ([`validate_public_key`]) at intake and inside
//! [`verify`]: small-order and non-canonical points are refused, because
//! under the identity point anyone can "sign" anything.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Raw public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Raw signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// An ed25519 signing key. The private half never appears in this API —
/// custody is PKCS#8 bytes at rest.
pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Generate a fresh keypair; returns the key and its PKCS#8 document
    /// (the only form the private key should ever be stored in). The
    /// document is private key material, so it comes back in a zeroizing
    /// wrapper: dropping it scrubs the bytes from memory.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the OS RNG fails.
    pub fn generate_pkcs8() -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| CryptoError::Rng)?;
        let pair =
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| CryptoError::InvalidKey)?;
        Ok((Self(pair), Zeroizing::new(pkcs8.as_ref().to_vec())))
    }

    /// Load a keypair from its PKCS#8 document.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] when the bytes are not a valid PKCS#8
    /// ed25519 key.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ed25519KeyPair::from_pkcs8(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// The raw 32-byte public key (presented at enrollment).
    #[allow(
        clippy::expect_used,
        reason = "the algorithm fixes the output length; the conversion cannot fail"
    )]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("ed25519 public keys are 32 bytes")
    }

    /// Sign `message`; returns the raw 64-byte signature.
    #[allow(
        clippy::expect_used,
        reason = "the algorithm fixes the output length; the conversion cannot fail"
    )]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0
            .sign(message)
            .as_ref()
            .try_into()
            .expect("ed25519 signatures are 64 bytes")
    }
}

/// The `y` coordinates (little-endian, sign bit excluded) of the eight
/// small-order points of edwards25519 — libsodium's `has_small_order`
/// blocklist. Compared with the encoding's sign bit masked off, so the
/// high-bit (`x`-sign) variants of each entry are caught too. Every entry
/// satisfies `8·P = identity`.
const SMALL_ORDER_Y: [[u8; 32]; 5] = [
    // y = 0: the two order-4 points (x = ±√−1).
    [0; 32],
    // y = 1: the identity (order 1).
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    // The two y values of the four order-8 points.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // y = p − 1: the order-2 point (x = 0).
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Is the encoding's `y` (sign bit excluded) ≥ p = 2²⁵⁵ − 19? Such a `y`
/// is a non-canonical encoding of `y − p` (only `y ∈ [p, 2²⁵⁵)`, i.e. the
/// 19 aliases of `0..19`, exist).
fn non_canonical_y(public_key: &[u8; PUBLIC_KEY_LEN]) -> bool {
    public_key[31] & 0x7f == 0x7f
        && public_key[1..31].iter().all(|&byte| byte == 0xff)
        && public_key[0] >= 0xed
}

/// Validate a raw Ed25519 public key at INTAKE (enrollment, config/key
/// install) — and, defense in depth, inside every [`verify`].
///
/// RFC 8032 requires no public-key validation, and AWS-LC performs none
/// that catches small-order keys: under the identity point `A = 01 00…00`,
/// `R = identity`, `S = 0` satisfies `[S]B = R + [k]A` for EVERY challenge
/// `k`: a signature over any message with no secret (reproduced and pinned
/// in `tests/ed25519.rs`). Refused:
///
/// - every **small-order** point (the eight torsion points, sign-bit
///   variants included — `SMALL_ORDER_Y`);
/// - every **non-canonical** `y ≥ p` encoding.
///
/// A constant byte-table comparison — no bignum.
///
/// # Errors
/// [`CryptoError::InvalidKey`] for a wrong-length, small-order, or
/// non-canonical key.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    let key: &[u8; PUBLIC_KEY_LEN] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    if non_canonical_y(key) {
        return Err(CryptoError::InvalidKey);
    }
    let small_order = SMALL_ORDER_Y
        .iter()
        .any(|y| y[..31] == key[..31] && y[31] == key[31] & 0x7f);
    if small_order {
        return Err(CryptoError::InvalidKey);
    }
    Ok(())
}

/// Verify `signature` over `message` against a raw 32-byte public key. The
/// key is [validated][validate_public_key] first (defense in depth — a
/// small-order key that slipped past intake stops verifying).
///
/// # Errors
/// [`CryptoError::InvalidKey`] for wrong-length, small-order, or
/// non-canonical key material ([`validate_public_key`]) or a wrong-length
/// signature; [`CryptoError::InvalidSignature`] when verification fails.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(CryptoError::InvalidKey);
    }
    validate_public_key(public_key)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let (key, pkcs8) = SigningKey::generate_pkcs8().expect("generate");
        let loaded = SigningKey::from_pkcs8(&pkcs8).expect("parse");

        let signature = loaded.sign(b"seaworthy");
        assert!(verify(&key.public_key(), b"seaworthy", &signature).is_ok());
        assert!(verify(&key.public_key(), b"other", &signature).is_err());
        assert!(verify(&key.public_key()[..31], b"seaworthy", &signature).is_err());
    }

    #[test]
    fn generated_pkcs8_document_is_zeroizing() {
        // The PKCS#8 document is the private key: it must come back in a
        // zeroizing wrapper so dropping it scrubs the bytes from memory.
        // (A plain `Vec<u8>` would leave the key material behind.)
        let (_, pkcs8) = SigningKey::generate_pkcs8().expect("generate");
        let _: &zeroize::Zeroizing<Vec<u8>> = &pkcs8;
    }

    #[test]
    fn generated_keypairs_are_distinct_and_sign_only_for_themselves() {
        // Key generation is CSPRNG-driven: two keygens must not repeat,
        // and each key's signatures verify only under its own public half.
        let (a, a_doc) = SigningKey::generate_pkcs8().expect("generate a");
        let (b, b_doc) = SigningKey::generate_pkcs8().expect("generate b");
        assert_ne!(a.public_key(), b.public_key(), "keygen must not repeat");
        assert_ne!(a_doc.as_slice(), b_doc.as_slice());

        let signature = a.sign(b"message");
        assert!(verify(&a.public_key(), b"message", &signature).is_ok());
        assert!(matches!(
            verify(&b.public_key(), b"message", &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }
}
