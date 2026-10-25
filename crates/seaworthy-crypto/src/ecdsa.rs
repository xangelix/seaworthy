//! ECDSA over NIST P-256 with SHA-256 (ASN.1/DER signatures) via AWS-LC.
//!
//! This is the **FIPS-approved-today** release-signing option: ECDSA P-256
//! with SHA-256 is approved by the linked AWS-LC FIPS 4.2.0 module (CMVP: in
//! process) AND listed on the validated AWS-LC 3 certificate (#5314/#5298),
//! as is Ed25519 ([`crate::ed25519`], EdDSA), unlike ML-DSA
//! ([`crate::mldsa`], approved by 4.2.0, not on the AWS-LC 3 certificate).
//! It is not post-quantum.
//!
//! **Malleability.** ECDSA signatures are malleable: for every valid
//! `(r, s)`, the counterpart `(r, n−s)` (the group order minus `s`) over the
//! same message also verifies. The verifier in this module is plain AWS-LC
//! verification: there is no low-S normalization (FIPS does not require it,
//! and the facade deliberately avoids a bignum dependency just to
//! canonicalize). Consumers must therefore NEVER treat signature bytes as a
//! uniqueness anchor: no dedup keys, no "have I seen this signature"
//! fingerprints, because two different byte strings can attest the same
//! message under the same key. Anchor on the message digest instead. (The
//! `malleated_counterpart_signature_also_verifies_no_low_s_enforcement`
//! test pins this behavior.)

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use zeroize::Zeroizing;

use crate::CryptoError;

/// An ECDSA P-256 signing key. The private half never appears in this API
/// in the clear: custody is the PKCS#8 document at rest.
pub struct SigningKey(EcdsaKeyPair);

impl SigningKey {
    /// Generate a fresh keypair; returns the key and its PKCS#8 document
    /// (the only form the private key should ever be stored in). The
    /// document is private key material, so it comes back in a zeroizing
    /// wrapper: dropping it scrubs the bytes from memory.
    ///
    /// # Errors
    /// [`CryptoError::Rng`] when the RNG fails.
    pub fn generate_pkcs8() -> Result<(Self, Zeroizing<Vec<u8>>), CryptoError> {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .map_err(|_| CryptoError::Rng)?;
        let pair = Self::from_pkcs8(pkcs8.as_ref())?;
        Ok((pair, Zeroizing::new(pkcs8.as_ref().to_vec())))
    }

    /// Load a keypair from its PKCS#8 document.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] when the bytes are not a valid PKCS#8
    /// P-256 key.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// The public key as a DER-encoded X.509 `SubjectPublicKeyInfo`: the
    /// interoperable form applications embed for signature verification
    /// (PEM-wrap it for configuration files). Verifying also accepts the raw
    /// X9.62 uncompressed point; see [`verify`].
    #[allow(
        clippy::expect_used,
        reason = "marshalling an in-memory P-256 point to SPKI fails only on allocation failure, \
                  which aborts the process anyway"
    )]
    pub fn public_key_der(&self) -> Vec<u8> {
        self.0
            .public_key()
            .as_der()
            .expect("P-256 public keys always marshal to SPKI")
            .as_ref()
            .to_vec()
    }

    /// Sign `message`; returns the ASN.1/DER-encoded signature (variable
    /// length, 70–72 bytes for P-256).
    ///
    /// # Errors
    /// [`CryptoError::Rng`] if signing fails (ECDSA signing consumes
    /// randomness per signature).
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0
            .sign(&SystemRandom::new(), message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| CryptoError::Rng)
    }
}

/// Verify an ASN.1/DER `signature` over `message` against a P-256 public
/// key given either as a DER-encoded X.509 `SubjectPublicKeyInfo` (the
/// [`SigningKey::public_key_der`] export) or as the raw X9.62 uncompressed
/// point (65 bytes).
///
/// Malleability: signatures are not canonical (see the module docs); never
/// fingerprint signature bytes.
///
/// # Errors
/// [`CryptoError::InvalidSignature`] when verification fails. AWS-LC does
/// not distinguish malformed key material from a bad signature on this
/// path, so both surface as `InvalidSignature`; unlike the fixed-length
/// schemes ([`crate::mldsa`], [`crate::ed25519`]) there is no useful length
/// pre-check for two accepted key encodings.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    // No facade-side key check needed (unlike `mldsa`/`ed25519`): AWS-LC
    // validates the point (on the curve, not the point at infinity, reduced
    // coordinates) before verifying, and a key it rejects fails here as
    // `InvalidSignature` (pinned by `tests/ecdsa.rs`).
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Validate a P-256 public key at INTAKE (a release-key embed, a
/// configuration install): the DER `SubjectPublicKeyInfo` or raw X9.62
/// uncompressed point [`verify`] accepts, parsed through AWS-LC, which
/// refuses off-curve points, the point at infinity, and unreduced
/// coordinates. The verify-time check is AWS-LC's own; this gives intake a
/// loud, early, named failure instead of a silent never-verifies key (the
/// same intake discipline as the other two schemes).
///
/// # Errors
/// [`CryptoError::InvalidKey`] when AWS-LC rejects the key.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    aws_lc_rs::signature::ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let (key, pkcs8) = SigningKey::generate_pkcs8().expect("generate");
        let loaded = SigningKey::from_pkcs8(&pkcs8).expect("parse");

        let signature = loaded.sign(b"seaworthy").expect("sign");
        assert!(verify(&key.public_key_der(), b"seaworthy", &signature).is_ok());
        assert!(verify(&key.public_key_der(), b"other", &signature).is_err());
    }

    #[test]
    fn generated_keypairs_are_distinct_and_sign_only_for_themselves() {
        // Key generation is CSPRNG-driven: two keygens must not repeat,
        // and each key's signatures verify only under its own public half.
        let (a, _) = SigningKey::generate_pkcs8().expect("generate a");
        let (b, _) = SigningKey::generate_pkcs8().expect("generate b");
        assert_ne!(
            a.public_key_der(),
            b.public_key_der(),
            "keygen must not repeat"
        );

        let signature = a.sign(b"message").expect("sign");
        assert!(verify(&a.public_key_der(), b"message", &signature).is_ok());
        assert!(matches!(
            verify(&b.public_key_der(), b"message", &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn generated_pkcs8_document_is_zeroizing() {
        // The PKCS#8 document is the private key: it must come back in a
        // zeroizing wrapper so dropping it scrubs the bytes from memory.
        let (_, pkcs8) = SigningKey::generate_pkcs8().expect("generate");
        let _: &zeroize::Zeroizing<Vec<u8>> = &pkcs8;
    }

    /// The P-256 group order n (FIPS 186-5 §B.4), big-endian.
    const P256_ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    /// Split a DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
    /// into `r` and `s` as 32-byte big-endian values. P-256 signatures are
    /// always short-form DER (under 128 bytes).
    fn der_to_r_s(signature: &[u8]) -> ([u8; 32], [u8; 32]) {
        assert_eq!(signature[0], 0x30, "SEQUENCE");
        assert_eq!(usize::from(signature[1]), signature.len() - 2);
        let mut rest = &signature[2..];
        let mut integer = || {
            assert_eq!(rest[0], 0x02, "INTEGER");
            let len = usize::from(rest[1]);
            let bytes = &rest[2..2 + len];
            rest = &rest[2 + len..];
            // Strip the sign-padding zero, then left-pad to 32 bytes.
            let bytes = &bytes[bytes.iter().take_while(|&&b| b == 0).count()..];
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(bytes);
            out
        };
        let r = integer();
        let s = integer();
        assert!(rest.is_empty(), "nothing after s");
        (r, s)
    }

    /// The DER encoding of a non-negative 32-byte big-endian INTEGER
    /// (minimal: leading zeros stripped, a zero prepended when the high bit
    /// is set).
    fn der_integer(value: &[u8; 32]) -> Vec<u8> {
        let zeros = value.iter().take_while(|&&b| b == 0).count().min(31);
        let mut body = value[zeros..].to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut out = vec![0x02, u8::try_from(body.len()).expect("short form")];
        out.extend_from_slice(&body);
        out
    }

    fn r_s_to_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let mut body = der_integer(r);
        body.extend_from_slice(&der_integer(s));
        let mut out = vec![0x30, u8::try_from(body.len()).expect("short form")];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn der_helpers_round_trip_real_signatures() {
        let (key, _) = SigningKey::generate_pkcs8().expect("generate");
        for _ in 0..16 {
            let signature = key.sign(b"round trip").expect("sign");
            let (r, s) = der_to_r_s(&signature);
            assert_eq!(r_s_to_der(&r, &s), signature);
        }
    }

    #[test]
    fn malleated_counterpart_signature_also_verifies_no_low_s_enforcement() {
        // PINS the module docs' malleability warning: for every valid
        // ECDSA signature (r, s), the counterpart (r, n−s) over the same
        // message ALSO verifies through the facade's `verify`: aws-lc-rs
        // does plain verification with no low-S normalization (the facade
        // deliberately avoids a bignum dependency just to canonicalize).
        // Consumers must never fingerprint signature bytes for
        // uniqueness/dedup.
        let (key, _) = SigningKey::generate_pkcs8().expect("generate");
        let public_key = key.public_key_der();
        let message = b"malleability pin";
        let signature = key.sign(message).expect("sign");
        verify(&public_key, message, &signature).expect("the original verifies");

        let (r, s) = der_to_r_s(&signature);
        // s' = n − s, 32-byte big-endian subtraction (s < n for every valid
        // signature, so the final borrow is 0).
        let mut malleated_s = [0u8; 32];
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let d = i16::from(P256_ORDER[i]) - i16::from(s[i]) - borrow;
            if d < 0 {
                malleated_s[i] = (d + 256) as u8;
                borrow = 1;
            } else {
                malleated_s[i] = d as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "s < n for a valid signature");
        assert_ne!(malleated_s, s, "n is odd, so n−s ≠ s always");
        let malleated = r_s_to_der(&r, &malleated_s);
        assert_ne!(malleated, signature);
        verify(&public_key, message, &malleated)
            .expect("the malleated counterpart also verifies: never fingerprint signature bytes");
    }
}
