//! ML-DSA-87 signatures (FIPS 204, pure: no context string) over AWS-LC.
//!
//! This is the post-quantum release-signing option. Of the facade's three
//! signature schemes:
//!
//! - **ML-DSA-87** (this module): post-quantum. **FIPS status:** under
//!   `seaworthy-crypto/fips` it runs in the AWS-LC FIPS 4.2.0 module (CMVP:
//!   in process, Comment Resolution), whose service indicator approves it;
//!   it is NOT on the validated AWS-LC 3 certificate (#5314/#5298 lack
//!   ML-DSA), so `fips_policy::Posture::CertifiedOnly` refuses it.
//! - **ECDSA P-256/SHA-256** ([`crate::ecdsa`]): approved by the 4.2.0
//!   module AND on the validated AWS-LC 3 certificate; not post-quantum.
//! - **Ed25519** ([`crate::ed25519`]): the fast/compact classical option,
//!   an approved service (EdDSA, FIPS 186-5), on the validated AWS-LC 3
//!   certificate too (see [`crate::fips_policy`]).
//!
//! **Public keys.** FIPS 204 defines no public-key validation: any 2592
//! bytes are a key to the verifier, and many of them (an all-zero `t1`, a
//! single non-zero coefficient, every coefficient 512, ...) verify a
//! signature anyone can compute from public data. [`validate_public_key`]
//! runs seaworthy's intake test, at intake and inside every [`verify`]: it
//! refuses those known forgery classes and any key whose forgeability is
//! measurable (the `intake` module documents the test and its false-reject
//! bound). It is defense in depth: trust only keys from your own
//! `seaworthy keygen` or HSM, or from their holder over an authenticated
//! channel.
//!
//! Key custody: the 32-byte seed ([`SigningKey::from_seed`]) is the root
//! secret; compromise of the seed is compromise of the key. That is also
//! what makes it the right shape for deterministic release keys: keep it in
//! a KMS/HSM or a sealed secret store, never in the repository.

use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
};
use zeroize::Zeroizing;

use crate::CryptoError;

mod intake;

/// Seed length in bytes (FIPS 204: all ML-DSA variants use 32-byte seeds).
pub const SEED_LEN: usize = 32;
/// Raw public key length in bytes (ML-DSA-87).
pub const PUBLIC_KEY_LEN: usize = 2592;
/// Raw signature length in bytes (ML-DSA-87).
pub const SIGNATURE_LEN: usize = 4627;

/// An ML-DSA-87 signing key. The private half never appears in this API in
/// the clear — custody is the 32-byte seed or the PKCS#8 document.
pub struct SigningKey(PqdsaKeyPair);

impl SigningKey {
    /// Generate a fresh keypair from the AWS-LC DRBG (the FIPS module's
    /// CTR_DRBG under `fips`).
    ///
    /// # Errors
    /// [`CryptoError::Rng`] on keygen failure.
    pub fn generate() -> Result<Self, CryptoError> {
        PqdsaKeyPair::generate(&ML_DSA_87_SIGNING)
            .map(Self)
            .map_err(|_| CryptoError::Rng)
    }

    /// Expand a keypair deterministically from a 32-byte seed — per FIPS
    /// 204 the same seed always produces the same keypair, so this is how
    /// deterministic release keys are reproduced on signing hosts.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] when `seed` is not exactly
    /// [`SEED_LEN`] bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, seed)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Serialize the private key to a PKCS#8 v1 document — AWS-LC emits the
    /// compact *seed* form (the expanded key is ~4.9 KB; this is tens of
    /// bytes). Private key material, so it comes back in a zeroizing
    /// wrapper: dropping it scrubs the bytes from memory.
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] if the key cannot be serialized.
    pub fn to_pkcs8v1(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.0
            .to_pkcs8v1()
            .map(|document| Zeroizing::new(document.as_ref().to_vec()))
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// Load a keypair from its PKCS#8 document (seed or expanded form).
    ///
    /// # Errors
    /// [`CryptoError::InvalidKey`] when the bytes are not a valid PKCS#8
    /// ML-DSA-87 key.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, CryptoError> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidKey)
    }

    /// The raw [`PUBLIC_KEY_LEN`]-byte public key (the form applications
    /// embed for signature verification).
    #[allow(
        clippy::expect_used,
        reason = "the algorithm fixes the output length; the conversion cannot fail"
    )]
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
            .public_key()
            .as_ref()
            .try_into()
            .expect("ML-DSA-87 public keys are 2592 bytes")
    }

    /// Sign `message`; returns the raw [`SIGNATURE_LEN`]-byte signature.
    ///
    /// ML-DSA signs *messages* (there is no pre-hashed variant in the pure
    /// scheme) — signing a digest means passing the digest bytes as the
    /// message, which is exactly what the release pipeline does.
    #[allow(
        clippy::expect_used,
        reason = "a valid key and an exact-size buffer leave AWS-LC no error path (its hedged \
                  signing RNG aborts on entropy failure rather than returning)"
    )]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let mut signature = [0u8; SIGNATURE_LEN];
        self.0
            .sign(message, &mut signature)
            .expect("ML-DSA-87 signing with a valid key and an exact-size buffer cannot fail");
        signature
    }
}

/// Validate a raw ML-DSA-87 public key at INTAKE (enrollment, config/key
/// install) and, defense in depth, inside every [`verify`].
///
/// FIPS 204 defines no public-key validation, and AWS-LC performs none.
/// The verifier computes `w1' = UseHint(h, A·z − c·t1·2^d)`, so with
/// `z = 0` and `h = 0` a signature `(c̃ = H(μ ‖ w1Encode(0)), 0, 0)`, which
/// anyone can compute, verifies whenever `HighBits(−c·t1·2^d)` is zero for
/// the challenge `c` it derives: always for an all-zero `t1`, for a `t1`
/// with one coefficient `1`, for every coefficient `512`, and for other
/// structured keys (reproduced against AWS-LC and pinned in
/// `tests/mldsa.rs`).
///
/// The intake test refuses, after fast pre-filters (all-zero, low-weight
/// and periodic `t1` polynomials), any key under which `HighBits(−c·t1·2^d)`
/// has too few non-zero coefficients for any of 128 fixed challenges: a
/// genuine key has about 1920 of 2048, a forgeable one (nearly) none. A
/// genuine key is refused with probability below `2^-147` (the derivation
/// is in the `intake` module). It refuses the known forgery classes and
/// keys whose forgeability is measurable, but cannot rule out every
/// conceivable weak key: trust keys only from your own `seaworthy keygen`
/// or HSM, or from their holder over an authenticated channel.
///
/// Costs about a millisecond (pure arithmetic over the public key).
///
/// # Errors
/// [`CryptoError::InvalidKey`] for a wrong-length key or one the intake
/// test refuses.
pub fn validate_public_key(public_key: &[u8]) -> Result<(), CryptoError> {
    intake::check(public_key).map_err(|_| CryptoError::InvalidKey)
}

/// Verify `signature` over `message` against a raw [`PUBLIC_KEY_LEN`]-byte
/// public key. The key is [validated][validate_public_key] first (defense
/// in depth: a forgeable key that slipped past intake stops verifying).
///
/// # Errors
/// [`CryptoError::InvalidKey`] for wrong-length or forgeable
/// ([`validate_public_key`]) key material or a wrong-length signature;
/// [`CryptoError::InvalidSignature`] when verification fails (including
/// valid-length garbage keys, which ML-DSA cannot distinguish from a wrong
/// key).
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(CryptoError::InvalidKey);
    }
    validate_public_key(public_key)?;
    UnparsedPublicKey::new(&ML_DSA_87, public_key)
        .verify(message, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let key = SigningKey::generate().expect("generate");

        let signature = key.sign(b"seaworthy");
        assert!(verify(&key.public_key(), b"seaworthy", &signature).is_ok());
        assert!(verify(&key.public_key(), b"other", &signature).is_err());
        assert!(
            verify(
                &key.public_key()[..PUBLIC_KEY_LEN - 1],
                b"seaworthy",
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn generated_keypairs_are_distinct_and_sign_only_for_themselves() {
        // Key generation is CSPRNG-driven: two keygens must not repeat,
        // and each key's signatures verify only under its own public half.
        let a = SigningKey::generate().expect("generate a");
        let b = SigningKey::generate().expect("generate b");
        assert_ne!(a.public_key(), b.public_key(), "keygen must not repeat");

        let signature = a.sign(b"message");
        assert!(verify(&a.public_key(), b"message", &signature).is_ok());
        assert!(matches!(
            verify(&b.public_key(), b"message", &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn pkcs8_document_is_zeroizing() {
        // The PKCS#8 document is the private key (seed form): it must come
        // back in a zeroizing wrapper so dropping it scrubs the bytes.
        let key = SigningKey::generate().expect("generate");
        let pkcs8 = key.to_pkcs8v1().expect("serialize");
        let _: &zeroize::Zeroizing<Vec<u8>> = &pkcs8;
    }
}
