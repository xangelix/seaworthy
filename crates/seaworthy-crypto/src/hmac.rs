//! Message authentication codes (AWS-LC HMAC): HMAC-SHA-256, the MAC of
//! the S3 publisher's AWS Signature Version 4 chain (four chained HMACs
//! derive the signing key, a fifth signs the request).
//!
//! **The 112-bit key floor.** SP 800-131A Rev. 2 §5 (and the AWS-LC
//! Security Policies' HMAC key length, 112–524288 bits) puts approved HMAC
//! at keys of at least [`MIN_KEY_LEN`] bytes. Every entry point here runs
//! [`ensure_key_strength`] first: under the `fips` feature (approved
//! services only) a shorter key is refused with
//! [`CryptoError::NotApproved`], and the certified-only
//! [`AlgorithmPolicy`] refuses it in any build; a default non-FIPS build is
//! unchanged. Intake points call [`ensure_key_strength`] when the secret is
//! CONFIGURED, so a short secret is a startup error rather than a failed
//! request.

use aws_lc_rs::hmac;

use crate::CryptoError;
use crate::fips_policy::{self, AlgorithmPolicy, Service};

/// The HMAC key-length floor: 14 bytes = 112 bits.
pub const MIN_KEY_LEN: usize = 14;

/// THE HMAC key-strength gate: a key of at least [`MIN_KEY_LEN`] bytes
/// passes; a shorter one is [`Service::HmacShortKey`] through
/// [`fips_policy::ensure_approved`]: refused under `fips`, and by the
/// installed certified-only policy. Only a SHORT key consults the policy
/// (so an HMAC never freezes the policy install at startup). Intake points
/// call this when a secret is configured.
///
/// # Errors
/// [`CryptoError::NotApproved`] / [`CryptoError::NotAllowed`] naming the
/// service.
pub fn ensure_key_strength(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() >= MIN_KEY_LEN {
        return Ok(());
    }
    fips_policy::ensure_approved(Service::HmacShortKey)
}

/// [`ensure_key_strength`] with the posture and the policy explicit: the
/// pure form every build profile can test.
///
/// # Errors
/// As [`ensure_key_strength`].
pub fn ensure_key_strength_for(
    key: &[u8],
    approved_only: bool,
    policy: &AlgorithmPolicy,
) -> Result<(), CryptoError> {
    if key.len() >= MIN_KEY_LEN {
        return Ok(());
    }
    fips_policy::ensure_admitted_by(Service::HmacShortKey, approved_only, policy)
}

/// HMAC-SHA-256 over `message`.
///
/// # Errors
/// A key below [`MIN_KEY_LEN`] as [`ensure_key_strength`] refuses it.
#[allow(
    clippy::expect_used,
    reason = "the algorithm fixes the output length; the conversion cannot fail"
)]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<[u8; 32], CryptoError> {
    ensure_key_strength(key)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    Ok(hmac::sign(&key, message)
        .as_ref()
        .try_into()
        .expect("HMAC-SHA-256 output is 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;
    use crate::fips_policy::AlgorithmPolicy;

    /// The floor is 112 bits (SP 800-131A Rev. 2 §5; the AWS-LC 3 Security
    /// Policy's HMAC key length 112–524288 bits).
    #[test]
    fn the_key_floor_is_112_bits() {
        assert_eq!(MIN_KEY_LEN * 8, 112);
    }

    /// A key below the floor is refused under the approved-only (`fips`)
    /// posture, by the certified-only policy in any build, and admitted
    /// otherwise (non-FIPS defaults unchanged).
    #[test]
    fn short_keys_are_refused_by_the_posture_and_the_policy() {
        let short = [0x0b; MIN_KEY_LEN - 1];
        let err = ensure_key_strength_for(&short, true, &AlgorithmPolicy::DEFAULT)
            .expect_err("refused under fips");
        assert!(
            matches!(err, CryptoError::NotApproved(name) if name.contains("112")),
            "names the floor: {err}"
        );
        assert!(
            ensure_key_strength_for(&[0x0b; MIN_KEY_LEN], true, &AlgorithmPolicy::DEFAULT).is_ok()
        );
        assert!(
            ensure_key_strength_for(&short, false, &AlgorithmPolicy::DEFAULT).is_ok(),
            "a non-FIPS default build is unchanged"
        );
        assert!(matches!(
            ensure_key_strength_for(&short, false, &AlgorithmPolicy::CERTIFIED_ONLY),
            Err(CryptoError::NotAllowed { .. })
        ));
        assert!(ensure_key_strength_for(&short, false, &AlgorithmPolicy::ML_DSA_87_ONLY).is_ok());
    }

    /// The facade's entry point applies the floor per the build's posture.
    #[test]
    fn the_hmac_entry_point_applies_the_floor() {
        let short = [0x0b; MIN_KEY_LEN - 1];
        assert_eq!(hmac_sha256(&short, b"m").is_err(), cfg!(feature = "fips"));
        assert!(hmac_sha256(&[0x0b; MIN_KEY_LEN], b"m").is_ok());
    }

    #[test]
    fn hmac_sha256_known_answer() {
        // RFC 4231 test case 1.
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There").expect("20-byte key")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 test case 6: a 131-byte key, longer than the block,
        // exercises the key-hashing path.
        assert_eq!(
            hex::encode(
                hmac_sha256(
                    &[0xaa; 131],
                    b"Test Using Larger Than Block-Size Key - Hash Key First"
                )
                .expect("131-byte key")
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_sha256_is_key_and_message_sensitive() {
        // The MAC's whole contract: deterministic on the same input,
        // different under any other key or message. (Keys at the 112-bit
        // floor: the suite also runs under `fips`.)
        let mac = |key: &[u8], message: &[u8]| hmac_sha256(key, message).expect("floor-sized key");
        let tag = mac(b"key-at-the-floor", b"message");
        assert_eq!(tag, mac(b"key-at-the-floor", b"message"), "deterministic");
        assert_ne!(
            tag,
            mac(b"key-at-the-floor2", b"message"),
            "wrong key mismatches"
        );
        assert_ne!(
            tag,
            mac(b"key-at-the-floor", b"message2"),
            "wrong message mismatches"
        );
        assert_ne!(
            tag,
            mac(b"key-at-the-floor", b"message\0"),
            "an appended NUL is a different message"
        );
    }
}
