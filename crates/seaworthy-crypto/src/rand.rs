//! Secure randomness: AWS-LC's `SystemRandom`, i.e. the AWS-LC CTR_DRBG.
//! Under `fips` it is the AWS-LC FIPS 4.2.0 module's SP 800-90A CTR_DRBG,
//! seeded inside the module (CPU-jitter entropy, which the 4.x module always
//! builds in, plus OS entropy), not a direct read of the operating system's
//! CSPRNG. The first draw of a process runs the jitter source's startup
//! health tests; [`crate::module::startup_self_check`] makes that happen at
//! boot.

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

use crate::CryptoError;

/// Fill `bytes` from the AWS-LC CTR_DRBG (the FIPS module's DRBG under
/// `fips`; see the module docs).
///
/// # Errors
/// [`CryptoError::Rng`] when the DRBG fails.
pub fn fill(bytes: &mut [u8]) -> Result<(), CryptoError> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|_| CryptoError::Rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_handles_empty_and_varied_lengths() {
        let mut empty: [u8; 0] = [];
        fill(&mut empty).expect("a zero-length fill is a no-op, not an error");
        for len in [1usize, 12, 64, 1024] {
            let mut buf = vec![0u8; len];
            fill(&mut buf).expect("fill");
            assert_eq!(buf.len(), len, "fill writes exactly the given buffer");
        }
        // A 1 KiB all-zero outcome is a broken RNG, not bad luck (2^-8192).
        let mut buf = [0u8; 1024];
        fill(&mut buf).expect("fill");
        assert!(buf.iter().any(|&b| b != 0));
    }
}
