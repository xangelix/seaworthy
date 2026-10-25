//! One process, one first random draw: a probe for measuring how often the
//! CPU-jitter entropy source's startup health tests fail on a given host.
//!
//! AWS-LC seeds its DRBG lazily, on the first `RAND_bytes` of a process.
//! With the CPU-jitter entropy source linked in (every FIPS build; every
//! non-FIPS build too unless `AWS_LC_SYS_NO_JITTER_ENTROPY_<target>` opts
//! out), that first draw runs the jitter collector's startup health tests
//! and the process `abort()`s when they fail: a silent `0xC0000409`
//! fast-fail on Windows, no panic, no output. The only way to see the rate
//! is to start many fresh processes and count the ones that die, which is
//! all this binary is for: the draw comes FIRST (nothing else may seed the
//! DRBG earlier), then one line on stdout for a script to check.
//!
//! ```text
//! entropy_probe          -> "entropy_probe ok fips=<true|false>", exit 0
//! ```

fn main() -> Result<(), seaworthy_crypto::CryptoError> {
    let mut seed = [0u8; 32];
    // The first random draw of the process.
    seaworthy_crypto::rand::fill(&mut seed)?;
    // Only after the draw: the posture needs the process-default provider
    // (`is_fips()` = FIPS backend ∧ FIPS provider ∧ any installed default).
    let _ = seaworthy_crypto::install_default_tls_provider();
    println!("entropy_probe ok fips={}", seaworthy_crypto::is_fips());
    Ok(())
}
