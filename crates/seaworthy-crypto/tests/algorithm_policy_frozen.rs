//! One configured authority: an intake point that already consulted the
//! default algorithm policy must not have its answer changed under it;
//! installing after a read is the typed `AlreadyRead`. One test function in
//! its own binary: the policy is one-shot process state.

use seaworthy_crypto::fips_policy::{self, AlgorithmPolicy, PolicyInstallError, Service};

#[test]
fn installing_after_a_read_is_refused() {
    // An intake point consults the gate first (and gets the default).
    fips_policy::ensure_approved(Service::Ed25519).expect("the default admits Ed25519");
    let observed = fips_policy::policy();
    assert_eq!(observed, AlgorithmPolicy::DEFAULT);
    assert_eq!(
        fips_policy::install_policy(AlgorithmPolicy::ML_DSA_87_ONLY),
        Err(PolicyInstallError::AlreadyRead)
    );
    // Whatever was observed stays the answer.
    assert_eq!(fips_policy::policy(), observed);
    fips_policy::ensure_approved(Service::Ed25519).expect("still the default");
}
