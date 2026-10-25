//! The installed algorithm policy, through the PROCESS-GLOBAL install. Its
//! own test binary on purpose: the policy is install-once process state.
//! The install sequence is ONE test function, so it runs in one process,
//! in order, under both nextest and `cargo test` (libtest runs the tests of
//! a binary on parallel threads of one process); the read-before-install
//! refusal lives in its own binary (`algorithm_policy_frozen.rs`).

use seaworthy_crypto::CryptoError;
use seaworthy_crypto::fips_policy::{
    self, AlgorithmPolicy, PolicyInstallError, Posture, Service, SignatureSet,
};

/// The post-quantum preset, installed first thing: ML-DSA-87 is the only
/// signature algorithm any intake point admits; Ed25519 and ECDSA are
/// refused by name with the typed `NotAllowed`. Install-once: a second
/// install is the typed `AlreadySet` (or `AlreadyRead`, once an intake
/// point consulted the policy), never a silent swap under live intake
/// points.
#[test]
fn the_installed_preset_governs_every_intake_and_a_second_install_is_refused() {
    fips_policy::install_policy(AlgorithmPolicy::ML_DSA_87_ONLY)
        .expect("installed before any intake point read the policy");
    assert_eq!(
        fips_policy::install_policy(AlgorithmPolicy::DEFAULT),
        Err(PolicyInstallError::AlreadySet),
        "a second install before any read"
    );

    assert_eq!(fips_policy::policy(), AlgorithmPolicy::ML_DSA_87_ONLY);
    fips_policy::ensure_approved(Service::MlDsa87).expect("ML-DSA-87 is admitted");
    for refused in [Service::Ed25519, Service::EcdsaP256] {
        let err = fips_policy::ensure_approved(refused).expect_err("refused by the policy");
        assert!(
            matches!(err, CryptoError::NotAllowed { service, .. } if service == refused.name()),
            "typed refusal naming {refused:?}: {err}"
        );
        assert!(err.to_string().contains(refused.name()), "{err}");
    }

    let err = fips_policy::install_policy(AlgorithmPolicy::DEFAULT).expect_err("second install");
    assert!(
        matches!(
            err,
            PolicyInstallError::AlreadySet | PolicyInstallError::AlreadyRead
        ),
        "{err}"
    );
    assert_eq!(fips_policy::policy(), AlgorithmPolicy::ML_DSA_87_ONLY);
}

/// The presets, as data: the default admits every signature algorithm the
/// facade offers under the linked module's indicator, the post-quantum
/// preset narrows the signature set only, the certified-only preset changes
/// the posture axis. (Touches no process state.)
#[test]
fn presets_are_what_their_names_say() {
    assert_eq!(AlgorithmPolicy::DEFAULT.signatures, SignatureSet::ALL);
    assert_eq!(
        AlgorithmPolicy::DEFAULT.posture,
        Posture::ApprovedInLinkedModule
    );
    assert_eq!(
        AlgorithmPolicy::ML_DSA_87_ONLY.signatures,
        SignatureSet::ML_DSA_87_ONLY
    );
    assert_eq!(
        AlgorithmPolicy::ML_DSA_87_ONLY.posture,
        Posture::ApprovedInLinkedModule
    );
    assert_eq!(
        AlgorithmPolicy::CERTIFIED_ONLY.posture,
        Posture::CertifiedOnly
    );
    for service in [Service::MlDsa87, Service::Ed25519, Service::EcdsaP256] {
        assert!(SignatureSet::ALL.contains(service), "{service:?}");
    }
    assert!(SignatureSet::ML_DSA_87_ONLY.contains(Service::MlDsa87));
    assert!(!SignatureSet::ML_DSA_87_ONLY.contains(Service::Ed25519));
}
