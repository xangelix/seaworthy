//! The canonical provider's TLS policy: the EXACT key-exchange group order,
//! pinned in both the default and the `fips` build. A regression here is
//! silent in production (a client leading with a classical group makes
//! every connection to a hybrid-capable server classical, with no error and
//! no log), so the order is a test, not a convention.
//!
//! This binary installs no policy (the defaults are under test); the
//! install/freeze semantics live in their own binaries
//! (`tls_policy_install.rs`, `tls_policy_frozen.rs`) — the policy is
//! one-shot process state.

use rustls::NamedGroup;

/// The default order, per build: both hybrids first (X25519MLKEM768, then
/// the P-256 hybrid a FIPS-mode peer without X25519 negotiates), then
/// classical; plain X25519 only outside `fips`.
fn expected_default_order() -> Vec<NamedGroup> {
    if cfg!(feature = "fips") {
        vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::secp256r1MLKEM768,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ]
    } else {
        vec![
            NamedGroup::X25519MLKEM768,
            NamedGroup::secp256r1MLKEM768,
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::secp384r1,
        ]
    }
}

#[test]
fn tls_provider_offers_exactly_the_policy_groups_in_order() {
    let groups: Vec<NamedGroup> = seaworthy_crypto::tls_provider()
        .kx_groups
        .iter()
        .map(|group| group.name())
        .collect();
    assert_eq!(groups, expected_default_order());
}

#[test]
fn the_first_offered_group_is_a_hybrid_in_every_build() {
    let provider = seaworthy_crypto::tls_provider();
    let first = provider.kx_groups.first().expect("a group").name();
    assert!(
        seaworthy_crypto::tls::is_post_quantum_group(first),
        "first group {first:?} is classical"
    );
}

/// `prefer-post-quantum` is stated by seaworthy-crypto itself, so even
/// third-party code that builds rustls's OWN default provider leads with
/// the hybrid, never by grace of another crate's features.
#[test]
fn rustls_own_default_provider_is_hybrid_first_without_unification() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    assert_eq!(
        provider.kx_groups.first().map(|group| group.name()),
        Some(NamedGroup::X25519MLKEM768)
    );
}

#[test]
fn the_default_policy_is_reported_and_backward_compatible() {
    let policy = seaworthy_crypto::tls::policy();
    assert_eq!(
        policy.min_version(),
        seaworthy_crypto::tls::MinTlsVersion::Tls12
    );
    assert!(!policy.requires_hybrid());
    assert_eq!(
        policy.suites(),
        seaworthy_crypto::tls::SuiteProfile::Default
    );
    // TLS 1.2 stays available by default (as far as the rustls build has
    // it): the policy itself never narrows the versions unasked.
    assert_eq!(
        seaworthy_crypto::tls::protocol_versions(),
        rustls::DEFAULT_VERSIONS
    );
    // AES-256-GCM is the first suite.
    assert_eq!(
        seaworthy_crypto::tls_provider()
            .cipher_suites
            .first()
            .map(|s| s.suite()),
        Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
    );
}

#[test]
fn the_post_quantum_provider_keeps_only_ml_kem_groups_in_order() {
    let groups: Vec<NamedGroup> = seaworthy_crypto::tls::post_quantum_provider()
        .expect("the defaults list hybrids")
        .kx_groups
        .iter()
        .map(|g| g.name())
        .collect();
    assert_eq!(
        groups,
        [NamedGroup::X25519MLKEM768, NamedGroup::secp256r1MLKEM768]
    );
}

#[test]
fn the_client_config_builder_takes_the_canonical_provider() {
    let config = seaworthy_crypto::tls::client_config_builder()
        .expect("versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(std::sync::Arc::ptr_eq(
        config.crypto_provider(),
        &seaworthy_crypto::tls_provider()
    ));
}
