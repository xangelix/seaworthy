//! `tls::install_policy`: installed first thing at boot, the policy shapes
//! the canonical provider; a second install is refused. One
//! test function (the policy is one-shot process state, so the sequence
//! runs in ONE process under both nextest and `cargo test`).

use rustls::NamedGroup;
use seaworthy_crypto::tls::{
    self, KxGroup, MinTlsVersion, SuiteProfile, TlsPolicy, TlsPolicyError,
};

#[test]
fn an_installed_policy_shapes_the_provider_and_a_second_install_is_refused() {
    let policy = TlsPolicy::from_config(|key| {
        Ok::<_, String>(match key {
            tls::GROUPS_KEY => Some("SECP256R1MLKEM768,X25519MLKEM768,SECP384R1".to_owned()),
            tls::MIN_VERSION_KEY => Some("1.3".to_owned()),
            tls::REQUIRE_HYBRID_KEY => Some("true".to_owned()),
            tls::SUITES_KEY => Some("aes256".to_owned()),
            _ => None,
        })
    })
    .expect("a valid policy");
    tls::install_policy(policy.clone()).expect("installed before any read");

    assert_eq!(tls::policy(), &policy);
    let provider = seaworthy_crypto::tls_provider();
    let groups: Vec<NamedGroup> = provider.kx_groups.iter().map(|g| g.name()).collect();
    // Hybrid required: P-384 is gone; the configured order holds.
    assert_eq!(
        groups,
        [NamedGroup::secp256r1MLKEM768, NamedGroup::X25519MLKEM768]
    );
    // TLS 1.3 minimum + aes256: one suite left.
    let suites: Vec<rustls::CipherSuite> =
        provider.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(suites, [rustls::CipherSuite::TLS13_AES_256_GCM_SHA384]);
    assert_eq!(tls::protocol_versions(), [&rustls::version::TLS13]);
    assert_eq!(policy.min_version(), MinTlsVersion::Tls13);
    assert_eq!(policy.suites(), SuiteProfile::Aes256Only);
    // A client config built now carries the installed policy's provider.
    let config = tls::client_config_builder()
        .expect("TLS 1.3")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(std::sync::Arc::ptr_eq(config.crypto_provider(), &provider));
    // The process default follows the policy too.
    assert!(seaworthy_crypto::install_default_tls_provider());
    let default = rustls::crypto::CryptoProvider::get_default().expect("installed");
    assert_eq!(
        default
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect::<Vec<_>>(),
        groups
    );

    assert_eq!(
        tls::install_policy(TlsPolicy::default().with_groups([KxGroup::Secp256r1Mlkem768])),
        Err(TlsPolicyError::AlreadyInstalled)
    );
}
