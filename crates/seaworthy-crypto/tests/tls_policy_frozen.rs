//! `tls::install_policy` after the provider was first read is refused:
//! live configs were already built from the default policy, so a
//! later policy would describe TLS nothing negotiates. One test function —
//! the policy is one-shot process state.

use seaworthy_crypto::tls::{self, TlsPolicy, TlsPolicyError};

#[test]
fn a_policy_installed_after_the_first_provider_read_is_refused() {
    let before = seaworthy_crypto::tls_provider();
    assert_eq!(
        tls::install_policy(TlsPolicy::default().with_require_hybrid(true)),
        Err(TlsPolicyError::AlreadyFrozen)
    );
    // Nothing changed underneath the live reader.
    assert!(std::sync::Arc::ptr_eq(
        &before,
        &seaworthy_crypto::tls_provider()
    ));
    assert!(!tls::policy().requires_hybrid());
    // An invalid policy is refused before the freeze check.
    assert!(matches!(
        tls::install_policy(TlsPolicy::default().with_groups([])),
        Err(TlsPolicyError::NoGroups { .. })
    ));
}
