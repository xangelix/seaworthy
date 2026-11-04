//! FIPS-posture tests, compiled only with `--features fips`.
//!
//! These live in their own integration-test binary (their own process) on
//! purpose: installing a rustls process-default crypto provider is global,
//! one-shot state, and it must not leak into the other test binaries that
//! observe `is_fips()` with no provider installed.

#![cfg(feature = "fips")]

#[test]
fn fips_backend_is_active_at_runtime() {
    // The AWS-LC FIPS module must actually be running in FIPS
    // mode — queried at runtime, not assumed from the compile-time feature.
    assert!(
        aws_lc_rs::try_fips_mode().is_ok(),
        "`fips` feature is enabled but the AWS-LC backend is not in FIPS mode"
    );
}

#[test]
fn is_fips_follows_the_canonical_provider_and_any_installed_default() {
    // is_fips() answers for the provider the TLS clients USE,
    // seaworthy_crypto::tls_provider(), FIPS-filtered by `rustls/fips`, so
    // it is true with no process default installed…
    assert!(aws_lc_rs::try_fips_mode().is_ok());
    let provider = seaworthy_crypto::tls_provider();
    assert!(provider.fips(), "the canonical provider is FIPS-restricted");
    assert!(seaworthy_crypto::is_fips());

    // …and installing the canonical provider as the process default keeps
    // it true (the idempotent helper installs once).
    assert!(seaworthy_crypto::install_default_tls_provider());
    assert!(
        !seaworthy_crypto::install_default_tls_provider(),
        "idempotent"
    );
    assert!(seaworthy_crypto::is_fips());
    assert_eq!(seaworthy_crypto::is_fips(), seaworthy_crypto::is_fips());
}

#[test]
fn even_rustls_default_provider_is_restricted_under_the_feature() {
    // Feature unification: with seaworthy-crypto/fips, rustls/fips is on for
    // the whole graph, so a stray `default_provider()` anywhere is
    // FIPS-filtered too.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    assert!(provider.fips());
}

/// The module this binary LINKS is an allowlisted AWS-LC FIPS module: the
/// release the build linked is on the allowlist, and the module reports, at
/// runtime, the version and branch the allowlist names for it (the version
/// string, `awslc_version()`; FIPS mode; the module branch, which the sys
/// crate's build-time constant agrees with). A `cargo update` to an unlisted
/// module (refused at build time), or a system AWS-LC picked up at build
/// time, fails here.
#[test]
fn the_linked_module_is_an_allowlisted_aws_lc_fips_module() {
    let linked = seaworthy_crypto::module::linked();
    let sys = linked
        .fips_sys
        .clone()
        .expect("a fips build records its release");
    let allowed = seaworthy_crypto::module::fips_module(&sys).expect("an allowlisted release");
    assert_eq!(linked.version, allowed.module);
    assert_eq!(linked.version, aws_lc_rs::awslc_version());
    assert!(linked.fips_build && linked.fips_mode, "{linked:?}");
    assert_eq!(linked.fips_branch, Some(allowed.branch));
    assert_eq!(
        seaworthy_crypto::module::compiled_branch(),
        Some(allowed.branch),
        "the sys crate's build-time branch agrees with the runtime"
    );
    let ensured =
        seaworthy_crypto::module::ensure_expected_module().expect("an allowlisted module");
    assert_eq!(ensured, linked);
    assert_eq!(linked.describe(), "AWS-LC FIPS 4.2.0");
    assert_eq!(
        linked.identity(),
        format!(
            "AWS-LC FIPS 4.2.0 (aws-lc-fips-sys {sys}, aws-lc-rs {})",
            seaworthy_crypto::module::LINKED_AWS_LC_RS
        )
    );
}

/// A FIPS build records the C toolchain that built the module.
#[test]
fn a_fips_build_records_the_module_toolchain() {
    let build = seaworthy_crypto::module::build_provenance();
    assert!(build.fips_feature);
    assert!(
        !build.c_compiler.contains("non-FIPS"),
        "{}",
        build.c_compiler
    );
    assert!(!build.cmake.contains("non-FIPS"), "{}", build.cmake);
    assert_eq!(
        Some(build.aws_lc_fips_sys),
        seaworthy_crypto::module::LINKED_FIPS_SYS,
        "the module's release is recorded"
    );
    assert!(
        build
            .module_build_env
            .contains("AWS_LC_FIPS_SYS_USE_SYSTEM="),
        "the source-build switch is recorded: {}",
        build.module_build_env
    );
}
