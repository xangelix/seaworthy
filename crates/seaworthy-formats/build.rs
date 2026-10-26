//! seaworthy-formats' build script: stamps the compile-time target triple
//! into `SEAWORTHY_FORMATS_TARGET_TRIPLE` for `TARGET_TRIPLE`, and sets
//! `cfg(seaworthy_ci_test_keys)` when the build runs with
//! `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` (the CI test-key switch, `src/ci_test.rs`:
//! only such a build can trust a product's public CI test keys).

fn main() {
    // `TARGET_TRIPLE` (the `{target}` placeholder of the update helper's
    // package URL, and the target every signed manifest must name) is the
    // compile-time target triple. Cargo always sets TARGET for build
    // scripts; were it missing, a loud build error (`cargo::error`), never
    // a panic. TARGET is fixed per target directory, so nothing but this
    // file needs to rerun it.
    println!("cargo::rerun-if-changed=build.rs");
    match std::env::var("TARGET") {
        Ok(target) => println!("cargo::rustc-env=SEAWORTHY_FORMATS_TARGET_TRIPLE={target}"),
        Err(e) => println!("cargo::error=seaworthy-formats: TARGET is unusable ({e})"),
    }

    // The CI test-key switch: `1` turns it on; unset, empty or `0` leaves
    // it off; anything else is a typo that must not silently mean either.
    println!("cargo::rustc-check-cfg=cfg(seaworthy_ci_test_keys)");
    println!("cargo::rerun-if-env-changed=SEAWORTHY_ALLOW_CI_TEST_KEYS");
    match std::env::var("SEAWORTHY_ALLOW_CI_TEST_KEYS") {
        Ok(value) if value == "1" => println!("cargo::rustc-cfg=seaworthy_ci_test_keys"),
        Ok(value) if value.is_empty() || value == "0" => {}
        Err(std::env::VarError::NotPresent) => {}
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => println!(
            "cargo::error=seaworthy-formats: SEAWORTHY_ALLOW_CI_TEST_KEYS must be 1 (trust the CI \
             test keys: never for a release) or unset/0"
        ),
    }
}
