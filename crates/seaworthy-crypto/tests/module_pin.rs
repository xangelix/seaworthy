//! The module pin and the boot self-check, in every build profile. The
//! FIPS-only assertions on the LINKED module (`awslc_version() == "4.2.0"`,
//! FIPS mode, the module branch) live in `tests/fips.rs`, which only a
//! `--features fips` build compiles; this file pins the expectation itself
//! so a `cargo update` that moves the module crates fails every test run,
//! not just the FIPS one.

use seaworthy_crypto::module::{self, LinkedModule};

/// Read a workspace file (a manifest or the lockfile), relative to this
/// crate's directory.
#[allow(
    clippy::panic,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn workspace_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `version = "…"` of package `name` in a Cargo.lock (every entry:
/// two versions of one module crate would itself be a finding).
#[allow(
    clippy::expect_used,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn locked_versions(lock: &str, name: &str) -> Vec<String> {
    let mut versions = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line == format!("name = \"{name}\"") {
            let version = lines.next().expect("a version line follows the name");
            versions.push(
                version
                    .trim_start_matches("version = \"")
                    .trim_end_matches('"')
                    .to_string(),
            );
        }
    }
    versions
}

/// The lockfile resolves exactly the pinned module crates. A routine
/// `cargo update` that moved `aws-lc-rs` (and with it the FIPS module it
/// binds; AWS-LC 5 is already on the CMVP Modules In Process list) fails
/// HERE, in every test run.
#[test]
fn the_lockfile_resolves_exactly_the_pinned_module_crates() {
    let lock = workspace_file("../../Cargo.lock");
    assert_eq!(
        locked_versions(&lock, "aws-lc-rs"),
        vec![module::EXPECTED_AWS_LC_RS_VERSION.to_string()]
    );
    assert_eq!(
        locked_versions(&lock, "aws-lc-fips-sys"),
        vec![module::EXPECTED_FIPS_SYS_VERSION.to_string()]
    );
}

/// The workspace manifest pins both crates with `=` (the lockfile alone is
/// one `cargo update` away from moving), and this crate's manifest takes
/// them from there: inherited, never re-versioned locally.
#[test]
fn the_manifest_pins_the_module_crates_exactly() {
    let workspace = workspace_file("../../Cargo.toml");
    let manifest = workspace_file("Cargo.toml");
    for (name, version) in [
        ("aws-lc-rs", module::EXPECTED_AWS_LC_RS_VERSION),
        ("aws-lc-fips-sys", module::EXPECTED_FIPS_SYS_VERSION),
    ] {
        let declarations: Vec<&str> = workspace
            .lines()
            .filter(|line| line.starts_with(&format!("{name} =")))
            .collect();
        assert_eq!(
            declarations.len(),
            1,
            "{name} is declared once in [workspace.dependencies]"
        );
        for line in declarations {
            assert!(
                line.contains(&format!("\"={version}\"")),
                "{name} must be pinned `={version}`: {line}"
            );
        }
        let local: Vec<&str> = manifest
            .lines()
            .filter(|line| line.starts_with(&format!("{name} =")))
            .collect();
        assert!(
            !local.is_empty(),
            "{name} is a direct dependency of seaworthy-crypto"
        );
        for line in local {
            assert!(
                line.contains("workspace = true") && !line.contains("version"),
                "{name} must be inherited from the workspace pin: {line}"
            );
        }
    }
}

/// The nm check's prefix and the pinned sys crate cannot drift apart.
#[test]
fn the_symbol_prefix_follows_the_pinned_sys_crate() {
    assert_eq!(
        module::FIPS_SYMBOL_PREFIX,
        format!(
            "aws_lc_fips_{}_",
            module::EXPECTED_FIPS_SYS_VERSION.replace('.', "_")
        )
    );
}

fn module_with(version: &str, fips_mode: bool, branch: Option<u32>) -> LinkedModule {
    LinkedModule {
        version: version.to_string(),
        fips_build: true,
        fips_mode,
        fips_branch: branch,
        cpu_jitter_entropy: true,
    }
}

/// The assertion itself, both arms, in every profile: only AWS-LC FIPS
/// 4.2.0 in FIPS mode on branch 4 passes a FIPS expectation.
#[test]
fn only_the_pinned_module_passes_the_fips_expectation() {
    module::check(
        &module_with(module::EXPECTED_FIPS_MODULE_VERSION, true, Some(4)),
        true,
    )
    .expect("the pinned module");
    for (bad, why) in [
        (module_with("4.3.0", true, Some(4)), "another 4.x release"),
        (module_with("5.0.0", true, Some(5)), "AWS-LC 5"),
        (module_with("4.2.0", false, Some(4)), "FIPS mode off"),
        (module_with("4.2.0", true, None), "not a FIPS branch"),
    ] {
        let err = module::check(&bad, true).expect_err(why);
        assert!(err.contains("4.2.0"), "{why}: names the expectation: {err}");
    }
    // Without a FIPS expectation there is no module to pin.
    module::check(&module_with("1.0.0", false, None), false).expect("non-FIPS");
}

/// The boot self-check draws from the module DRBG (so a CPU-jitter
/// first-draw abort happens at boot), and in this build it answers for the
/// module this build links.
#[test]
fn the_startup_self_check_draws_from_the_module_rng() {
    let check = module::startup_self_check().expect("self-check");
    assert_eq!(check.rng_bytes_drawn, module::SELF_CHECK_RNG_BYTES);
    assert_eq!(check.module.fips_build, cfg!(feature = "fips"));
    assert_eq!(check.module, module::linked());
    assert!(!check.module.version.is_empty());
}

/// The build provenance is stamped at compile time; the Rust
/// toolchain is always recorded, the C toolchain under `fips` (the module
/// build is the C toolchain's).
#[test]
fn the_build_provenance_is_stamped() {
    let build = module::build_provenance();
    assert!(build.rustc.starts_with("rustc "), "{}", build.rustc);
    assert!(!build.target.is_empty());
    assert_eq!(build.fips_feature, cfg!(feature = "fips"));
    let fields = build.fields();
    for key in [
        "rustc",
        "target",
        "profile",
        "c_compiler",
        "cmake",
        "go",
        "perl",
        "module_build_env",
        "target_cpu",
        "acknowledged_knobs",
    ] {
        assert!(
            fields.iter().any(|(k, _)| *k == key),
            "provenance carries {key}"
        );
    }
    for (key, value) in &fields {
        assert!(
            !value.chars().any(char::is_control),
            "{key} is one printable line: {value:?}"
        );
    }
    if !cfg!(feature = "fips") {
        assert!(
            build.c_compiler.contains("non-FIPS"),
            "{}",
            build.c_compiler
        );
    }
}
