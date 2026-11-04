//! The FIPS allowlist and the boot self-check, in every build profile. The
//! FIPS-only assertions on the LINKED module (an allowlisted release, FIPS
//! mode, the module branch) live in `tests/fips.rs`, which only a
//! `--features fips` build compiles; this file holds the manifest, the
//! lockfile and the assertion itself to the allowlist, so a `cargo update`
//! that moves to an unlisted module fails every test run, not just the FIPS
//! one.

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

/// The workspace's lockfile locks one release of each module crate, both
/// on the allowlist (`scripts/check-fips-lock.sh` holds every lockfile of
/// the repository to the same rule). A routine `cargo update` that moved
/// `aws-lc-fips-sys` to an unlisted release (AWS-LC 5 is already on the
/// CMVP Modules In Process list) fails HERE, in every test run.
#[test]
fn the_lockfile_locks_allowlisted_module_crates() {
    let lock = workspace_file("../../Cargo.lock");
    let rs = locked_versions(&lock, "aws-lc-rs");
    assert_eq!(rs.len(), 1, "one aws-lc-rs: {rs:?}");
    assert!(
        module::aws_lc_rs_release(&rs[0]).is_some(),
        "aws-lc-rs {} is on the allowlist",
        rs[0]
    );
    let sys = locked_versions(&lock, "aws-lc-fips-sys");
    assert_eq!(sys.len(), 1, "one aws-lc-fips-sys: {sys:?}");
    assert!(
        module::fips_module(&sys[0]).is_some(),
        "aws-lc-fips-sys {} is on the allowlist ({})",
        sys[0],
        module::describe_allowlist()
    );
}

/// The workspace manifest declares a RANGE of each crate (an exact pin in a
/// library forces every library in a graph to move together), the range
/// admits every allowlisted release, and this crate's manifest inherits it,
/// never re-versioned locally.
#[test]
fn the_manifest_declares_ranges_that_admit_the_allowlist() {
    let workspace = workspace_file("../../Cargo.toml");
    let manifest = workspace_file("Cargo.toml");
    for (name, range) in [
        ("aws-lc-rs", "\">=1.18.2, <2\""),
        ("aws-lc-fips-sys", "\">=0.14.2, <0.15\""),
    ] {
        let declarations: Vec<&str> = workspace
            .lines()
            .filter(|line| line.starts_with(&format!("{name} =")))
            .collect();
        assert_eq!(
            declarations,
            vec![
                if name == "aws-lc-rs" {
                    format!("{name} = {{ version = {range}, default-features = false }}")
                } else {
                    format!("{name} = {range}")
                }
                .as_str()
            ],
            "{name} is declared once in [workspace.dependencies], as the range {range}"
        );
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
                "{name} must be inherited from the workspace range: {line}"
            );
        }
    }
    // The ranges admit every allowlisted release, and nothing of another
    // series: aws-lc-fips-sys 0.14.x (>= 0.14.2), aws-lc-rs 1.x (>= 1.18.2).
    for m in module::FIPS_MODULES {
        let (major, minor, patch) = triple(m.sys);
        assert!(
            (major, minor) == (0, 14) && patch >= 2,
            "{} in range",
            m.sys
        );
    }
    for r in module::AWS_LC_RS_RELEASES {
        assert!(triple(r.version) >= (1, 18, 2) && triple(r.version) < (2, 0, 0));
        assert_eq!(
            r.binds, "0.14",
            "aws-lc-rs {} binds the range's series",
            r.version
        );
    }
}

#[allow(
    clippy::expect_used,
    reason = "a test helper: a malformed fixture is a bug in the test, and a panic fails it"
)]
fn triple(release: &str) -> (u64, u64, u64) {
    let parts: Vec<u64> = release
        .split('.')
        .map(|p| p.parse().expect("a numeric component"))
        .collect();
    assert_eq!(parts.len(), 3, "{release}");
    (parts[0], parts[1], parts[2])
}

/// The allowlist the build script generated is the file's: every entry, in
/// order, and nothing else. The modules are all AWS-LC FIPS 4.2.0 on branch
/// 4, which [`module::CMVP_STATUS`] describes: a module of another version
/// joins only with its own CMVP wording.
#[test]
fn the_generated_allowlist_is_the_file() {
    let file = workspace_file("fips-allowlist.txt");
    assert_eq!(module::ALLOWLIST, file);
    let mut modules = Vec::new();
    let mut releases = Vec::new();
    for line in file.lines().map(str::trim) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["module", sys, version, branch] => modules.push((*sys, *version, *branch)),
            ["aws-lc-rs", version, binds] => releases.push((*version, *binds)),
            _ => assert!(line.is_empty() || line.starts_with('#'), "{line:?}"),
        }
    }
    let generated: Vec<(&str, &str, String)> = module::FIPS_MODULES
        .iter()
        .map(|m| (m.sys, m.module, m.branch.to_string()))
        .collect();
    let listed: Vec<(&str, &str, String)> = modules
        .iter()
        .map(|(s, v, b)| (*s, *v, (*b).to_string()))
        .collect();
    assert_eq!(generated, listed);
    let generated: Vec<(&str, &str)> = module::AWS_LC_RS_RELEASES
        .iter()
        .map(|r| (r.version, r.binds))
        .collect();
    assert_eq!(generated, releases);
    for m in module::FIPS_MODULES {
        assert!(
            module::CMVP_STATUS.contains(&format!("AWS-LC FIPS {} ", m.module)),
            "CMVP_STATUS covers {}",
            m.module
        );
        assert_eq!(m.branch, 4);
        assert_eq!(
            m.symbol_prefix(),
            format!("aws_lc_fips_{}_", m.sys.replace('.', "_"))
        );
    }
    assert_eq!(
        module::describe_allowlist(),
        "0.14.2 (AWS-LC FIPS 4.2.0), 0.14.3 (AWS-LC FIPS 4.2.0), 0.14.4 (AWS-LC FIPS 4.2.0)"
    );
}

/// The releases this build links, as its build script read them from the
/// graph: the lockfile's, on the allowlist (under `fips`; without it no
/// module is linked).
#[test]
fn the_build_records_the_releases_it_links() {
    let lock = workspace_file("../../Cargo.lock");
    assert_eq!(
        vec![module::LINKED_AWS_LC_RS.to_string()],
        locked_versions(&lock, "aws-lc-rs")
    );
    if cfg!(feature = "fips") {
        let sys = module::LINKED_FIPS_SYS.expect("a fips build links a module");
        assert_eq!(
            vec![sys.to_string()],
            locked_versions(&lock, "aws-lc-fips-sys")
        );
        assert!(module::fips_module(sys).is_some());
    } else {
        assert_eq!(module::LINKED_FIPS_SYS, None);
    }
    let build = module::build_provenance();
    assert_eq!(build.aws_lc_rs, module::LINKED_AWS_LC_RS);
}

fn module_with(
    version: &str,
    fips_mode: bool,
    branch: Option<u32>,
    sys: Option<&str>,
) -> LinkedModule {
    LinkedModule {
        version: version.to_string(),
        fips_build: true,
        fips_mode,
        fips_branch: branch,
        cpu_jitter_entropy: true,
        fips_sys: sys.map(str::to_string),
        aws_lc_rs: "1.19.0".to_string(),
    }
}

/// The assertion itself, both arms, in every profile: every allowlisted
/// module passes a FIPS expectation, in FIPS mode, with the version and
/// branch the allowlist names for its release; anything else is refused,
/// naming the allowlist.
#[test]
fn only_allowlisted_modules_pass_the_fips_expectation() {
    for m in module::FIPS_MODULES {
        module::check(
            &module_with(m.module, true, Some(m.branch), Some(m.sys)),
            true,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", m.sys));
    }
    for (bad, why) in [
        (
            module_with("4.2.0", true, Some(4), Some("0.14.5")),
            "an unlisted release",
        ),
        (
            module_with("4.2.0", true, Some(4), Some("0.14.1")),
            "an older, unlisted release",
        ),
        (
            module_with("5.0.0", true, Some(5), Some("0.15.0")),
            "AWS-LC 5",
        ),
        (
            module_with("4.3.0", true, Some(4), Some("0.14.4")),
            "another module version",
        ),
        (
            module_with("4.2.0", false, Some(4), Some("0.14.4")),
            "FIPS mode off",
        ),
        (
            module_with("4.2.0", true, None, Some("0.14.4")),
            "not a FIPS branch",
        ),
        (
            module_with("4.2.0", true, Some(3), Some("0.14.4")),
            "another branch",
        ),
        (
            module_with("4.2.0", true, Some(4), None),
            "no release recorded",
        ),
    ] {
        let err = module::check(&bad, true).expect_err(why);
        assert!(
            err.contains(&module::describe_allowlist()),
            "{why}: names the allowlist: {err}"
        );
    }
    // Without a FIPS expectation there is no module to check.
    module::check(&module_with("1.0.0", false, None, None), false).expect("non-FIPS");
}

/// The identity line names the crates that built the module.
#[test]
fn the_identity_names_the_releases() {
    let m = module_with("4.2.0", true, Some(4), Some("0.14.3"));
    assert_eq!(m.describe(), "AWS-LC FIPS 4.2.0");
    assert_eq!(
        m.identity(),
        "AWS-LC FIPS 4.2.0 (aws-lc-fips-sys 0.14.3, aws-lc-rs 1.19.0)"
    );
    let mut plain = module_with("5.12.0", false, None, None);
    plain.fips_build = false;
    assert_eq!(
        plain.identity(),
        "AWS-LC 5.12.0 (non-FIPS) (aws-lc-rs 1.19.0)"
    );
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
        "aws_lc_rs",
        "aws_lc_fips_sys",
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
