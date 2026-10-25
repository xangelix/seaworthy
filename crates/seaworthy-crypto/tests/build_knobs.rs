//! The FIPS module build-environment guard, exercised directly:
//! `build/knobs.rs` is pure, so the build script's rules are tested here in
//! every profile (a `--features fips` build proves the script runs).

#[path = "../build/knobs.rs"]
#[allow(
    dead_code,
    reason = "shared with build.rs; not every item is asserted here"
)]
mod knobs;

const LINUX: &str = "x86_64-unknown-linux-gnu";

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// The repository's own `.cargo/config.toml` [env]: the clean FIPS build.
fn clean() -> Vec<(&'static str, &'static str)> {
    vec![
        ("AWS_LC_FIPS_SYS_CC", "clang"),
        ("AWS_LC_FIPS_SYS_USE_SYSTEM", "0"),
        ("AWS_LC_FIPS_SYS_CC_x86_64_pc_windows_msvc", "cl"),
        ("AWS_LC_FIPS_SYS_CXX_x86_64_pc_windows_msvc", "cl"),
        ("CARGO_ENCODED_RUSTFLAGS", "--cfg\x1fsome_cfg"),
    ]
}

fn refused_keys(verdict: &knobs::Verdict) -> Vec<&str> {
    verdict.refused.iter().map(|f| f.key.as_str()).collect()
}

#[test]
fn the_repositorys_own_environment_is_a_clean_fips_build() {
    let verdict = knobs::evaluate(&env(&clean()), LINUX, true);
    assert!(verdict.refused.is_empty(), "{:?}", verdict.refused);
    assert!(verdict.acknowledged.is_empty());
    assert!(verdict.warnings.is_empty(), "{:?}", verdict.warnings);
    // The compiler selection and the source-build switch are recorded; the
    // other target's (msvc) selections are not read on Linux.
    assert_eq!(
        verdict.recorded,
        vec![
            "AWS_LC_FIPS_SYS_CC=clang".to_string(),
            "AWS_LC_FIPS_SYS_USE_SYSTEM=0".to_string()
        ]
    );
}

/// A Windows FIPS build's environment: the msvc-scoped `cl` selections
/// apply there, plus the `+crt-static` target feature (CRT linkage: the
/// sys crate reads it itself; cc-rs maps no C flag from it).
#[test]
fn a_windows_fips_build_is_clean_too() {
    let mut vars = clean();
    vars.retain(|(k, _)| *k != "CARGO_ENCODED_RUSTFLAGS");
    vars.push((
        "CARGO_ENCODED_RUSTFLAGS",
        "--cfg\x1fsome_cfg\x1f-C\x1ftarget-feature=+crt-static",
    ));
    let verdict = knobs::evaluate(&env(&vars), "x86_64-pc-windows-msvc", true);
    assert!(verdict.refused.is_empty(), "{:?}", verdict.refused);
    assert!(
        verdict
            .recorded
            .contains(&"AWS_LC_FIPS_SYS_CC_x86_64_pc_windows_msvc=cl".to_string())
    );
}

#[test]
fn module_altering_sys_knobs_are_refused_by_name() {
    for knob in [
        "AWS_LC_FIPS_SYS_SMALL",
        "AWS_LC_FIPS_SYS_NO_ASM",
        "AWS_LC_FIPS_SYS_SANITIZER",
        "AWS_LC_FIPS_SYS_C_STD",
        "AWS_LC_FIPS_SYS_CFLAGS",
        "AWS_LC_FIPS_SYS_TARGET_CFLAGS",
        "AWS_LC_FIPS_SYS_SYSTEM_DIR",
        "AWS_LC_FIPS_SYS_EFFECTIVE_TARGET",
        "AWS_LC_FIPS_SYS_CMAKE_TOOLCHAIN_FILE",
        "AWS_LC_FIPS_SYS_SMALL_x86_64_unknown_linux_gnu",
        "AWS_LC_FIPS_SYS_SOMETHING_NEW",
    ] {
        let mut vars = clean();
        vars.push((knob, "1"));
        let verdict = knobs::evaluate(&env(&vars), LINUX, true);
        assert_eq!(refused_keys(&verdict), vec![knob], "{knob}");
        assert!(verdict.refused[0].detail.contains(knob));
    }
}

#[test]
fn c_flags_that_reach_the_module_build_are_refused() {
    for knob in [
        "CFLAGS",
        "TARGET_CFLAGS",
        "HOST_CFLAGS",
        "CXXFLAGS",
        "CFLAGS_x86_64_unknown_linux_gnu",
        "CFLAGS_x86_64-unknown-linux-gnu",
        "CRATE_CC_NO_DEFAULTS",
        "CMAKE_TOOLCHAIN_FILE",
    ] {
        let mut vars = clean();
        vars.push((knob, "-O1 -march=znver4"));
        let verdict = knobs::evaluate(&env(&vars), LINUX, true);
        assert_eq!(refused_keys(&verdict), vec![knob], "{knob}");
    }
    // An EMPTY flags variable changes nothing.
    let mut vars = clean();
    vars.push(("CFLAGS", ""));
    assert!(knobs::evaluate(&env(&vars), LINUX, true).refused.is_empty());
}

/// Auto-detection of a pre-installed AWS-LC is a silent module swap: the
/// source-build switch is required, and turning it on is refused.
#[test]
fn the_source_build_switch_is_required() {
    let mut vars = clean();
    vars.retain(|(k, _)| *k != "AWS_LC_FIPS_SYS_USE_SYSTEM");
    let verdict = knobs::evaluate(&env(&vars), LINUX, true);
    assert_eq!(refused_keys(&verdict), vec!["AWS_LC_FIPS_SYS_USE_SYSTEM"]);
    assert!(verdict.refused[0].detail.contains("pre-installed"));

    let mut vars = clean();
    vars.retain(|(k, _)| *k != "AWS_LC_FIPS_SYS_USE_SYSTEM");
    vars.push(("AWS_LC_FIPS_SYS_USE_SYSTEM", "1"));
    let verdict = knobs::evaluate(&env(&vars), LINUX, true);
    assert_eq!(refused_keys(&verdict), vec!["AWS_LC_FIPS_SYS_USE_SYSTEM"]);
}

/// cc-rs 1.x inherits `-C target-feature` (and other codegen options) into
/// every C build it drives — the module's included; `-C target-cpu` it
/// does not (recorded with a warning).
#[test]
fn inherited_rustflags_are_refused_and_target_cpu_is_recorded() {
    for (flags, key) in [
        (
            "-C\x1ftarget-feature=+avx2,+bmi2",
            "rustflags:target-feature",
        ),
        ("-Ctarget-feature=+avx512f", "rustflags:target-feature"),
        ("--codegen=code-model=large", "rustflags:code-model"),
        ("-C\x1fprofile-use=/tmp/p.profdata", "rustflags:profile-use"),
        ("-Z\x1fbranch-protection=bti", "rustflags:branch-protection"),
    ] {
        let mut vars = clean();
        vars.retain(|(k, _)| *k != "CARGO_ENCODED_RUSTFLAGS");
        vars.push(("CARGO_ENCODED_RUSTFLAGS", flags));
        let verdict = knobs::evaluate(&env(&vars), LINUX, true);
        assert_eq!(refused_keys(&verdict), vec![key], "{flags:?}");
    }
    let mut vars = clean();
    vars.retain(|(k, _)| *k != "CARGO_ENCODED_RUSTFLAGS");
    vars.push(("CARGO_ENCODED_RUSTFLAGS", "-C\x1ftarget-cpu=x86-64-v3"));
    let verdict = knobs::evaluate(&env(&vars), LINUX, true);
    assert!(verdict.refused.is_empty(), "{:?}", verdict.refused);
    assert_eq!(verdict.target_cpu.as_deref(), Some("x86-64-v3"));
    assert!(verdict.warnings.iter().any(|w| w.contains("target-cpu")));
}

/// The explicit escape: a knob named in the acknowledgement variable is
/// allowed — and reported as acknowledged (stamped into provenance), so it
/// is never silent. A stale acknowledgement warns.
#[test]
fn acknowledged_knobs_pass_and_are_reported() {
    let mut vars = clean();
    vars.retain(|(k, _)| *k != "CARGO_ENCODED_RUSTFLAGS");
    vars.push(("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-feature=+avx2"));
    vars.push(("AWS_LC_FIPS_SYS_SMALL", "1"));
    vars.push((
        knobs::ACK_VAR,
        "rustflags:target-feature, AWS_LC_FIPS_SYS_SMALL,CFLAGS",
    ));
    let verdict = knobs::evaluate(&env(&vars), LINUX, true);
    assert!(verdict.refused.is_empty(), "{:?}", verdict.refused);
    let acknowledged: Vec<&str> = verdict
        .acknowledged
        .iter()
        .map(|f| f.key.as_str())
        .collect();
    assert_eq!(
        acknowledged,
        vec!["AWS_LC_FIPS_SYS_SMALL", "rustflags:target-feature"]
    );
    assert!(
        verdict.warnings.iter().any(|w| w.contains("CFLAGS")),
        "stale ack warns: {:?}",
        verdict.warnings
    );
}

/// A non-FIPS build compiles no module: nothing is refused.
#[test]
fn a_non_fips_build_is_never_refused() {
    let vars = env(&[
        ("AWS_LC_FIPS_SYS_SMALL", "1"),
        ("CFLAGS", "-O0"),
        ("CARGO_ENCODED_RUSTFLAGS", "-Ctarget-feature=+avx2"),
    ]);
    let verdict = knobs::evaluate(&vars, LINUX, false);
    assert!(verdict.refused.is_empty());
    assert!(verdict.warnings.is_empty());
}

/// The rerun triggers cover every knob the sys crate reads, for this
/// target, plus the acknowledgement variable.
#[test]
fn the_watch_list_covers_the_knobs() {
    let watched = knobs::watched_names(LINUX);
    for name in [
        "AWS_LC_FIPS_SYS_SMALL",
        "AWS_LC_FIPS_SYS_SMALL_x86_64_unknown_linux_gnu",
        "AWS_LC_FIPS_SYS_USE_SYSTEM",
        "CFLAGS",
        "CFLAGS_x86_64_unknown_linux_gnu",
        "CFLAGS_x86_64-unknown-linux-gnu",
        "OPENSSL_DIR",
        knobs::ACK_VAR,
    ] {
        assert!(watched.iter().any(|w| w == name), "{name}");
    }
}

/// The repository's cargo configuration carries the two switches the guard
/// needs, so a `--features fips` build from a checkout passes the guard
/// without extra environment.
#[test]
fn the_repository_cargo_config_sets_the_required_switches() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let file = ".cargo/config.toml";
    let text =
        std::fs::read_to_string(format!("{root}/{file}")).unwrap_or_else(|e| panic!("{file}: {e}"));
    let value = |key: &str| {
        text.lines()
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim().trim_matches('"').to_owned())
    };
    let cc = value("AWS_LC_FIPS_SYS_CC").unwrap_or_default();
    let use_system = value("AWS_LC_FIPS_SYS_USE_SYSTEM").unwrap_or_default();
    assert_eq!(cc, "clang", "{file}");
    assert_eq!(use_system, "0", "{file}");
    // What the guard makes of the file's own values.
    let vars = env(&[
        ("AWS_LC_FIPS_SYS_CC", cc.as_str()),
        ("AWS_LC_FIPS_SYS_USE_SYSTEM", use_system.as_str()),
    ]);
    assert!(
        knobs::evaluate(&vars, LINUX, true).refused.is_empty(),
        "{file}"
    );
}
