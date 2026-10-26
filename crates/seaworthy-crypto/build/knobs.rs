//! The FIPS module build-environment guard: pure logic, shared by
//! `build.rs` and `tests/build_knobs.rs` (included by path; no crate
//! dependencies, no I/O).
//!
//! `aws-lc-fips-sys` builds the AWS-LC FIPS module from source with CMake,
//! and a set of environment variables silently changes what goes into the
//! module boundary: `AWS_LC_FIPS_SYS_*` knobs (`SMALL`, `NO_ASM`,
//! `SANITIZER`, `C_STD`, a pre-installed library via `SYSTEM_DIR` …), the
//! C flags cc-rs/cmake-rs pass to the C build (`CFLAGS`, `TARGET_CFLAGS`,
//! `CFLAGS_<target>`, `CRATE_CC_NO_DEFAULTS`, a CMake toolchain file), and
//! the Rust codegen flags cc-rs 1.x INHERITS into every C build it drives
//! (`-C target-feature`, `-C code-model`, `-C relocation-model`, PGO, …).
//! The Security Policy's build procedure (§11.1) admits "no additions,
//! deletions, or alterations". Under `seaworthy-crypto/fips` every such knob
//! is REFUSED (a build error naming it) unless the build explicitly
//! acknowledges it in `SEAWORTHY_FIPS_MODULE_BUILD_ACK`; then it is allowed
//! and stamped into the binary's build provenance, never silent.
//!
//! Allowed without acknowledgement (recorded in provenance): the compiler
//! selection (`AWS_LC_FIPS_SYS_CC`/`CXX`, host/target forms, and the
//! generic `CC`/`CXX` fallbacks the sys crate consults), the CMake binary
//! and generator, and `AWS_LC_FIPS_SYS_USE_SYSTEM=0`, which is REQUIRED:
//! without it the sys crate auto-detects a pre-installed AWS-LC
//! (`OPENSSL_DIR`, pkg-config) and links that instead of building the
//! module. `-C target-cpu` is recorded with a warning: cc-rs 1.x does not
//! pass it to C builds (its inherited-flag list ignores it), so it changes
//! Rust codegen only.

/// The sys crate's environment prefix.
pub(crate) const PREFIX: &str = "AWS_LC_FIPS_SYS_";
/// The acknowledgement variable: a comma-separated list of finding keys
/// (an environment variable name, or `rustflags:<flag>`).
pub(crate) const ACK_VAR: &str = "SEAWORTHY_FIPS_MODULE_BUILD_ACK";

/// `AWS_LC_FIPS_SYS_<suffix>` knobs that only SELECT tools (recorded).
const TOOL_SUFFIXES: [&str; 8] = [
    "CC",
    "CXX",
    "HOST_CC",
    "HOST_CXX",
    "TARGET_CC",
    "TARGET_CXX",
    "CMAKE",
    "CMAKE_GENERATOR",
];

/// Every `AWS_LC_FIPS_SYS_<suffix>` aws-lc-fips-sys 0.14.3 reads (its
/// builder's `optional_env*` / `env_crate_var_to_bool` calls) — the
/// rerun triggers. Unknown suffixes are refused too (fail closed).
const KNOWN_SUFFIXES: [&str; 35] = [
    "CC",
    "CXX",
    "HOST_CC",
    "HOST_CXX",
    "TARGET_CC",
    "TARGET_CXX",
    "CMAKE",
    "CMAKE_GENERATOR",
    "USE_SYSTEM",
    "CFLAGS",
    "HOST_CFLAGS",
    "TARGET_CFLAGS",
    "CMAKE_TOOLCHAIN_FILE",
    "CMAKE_BUILDER",
    "C_STD",
    "EFFECTIVE_TARGET",
    "EXTERNAL_BINDGEN",
    "INCLUDES",
    "LINK_WHOLE_ARCHIVE",
    "NO_ASM",
    "NO_JITTER_ENTROPY",
    "NO_PREFIX",
    "NO_PREGENERATED_SRC",
    "NO_U1_BINDINGS",
    "PREBUILT_NASM",
    "PREGENERATING_BINDINGS",
    "SANITIZER",
    "SMALL",
    "STATIC",
    "SYSTEM_BINDINGS",
    "SYSTEM_DIR",
    "SYSTEM_SKIP_VERSION_CHECK",
    "ANDROID_NDK",
    "ANDROID_NDK_ROOT",
    "ANDROID_STANDALONE_TOOLCHAIN",
];

/// Unprefixed variables that change the C build (cc-rs / cmake-rs / the
/// sys crate's fallbacks); a `_<target>` form is checked too.
const GENERIC_FLAG_VARS: [&str; 9] = [
    "CFLAGS",
    "CXXFLAGS",
    "HOST_CFLAGS",
    "TARGET_CFLAGS",
    "HOST_CXXFLAGS",
    "TARGET_CXXFLAGS",
    "ASMFLAGS",
    "CMAKE_TOOLCHAIN_FILE",
    "CRATE_CC_NO_DEFAULTS",
];

/// Unprefixed tool selections the sys crate falls back to (recorded).
const GENERIC_TOOL_VARS: [&str; 7] = [
    "CC",
    "CXX",
    "HOST_CC",
    "HOST_CXX",
    "TARGET_CC",
    "TARGET_CXX",
    "CMAKE_GENERATOR",
];

/// The `-C` codegen options cc-rs 1.x maps into every C build it drives
/// (its `RustcCodegenFlags`), i.e. into the module's CMake flags.
const INHERITED_CODEGEN_FLAGS: [&str; 16] = [
    "target-feature",
    "code-model",
    "relocation-model",
    "profile-generate",
    "profile-use",
    "force-frame-pointers",
    "no-redzone",
    "soft-float",
    "embed-bitcode",
    "linker-plugin-lto",
    "control-flow-guard",
    "lto",
    "dwarf-version",
    "no-vectorize-loops",
    "no-vectorize-slp",
    "stack-protector",
];

/// One refused (or acknowledged) knob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    /// The key `SEAWORTHY_FIPS_MODULE_BUILD_ACK` names to acknowledge it.
    pub(crate) key: String,
    /// What it is and why it matters.
    pub(crate) detail: String,
}

/// The guard's answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    /// Knobs that fail a FIPS build.
    pub(crate) refused: Vec<Finding>,
    /// Knobs a FIPS build acknowledged (allowed, stamped into provenance).
    pub(crate) acknowledged: Vec<Finding>,
    /// Non-fatal observations (cargo warnings).
    pub(crate) warnings: Vec<String>,
    /// The module-relevant variables present, `NAME=value`, sorted.
    pub(crate) recorded: Vec<String>,
    /// The `-C target-cpu` value, when one was set.
    pub(crate) target_cpu: Option<String>,
}

/// `x86_64-unknown-linux-gnu` → `x86_64_unknown_linux_gnu` (the sys
/// crate's target-suffix convention).
#[must_use]
pub(crate) fn target_suffix(target: &str) -> String {
    target.to_lowercase().replace('-', "_")
}

/// Whether `rest` names `base` for THIS target (`base` or
/// `base_<target>`); `Some(false)` when it names `base` for another target
/// (not read by this build); `None` when it is not `base` at all.
fn names_base(rest: &str, base: &str, target: &str) -> Option<bool> {
    if rest == base {
        return Some(true);
    }
    let tail = rest.strip_prefix(base)?.strip_prefix('_')?;
    if tail == target_suffix(target) || tail == target {
        return Some(true);
    }
    // `base_<some other triple>`: a triple has at least two separators.
    (tail.matches(['_', '-']).count() >= 2).then_some(false)
}

/// Classify `rest` (the part after the prefix) against the known
/// suffixes, longest first: `Some((suffix, applies_here))`.
fn classify_suffix(rest: &str, target: &str) -> Option<(&'static str, bool)> {
    let mut known: Vec<&'static str> = KNOWN_SUFFIXES.to_vec();
    known.sort_by_key(|suffix| std::cmp::Reverse(suffix.len()));
    known
        .into_iter()
        .find_map(|suffix| names_base(rest, suffix, target).map(|applies| (suffix, applies)))
}

/// The sys crate's boolean reading (`parse_to_bool`): `0…`, `n…`, `off…`,
/// `f…` are false.
fn is_false(value: &str) -> bool {
    let value = value.to_lowercase();
    value.starts_with('0')
        || value.starts_with('n')
        || value.starts_with("off")
        || value.starts_with('f')
}

/// The variable names the guard watches (the build script's
/// `rerun-if-env-changed` list), for `target`.
#[must_use]
pub(crate) fn watched_names(target: &str) -> Vec<String> {
    let suffix = target_suffix(target);
    let mut names = vec![ACK_VAR.to_string()];
    for known in KNOWN_SUFFIXES {
        names.push(format!("{PREFIX}{known}"));
        names.push(format!("{PREFIX}{known}_{suffix}"));
    }
    for generic in GENERIC_FLAG_VARS
        .iter()
        .chain(GENERIC_TOOL_VARS.iter())
        .chain(
            [
                "OPENSSL_DIR",
                "OPENSSL_LIB_DIR",
                "OPENSSL_INCLUDE_DIR",
                "CMAKE",
            ]
            .iter(),
        )
    {
        names.push((*generic).to_string());
        names.push(format!("{generic}_{suffix}"));
        names.push(format!("{generic}_{target}"));
    }
    names.sort();
    names.dedup();
    names
}

/// Split `CARGO_ENCODED_RUSTFLAGS` (0x1f-separated) into `-C` codegen
/// options (`name`, `value`), accepting `-C x`, `-Cx`, `--codegen x`,
/// `--codegen=x`, and `-Z` options as `Z:<name>`.
fn codegen_options(encoded: &str) -> Vec<(String, String)> {
    let mut options = Vec::new();
    let mut pending: Option<&str> = None;
    for flag in encoded.split('\x1f').filter(|flag| !flag.is_empty()) {
        let option = match pending.take() {
            Some("-C" | "--codegen") => Some(flag.to_string()),
            Some("-Z") => Some(format!("Z:{flag}")),
            _ => {
                if matches!(flag, "-C" | "--codegen" | "-Z") {
                    pending = Some(flag);
                    None
                } else if let Some(rest) = flag.strip_prefix("--codegen=") {
                    Some(rest.to_string())
                } else if let Some(rest) = flag.strip_prefix("-C") {
                    Some(rest.to_string())
                } else {
                    flag.strip_prefix("-Z").map(|rest| format!("Z:{rest}"))
                }
            }
        };
        if let Some(option) = option {
            let (name, value) = option.split_once('=').unwrap_or((option.as_str(), ""));
            options.push((name.to_string(), value.to_string()));
        }
    }
    options
}

/// Evaluate the build environment. `vars` is the whole environment the
/// build script sees; `fips` is whether `seaworthy-crypto/fips` is on (only
/// then is anything refused: a non-FIPS build compiles no module).
#[must_use]
pub(crate) fn evaluate(vars: &[(String, String)], target: &str, fips: bool) -> Verdict {
    let mut verdict = Verdict::default();
    let get = |name: &str| {
        vars.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let acknowledged: Vec<String> = get(ACK_VAR)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_string)
        .collect();
    let mut found: Vec<Finding> = Vec::new();
    let suffix = target_suffix(target);
    let mut use_system_false = false;

    // 1. The sys crate's own knobs.
    for (name, value) in vars {
        let Some(rest) = name.strip_prefix(PREFIX) else {
            continue;
        };
        match classify_suffix(rest, target) {
            Some((_, false)) => {} // another target's knob: not read here
            Some((known, true)) if TOOL_SUFFIXES.contains(&known) => {
                verdict.recorded.push(format!("{name}={value}"));
            }
            Some(("USE_SYSTEM", true)) if is_false(value) => {
                use_system_false = true;
                verdict.recorded.push(format!("{name}={value}"));
            }
            Some(("USE_SYSTEM", true)) => found.push(Finding {
                key: name.clone(),
                detail: format!(
                    "{name}={value} links a pre-installed AWS-LC instead of building the \
                     pinned FIPS module from source"
                ),
            }),
            Some((known, true)) => found.push(Finding {
                key: name.clone(),
                detail: format!(
                    "{name}={value} changes the AWS-LC FIPS module build ({known}) — the \
                     Security Policy's build procedure admits no alterations"
                ),
            }),
            None => found.push(Finding {
                key: name.clone(),
                detail: format!(
                    "{name} is not a knob this guard knows (aws-lc-fips-sys 0.14.3) — refused \
                     until reviewed"
                ),
            }),
        }
    }

    // 2. Unprefixed flags that reach the C build.
    for base in GENERIC_FLAG_VARS {
        for name in [
            base.to_string(),
            format!("{base}_{suffix}"),
            format!("{base}_{target}"),
        ] {
            if let Some(value) = get(&name)
                && !value.trim().is_empty()
                && !found.iter().any(|f| f.key == name)
            {
                found.push(Finding {
                    key: name.clone(),
                    detail: format!(
                        "{name}={value} reaches the AWS-LC FIPS module's C build (cc-rs / \
                         cmake-rs) — the Security Policy's build procedure admits no alterations"
                    ),
                });
            }
        }
    }
    for base in GENERIC_TOOL_VARS.iter().chain(["CMAKE"].iter()) {
        for name in [
            base.to_string(),
            format!("{base}_{suffix}"),
            format!("{base}_{target}"),
        ] {
            if let Some(value) = get(&name) {
                verdict.recorded.push(format!("{name}={value}"));
            }
        }
    }

    // 3. The source-build switch: required (auto-detection would link a
    //    pre-installed library — `OPENSSL_DIR` / pkg-config).
    if !use_system_false && !found.iter().any(|f| f.key.contains("USE_SYSTEM")) {
        found.push(Finding {
            key: format!("{PREFIX}USE_SYSTEM"),
            detail: format!(
                "{PREFIX}USE_SYSTEM is not 0: aws-lc-fips-sys then auto-detects and links a \
                 pre-installed AWS-LC (OPENSSL_DIR / OPENSSL_LIB_DIR / pkg-config) instead of \
                 building the pinned module; set {PREFIX}USE_SYSTEM=0 (the repository's \
                 .cargo/config.toml [env] does)"
            ),
        });
    }

    // 4. Rust codegen flags cc-rs inherits into the C build.
    for (name, value) in codegen_options(get("CARGO_ENCODED_RUSTFLAGS").unwrap_or("")) {
        let flag = name.trim_start_matches("Z:");
        if name == "target-cpu" {
            verdict.target_cpu = Some(value.clone());
            continue;
        }
        if name == "target-feature" {
            let features: Vec<&str> = value
                .split(',')
                .filter(|feature| {
                    !feature.is_empty() && feature.trim_start_matches(['+', '-']) != "crt-static"
                })
                .collect();
            if features.is_empty() {
                continue; // the msvc `+crt-static` (CRT linkage, read by the sys crate itself)
            }
        }
        if INHERITED_CODEGEN_FLAGS.contains(&flag)
            || (name.starts_with("Z:") && flag == "branch-protection")
        {
            let key = format!("rustflags:{flag}");
            if !found.iter().any(|f| f.key == key) {
                found.push(Finding {
                    key,
                    detail: format!(
                        "RUSTFLAGS -C {flag}={value}: cc-rs inherits it into the AWS-LC FIPS \
                         module's C build — the Security Policy's build procedure admits no \
                         alterations"
                    ),
                });
            }
        }
    }
    if let Some(cpu) = verdict.target_cpu.as_ref().filter(|_| fips) {
        verdict.warnings.push(format!(
            "RUSTFLAGS -C target-cpu={cpu}: recorded in the build provenance (cc-rs does not \
             pass it to the FIPS module's C build; it changes Rust codegen only)"
        ));
    }

    if fips {
        for finding in found {
            if acknowledged.contains(&finding.key) {
                verdict.acknowledged.push(finding);
            } else {
                verdict.refused.push(finding);
            }
        }
        for key in &acknowledged {
            if !verdict.acknowledged.iter().any(|f| f.key == *key) {
                verdict.warnings.push(format!(
                    "{ACK_VAR} names {key}, which this build does not set (stale acknowledgement)"
                ));
            }
        }
    }
    verdict.recorded.sort();
    verdict.recorded.dedup();
    verdict
}
