//! Reading the effective `-C target-cpu` out of the flags cargo hands a
//! build script (`CARGO_ENCODED_RUSTFLAGS`, `0x1f`-separated). Shared by
//! `build.rs` (which includes this file by path) and the crate's tests.

/// Splits `CARGO_ENCODED_RUSTFLAGS` into its arguments.
pub(crate) fn split(encoded: &str) -> Vec<String> {
    if encoded.is_empty() {
        return Vec::new();
    }
    encoded.split('\u{1f}').map(str::to_owned).collect()
}

/// The `-C` / `--codegen` option values in `flags`, in order: `-C x`,
/// `-Cx`, `--codegen x` and `--codegen=x`.
fn codegen_options(flags: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut iter = flags.iter();
    while let Some(flag) = iter.next() {
        if flag == "-C" || flag == "--codegen" {
            if let Some(value) = iter.next() {
                out.push(value.as_str());
            }
        } else if let Some(value) = flag.strip_prefix("--codegen=") {
            out.push(value);
        } else if let Some(value) = flag.strip_prefix("-C") {
            out.push(value);
        }
    }
    out
}

/// The effective `target-cpu` (rustc keeps the last one), if any.
pub(crate) fn target_cpu(flags: &[String]) -> Option<String> {
    codegen_options(flags)
        .into_iter()
        .rev()
        .find_map(|option| option.strip_prefix("target-cpu="))
        .map(str::to_owned)
}

/// Target features that are not CPU features: `crt-static` selects the
/// static C runtime (cargo-xwin and many Windows builds set
/// `+crt-static`), and appears in `--print cfg` as a `target_feature`. It
/// is never part of a requirement record — a record must list only what the
/// launcher can check against the CPU.
pub(crate) const NON_CPU_FEATURES: [&str; 1] = ["crt-static"];

/// The `-C target-feature=…` entries in `flags`, in order, as written
/// (`+avx2`, `-sse4.2`, `+crt-static`).
fn target_feature_entries(flags: &[String]) -> Vec<&str> {
    codegen_options(flags)
        .into_iter()
        .filter_map(|option| option.strip_prefix("target-feature="))
        .flat_map(|list| list.split(','))
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Whether `flags` adjust CPU target features directly
/// (`-C target-feature=…` naming anything but [`NON_CPU_FEATURES`]): the
/// design builds each core with `-C target-cpu` and nothing else
/// CPU-related, so the build script warns.
pub(crate) fn sets_target_features(flags: &[String]) -> bool {
    target_feature_entries(flags)
        .into_iter()
        .map(|entry| entry.trim_start_matches(['+', '-']))
        .any(|name| !name.is_empty() && !NON_CPU_FEATURES.contains(&name))
}

/// The features `flags` ENABLE (`+name`) that `known` rejects and that
/// aren't [`NON_CPU_FEATURES`]. rustc passes an unknown name straight to
/// LLVM — `+nf`, `+ndd`, `+egpr` turn on APX code generation that
/// `--print cfg` never reports — so a record could not describe the core.
/// Disabling (`-name`) only removes instructions and is always safe.
pub(crate) fn enabled_unknown_features(
    flags: &[String],
    known: impl Fn(&str) -> bool,
) -> Vec<&str> {
    target_feature_entries(flags)
        .into_iter()
        .filter_map(|entry| entry.strip_prefix('+'))
        .filter(|name| !name.is_empty() && !NON_CPU_FEATURES.contains(name) && !known(name))
        .collect()
}

/// The concrete CPU `native` stands for, from `rustc --print target-cpus`
/// output (`native - Select the CPU of the current host (currently
/// znver5).`).
pub(crate) fn resolve_native(target_cpus: &str) -> Option<String> {
    target_cpus
        .lines()
        .find(|line| line.split_whitespace().next() == Some("native"))
        .and_then(|line| line.split("(currently ").nth(1))
        .and_then(|rest| rest.split(')').next())
        .map(|cpu| cpu.trim_end_matches('.').to_owned())
        .filter(|cpu| !cpu.is_empty())
}

/// The target's default CPU when no `target-cpu` is given (the target
/// spec's `cpu`: `apple-m1` for Apple Silicon, `penryn` for Intel macOS,
/// `x86-64` for the other x86-64 targets).
pub(crate) fn default_cpu(target: &str) -> &'static str {
    if target.starts_with("aarch64-apple-") {
        "apple-m1"
    } else if target.starts_with("x86_64-apple-") {
        "penryn"
    } else if target.starts_with("x86_64-") {
        "x86-64"
    } else {
        "generic"
    }
}

/// The CPU `target_feature="…"` names in `rustc --print cfg` output
/// (everything but [`NON_CPU_FEATURES`]), sorted and unique.
pub(crate) fn parse_print_cfg(output: &str) -> Vec<String> {
    let mut features: Vec<String> = output
        .lines()
        .filter_map(|line| line.strip_prefix("target_feature=\""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter(|name| !NON_CPU_FEATURES.contains(name))
        .map(str::to_owned)
        .collect();
    features.sort();
    features.dedup();
    features
}
