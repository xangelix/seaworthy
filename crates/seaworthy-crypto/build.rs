//! seaworthy-crypto's build script:
//!
//! 1. **The FIPS module build-environment guard.** Under the `fips`
//!    feature, refuse (`cargo::error`) every environment knob that silently
//!    changes the AWS-LC FIPS module build: see `build/knobs.rs` for the
//!    rules and the `SEAWORTHY_FIPS_MODULE_BUILD_ACK` escape, which allows a
//!    knob only by name and stamps it into the provenance. Cargo hands every
//!    build script in one invocation the same environment, so what this
//!    script sees is what `aws-lc-fips-sys`'s build script sees.
//! 2. **Build provenance.** Stamp the toolchain that built this binary into
//!    `SEAWORTHY_BUILD_*` compile-time variables
//!    (`seaworthy_crypto::module::build_provenance()`, for boot evidence and
//!    logs): rustc always; under `fips` also the C compiler, CMake, Go and
//!    Perl that build the module, the module-relevant environment,
//!    `-C target-cpu`, and any acknowledged knobs.
//!
//! The provenance is recorded when this script runs — on the first build
//! and whenever a watched variable changes. A system toolchain upgrade with
//! no environment change re-runs neither this script nor the module's own
//! build (cargo does not track system compilers), so the stamp and the
//! module stay consistent; `cargo clean -p seaworthy-crypto -p
//! aws-lc-fips-sys` rebuilds both.

#[path = "build/knobs.rs"]
mod knobs;

use std::process::Command;

/// The longest provenance value kept (one log-safe line).
const MAX_VALUE_LEN: usize = 240;

/// One printable line: the first line of `text`, control characters
/// stripped, capped.
fn one_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    let clean: String = line
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_VALUE_LEN)
        .collect();
    clean.trim().to_string()
}

/// `program args…` → the first non-empty line of stdout (else stderr: MSVC
/// `cl` prints its banner there), or `"<program> (version unavailable)"`.
fn tool_version(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = one_line(&String::from_utf8_lossy(&output.stdout));
            if stdout.is_empty() {
                let stderr = one_line(&String::from_utf8_lossy(&output.stderr));
                if stderr.is_empty() {
                    format!("{program} (version unavailable)")
                } else {
                    stderr
                }
            } else {
                stdout
            }
        }
        Err(_) => format!("{program} (not found)"),
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The sys crate's own lookup chain for a tool (`get_crate_cc` and
/// friends): the host/target form first, then the plain one; each as
/// `AWS_LC_FIPS_SYS_<X>_<target>`, `AWS_LC_FIPS_SYS_<X>`, `<X>_<target>`,
/// `<X>`.
fn sys_crate_tool(base: &str, target: &str, cross: bool) -> Option<String> {
    let suffix = knobs::target_suffix(target);
    let chain = |name: &str| {
        env(&format!("{}{name}_{suffix}", knobs::PREFIX))
            .or_else(|| env(&format!("{}{name}", knobs::PREFIX)))
            .or_else(|| env(&format!("{name}_{suffix}")))
            .or_else(|| env(name))
    };
    let scoped = if cross {
        format!("TARGET_{base}")
    } else {
        format!("HOST_{base}")
    };
    chain(&scoped).or_else(|| chain(base))
}

fn stamp(name: &str, value: &str) {
    println!(
        "cargo::rustc-env=SEAWORTHY_BUILD_{name}={}",
        one_line(value)
    );
}

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=build/knobs.rs");
    let target = env("TARGET").unwrap_or_default();
    let host = env("HOST").unwrap_or_default();
    for name in knobs::watched_names(&target) {
        println!("cargo::rerun-if-env-changed={name}");
    }
    let fips = std::env::var_os("CARGO_FEATURE_FIPS").is_some();

    // 1. The guard.
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let verdict = knobs::evaluate(&vars, &target, fips);
    for warning in &verdict.warnings {
        println!("cargo::warning=seaworthy-crypto: {warning}");
    }
    if !verdict.refused.is_empty() {
        for finding in &verdict.refused {
            println!(
                "cargo::error=seaworthy-crypto/fips (FIPS module build guard): {}; unset it, or \
                 acknowledge it by name in {} (it is then stamped into the build provenance)",
                finding.detail,
                knobs::ACK_VAR
            );
        }
        return;
    }

    // 2. The provenance.
    let rustc = env("RUSTC").unwrap_or_else(|| "rustc".to_string());
    stamp("RUSTC", &tool_version(&rustc, &["-V"]));
    stamp("TARGET", &target);
    stamp("PROFILE", &env("PROFILE").unwrap_or_default());
    stamp("OPT_LEVEL", &env("OPT_LEVEL").unwrap_or_default());
    stamp(
        "TARGET_CPU",
        verdict.target_cpu.as_deref().unwrap_or("default"),
    );
    if fips {
        let cross = host != target;
        let cc = sys_crate_tool("CC", &target, cross).unwrap_or_else(|| "cc".to_string());
        let cc_version = if cc == "cl" || cc.ends_with("cl.exe") {
            tool_version(&cc, &[])
        } else {
            tool_version(&cc, &["--version"])
        };
        stamp("CC", &format!("{cc}: {cc_version}"));
        let cmake = env(&format!("{}CMAKE", knobs::PREFIX))
            .or_else(|| env("CMAKE"))
            .unwrap_or_else(|| "cmake".to_string());
        stamp("CMAKE", &tool_version(&cmake, &["--version"]));
        stamp("GO", &tool_version("go", &["version"]));
        stamp("PERL", &tool_version("perl", &["-e", "print qq{perl $^V}"]));
        stamp("MODULE_ENV", &verdict.recorded.join(" "));
        let acknowledged: Vec<&str> = verdict
            .acknowledged
            .iter()
            .map(|finding| finding.key.as_str())
            .collect();
        stamp("ACKNOWLEDGED", &acknowledged.join(","));
    } else {
        let none = "n/a (non-FIPS build: no module is compiled)";
        for name in ["CC", "CMAKE", "GO", "PERL"] {
            stamp(name, none);
        }
        stamp("MODULE_ENV", none);
        stamp("ACKNOWLEDGED", "");
    }
}
