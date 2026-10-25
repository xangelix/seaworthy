//! Writes the requirement record a core carries in its `.cpureq` section.
//!
//! A core crate depends on seaworthy-launcher, so cargo compiles
//! seaworthy-launcher — and runs this script — with exactly the core's
//! target and flags. Each
//! CPU target is built in its own target directory with its own
//! `-C target-cpu`, so the record always describes the binary it ends up
//! in. (Flags given to the core crate ALONE — `cargo rustc -- -C …` — never
//! reach this script; `core_main!` catches that mismatch at compile time
//! from the list this script also writes, `visible.rs`.)
//!
//! The feature list comes from `$RUSTC --print cfg` with the same target
//! and flags, and `RUSTC_BOOTSTRAP=1` for that one query: stable rustc hides
//! unstable target features from `--print cfg` (and from
//! `CARGO_CFG_TARGET_FEATURE`) even though `-C target-cpu` still enables
//! them. It enables nothing in any compiled code. To that list the script
//! adds the features the CPU target uses without `--print cfg` reporting
//! them ([`seaworthy_levels::IMPLIED_FEATURES`] — APX on `diamondrapids` and
//! `novalake`), and it refuses what no record could describe: a
//! `-C target-feature=+name` naming something seaworthy-levels has no row for
//! on the target's architecture (x86-64 or aarch64), and any enabled name
//! without a row.

// The crate's own rules hold here too (this script and `src/rustflags.rs`
// parse what cargo and rustc hand them).
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

#[path = "src/rustflags.rs"]
mod rustflags;

use std::process::Command;

fn env(name: &str) -> String {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).unwrap_or_else(|_| fail(&format!("cargo did not set {name}")))
}

fn fail(message: &str) -> ! {
    eprintln!("seaworthy-launcher build script: {message}");
    std::process::exit(1);
}

/// Runs `$RUSTC` with `args` and the core's target and flags; its stdout.
fn query(rustc: &str, target: &str, flags: &[String], args: &[&str]) -> String {
    let output = Command::new(rustc)
        .env("RUSTC_BOOTSTRAP", "1")
        .args(args)
        .args(["--target", target])
        .args(flags)
        .output()
        .unwrap_or_else(|e| fail(&format!("cannot run {rustc}: {e}")));
    if !output.status.success() {
        fail(&format!(
            "`{rustc} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/rustflags.rs");
    let target = env("TARGET");
    let rustc = env("RUSTC");
    let out_dir = env("OUT_DIR");
    let flags = rustflags::split(&std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default());

    let cpu =
        rustflags::target_cpu(&flags).unwrap_or_else(|| rustflags::default_cpu(&target).to_owned());
    if rustflags::sets_target_features(&flags) {
        println!(
            "cargo:warning=seaworthy-launcher: `-C target-feature` is set; a core should be built with \
             `-C target-cpu` alone (the record still lists exactly what the compiler enabled)"
        );
    }
    let unknown =
        rustflags::enabled_unknown_features(&flags, |name| seaworthy_levels::known(&target, name));
    if !unknown.is_empty() {
        fail(&format!(
            "`-C target-feature` enables {}, which seaworthy-levels has no row for: the compiler would \
             emit instructions no requirement record can name (APX's `nf`/`ndd`/`egpr`, for one), \
             so the launcher could load this core on a CPU that faults on it. Build cores with \
             `-C target-cpu` alone",
            unknown.join(", ")
        ));
    }

    let mut features =
        rustflags::parse_print_cfg(&query(&rustc, &target, &flags, &["--print", "cfg"]));
    // What the CPU target uses without `--print cfg` saying so. `native`
    // is looked up as the host CPU it stands for.
    let concrete = if cpu == "native" {
        println!(
            "cargo:warning=seaworthy-launcher: `-C target-cpu=native` builds a core for this machine only; \
             the launcher refuses it (its record names `native`, not one of the product's CPU targets)"
        );
        rustflags::resolve_native(&query(&rustc, &target, &flags, &["--print", "target-cpus"]))
            .unwrap_or_else(|| fail("cannot tell which CPU `-C target-cpu=native` stands for"))
    } else {
        cpu.clone()
    };
    for implied in seaworthy_levels::implied_features(&concrete) {
        if !features.iter().any(|feature| feature == implied) {
            features.push(implied.to_owned());
        }
    }
    features.sort();

    // Every name must be one the launcher can check: an unknown one makes
    // the core unloadable on every machine.
    if let Some(name) = features
        .iter()
        .find(|name| !seaworthy_levels::known(&target, name))
    {
        let table = match seaworthy_levels::Arch::of_target(&target) {
            Some(seaworthy_levels::Arch::Aarch64) => "crates/seaworthy-levels/src/aarch64.rs",
            Some(seaworthy_levels::Arch::X86_64) => "crates/seaworthy-levels/src/table.rs",
            None => {
                fail(&format!(
                    "{target}: seaworthy-levels has no feature table for this architecture (x86-64 and aarch64 only)"
                ));
            }
        };
        fail(&format!(
            "the compiler enables `{name}` for {target} {cpu}, which seaworthy-levels has no row for — the \
             launcher would refuse this core everywhere. Add the row ({table}; \
             crates/seaworthy-levels/tests/vocabulary.rs names what is missing for this toolchain)"
        ));
    }

    // The record must cover everything cargo itself sees enabled — the
    // features `cfg!(target_feature)` reports on this toolchain.
    let visible: Vec<String> = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty() && !rustflags::NON_CPU_FEATURES.contains(name))
        .map(str::to_owned)
        .collect();
    if let Some(name) = visible.iter().find(|name| !features.contains(name)) {
        fail(&format!(
            "`--print cfg` did not list `{name}`, which cargo reports enabled — the record would under-report"
        ));
    }

    let record = seaworthy_levels::Requirement {
        target: target.clone(),
        cpu: cpu.clone(),
        features,
    };
    let text = record.render();
    // Refuse to write a record the launcher would refuse to read.
    if let Err(e) = seaworthy_levels::Requirement::parse(text.as_bytes()) {
        fail(&format!("the record for {target} {cpu} is malformed: {e}"));
    }
    let out = std::path::Path::new(&out_dir);
    let write = |name: &str, contents: &str| {
        let path = out.join(name);
        std::fs::write(&path, contents)
            .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", path.display())));
    };
    write("cpureq.bin", &text);
    // The names `cfg!(target_feature)` sees in this build, for `core_main!`'s
    // compile-time check that the core crate was built with the same flags.
    write("visible.rs", &format!("&{visible:?}"));
    println!("cargo:rustc-env=SEAWORTHY_LAUNCHER_TARGET={target}");
    println!("cargo:rustc-env=SEAWORTHY_LAUNCHER_CPU={cpu}");
}
