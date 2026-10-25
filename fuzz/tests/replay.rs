//! Replay every committed seed (`fuzz/corpus/<target>/`) and every minimized
//! regression input (`fuzz/regressions/<target>/`) through its target
//! function on STABLE: no libFuzzer, no sanitizer. A crash found by fuzzing
//! becomes a permanent regression test by dropping its minimized input into
//! `regressions/<target>/` (fuzz/README.md).
//!
//! Run: `cargo test --manifest-path fuzz/Cargo.toml`.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The regular files in `dir` (sorted), without `.gitkeep`; none when the
/// directory does not exist.
fn files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.file_name().is_some_and(|n| n != ".gitkeep"))
        .collect();
    files.sort();
    files
}

/// The file stems of the `.rs` files in `dir` (sorted).
fn rust_stems(dir: &Path) -> Vec<String> {
    let mut stems: Vec<String> = files(dir)
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
        .collect();
    stems.sort();
    stems
}

/// The `name` of every `[[bin]]` table in the fuzz crate's Cargo.toml.
fn bin_names() -> Vec<String> {
    let manifest = std::fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let mut names = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin && let Some(rest) = line.strip_prefix("name") {
            let value = rest.trim_start().strip_prefix('=').unwrap().trim();
            names.push(value.trim_matches('"').to_owned());
        }
    }
    names.sort();
    names
}

fn target_names() -> Vec<String> {
    let mut names: Vec<String> = seaworthy_fuzz::TARGETS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_seed_and_regression_replays_clean() {
    let mut failures = Vec::new();
    for (name, run) in seaworthy_fuzz::TARGETS {
        for kind in ["corpus", "regressions"] {
            for file in files(&root().join(kind).join(name)) {
                let data = std::fs::read(&file).unwrap();
                if std::panic::catch_unwind(|| run(&data)).is_err() {
                    failures.push(format!("{name}: {}", file.display()));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "inputs that panicked:\n{}",
        failures.join("\n")
    );
}

/// The target list in src/lib.rs, the `[[bin]]` entries, the wrappers, the
/// target modules and the seed directories all name the same targets.
#[test]
fn targets_bins_wrappers_and_seeds_agree() {
    let targets = target_names();
    assert_eq!(
        bin_names(),
        targets,
        "Cargo.toml [[bin]] names != the targets! list in src/lib.rs"
    );
    assert_eq!(
        rust_stems(&root().join("fuzz_targets")),
        targets,
        "fuzz_targets/*.rs != the targets! list in src/lib.rs"
    );
    assert_eq!(
        rust_stems(&root().join("src").join("targets")),
        targets,
        "src/targets/*.rs != the targets! list in src/lib.rs (an unlisted target is never compiled)"
    );
    for name in &targets {
        assert!(
            !files(&root().join("corpus").join(name)).is_empty(),
            "{name}: no seeds in corpus/{name}/"
        );
    }
}

/// Seed and regression directories belong to a known target: a renamed or
/// removed target must not leave inputs behind that silently stop replaying.
#[test]
fn every_input_directory_has_a_target() {
    let targets = target_names();
    for kind in ["corpus", "regressions"] {
        let Ok(entries) = std::fs::read_dir(root().join(kind)) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                targets.contains(&name),
                "{kind}/{name}/ has no target in src/lib.rs"
            );
        }
    }
}
