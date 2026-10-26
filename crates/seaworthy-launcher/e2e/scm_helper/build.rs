//! Compiles the update lane's inputs into the helper, as a product's helper
//! compiles its `seaworthy.toml` and release keys in:
//! `SEAWORTHY_E2E_HELPER_CONFIG` (the product's seaworthy.toml) and
//! `SEAWORTHY_E2E_HELPER_RELEASE_KEY` (the ML-DSA-87 release key, hex as
//! `seaworthy keygen --public` writes it), each a file path. Unset (any
//! other build of this workspace), each becomes an empty file, and the
//! helper refuses to run.

use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    for (var, name) in [
        ("SEAWORTHY_E2E_HELPER_CONFIG", "seaworthy.toml"),
        ("SEAWORTHY_E2E_HELPER_RELEASE_KEY", "release.pub"),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let bytes = match std::env::var_os(var) {
            Some(path) => {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
                std::fs::read(&path).unwrap_or_else(|e| panic!("{var}: {e}"))
            }
            None => Vec::new(),
        };
        std::fs::write(out.join(name), bytes).expect("write an OUT_DIR input");
    }
}
