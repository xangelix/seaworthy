//! Compiles a lab lane's inputs into the helper, as a product's helper
//! compiles its `seaworthy.toml`, keys and URLs in. Each is an environment
//! variable naming a file, or for the URLs and the product, a value:
//!
//! - `SEAWORTHY_LAB_CONFIG`: the product's `seaworthy.toml`;
//! - `SEAWORTHY_LAB_RELEASE_PUB`: the trusted ML-DSA-87 release keys, one
//!   lowercase hex public key per line (`seaworthy keygen --public`);
//! - `SEAWORTHY_LAB_OPENPGP` (optional): the pinned OpenPGP keys, armored;
//!   without it (a pkg, an MSI, a lane that doesn't sign its rpm and
//!   pacman packages) only the manifest is checked;
//! - `SEAWORTHY_LAB_PRODUCT` (default `agent`): the product's id in the
//!   configuration;
//! - `SEAWORTHY_LAB_PACKAGE_URL` (default
//!   `http://127.0.0.1:8470/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}`,
//!   the conformance lane's release tree): the helper's URL template;
//! - `SEAWORTHY_LAB_VERSION_URL` (default
//!   `http://127.0.0.1:8470/_lab/required-version`): the required-version
//!   endpoint its version source asks.
//!
//! Unset (the launcher lane builds this workspace too), the files are
//! empty and the helper refuses to run.

use std::path::PathBuf;

const PACKAGE_URL: &str =
    "http://127.0.0.1:8470/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}";
const VERSION_URL: &str = "http://127.0.0.1:8470/_lab/required-version";

fn main() {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    for (var, name) in [
        ("SEAWORTHY_LAB_CONFIG", "seaworthy.toml"),
        ("SEAWORTHY_LAB_RELEASE_PUB", "release.pub"),
        ("SEAWORTHY_LAB_OPENPGP", "openpgp.asc"),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let bytes = match std::env::var_os(var) {
            Some(path) => {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
                std::fs::read(&path).unwrap_or_else(|e| panic!("{var}: {e}"))
            }
            None => Vec::new(),
        };
        std::fs::write(out.join(name), bytes).expect("write OUT_DIR input");
    }
    for (var, default, name) in [
        ("SEAWORTHY_LAB_PRODUCT", "agent", "LAB_PRODUCT"),
        ("SEAWORTHY_LAB_PACKAGE_URL", PACKAGE_URL, "LAB_PACKAGE_URL"),
        ("SEAWORTHY_LAB_VERSION_URL", VERSION_URL, "LAB_VERSION_URL"),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let value = std::env::var(var).unwrap_or_else(|_| default.to_owned());
        assert!(
            !value.is_empty() && !value.chars().any(char::is_control),
            "{var} must be one line"
        );
        println!("cargo:rustc-env={name}={value}");
    }
}
