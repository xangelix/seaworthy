//! Compiles a Windows lane's inputs into the helper, as a product's helper
//! compiles its `seaworthy.toml`, release key and URLs in:
//!
//! - `SEAWORTHY_E2E_HELPER_CONFIG` (a file): the product's seaworthy.toml;
//! - `SEAWORTHY_E2E_HELPER_RELEASE_KEY` (a file): the one trusted ML-DSA-87
//!   release key, hex as `seaworthy keygen --public` writes it (the update
//!   lane's throwaway key, or the upgrade lane's public CI test key,
//!   `scm/keys/ci-test.pub`);
//! - `SEAWORTHY_E2E_HELPER_PACKAGE_URL` (a value; default the update lane's
//!   loopback stub, `PACKAGE_URL` below): the URL template releases are
//!   fetched from;
//! - `SEAWORTHY_E2E_HELPER_VERSION_URL` (a value; default the stub's
//!   `/required`, `VERSION_URL`): the endpoint the version source asks.
//!
//! A URL is plain HTTP to 127.0.0.1 (the update lane's stub) or HTTPS to a
//! name under `.invalid` (the upgrade lane's lab, behind its hosts entries):
//! a helper that trusts the public CI test key accepts a release anyone
//! signed, so it must never dial a name that resolves outside a lab.
//! Anything else fails the build.
//!
//! Unset (any other build of this workspace), the files are empty and the
//! helper refuses to run.

use std::path::PathBuf;

const PACKAGE_URL: &str =
    "http://127.0.0.1:8470/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}";
const VERSION_URL: &str = "http://127.0.0.1:8470/required";

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
    for (var, default, name) in [
        (
            "SEAWORTHY_E2E_HELPER_PACKAGE_URL",
            PACKAGE_URL,
            "SCM_HELPER_PACKAGE_URL",
        ),
        (
            "SEAWORTHY_E2E_HELPER_VERSION_URL",
            VERSION_URL,
            "SCM_HELPER_VERSION_URL",
        ),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let value = std::env::var(var).unwrap_or_else(|_| default.to_owned());
        check_url(var, &value);
        println!("cargo:rustc-env={name}={value}");
    }
}

/// Plain HTTP to 127.0.0.1, or HTTPS to a name under `.invalid`; one line,
/// no credentials.
fn check_url(var: &str, url: &str) {
    assert!(
        !url.is_empty() && !url.chars().any(|c| c.is_control() || c.is_whitespace()),
        "{var} must be one URL without spaces"
    );
    let (scheme, rest) = url
        .split_once("://")
        .unwrap_or_else(|| panic!("{var}: {url:?} is not a URL"));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    assert!(
        !authority.contains('@'),
        "{var}: {url:?} carries credentials"
    );
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    let lab_name = host.len() > ".invalid".len()
        && host.ends_with(".invalid")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    match scheme {
        "http" => assert!(
            host == "127.0.0.1",
            "{var}: plain HTTP goes to 127.0.0.1 only (the update lane's stub), not {url:?}"
        ),
        "https" => assert!(
            lab_name,
            "{var}: HTTPS goes to a name under .invalid only (the upgrade lane's lab), not {url:?}"
        ),
        _ => panic!("{var}: {url:?} is neither http nor https"),
    }
}
