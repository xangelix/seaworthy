//! Compiles a lab lane's inputs into the helper, as a product's helper
//! compiles its `seaworthy.toml`, keys and URLs in. Each is an environment
//! variable naming a file, or for the URLs and the product, a value:
//!
//! - `SEAWORTHY_LAB_CONFIG`: the product's `seaworthy.toml`;
//! - `SEAWORTHY_LAB_RELEASE_PUB`: the trusted ML-DSA-87 release keys, one
//!   lowercase hex public key per line (`seaworthy keygen --public`);
//! - `SEAWORTHY_LAB_CI_TEST_PUB` (optional): the product's public CI test
//!   keys, one lowercase hex ML-DSA-87 key per line (the upgrade lanes:
//!   the desktop fixture's `keys/ci-test.pub`), which the helper trusts
//!   beside the release keys through `ci_test_keys!` and
//!   `ManifestTrust::with_ci_test_keys`. Anyone can sign with them, so the
//!   build must carry seaworthy-formats' CI test-key switch
//!   (`SEAWORTHY_ALLOW_CI_TEST_KEYS=1`: the binary then carries the CI
//!   test-key marker, which `seaworthy verify` refuses outside a
//!   `--ci-test-signing` build), and both URLs must reach the lab alone
//!   (HTTPS to a name under `.invalid`, or plain HTTP to 127.0.0.1);
//!   anything else fails the build;
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
        ("SEAWORTHY_LAB_CI_TEST_PUB", "ci-test.pub"),
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
    // The CI test keys need the switch (seaworthy-formats' build script
    // reads the same variable): without it the helper would quietly drop
    // them and refuse every test-signed release at run time.
    println!("cargo:rerun-if-env-changed=SEAWORTHY_ALLOW_CI_TEST_KEYS");
    let test_keys = std::env::var_os("SEAWORTHY_LAB_CI_TEST_PUB").is_some();
    if test_keys {
        assert!(
            std::env::var("SEAWORTHY_ALLOW_CI_TEST_KEYS").as_deref() == Ok("1"),
            "SEAWORTHY_LAB_CI_TEST_PUB needs the CI test-key switch, SEAWORTHY_ALLOW_CI_TEST_KEYS=1 \
             (a lab build, never a release)"
        );
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
        if test_keys && name != "LAB_PRODUCT" {
            check_lab_url(var, &value);
        }
        println!("cargo:rustc-env={name}={value}");
    }
}

/// A helper that trusts the public CI test keys accepts a release anyone
/// signed: it may reach the lab alone, plain HTTP to 127.0.0.1 or HTTPS
/// to a name under `.invalid` (which never resolves outside a lab's hosts
/// entries); one URL, no credentials.
fn check_lab_url(var: &str, url: &str) {
    assert!(
        !url.chars().any(char::is_whitespace),
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
            "{var}: a helper trusting the CI test keys uses plain HTTP to 127.0.0.1 only, not {url:?}"
        ),
        "https" => assert!(
            lab_name,
            "{var}: a helper trusting the CI test keys uses HTTPS to a name under .invalid only, not {url:?}"
        ),
        _ => panic!("{var}: {url:?} is neither http nor https"),
    }
}
