//! The Windows lanes' update helper: seaworthy-updater's real helper, set up
//! as a product's helper is (`seaworthy_updater::helper` module docs), with
//! a lane's seaworthy.toml, release key and URLs compiled in (build.rs).
//! The MSI installs it as the `<service>-update` service (LocalSystem,
//! demand start).
//!
//! Its version source is `seaworthy_lab::client`, the lab's
//! required-version client (TLS on seaworthy-crypto's policy with the
//! operating system's trust store, or plain HTTP to loopback): the update
//! lane builds it against its loopback stub (`GET /required` on
//! 127.0.0.1:8470, seaworthy-service's `windows_scm_e2e serve`, which
//! `scripts/windows-msi-update.ps1` starts), the upgrade lane against the
//! lab server's required-version endpoint under `updates.lab.invalid`
//! (`scripts/windows-upgrade.ps1`). It fetches releases from the release
//! tree's layout at its URL template: `repo/releases/<package>/<channel>/
//! <token>/<target>/<package>.<format>` and its `.manifest`.
//!
//! The upgrade lane's candidate trusts the fixture's public CI test key as
//! a product's CI build would: through `ci_test_keys!` and
//! `ManifestTrust::with_ci_test_keys`, in a build made with the CI
//! test-key switch (`SEAWORTHY_ALLOW_CI_TEST_KEYS=1`), never as its release
//! key. Such a binary carries the CI test-key marker and logs the warning
//! at every run.
//!
//! Under the Service Control Manager a service has no stderr, so it also
//! logs to `%ProgramData%\<Vendor>\<Directory>\update-logs\scm_helper.log`,
//! the helper's own directory, SYSTEM and Administrators only
//! (`seaworthy_updater::helper::log_file`).

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use seaworthy_lab::client::RequiredVersionClient;
use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
use seaworthy_updater::{ManifestTrust, Product, ReleaseKey, SignatureAlgorithm};

// The service's line logger, shared source (the fixture carries no
// tracing-subscriber).
#[allow(dead_code, reason = "the helper uses part of the service's logger")]
#[path = "../../scm_core/src/line_log.rs"]
mod line_log;

const CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/seaworthy.toml"));
const RELEASE_KEY_HEX: &str = include_str!(concat!(env!("OUT_DIR"), "/release.pub"));

/// The product's public CI test key (`SEAWORTHY_E2E_HELPER_CI_TEST_KEY`):
/// `Some` only in a build made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1`, whose
/// binary then carries the CI test-key marker; in any other build the file
/// is never compiled in.
fn ci_test_key() -> Option<&'static str> {
    seaworthy_updater::ci_test_keys!(include_str!(concat!(env!("OUT_DIR"), "/ci-test.pub")))
}
/// The product this helper updates.
const PRODUCT: &str = "agent";
/// The lane's release tree (build.rs: the stub, or the lab under
/// `packages.lab.invalid`).
const PACKAGE_URL: &str = env!("SCM_HELPER_PACKAGE_URL");
/// The lane's version gate (build.rs: the stub's `/required`, or the lab's
/// required-version endpoint under `updates.lab.invalid`).
const VERSION_URL: &str = env!("SCM_HELPER_VERSION_URL");
/// The version source's budget per request; the helper's own probe
/// timeout leaves it room to fail with its own reason first.
const PROBE_BUDGET: Duration = Duration::from_secs(30);

fn main() -> ExitCode {
    let mut outputs: Vec<Box<dyn Write + Send>> = vec![Box::new(std::io::stderr())];
    if let Some(file) = log_file() {
        outputs.push(Box::new(file));
    }
    line_log::install(outputs);
    match config() {
        Ok(config) => seaworthy_updater::helper::main(config),
        Err(error) => {
            tracing::error!("scm_helper: {}", line_log::line_safe(&error));
            ExitCode::FAILURE
        }
    }
}

/// Windows: the helper's own log directory (`update-logs`); elsewhere
/// `None` (the service manager keeps stderr).
fn log_file() -> Option<std::fs::File> {
    let product = Product::from_config(CONFIG, PRODUCT).ok()?;
    seaworthy_updater::helper::log_file(&product, "scm_helper")
}

fn config() -> Result<HelperConfig, String> {
    if CONFIG.trim().is_empty() || RELEASE_KEY_HEX.trim().is_empty() {
        return Err("built without a lane's seaworthy.toml and release key \
                    (scripts/windows-lab-build.ps1 builds it with them)"
            .to_owned());
    }
    let product = Product::from_config(CONFIG, PRODUCT).map_err(|e| e.to_string())?;
    let key = hex::decode(RELEASE_KEY_HEX.trim()).map_err(|e| format!("release key: {e}"))?;
    let key = ReleaseKey::new(key, SignatureAlgorithm::MlDsa87).map_err(|e| e.to_string())?;
    let mut test_keys = Vec::new();
    if let Some(text) = ci_test_key().filter(|text| !text.trim().is_empty()) {
        let test = hex::decode(text.trim()).map_err(|e| format!("CI test key: {e}"))?;
        test_keys.push(
            ReleaseKey::new(test, SignatureAlgorithm::MlDsa87)
                .map_err(|e| format!("CI test key: {e}"))?,
        );
    }
    let trust = ManifestTrust::for_product(&product, [key])
        .and_then(|trust| trust.with_ci_test_keys(test_keys))
        .map_err(|e| e.to_string())?;
    // Checked now: a bad URL fails the run at once, not at the first probe.
    RequiredVersionClient::new(VERSION_URL, PROBE_BUDGET).map_err(|e| e.to_string())?;
    let config = HelperConfig::new(
        product,
        trust,
        PACKAGE_URL,
        || async {
            RequiredVersionClient::new(VERSION_URL, PROBE_BUDGET)?
                .fetch()
                .await
        },
        PackageSignatures::ManifestOnly,
    )
    .map_err(|e| e.to_string())?;
    Ok(config.probe_timeout(PROBE_BUDGET + Duration::from_secs(10)))
}
