//! The lab fixture's update helper: seaworthy-updater's real helper, set up
//! as a product's helper is (`seaworthy_updater::helper` module docs), with
//! a lab lane's configuration, keys and URLs compiled in (build.rs).
//!
//! Its version source (the caller closure the helper asks once per run) is
//! the lab server's required-version endpoint, through
//! `seaworthy_lab::client`: TLS on seaworthy-crypto's policy with the
//! operating system's trust store, or plain HTTP to loopback (the
//! conformance lanes). It fetches releases from the lab's release tree, as
//! `seaworthy repo` publishes it: `releases/<package>/<channel>/<token>/
//! <target>/<package>.<format>`, its `.manifest`, and for pacman its `.sig`.
//! The lanes lay their refused cases out in the same place.

use std::process::ExitCode;
use std::time::Duration;

use seaworthy_lab::client::RequiredVersionClient;
use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
use seaworthy_updater::openpgp::OpenPgpKeys;
use seaworthy_updater::{ManifestTrust, Product, ReleaseKey, SignatureAlgorithm};

const CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/seaworthy.toml"));
const RELEASE_KEYS_HEX: &str = include_str!(concat!(env!("OUT_DIR"), "/release.pub"));
const OPENPGP_KEYS: &str = include_str!(concat!(env!("OUT_DIR"), "/openpgp.asc"));
const PRODUCT: &str = env!("LAB_PRODUCT");
const PACKAGE_URL: &str = env!("LAB_PACKAGE_URL");
const VERSION_URL: &str = env!("LAB_VERSION_URL");

/// The version source may wait on the lab's held endpoint (a run an
/// administrator's upgrade overtakes): well past the lab's two-minute
/// hold.
const PROBE_BUDGET: Duration = Duration::from_secs(180);

fn main() -> ExitCode {
    let logs = tracing_subscriber::fmt().with_ansi(false).without_time();
    match log_file() {
        Some(file) => {
            use tracing_subscriber::fmt::writer::MakeWriterExt as _;
            logs.with_writer(std::sync::Mutex::new(file).and(std::io::stderr))
                .init();
        }
        None => logs.with_writer(std::io::stderr).init(),
    }
    match config() {
        Ok(config) => seaworthy_updater::helper::main(config),
        Err(error) => {
            eprintln!("demo_helper: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Windows: the Service Control Manager gives a service no stderr, so the
/// helper logs to its product's log directory (`helper::log_file`), which
/// a Windows lane reads. Elsewhere `None`: the service manager keeps
/// stderr (the journal, launchd's log file).
fn log_file() -> Option<std::fs::File> {
    let product = Product::from_config(CONFIG, PRODUCT).ok()?;
    seaworthy_updater::helper::log_file(&product, "demo_helper")
}

fn config() -> Result<HelperConfig, String> {
    if CONFIG.is_empty() || RELEASE_KEYS_HEX.trim().is_empty() {
        return Err("built without a lab lane's seaworthy.toml and release keys \
                    (SEAWORTHY_LAB_CONFIG, SEAWORTHY_LAB_RELEASE_PUB: the lab scripts build it with them)"
            .to_owned());
    }
    let product = Product::from_config(CONFIG, PRODUCT).map_err(|e| e.to_string())?;
    let mut keys = Vec::new();
    for line in RELEASE_KEYS_HEX
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let key = hex::decode(line).map_err(|e| format!("release key: {e}"))?;
        keys.push(ReleaseKey::new(key, SignatureAlgorithm::MlDsa87).map_err(|e| e.to_string())?);
    }
    let trust = ManifestTrust::for_product(&product, keys).map_err(|e| e.to_string())?;
    let signatures = if OPENPGP_KEYS.trim().is_empty() {
        PackageSignatures::ManifestOnly
    } else {
        PackageSignatures::Pinned(
            OpenPgpKeys::new([OPENPGP_KEYS]).map_err(|e| format!("openpgp keys: {e}"))?,
        )
    };
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
        signatures,
    )
    .map_err(|e| e.to_string())?;
    Ok(config.probe_timeout(PROBE_BUDGET + Duration::from_secs(10)))
}
