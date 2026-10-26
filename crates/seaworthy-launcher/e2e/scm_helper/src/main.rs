//! The update lane's helper: seaworthy-updater's real helper, set up as a
//! product's helper is (`seaworthy_updater::helper` module docs), with the
//! lane's seaworthy.toml and release key compiled in (build.rs). The MSI
//! installs it as the `<service>-update` service (LocalSystem, demand
//! start). It learns the server's version from the lane's stub on loopback
//! (`GET /required` on 127.0.0.1:8470: seaworthy-service's
//! `windows_scm_e2e serve`, which `scripts/windows-msi-update.ps1` starts)
//! and fetches the release from the same stub, from the release tree's
//! layout: `repo/releases/<package>/<channel>/<token>/<target>/
//! <package>.<format>` and its `.manifest`.
//!
//! Under the Service Control Manager a service has no stderr, so it also
//! logs to `%ProgramData%\<Vendor>\<Directory>\logs\scm_helper.log`, the
//! MSI's locked logs directory (`seaworthy_updater::helper::log_file`).

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
use seaworthy_updater::{ManifestTrust, Product, ReleaseKey, SignatureAlgorithm};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// The service's line logger, shared source (the fixture carries no
// tracing-subscriber).
#[allow(dead_code, reason = "the helper uses part of the service's logger")]
#[path = "../../scm_core/src/line_log.rs"]
mod line_log;

const CONFIG: &str = include_str!(concat!(env!("OUT_DIR"), "/seaworthy.toml"));
const RELEASE_KEY_HEX: &str = include_str!(concat!(env!("OUT_DIR"), "/release.pub"));
/// The product this helper updates.
const PRODUCT: &str = "agent";
/// The lane's version gate and release server (one loopback stub).
const STUB: &str = "127.0.0.1:8470";
const PACKAGE_URL: &str =
    "http://127.0.0.1:8470/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}";
/// The probe's budget: a loopback answer, or a stub that isn't running.
const PROBE_BUDGET: Duration = Duration::from_secs(30);
/// The most of the stub's answer read (a version token).
const MAX_ANSWER: u64 = 64 * 1024;

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

/// Windows: the MSI's logs directory; elsewhere `None` (the service
/// manager keeps stderr).
fn log_file() -> Option<std::fs::File> {
    let product = Product::from_config(CONFIG, PRODUCT).ok()?;
    seaworthy_updater::helper::log_file(&product, "scm_helper")
}

fn config() -> Result<HelperConfig, String> {
    if CONFIG.trim().is_empty() || RELEASE_KEY_HEX.trim().is_empty() {
        return Err(
            "built without the update lane's seaworthy.toml and release key \
                    (scripts/windows-lab-build.ps1 builds it with them)"
                .to_owned(),
        );
    }
    let product = Product::from_config(CONFIG, PRODUCT).map_err(|e| e.to_string())?;
    let key = hex::decode(RELEASE_KEY_HEX.trim()).map_err(|e| format!("release key: {e}"))?;
    let key = ReleaseKey::new(key, SignatureAlgorithm::MlDsa87).map_err(|e| e.to_string())?;
    let trust = ManifestTrust::for_product(&product, [key]).map_err(|e| e.to_string())?;
    let config = HelperConfig::new(
        product,
        trust,
        PACKAGE_URL,
        required_version,
        PackageSignatures::ManifestOnly,
    )
    .map_err(|e| e.to_string())?;
    Ok(config.probe_timeout(PROBE_BUDGET))
}

/// The version source: the token the stub's `/required` answers.
async fn required_version() -> Result<String, String> {
    let mut stream = tokio::net::TcpStream::connect(STUB)
        .await
        .map_err(|e| format!("connecting to the version gate {STUB}: {e}"))?;
    stream
        .write_all(b"GET /required HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("asking the version gate: {e}"))?;
    let mut response = Vec::new();
    stream
        .take(MAX_ANSWER)
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("reading the version gate's answer: {e}"))?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the version gate's answer has no header terminator")?;
    let (head, body) = response.split_at(split);
    let status = String::from_utf8_lossy(head)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .unwrap_or_default();
    if status != "200" {
        return Err(format!(
            "the version gate answered HTTP {}",
            line_log::line_safe(&status)
        ));
    }
    Ok(String::from_utf8_lossy(body.get(4..).unwrap_or_default())
        .trim()
        .to_owned())
}
