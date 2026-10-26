//! The update helper: a per-product binary running as root (on Windows as
//! LocalSystem, the `<service>-update` service the MSI installs), started
//! by the app's request, that installs the release the server names, or
//! nothing.
//!
//! It takes no input from the app: no arguments, no request contents. It
//! learns everything itself, from what an administrator or the release
//! pipeline controls:
//!
//! 1. **The policy**, re-read ([`crate::read_policy`]): anything but
//!    `auto` ends the run.
//! 2. **Its staging directory**, `/var/cache/<vendor>/<id>`
//!    ([`Product::cache_directory`]; systemd's `CacheDirectory=` makes it;
//!    on macOS [`Product::macos_staging_directory`], which the package
//!    makes; on Windows [`Product::windows_staging_directory`] under
//!    `%ProgramData%`, which the MSI makes),
//!    which must be root's and private, every directory above it root's
//!    and not writable by anyone else (on Windows: owned by SYSTEM,
//!    Administrators or TrustedInstaller, writable by no one else, and no
//!    reparse point, up to `%ProgramData%`). A lock in it means one run at
//!    a time; a previous run's leftovers are swept under it; and a run
//!    that starts within [`MIN_RUN_INTERVAL`] of the last ends there,
//!    before any network I/O.
//! 3. **What's installed**: the package manager that installed the product
//!    ([`crate::installer::detect`], Linux; the bundle id's receipt on
//!    macOS; the MSI's `Release` value on Windows) and the release it
//!    reports.
//! 4. **The server's version**, from the **version source** the product
//!    passes to [`HelperConfig::new`]: an async closure answering the
//!    version token the product's server requires (a product with a server
//!    asks it, typically with the same version check its app's connection
//!    makes; a serverless product can answer from a signed "latest"
//!    record). A configured prefix (`v`) is removed.
//! 5. **The failure memo**: a version that failed recently isn't tried
//!    again until its backoff (1 minute, doubling to 6 hours) passes, and
//!    nothing is fetched. Past it, the attempt is recorded before anything
//!    is fetched, so a run that dies midway backs off too.
//! 6. **The signed manifest** for that exact token, this target and the
//!    installer's format, verified against the release keys compiled into
//!    the helper ([`ManifestTrust`]), and naming the product's package and
//!    channel.
//! 7. **The version floor**: the manifest's release (version, then
//!    sequence) must be newer than the installed one; the same release is
//!    nothing to do; an older one is refused unless the product opts into
//!    downgrades.
//! 8. **The package**, downloaded into the staging directory (exclusive,
//!    0600, never through a symlink), its size and digest checked against
//!    the manifest, its format magic checked, and its OpenPGP signature
//!    (rpm, pacman) checked against the product's pinned keys as a second
//!    layer.
//! 9. **The install**: the installed release is asked for again (someone
//!    may have changed it during the download), then the file goes to the
//!    [`Installer`] (which checks the file's own version and plan, and
//!    runs the install in a transient systemd unit on Linux), then the
//!    package manager must report the new release. On Windows the MSI
//!    replaces the helper's own binary, so the install is handed off
//!    ([`Installer::hands_off`]): msiexec starts detached, the helper exits
//!    ([`HelperOutcome::HandedOff`]), and the next run confirms it.
//!
//! Only a confirmed install clears the memo. [`main`] bounds the whole run
//! with [`RUN_TIMEOUT`], under the helper unit's `TimeoutStartSec=1800`.
//! On Windows [`main`] runs under the Service Control Manager (`Running`
//! at once, STOP and SHUTDOWN end the run, `Stopped` with the run's exit
//! status), or in the foreground when started from a console.
//!
//! A product's helper is a few lines:
//!
//! ```no_run
//! # fn trust(product: &seaworthy_updater::Product) -> seaworthy_updater::ManifestTrust { unimplemented!() }
//! # async fn ask_the_server(url: &str) -> Result<String, std::io::Error> { unimplemented!() }
//! use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
//!
//! fn main() -> std::process::ExitCode {
//!     // First, as in the app: the process's crypto policies, if it sets
//!     // any (seaworthy_crypto::fips_policy::install_policy and
//!     // seaworthy_crypto::tls::install_policy, before any key or TLS
//!     // use), and a tracing subscriber writing to the journal (the
//!     // helper's warnings and failure reasons go through `tracing`).
//!     // The product's seaworthy.toml, compiled in:
//!     // `include_str!("../../seaworthy.toml")`.
//!     # let config = "[defaults]\nvendor = \"Acme\"\nchannel = \"stable\"\n[product.agent]\ndisplay-name = \"Acme Agent\"\nexecutable = \"AcmeAgent\"\n";
//!     let product = seaworthy_updater::Product::from_config(config, "agent")
//!         .expect("the compiled-in seaworthy.toml names the product");
//!     // The release keys `seaworthy.toml`'s `release-keys` lists, compiled
//!     // in, as ManifestTrust::for_product(&product, keys) (it applies
//!     // `release-trust`). CI test keys join only through
//!     // `seaworthy_updater::ci_test_keys!` and `with_ci_test_keys`, which
//!     // only a build made with SEAWORTHY_ALLOW_CI_TEST_KEYS=1 accepts.
//!     let trust = trust(&product);
//!     let config = HelperConfig::new(
//!         product,
//!         trust,
//!         "https://packages.example.com/{product}/{channel}/{version}/{target}/{product}.{format}",
//!         // The version source: the token the product's server requires,
//!         // asked of the server an administrator set for the machine
//!         // (seaworthy_updater::read_admin_server), else the default.
//!         || async { ask_the_server("https://updates.example.com").await },
//!         PackageSignatures::ManifestOnly,
//!     )
//!     .expect("the helper's configuration is consistent");
//!     seaworthy_updater::helper::main(config)
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::UpdatePolicy;
use crate::installer::{Install, InstallError, Installer};
use crate::memo::FailureMemo;
use crate::net::{self, Limits};
use crate::openpgp::{self, OpenPgpKeys};
use crate::policy::{PolicyDecision, read_policy};
use crate::release::Release;
use crate::staging::{Expected, StagedFile, TargetLock};
use crate::{ArtifactFormat, ManifestTrust, Product, ReleaseTrust, UpdateError};

/// How long the server probe may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// The package download's whole-transfer budget by default.
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// A whole run's budget by default, under the helper unit's
/// `TimeoutStartSec=1800`: [`main`] stops a run that reaches it and exits
/// failed. Every phase has its own bound too (the probe, each
/// metadata fetch, the download, each tool, the wait for the install's
/// unit). An install already handed to its transient unit runs to its end
/// either way; only the confirmation is lost, the attempt is
/// already in the memo, and the next run sees the installed release.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(1700);

/// The shortest interval between two runs by default: a run that starts
/// sooner after the last one ends at once, before any network I/O. It
/// bounds what repeated requests can cost (the helper's unit sets no
/// systemd start limit, which would leave its path unit failed and
/// updates off until a reboot).
pub const MIN_RUN_INTERVAL: Duration = Duration::from_secs(30);

/// The files a run keeps in the staging directory; everything else is a
/// previous run's leftover and is removed at the start of the next.
const STAGING_KEEPS: [&str; 4] = [
    ".lock",
    "failure-memo",
    "last-run",
    crate::installer::MSIEXEC_LOG,
];

type ProbeFuture = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;
type ProbeFn = Arc<dyn Fn() -> ProbeFuture + Send + Sync>;

/// How the downloaded package's own signature is checked, beside the
/// release manifest's.
#[derive(Debug, Clone)]
pub enum PackageSignatures {
    /// rpm and pacman packages must carry a signature from one of these
    /// keys (`seaworthy.toml`'s `openpgp-keys`, compiled in). deb packages carry
    /// none; the manifest is their only layer.
    Pinned(OpenPgpKeys),
    /// Only the manifest is checked (a product that doesn't sign its
    /// packages).
    ManifestOnly,
}

/// What the helper installs and how (see the module docs).
pub struct HelperConfig {
    product: Product,
    trust: ManifestTrust,
    url_template: String,
    probe: ProbeFn,
    signatures: PackageSignatures,
    token_prefix: String,
    downgrades: bool,
    limits: Limits,
    probe_timeout: Duration,
    run_timeout: Duration,
    min_run_interval: Duration,
    staging: Option<PathBuf>,
    installer: Option<Arc<dyn Installer>>,
    require_root: bool,
}

impl fmt::Debug for HelperConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperConfig")
            .field("product", &self.product)
            .field("trust", &self.trust)
            .field("url_template", &self.url_template)
            .field("signatures", &self.signatures)
            .field("token_prefix", &self.token_prefix)
            .field("downgrades", &self.downgrades)
            .field("staging", &self.staging)
            .field("installer", &self.installer)
            .finish_non_exhaustive()
    }
}

/// The placeholders a package URL template may use.
const PLACEHOLDERS: &str = "{version}, {target}, {format}, {product}, {channel}";

/// Expands a package URL template. `{format}` is the manifest's format tag
/// (`deb`), `{product}` the package name, `{channel}` the channel; the
/// version must pass the version-token charset check, and its `+` (the
/// build metadata's separator) is sent as `%2B`: AWS S3 decodes a literal
/// `+` in a path as a space (other stores may too), and every server
/// decodes `%2B` to `+` (the object is still `…/1.4.0+abc/…`).
pub(crate) fn expand_package_url(
    template: &str,
    version: &str,
    product: &Product,
    format: ArtifactFormat,
) -> Result<String, UpdateError> {
    crate::validate_version(version)?;
    let version = version.replace('+', "%2B");
    let package = product.package();
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or_else(|| {
            UpdateError::InvalidConfig(format!(
                "unterminated placeholder in url template {template:?}"
            ))
        })?;
        out.push_str(match &after[..close] {
            "version" => &version,
            "target" => crate::TARGET_TRIPLE,
            "format" => format.tag(),
            "product" => &package,
            "channel" => product.channel(),
            other => {
                return Err(UpdateError::InvalidConfig(format!(
                    "unknown placeholder {{{other}}} in url template (known: {PLACEHOLDERS})"
                )));
            }
        });
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

impl HelperConfig {
    /// The helper for `product`: manifests verified against `trust`,
    /// fetched from `url_template` (`{version}`, `{target}`, `{format}`,
    /// `{product}`, `{channel}`; the token's `+` is sent as `%2B`; the
    /// manifest is at `<url>.manifest`, a pacman signature at `<url>.sig`),
    /// the server's version learned by `probe`.
    ///
    /// **The version source** (`probe`) is the product's own: an async
    /// closure, called once per run within [`PROBE_TIMEOUT`]
    /// ([`probe_timeout`](Self::probe_timeout)), answering the version
    /// token the product's server requires (its `Display`, e.g. a `String`
    /// `"1.4.0+a1b2c3"`) or why it couldn't (its error's `Display`, logged
    /// line-safe). The helper trusts the answer only as far as it goes: the
    /// token must pass [`validate_version`](crate::validate_version), and
    /// a manifest signed by a trusted key must name exactly that token, so
    /// a lying source can make the helper install at most a validly signed
    /// release that is newer than the installed one (or older, under
    /// [`allow_downgrades`](Self::allow_downgrades)). Keep it on
    /// administrator-controlled inputs (the compiled-in default server, or
    /// [`read_admin_server`](crate::read_admin_server)), never on anything
    /// a user can set.
    ///
    /// ```no_run
    /// # fn trust(product: &seaworthy_updater::Product) -> seaworthy_updater::ManifestTrust { unimplemented!() }
    /// # async fn required_version(server: &str) -> Result<String, std::io::Error> { unimplemented!() }
    /// use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
    /// use seaworthy_updater::{Product, read_admin_server};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let product = Product::new("Acme", "agent", "Agent", "stable")?;
    /// let trust = trust(&product);
    /// // The server: the administrator's, else the product's default.
    /// let server = read_admin_server(&product)?
    ///     .map_or_else(|| "https://updates.example.com".to_owned(), |admin| admin.url);
    /// let config = HelperConfig::new(
    ///     product,
    ///     trust,
    ///     "https://packages.example.com/{product}/{channel}/{version}/{target}/{product}.{format}",
    ///     move || {
    ///         let server = server.clone();
    ///         async move { required_version(&server).await }
    ///     },
    ///     PackageSignatures::ManifestOnly,
    /// )?;
    /// # let _ = config;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// [`HelperError::Config`] when `trust` names another product (it must
    /// be the package name, `<vendor>-<id>`) or channel than `product`,
    /// accepts any one key while `product` requires every algorithm
    /// (`seaworthy.toml`'s `release-trust`; [`ManifestTrust::for_product`]
    /// carries it over), or `url_template` doesn't expand to an `https` URL
    /// (or `http` to loopback).
    pub fn new<F, Fut, T, E>(
        product: Product,
        trust: ManifestTrust,
        url_template: impl Into<String>,
        probe: F,
        signatures: PackageSignatures,
    ) -> Result<Self, HelperError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: fmt::Display,
        E: fmt::Display,
    {
        let package = product.package();
        if trust.product() != package {
            return Err(HelperError::Config(format!(
                "the manifest trust names product {:?}, but the seaworthy CLI signs this product's manifests as {package:?}",
                trust.product()
            )));
        }
        if trust.channel_name() != Some(product.channel()) {
            return Err(HelperError::Config(format!(
                "the manifest trust names channel {:?}, but this product's channel is {:?}",
                trust.channel_name().unwrap_or(""),
                product.channel()
            )));
        }
        if product.release_trust() == ReleaseTrust::EveryAlgorithm
            && trust.release_trust() != ReleaseTrust::EveryAlgorithm
        {
            return Err(HelperError::Config(format!(
                "seaworthy.toml's release-trust is {:?}, but the manifest trust accepts any one key: build it with ManifestTrust::for_product",
                product.release_trust().as_str()
            )));
        }
        let url_template = url_template.into();
        let sample = expand_package_url(&url_template, "0.0.0", &product, ArtifactFormat::Deb)
            .map_err(|e| HelperError::Config(e.to_string()))?;
        net::ensure_tls_url(&sample).map_err(|e| HelperError::Config(e.to_string()))?;
        let probe: ProbeFn = Arc::new(move || {
            let future = probe();
            Box::pin(async move {
                future
                    .await
                    .map(|token| token.to_string())
                    .map_err(|e| e.to_string())
            })
        });
        Ok(Self {
            product,
            trust,
            url_template,
            probe,
            signatures,
            token_prefix: String::new(),
            downgrades: false,
            limits: Limits {
                download_timeout: DOWNLOAD_TIMEOUT,
                ..Limits::default()
            },
            probe_timeout: PROBE_TIMEOUT,
            run_timeout: RUN_TIMEOUT,
            min_run_interval: MIN_RUN_INTERVAL,
            staging: None,
            installer: None,
            require_root: true,
        })
    }

    /// The server's tokens carry this prefix before the release version
    /// (a server answering `v1.4.0+abc123`; the seaworthy CLI's versions
    /// have none): it's
    /// removed before the manifest is fetched, and a token without it is
    /// refused.
    #[must_use]
    pub fn server_token_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.token_prefix = prefix.into();
        self
    }

    /// Installs an older release when the server names one (the version
    /// floor's opt-out; off by default: rollbacks roll forward).
    #[must_use]
    pub fn allow_downgrades(mut self) -> Self {
        self.downgrades = true;
        self
    }

    /// Hosts a download may be redirected to (none by default).
    #[must_use]
    pub fn allow_redirect_hosts<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.limits.redirect_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    /// The largest package accepted (default 1 GiB).
    #[must_use]
    pub fn max_artifact_bytes(mut self, bytes: u64) -> Self {
        self.limits.max_artifact_bytes = bytes;
        self
    }

    /// The download's whole-transfer budget (default [`DOWNLOAD_TIMEOUT`]).
    #[must_use]
    pub fn download_timeout(mut self, timeout: Duration) -> Self {
        self.limits.download_timeout = timeout;
        self
    }

    /// The probe's budget (default [`PROBE_TIMEOUT`]).
    #[must_use]
    pub fn probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// A whole run's budget (default [`RUN_TIMEOUT`]).
    #[must_use]
    pub fn run_timeout(mut self, timeout: Duration) -> Self {
        self.run_timeout = timeout;
        self
    }

    /// The shortest interval between two runs (default
    /// [`MIN_RUN_INTERVAL`]).
    #[must_use]
    pub fn min_run_interval(mut self, interval: Duration) -> Self {
        self.min_run_interval = interval;
        self
    }

    /// Installs through `installer` instead of the detected package
    /// manager (a caller with its own).
    #[must_use]
    pub fn installer(mut self, installer: impl Installer + 'static) -> Self {
        self.installer = Some(Arc::new(installer));
        self
    }

    /// Stages in `dir` instead of `/var/cache/<vendor>/<id>` (macOS:
    /// [`Product::macos_staging_directory`]; Windows:
    /// [`Product::windows_staging_directory`]).
    #[must_use]
    pub fn staging_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.staging = Some(dir.into());
        self
    }

    /// Runs without root and accepts a staging directory the test user
    /// owns: this crate's tests only.
    #[cfg(all(test, unix))]
    pub(crate) fn unprivileged_for_tests(mut self) -> Self {
        self.require_root = false;
        self
    }

    /// The product.
    #[must_use]
    pub fn product(&self) -> &Product {
        &self.product
    }

    fn staging(&self) -> Result<PathBuf, HelperError> {
        if let Some(dir) = &self.staging {
            return Ok(dir.clone());
        }
        #[cfg(windows)]
        {
            let program_data = windows::program_data().map_err(HelperError::Staging)?;
            Ok(self.product.windows_staging_directory(&program_data))
        }
        #[cfg(target_os = "macos")]
        {
            Ok(self.product.macos_staging_directory())
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Ok(PathBuf::from("/var/cache").join(self.product.cache_directory()))
        }
    }
}

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperOutcome {
    /// The policy isn't `auto`: nothing was fetched or installed.
    PolicyNotAuto(PolicyDecision),
    /// The server's release is the installed one: nothing to do (the
    /// service may be running an older build; restarting it loads the
    /// installed one).
    UpToDate {
        /// The installed release.
        installed: Release,
    },
    /// The server's release was installed and confirmed.
    Installed {
        /// The release before.
        from: Release,
        /// The release now installed.
        to: Release,
    },
    /// The server's release was verified and handed to an installer that
    /// finishes after the helper exits ([`Installer::hands_off`]: Windows'
    /// msiexec). The next run confirms it.
    HandedOff {
        /// The release before.
        from: Release,
        /// The release handed to the installer.
        to: Release,
    },
}

/// Why a run installed nothing.
#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    /// Not running as root.
    #[error("the update helper must run as root (it installs packages); started as uid {0}")]
    NotPrivileged(u32),
    /// Not running as LocalSystem or an elevated administrator (Windows).
    #[error(
        "the update helper must run as LocalSystem or an elevated administrator (it installs packages): {0}"
    )]
    NotElevated(String),
    /// The platform has no helper yet.
    #[error("{0}")]
    Unsupported(String),
    /// The helper's configuration is inconsistent.
    #[error("helper configuration: {0}")]
    Config(String),
    /// The staging directory is missing, not private, or under a directory
    /// someone else can write.
    #[error("staging directory: {0}")]
    Staging(String),
    /// Another run holds the lock.
    #[error("another update run is in progress")]
    InProgress,
    /// The last run started less than the minimum interval ago.
    #[error("the last update run started less than {} s ago; the next is allowed in {} s", interval.as_secs(), retry_after.as_secs())]
    Throttled {
        /// The minimum interval.
        interval: Duration,
        /// How long until another run.
        retry_after: Duration,
    },
    /// The version failed recently and is backing off.
    #[error("updating to {version} failed recently; the next attempt is allowed in {} s", retry_after.as_secs())]
    Backoff {
        /// The server's token.
        version: String,
        /// How long until another attempt.
        retry_after: Duration,
    },
    /// Learning the server's version failed.
    #[error("probing the server's version failed: {0}")]
    Probe(String),
    /// The server's token, or the manifest's version, isn't a release this
    /// helper can order.
    #[error("version: {0}")]
    Version(String),
    /// Fetching or verifying the manifest or the package failed.
    #[error(transparent)]
    Update(#[from] UpdateError),
    /// The server's release is older than the installed one.
    #[error(
        "the server's release {offered} is older than the installed {installed}; refusing to downgrade (rollbacks roll forward)"
    )]
    Downgrade {
        /// The installed release.
        installed: Box<Release>,
        /// The manifest's release.
        offered: Box<Release>,
    },
    /// The package's own signature didn't verify against the pinned keys.
    #[error("package signature: {0}")]
    Signature(String),
    /// The installer couldn't query or install.
    #[error(transparent)]
    Install(#[from] InstallError),
    /// The installed release changed while the run downloaded (someone
    /// else installed or removed a release): nothing is installed over it.
    #[error("the installed release changed during the run: it was {was}, it is now {now}")]
    InstalledChanged {
        /// The release the run compared against.
        was: Box<Release>,
        /// What the package manager reports now.
        now: String,
    },
    /// The installer reported success, but the package manager doesn't
    /// report the new release.
    #[error("the install didn't take: expected {expected}, the package manager reports {found}")]
    NotTaken {
        /// The release installed.
        expected: Box<Release>,
        /// What the package manager reports instead.
        found: String,
    },
}

impl HelperError {
    /// Whether this is an expected state rather than a failure: another
    /// run in progress, a backoff, or a run too soon after the last.
    /// `main` exits 0 for these.
    #[must_use]
    pub fn is_expected(&self) -> bool {
        matches!(
            self,
            Self::InProgress | Self::Backoff { .. } | Self::Throttled { .. }
        )
    }
}

/// Runs `config` once (see the module docs).
///
/// # Errors
/// [`HelperError`] naming why nothing (more) was installed.
pub async fn run(config: &HelperConfig) -> Result<HelperOutcome, HelperError> {
    // A build that trusts the public CI test keys says so at every run.
    if let Some(notice) = config.trust.ci_test_keys_notice() {
        tracing::warn!("{notice}");
    }
    check_privileges(config)?;
    let product = config.product.clone();
    let decision = blocking(move || read_policy(&product)).await?;
    if decision.policy != UpdatePolicy::Auto {
        tracing::info!("update policy is {decision}: not installing");
        return Ok(HelperOutcome::PolicyNotAuto(decision));
    }
    let staging = config.staging()?;
    prepare_staging(&staging, config.require_root)?;
    let _lock = TargetLock::try_acquire(&staging.join(".lock")).map_err(|e| match e {
        UpdateError::UpdateInProgress => HelperError::InProgress,
        other => HelperError::Staging(other.to_string()),
    })?;
    sweep_staging(&staging);
    throttle(&staging, config.min_run_interval)?;
    let package = config.product.package();
    let installer = match &config.installer {
        Some(installer) => Arc::clone(installer),
        None => detect_installer(&config.product).await?,
    };
    let query = Arc::clone(&installer);
    let query_package = package.clone();
    let installed = blocking(move || query.installed(&query_package))
        .await??
        .ok_or_else(|| {
            InstallError::Unsupported(format!(
                "{package} is not installed (by {})",
                installer.name()
            ))
        })?;
    let token = server_token(config).await?;
    let memo = FailureMemo::new(staging.join("failure-memo"));
    if let Some(retry_after) = memo.backoff_for(&token) {
        return Err(HelperError::Backoff {
            version: token,
            retry_after,
        });
    }
    tracing::info!(
        "{package} {installed} is installed (by {}); the server runs {token}",
        installer.name()
    );
    // The attempt is recorded before any fetch, so a run that dies midway
    // (a timeout, a reboot) backs off too. A no-op keeps it: the
    // app keeps asking while it runs an older build than the installed
    // one. Only a confirmed install clears it.
    memo.record_attempt(&token);
    let result = update(config, &staging, installer, &installed, &token).await;
    if matches!(result, Ok(HelperOutcome::Installed { .. })) {
        memo.clear();
    }
    result
}

/// Removes a previous run's leftovers (a download, a signature, a scratch
/// directory) from the staging directory, under the lock: everything but
/// [`STAGING_KEEPS`]. Best effort; the directory is root's and private.
fn sweep_staging(staging: &Path) {
    let Ok(entries) = std::fs::read_dir(staging) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if STAGING_KEEPS.iter().any(|keep| name == *keep) {
            continue;
        }
        let path = entry.path();
        let removed = match entry.file_type() {
            Ok(kind) if kind.is_dir() => std::fs::remove_dir_all(&path),
            _ => std::fs::remove_file(&path),
        };
        match removed {
            Ok(()) => tracing::info!("removed a previous run's {}", path.display()),
            Err(e) => tracing::warn!("couldn't remove {}: {e}", path.display()),
        }
    }
}

/// Refuses a run that starts less than `interval` after the last one
/// (`last-run`'s modification time; a time in the future counts as long
/// ago), then records this run's start.
fn throttle(staging: &Path, interval: Duration) -> Result<(), HelperError> {
    let marker = staging.join("last-run");
    if let Ok(modified) = std::fs::symlink_metadata(&marker).and_then(|m| m.modified())
        && let Ok(elapsed) = std::time::SystemTime::now().duration_since(modified)
        && elapsed < interval
    {
        return Err(HelperError::Throttled {
            interval,
            retry_after: interval - elapsed,
        });
    }
    let _ = std::fs::remove_file(&marker);
    write_private(&marker, b"")
}

/// Whether a run's result counts as success for the exit status: an
/// install, nothing to do, a policy that isn't `auto`, or an expected
/// state (another run, a backoff, a run too soon).
fn succeeded(result: &Result<HelperOutcome, HelperError>) -> bool {
    match result {
        Ok(_) => true,
        Err(error) => error.is_expected(),
    }
}

/// Runs `config` on a single-threaded runtime and logs the result: the
/// body of a product's helper `main`. Arguments are ignored (the helper
/// takes no input). Exits 0 when the run installed, handed the install
/// off, found nothing to do, found the policy not `auto`, or met another
/// run or a backoff; 1 otherwise, so the unit shows as failed. On Windows
/// it runs as the helper's service under the Service Control Manager, or
/// in the foreground when started from a console.
#[must_use]
pub fn main(config: HelperConfig) -> ExitCode {
    if std::env::args_os().len() > 1 {
        tracing::warn!("the update helper takes no arguments; ignoring them");
    }
    #[cfg(windows)]
    let ok = windows::main(config);
    #[cfg(not(windows))]
    let ok = run_once(&config, std::future::pending());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// One run of `config` on its own runtime, ended early by `stop` (the
/// Service Control Manager's STOP on Windows); `true` when it succeeded
/// for the exit status ([`succeeded`]).
fn run_once(config: &HelperConfig, stop: impl Future<Output = ()>) -> bool {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!("the update helper can't start its runtime: {e}");
            return false;
        }
    };
    let ran = runtime.block_on(async {
        let run = std::pin::pin!(tokio::time::timeout(config.run_timeout, run(config)));
        match futures_util::future::select(run, std::pin::pin!(stop)).await {
            futures_util::future::Either::Left((result, _)) => Some(result.ok()),
            futures_util::future::Either::Right(((), _)) => None,
        }
    });
    let Some(result) = ran else {
        tracing::info!(
            "the update run was stopped; an install already handed off runs on, and the next run sees its outcome"
        );
        runtime.shutdown_timeout(Duration::from_secs(5));
        return true;
    };
    let Some(result) = result else {
        tracing::error!(
            "the update run didn't finish within {} s; an install already handed to its unit runs on, and the next run sees its outcome",
            config.run_timeout.as_secs()
        );
        // Don't wait for a blocking task still running (a tool's own
        // deadline ends it, or the process exit does).
        runtime.shutdown_timeout(Duration::from_secs(5));
        return false;
    };
    let package = config.product.package();
    match &result {
        Ok(HelperOutcome::Installed { from, to }) => {
            tracing::info!("installed {package} {to} (was {from})");
        }
        Ok(HelperOutcome::HandedOff { from, to }) => {
            tracing::info!(
                "handed {package} {to} to its installer (was {from}); the next run confirms it"
            );
        }
        Ok(HelperOutcome::UpToDate { installed }) => {
            tracing::warn!(
                "{package} {installed}, the server's release, is already installed; if the service still runs an older build, restart it"
            );
        }
        Ok(HelperOutcome::PolicyNotAuto(_)) => {}
        Err(error) if error.is_expected() => tracing::info!("{error}"),
        Err(error) => tracing::error!("update failed: {error}"),
    }
    succeeded(&result)
}

/// Windows: reads a small file a product's helper trusts as configuration
/// (for example a machine enrollment record naming the server the helper
/// asks for the version) after the staging directory's audit: the file,
/// and each directory above it up to `%ProgramData%`, is no reparse point,
/// is owned by SYSTEM, Administrators or TrustedInstaller, and is writable
/// by no one else. `Ok(None)` when the file doesn't exist.
///
/// # Errors
/// A failed audit (naming the refused path and why), an unreadable file,
/// or one larger than `max_bytes`.
#[cfg(windows)]
pub fn read_protected_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, String> {
    windows::read_protected_file(path, max_bytes)
}

/// The helper's log file on Windows, `<stem>.log` in the product's log
/// directory ([`Product::windows_log_directory`], which the MSI creates
/// and locks), opened to append: under the Service Control Manager a
/// service has no stderr, so a product's helper `main` points its log
/// here. `None` elsewhere (journald and launchd keep a helper's stderr),
/// or when the directory isn't there.
#[must_use]
pub fn log_file(product: &Product, stem: &str) -> Option<std::fs::File> {
    #[cfg(windows)]
    {
        let dir = product.windows_log_directory(&windows::program_data().ok()?);
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{stem}.log")))
            .ok()
    }
    #[cfg(not(windows))]
    {
        let _ = (product, stem);
        None
    }
}

/// Runs a blocking closure off the async executor.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, HelperError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| HelperError::Update(UpdateError::Task(e.to_string())))
}

#[cfg(target_os = "linux")]
async fn detect_installer(product: &Product) -> Result<Arc<dyn Installer>, HelperError> {
    let package = product.package();
    let tools = crate::installer::Tools::system();
    let installer = blocking(move || crate::installer::detect(&package, &tools)).await??;
    Ok(Arc::from(installer))
}

/// macOS: the package's receipt is its bundle id's; its service is loaded
/// again after a failed install that left it unloaded.
#[cfg(target_os = "macos")]
async fn detect_installer(product: &Product) -> Result<Arc<dyn Installer>, HelperError> {
    let identifier = product.macos_package_id().ok_or_else(|| {
        HelperError::Unsupported(format!(
            "product {} has no [product.<id>.macos] bundle-id: its macOS package has no identifier",
            product.package()
        ))
    })?;
    let mut pkg = crate::installer::MacPkg::new(identifier);
    if let Some(service) = product.service() {
        pkg = pkg.with_service(&service.name);
    }
    Ok(Arc::new(pkg))
}

/// Windows: the MSI, its release under the product's install key.
#[cfg(windows)]
async fn detect_installer(product: &Product) -> Result<Arc<dyn Installer>, HelperError> {
    Ok(Arc::new(crate::installer::Msi::new(product.install_key())))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn detect_installer(_product: &Product) -> Result<Arc<dyn Installer>, HelperError> {
    Err(HelperError::Unsupported(
        "no installer for this platform".to_owned(),
    ))
}

#[cfg(unix)]
fn check_privileges(config: &HelperConfig) -> Result<(), HelperError> {
    #[allow(unsafe_code, reason = "geteuid(2)")]
    // SAFETY: geteuid takes no arguments and can't fail.
    let euid = unsafe { libc::geteuid() };
    if config.require_root && euid != 0 {
        return Err(HelperError::NotPrivileged(euid));
    }
    Ok(())
}

#[cfg(windows)]
fn check_privileges(config: &HelperConfig) -> Result<(), HelperError> {
    if config.require_root {
        windows::check_privileges()?;
    }
    Ok(())
}

/// Makes sure `dir` exists, is a private directory (root's, unless
/// `require_root` is off for tests) and sits under directories only root
/// can write, up to `/var` or the filesystem root.
#[cfg(unix)]
fn prepare_staging(dir: &Path, require_root: bool) -> Result<(), HelperError> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    let staging = |why: String| HelperError::Staging(why);
    if !dir.is_absolute() {
        return Err(staging(format!("{} is not absolute", dir.display())));
    }
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| staging(format!("{}: {e}", dir.display())))?;
        }
        Err(e) => return Err(staging(format!("{}: {e}", dir.display()))),
        Ok(_) => {}
    }
    let metadata =
        std::fs::symlink_metadata(dir).map_err(|e| staging(format!("{}: {e}", dir.display())))?;
    if !metadata.is_dir() {
        return Err(staging(format!("{} is not a directory", dir.display())));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(staging(format!(
            "{} is open to group or others (mode {:o}; systemd's CacheDirectoryMode=0700 makes it private)",
            dir.display(),
            metadata.mode() & 0o7777
        )));
    }
    let mut current = Some(dir);
    while let Some(path) = current {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| staging(format!("{}: {e}", path.display())))?;
        if metadata.file_type().is_symlink() {
            return Err(staging(format!("{} is a symlink", path.display())));
        }
        if require_root && metadata.uid() != 0 {
            return Err(staging(format!(
                "{} is owned by uid {}, not root",
                path.display(),
                metadata.uid()
            )));
        }
        // The sticky bit doesn't help here: anyone could replace a
        // directory in a world-writable parent they created.
        if metadata.mode() & 0o022 != 0 {
            return Err(staging(format!(
                "{} is writable by group or others (mode {:o})",
                path.display(),
                metadata.mode() & 0o7777
            )));
        }
        if !require_root && path.parent().is_some_and(|p| p == std::env::temp_dir()) {
            // Tests stage under the temporary directory, which is
            // world-writable by design.
            break;
        }
        current = path.parent().filter(|p| *p != Path::new("/"));
    }
    Ok(())
}

#[cfg(windows)]
fn prepare_staging(dir: &Path, require_root: bool) -> Result<(), HelperError> {
    windows::prepare_staging(dir, require_root)
}

/// The server's token, with the configured prefix removed.
async fn server_token(config: &HelperConfig) -> Result<String, HelperError> {
    let raw = tokio::time::timeout(config.probe_timeout, (config.probe)())
        .await
        .map_err(|_| {
            HelperError::Probe(format!(
                "no answer within {} s",
                config.probe_timeout.as_secs()
            ))
        })?
        .map_err(|e| HelperError::Probe(crate::log::line_safe(&e)))?;
    let token = raw
        .strip_prefix(config.token_prefix.as_str())
        .ok_or_else(|| {
            HelperError::Version(format!(
                "the server's token {:?} doesn't start with {:?}",
                crate::log::line_safe(&raw),
                config.token_prefix
            ))
        })?;
    crate::validate_version(token).map_err(|e| HelperError::Version(e.to_string()))?;
    Ok(token.to_owned())
}

/// The file name a package is staged under: `<package>-<version>-<sequence>`
/// with the format's extension (apt and dnf install a local file only by
/// its extension).
fn staged_name(package: &str, release: &Release, format: ArtifactFormat) -> String {
    let extension = match format {
        ArtifactFormat::Deb => ".deb",
        ArtifactFormat::Rpm => ".rpm",
        ArtifactFormat::Pacman => ".pkg.tar.zst",
        ArtifactFormat::Msi => ".msi",
        ArtifactFormat::Zip => ".zip",
        ArtifactFormat::Tar => ".tar.zst",
        ArtifactFormat::Pkg => ".pkg",
    };
    format!(
        "{package}-{}-{}{extension}",
        release.version, release.sequence
    )
}

/// Removes the files a run staged, when it ends.
struct Cleanup(Vec<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        for path in &self.0 {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    tracing::warn!("couldn't remove {}: {e}", path.display());
                }
                _ => {}
            }
        }
    }
}

/// Steps 6 to 9: the manifest, the floor, the download, the checks, the
/// install and its confirmation.
async fn update(
    config: &HelperConfig,
    staging: &Path,
    installer: Arc<dyn Installer>,
    installed: &Release,
    token: &str,
) -> Result<HelperOutcome, HelperError> {
    let format = installer.format();
    let package = config.product.package();
    let url = expand_package_url(&config.url_template, token, &config.product, format)?;
    net::ensure_tls_url(&url)?;
    let manifest_url = net::metadata_url(&url, ".manifest")?;
    let bytes = net::fetch_metadata(&manifest_url, "release manifest", &config.limits).await?;
    let manifest = config
        .trust
        .verify_with_limit(&bytes, token, format, config.limits.max_artifact_bytes)
        .map_err(UpdateError::from)?;
    let offered = Release::new(&manifest.version, manifest.sequence)
        .map_err(|e| HelperError::Version(format!("the manifest's version: {e}")))?;
    tracing::info!(
        "release manifest verified: {package} {} ({offered}) for {}, {} bytes",
        manifest.token(),
        manifest.target,
        manifest.size
    );
    match offered.cmp(installed) {
        std::cmp::Ordering::Equal => {
            return Ok(HelperOutcome::UpToDate {
                installed: installed.clone(),
            });
        }
        std::cmp::Ordering::Less if !config.downgrades => {
            return Err(HelperError::Downgrade {
                installed: Box::new(installed.clone()),
                offered: Box::new(offered),
            });
        }
        _ => {}
    }

    // The download: exclusive, private, never through a symlink, bounded
    // to the manifest's exact size.
    let final_path = staging.join(staged_name(&package, &offered, format));
    let signature_path = PathBuf::from(format!("{}.download-sig", final_path.display()));
    let mut cleanup = Cleanup(vec![final_path.clone(), signature_path.clone()]);
    let mut staged = StagedFile::create(staging, std::ffi::OsStr::new(&package), "download")
        .map_err(UpdateError::Io)?;
    let mut file = tokio::fs::File::from_std(
        staged
            .file_mut()
            .map_err(UpdateError::Io)?
            .try_clone()
            .map_err(UpdateError::Io)?,
    );
    tracing::info!("downloading {package} {offered}");
    net::download_to(&url, &mut file, &config.limits, Some(manifest.size)).await?;
    drop(file);
    let expected = Expected {
        algorithm: manifest.digest_algorithm,
        hex: hex::encode(&manifest.digest),
    };
    let (actual, header) = {
        let file = staged.file_mut().map_err(UpdateError::Io)?;
        crate::staging::hash_staged(file, expected.algorithm).map_err(UpdateError::Io)?
    };
    if !seaworthy_crypto::ct_eq(actual.as_bytes(), expected.hex.as_bytes()) {
        return Err(UpdateError::HashMismatch {
            expected: expected.hex,
            actual,
        }
        .into());
    }
    crate::format_check::check_package(&header, format).map_err(UpdateError::from)?;
    let _ = std::fs::remove_file(&final_path);
    staged.persist_over(&final_path).map_err(UpdateError::Io)?;
    tracing::info!(
        "{package} {offered} downloaded and verified ({}: {actual})",
        expected.algorithm
    );

    // The package's own signature, a second layer.
    let signature = match (&config.signatures, format) {
        (PackageSignatures::Pinned(keys), ArtifactFormat::Rpm) => {
            let (keys, rpm, scratch) = (keys.clone(), final_path.clone(), staging.to_owned());
            blocking(move || openpgp::check_rpm(&keys, &rpm, &scratch, &openpgp::Tools::system()))
                .await?
                .map_err(|e| HelperError::Signature(e.to_string()))?;
            None
        }
        (PackageSignatures::Pinned(keys), ArtifactFormat::Pacman) => {
            let sig_url = net::metadata_url(&url, ".sig")?;
            let bytes = net::fetch_metadata(&sig_url, "package signature", &config.limits).await?;
            write_private(&signature_path, &bytes)?;
            let (keys, sig, pkg, scratch) = (
                keys.clone(),
                signature_path.clone(),
                final_path.clone(),
                staging.to_owned(),
            );
            blocking(move || {
                openpgp::check_detached(&keys, &sig, &pkg, &scratch, &openpgp::Tools::system())
            })
            .await?
            .map_err(|e| HelperError::Signature(e.to_string()))?;
            Some(signature_path.clone())
        }
        (PackageSignatures::Pinned(_), _) | (PackageSignatures::ManifestOnly, _) => None,
    };
    if signature.is_some()
        || matches!(
            (&config.signatures, format),
            (PackageSignatures::Pinned(_), ArtifactFormat::Rpm)
        )
    {
        tracing::info!(
            "{package} {offered}: the package's signature verified against the pinned keys"
        );
    }

    // The install, then its confirmation. The floor compared against the
    // release installed when the run began; the download can take minutes,
    // so ask again right before installing.
    let again = Arc::clone(&installer);
    let again_package = package.clone();
    let now = blocking(move || again.installed(&again_package)).await??;
    if now.as_ref() != Some(installed) {
        return Err(HelperError::InstalledChanged {
            was: Box::new(installed.clone()),
            now: now.map_or_else(|| "not installed".to_owned(), |r| r.to_string()),
        });
    }
    let install_installer = Arc::clone(&installer);
    let (install_package, install_file, install_release, install_replaces) = (
        package.clone(),
        final_path.clone(),
        offered.clone(),
        installed.clone(),
    );
    blocking(move || {
        install_installer.install(&Install {
            package: &install_package,
            file: &install_file,
            signature: signature.as_deref(),
            release: &install_release,
            replaces: &install_replaces,
        })
    })
    .await??;
    if installer.hands_off() {
        // The installer reads the file after the helper exits: it stays,
        // and the next run's sweep removes it.
        cleanup.0.retain(|path| *path != final_path);
        return Ok(HelperOutcome::HandedOff {
            from: installed.clone(),
            to: offered,
        });
    }
    let confirm = Arc::clone(&installer);
    let confirm_package = package.clone();
    let now = blocking(move || confirm.installed(&confirm_package)).await??;
    if now.as_ref() != Some(&offered) {
        return Err(HelperError::NotTaken {
            expected: Box::new(offered),
            found: now.map_or_else(|| "it not installed".to_owned(), |r| r.to_string()),
        });
    }
    Ok(HelperOutcome::Installed {
        from: installed.clone(),
        to: offered,
    })
}

/// Writes `bytes` to a new private file at `path` (never through a
/// symlink; an existing file is replaced).
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), HelperError> {
    use std::io::Write as _;
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| HelperError::Update(UpdateError::Io(e)))
}

// The flow's tests run on Unix (the Windows half's FFI is exercised on the
// Windows runner).
#[cfg(windows)]
#[path = "helper_windows.rs"]
mod windows;

#[cfg(test)]
#[cfg(unix)]
#[path = "helper_tests.rs"]
mod tests;
