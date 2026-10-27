//! The `seaworthy` command line.
//!
//! ```text
//! seaworthy check  [--config seaworthy.toml]
//! seaworthy verify [--config seaworthy.toml] --artifacts DIR [--product ID] [--platforms LIST]
//! seaworthy layout [--config seaworthy.toml] --artifacts DIR --out DIR [--product ID] [--platforms LIST] [--no-strip]
//! seaworthy package [--config seaworthy.toml] --artifacts DIR --out DIR --release VERSION --sequence N
//!                   [--build METADATA] [--product ID|repository] [--platforms LIST] [--no-strip]
//!                   [--signing signing.toml] [--authenticode-only]
//!                   [--ci-test-signing signing.ci-test.toml]
//! seaworthy repo [--config seaworthy.toml] --packages DIR --out DIR --signing signing.toml
//!                [--previous publish-plan.json] [--date EPOCH] [--allow-older]
//! seaworthy publish --repo DIR --target publish.toml [--dry-run] [--no-prune]
//! seaworthy build-plan [--config seaworthy.toml] --triple TRIPLE [--product ID] [--manifest Cargo.toml]
//! seaworthy ci-order --ci .gitlab-ci.yml [--root DIR] [--include FILE,…] --server JOB,… --client JOB,…  (GitLab CI)
//! seaworthy version --release VERSION --sequence N [--json]
//! seaworthy manifest-version --manifest Cargo.toml
//! seaworthy apple-team [--config seaworthy.toml]
//! seaworthy keygen --algorithm ALG --secret FILE --public FILE
//! seaworthy sign-statement --algorithm ALG --key FILE [--raw]
//! seaworthy fips-check FILE…
//! seaworthy glibc-check [--floor X.Y] FILE…
//! seaworthy --version | --help
//! ```
//!
//! Exit codes: 0 success, 1 a refusal (invalid config, failed checks, a
//! tool that failed), 2 usage (an unknown, repeated, missing or
//! inapplicable option). Without `--product`, `verify`, `layout` and
//! `package` cover every product, and `verify` reports every product's
//! findings before failing. `--platforms` (comma-separated: `linux`,
//! `windows`, `macos`) narrows them to those platforms' outputs, and skips
//! a product with none there (CI packages macOS on the Mac and the rest on
//! Linux); without `linux`, `package` builds no repository package.
//! `layout` and `package` run the strip tool named by `$STRIP`, else
//! `strip`.
//!
//! Every packaging and checking program `seaworthy` runs (nFPM, strip,
//! WiX, msitools, gpg, rpmsign, rpmkeys, osslsigncode, the repository and
//! macOS tools, git) starts with an allowlisted environment
//! (`seaworthy::process::tool`: the system's variables, never a
//! `SEAWORTHY_*`, `ACTIONS_*`, `AZURE_*` or `AWS_*` one or a CI token;
//! `SEAWORTHY_TOOL_ENV` names more). Signing commands `signing.toml` names
//! inherit the environment, less the keys it hands over, plus the runner's
//! and clouds' credentials, which no other program sees.
//!
//! `package` runs `verify` and `layout`, then builds every output in
//! `seaworthy.toml` (`seaworthy::package`). With `[defaults.repository]`, a
//! run without `--product` also builds the repository package
//! (`<vendor>-repository`, `seaworthy::repository_package`) into
//! `<out>/repository/`; `--product repository` builds it alone (no
//! `--artifacts` needed). The environment it reads, all conventional
//! build-tool settings:
//!
//! - `NFPM`: the nFPM binary (default `nfpm`; `scripts/ci/install-nfpm.sh`
//!   installs the pinned release);
//! - `SEAWORTHY_WIX`: the WiX binary. Unset, an `msi` output writes the
//!   `.wxs` for the Windows runner to build. (Not `WIX`: WiX v3's installer
//!   sets that, machine-wide, to its install folder.)
//! - `SOURCE_DATE_EPOCH`: every timestamp in every artifact (default
//!   315532800, 1980-01-01, the earliest a zip holds; at most 4294967295,
//!   2106-02-07, the most an rpm holds).
//!
//! With `--signing`, `package` writes a signed release manifest beside every
//! installable artifact, from the signers `signing.toml` names
//! (`seaworthy::sign::SigningConfig`), after checking them against
//! `release-signatures` and `release-keys`. Without it, no manifests are
//! written. `--build` is the version token's build metadata (the part
//! after `+`, often the commit): the manifests' `build` field, so a
//! manifest matches only the exact build the version-gate server names,
//! and a line of every Linux package's description and a property of
//! every SBOM, signed or not.
//! `--authenticode-only` (with `--signing`) is a dev build: only
//! `[authenticode]` signs (the Windows binaries, and later the MSI with
//! `adopt-msi --authenticode-only`), no manifest or OpenPGP key is read,
//! and its listing says so, so `repo` refuses it like an unsigned build.
//!
//! `repo` publishes every product's release as `package` left it
//! (`<packages>/<product>/packages.json`, one per product `seaworthy.toml`
//! defines, and `<packages>/repository/` with `[defaults.repository]`)
//! into a new directory `--out`: signed APT, DNF and pacman repositories,
//! the update helper's release tree, the repositories' key, the
//! repository package under stable names in `setup/`, and
//! `publish-plan.json` (`seaworthy::repo`). Each release is checked
//! first as a client would: its files against `packages.json`, every
//! manifest against `release-keys`, every rpm and pacman signature against
//! `openpgp-keys`. `signing.toml`'s `[openpgp]` signs the indexes. It runs
//! `dpkg-scanpackages`, `createrepo_c` and `repo-add` from `PATH`.
//! `--previous` is the last publication's plan: no immutable file it lists
//! may get other bytes, the indexes must be newer, and no release may be
//! older than its (by version, then sequence, as clients order releases)
//! without `--allow-older` (a deliberate rollback, which the plan records
//! for `publish`). `--date` is the
//! indexes' date (default: now; never in the future, which apt refuses).
//!
//! `publish` uploads what `repo` built (`--repo`, its `publish-plan.json`)
//! to the S3-compatible store `publish.toml` names (`seaworthy::publish`):
//! everything checked first (the files against the plan, the published
//! plan's repository and date, every immutable path against the bucket),
//! then the immutable files, the indexes in order and the plan last, then
//! the public URL checked and old files pruned (`--no-prune` skips it; a
//! pruning failure exits 1 after the publication is reported). Pruning
//! never deletes a file no plan lists that predates the repository's first
//! plan in the store (on a first publication into a non-empty prefix, all
//! of them): it names them instead.
//! `--dry-run` checks and reports what would be uploaded and pruned. The store's
//! credentials come from `SEAWORTHY_S3_ACCESS_KEY_ID`,
//! `SEAWORTHY_S3_SECRET_ACCESS_KEY` (and optionally
//! `SEAWORTHY_S3_SESSION_TOKEN`).
//!
//! `build-plan` prints what the CI templates' build job runs for one target
//! triple (`seaworthy::build_plan`): per product whose outputs need it, the
//! launcher and helper once and the core once per CPU target, each step a
//! tab-separated line `scripts/ci/seaworthy.sh build` (Linux) or
//! `seaworthy-build.ps1` (Windows) carries out. `--manifest` (default
//! `Cargo.toml`) is the workspace manifest as the builds name it:
//! `seaworthy.toml`'s crate paths (`launcher`, `helper-crate`) are relative to its
//! directory, and the plan names them through it. It refuses a product whose
//! cargo configuration (beside `--manifest`, or above) sets
//! `build.rustflags`, which cargo would ignore for the per-CPU builds.
//!
//! `ci-order` is the release-ordering lint for GitLab CI
//! (`seaworthy::ci_order`; GitLab's pipeline syntax only): it reads the CI
//! file `--ci` (its local includes resolved against `--root`,
//! default the file's directory, and `--include`'s files merged first, such
//! as seaworthy's template) and refuses unless every `--server` job waits for
//! every `--client` job through explicit, non-optional needs, no client job
//! may fail without stopping the server, and no server job runs past failed
//! needs. Job lists are comma-separated; an empty `--server` checks nothing.
//!
//! `keygen` writes a new release key: the secret as hex to `--secret` (mode
//! 0600) and the public key as hex to `--public`, both created before
//! either is written and never over an existing file, and prints the key
//! id. For tests and throwaway CI keys; a production key is generated in its
//! custody system. `sign-statement` reads a release statement on stdin
//! (refusing anything but a canonical `seaworthy-release-manifest:1` statement)
//! and prints its signature, hex or `--raw`: the reference command signer
//! (`command = ["seaworthy", "sign-statement", …]`), and a way to check a
//! signing setup end to end.
//!
//! `apple-team` prints the Apple team `[defaults.apple]` pins, or nothing
//! when it pins none: a pinned team means the macOS outputs ship Developer
//! ID-signed, so the CI scripts refuse a release whose macOS step got no
//! `[apple]` signer rather than ship its outputs ad hoc-signed.
//!
//! `glibc-check` reads each ELF file's glibc version needs as glibc's
//! loader does (the version-needs table, ABI markers included) and refuses
//! any past the floor (default 2.34, `verify`'s): the check
//! `verify` applies to a product's Linux binaries, for one file (a build
//! from a separate FIPS builder, for example).
//!
//! `fips-check` runs `scripts/verify-fips-binary.sh`'s checks over each ELF
//! file's symbol table, as `nm` reads it, for the pinned module
//! (`seaworthy_crypto::module::FIPS_SYMBOL_PREFIX`). It's what `verify` applies
//! to every Linux core of a FIPS product, one binary at a time.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use seaworthy::config::{Config, Output, Platform};
use seaworthy::version::Release;
use seaworthy::{DistError, layout, package, verify};

const USAGE: &str = "usage:
  seaworthy check  [--config seaworthy.toml]
  seaworthy verify [--config seaworthy.toml] --artifacts DIR [--product ID] [--platforms LIST]
  seaworthy layout [--config seaworthy.toml] --artifacts DIR --out DIR [--product ID] [--platforms LIST] [--no-strip]
  seaworthy package [--config seaworthy.toml] --artifacts DIR --out DIR --release VERSION --sequence N
                    [--build METADATA] [--product ID|repository] [--platforms LIST] [--no-strip]
                    [--signing signing.toml] [--authenticode-only] [--ci-test-signing FILE]
  seaworthy adopt-msi [--config seaworthy.toml] --out DIR --product ID --msi FILE [--signing signing.toml] [--authenticode-only]
                      [--ci-test-signing FILE]
  seaworthy repo [--config seaworthy.toml] --packages DIR --out DIR --signing signing.toml
                 [--previous publish-plan.json] [--date EPOCH] [--allow-older]
  seaworthy publish --repo DIR --target publish.toml [--dry-run] [--no-prune]
  seaworthy build-plan [--config seaworthy.toml] --triple TRIPLE [--product ID] [--manifest Cargo.toml]
  seaworthy ci-order --ci .gitlab-ci.yml [--root DIR] [--include FILE,…] --server JOB,… --client JOB,…  (GitLab CI)
  seaworthy version --release VERSION --sequence N [--json]
  seaworthy manifest-version --manifest Cargo.toml
  seaworthy apple-team [--config seaworthy.toml]
  seaworthy keygen --algorithm ml-dsa-87|ecdsa-p256|ed25519 --secret FILE --public FILE
  seaworthy sign-statement --algorithm ml-dsa-87|ecdsa-p256|ed25519 --key FILE [--raw]
  seaworthy fips-check FILE...
  seaworthy glibc-check [--floor X.Y] FILE...
  seaworthy --version | --help";

/// A command line that can't be run: exit 2 with the usage.
struct Usage(String);

#[derive(Default)]
struct Args {
    config: Option<PathBuf>,
    artifacts: Option<PathBuf>,
    out: Option<PathBuf>,
    product: Option<String>,
    platforms: Option<Vec<Platform>>,
    release: Option<String>,
    sequence: Option<String>,
    signing: Option<PathBuf>,
    /// `--ci-test-signing`: the CI test keys' signing configuration.
    ci_test_signing: Option<PathBuf>,
    algorithm: Option<String>,
    secret: Option<PathBuf>,
    public: Option<PathBuf>,
    key: Option<PathBuf>,
    build: Option<String>,
    packages: Option<PathBuf>,
    msi: Option<PathBuf>,
    previous: Option<PathBuf>,
    date: Option<String>,
    repo: Option<PathBuf>,
    target: Option<PathBuf>,
    ci: Option<PathBuf>,
    root: Option<PathBuf>,
    include: Option<String>,
    server: Option<String>,
    client: Option<String>,
    triple: Option<String>,
    manifest: Option<PathBuf>,
    dry_run: bool,
    no_prune: bool,
    authenticode_only: bool,
    allow_older: bool,
    /// The secrets `--signing`'s file takes from the environment, taken out
    /// of it before anything runs ([`take_secrets`]).
    secrets: seaworthy::sign::EnvSecrets,
    no_strip: bool,
    json: bool,
    raw: bool,
}

/// The options each command accepts.
fn accepted(command: &str) -> &'static [&'static str] {
    match command {
        "check" => &["--config"],
        "verify" => &["--config", "--artifacts", "--product", "--platforms"],
        "layout" => &[
            "--config",
            "--artifacts",
            "--out",
            "--product",
            "--platforms",
            "--no-strip",
        ],
        "package" => &[
            "--config",
            "--artifacts",
            "--out",
            "--release",
            "--sequence",
            "--product",
            "--platforms",
            "--no-strip",
            "--signing",
            "--build",
            "--authenticode-only",
            "--ci-test-signing",
        ],
        "adopt-msi" => &[
            "--config",
            "--out",
            "--product",
            "--msi",
            "--signing",
            "--authenticode-only",
            "--ci-test-signing",
        ],
        "repo" => &[
            "--config",
            "--packages",
            "--out",
            "--signing",
            "--previous",
            "--date",
            "--allow-older",
        ],
        "publish" => &["--repo", "--target", "--dry-run", "--no-prune"],
        "ci-order" => &["--ci", "--root", "--include", "--server", "--client"],
        "build-plan" => &["--config", "--triple", "--product", "--manifest"],
        "version" => &["--release", "--sequence", "--json"],
        "manifest-version" => &["--manifest"],
        "apple-team" => &["--config"],
        "keygen" => &["--algorithm", "--secret", "--public"],
        "sign-statement" => &["--algorithm", "--key", "--raw"],
        _ => &[],
    }
}

fn parse(command: &str, args: &[String]) -> Result<Args, Usage> {
    let allowed = accepted(command);
    let mut parsed = Args::default();
    let mut seen = BTreeSet::new();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if !allowed.contains(&flag.as_str()) {
            return Err(Usage(format!("{command} does not take {flag:?}")));
        }
        if !seen.insert(flag.clone()) {
            return Err(Usage(format!("{flag} given twice")));
        }
        let mut value = || match iter.next() {
            Some(value) if !value.starts_with("--") => Ok(value.clone()),
            _ => Err(Usage(format!("{flag} needs a value"))),
        };
        match flag.as_str() {
            "--config" => parsed.config = Some(value()?.into()),
            "--artifacts" => parsed.artifacts = Some(value()?.into()),
            "--out" => parsed.out = Some(value()?.into()),
            "--product" => parsed.product = Some(value()?),
            "--platforms" => {
                parsed.platforms = Some(
                    Platform::parse_list(&value()?)
                        .map_err(|e| Usage(format!("--platforms: {e}")))?,
                );
            }
            "--release" => parsed.release = Some(value()?),
            "--sequence" => parsed.sequence = Some(value()?),
            "--signing" => parsed.signing = Some(value()?.into()),
            "--ci-test-signing" => parsed.ci_test_signing = Some(value()?.into()),
            "--algorithm" => parsed.algorithm = Some(value()?),
            "--secret" => parsed.secret = Some(value()?.into()),
            "--public" => parsed.public = Some(value()?.into()),
            "--key" => parsed.key = Some(value()?.into()),
            "--build" => parsed.build = Some(value()?),
            "--packages" => parsed.packages = Some(value()?.into()),
            "--msi" => parsed.msi = Some(value()?.into()),
            "--previous" => parsed.previous = Some(value()?.into()),
            "--repo" => parsed.repo = Some(value()?.into()),
            "--target" => parsed.target = Some(value()?.into()),
            "--ci" => parsed.ci = Some(value()?.into()),
            "--root" => parsed.root = Some(value()?.into()),
            "--include" => parsed.include = Some(value()?),
            "--server" => parsed.server = Some(value()?),
            "--client" => parsed.client = Some(value()?),
            "--triple" => parsed.triple = Some(value()?),
            "--manifest" => parsed.manifest = Some(value()?.into()),
            "--dry-run" => parsed.dry_run = true,
            "--no-prune" => parsed.no_prune = true,
            "--authenticode-only" => parsed.authenticode_only = true,
            "--allow-older" => parsed.allow_older = true,
            "--date" => parsed.date = Some(value()?),
            "--raw" => parsed.raw = true,
            "--no-strip" => parsed.no_strip = true,
            "--json" => parsed.json = true,
            _ => return Err(Usage(format!("unknown option {flag:?}"))),
        }
    }
    if parsed.authenticode_only && parsed.signing.is_none() {
        return Err(Usage(
            "--authenticode-only signs with --signing's [authenticode]: it needs --signing"
                .to_owned(),
        ));
    }
    // A release never signs with the CI test keys: only a dev
    // build's Authenticode joins them.
    if parsed.ci_test_signing.is_some() && parsed.signing.is_some() && !parsed.authenticode_only {
        return Err(Usage(
            "--ci-test-signing never joins a release's --signing: with --signing, only a dev build's --authenticode-only"
                .to_owned(),
        ));
    }
    Ok(parsed)
}

/// `--ci-test-signing`'s signers joined to `signing`: the CI test
/// keys' release-manifest signers and `[openpgp]`, from files in the
/// repository (never the environment: they are public test keys), and the
/// listing marked as theirs. `config` must trust them
/// ([`Config::use_ci_test_keys`]). `openpgp`: whether the run makes a
/// package OpenPGP signs (an rpm or pacman package, a product's or the
/// repository's); without one the file's `[openpgp]` is checked but never
/// loaded, so a macOS run or an MSI's adoption needs no gpg.
fn with_ci_test_signing(
    path: &Path,
    config: &Config,
    mut signing: package::Signing,
    openpgp: bool,
) -> Result<package::Signing, DistError> {
    let (mut file, base) = seaworthy::sign::SigningConfig::load(path)?;
    if file.authenticode.is_some() {
        return Err(DistError::Sign(format!(
            "{}: the CI test keys sign manifests and packages, never Authenticode: drop [authenticode]",
            path.display()
        )));
    }
    if !file.secret_variables().is_empty() {
        return Err(DistError::Sign(format!(
            "{}: the CI test keys are files in the repository, not secrets in the environment: name them with key and secret-key-file",
            path.display()
        )));
    }
    if file.manifest.is_empty() {
        return Err(DistError::Sign(format!(
            "{}: no [[manifest]] signer: the CI test keys sign release manifests",
            path.display()
        )));
    }
    if !openpgp {
        file.openpgp = None;
    }
    let test = file.signing(&base)?;
    seaworthy::sign::check_policy(config, &test.manifest)?;
    seaworthy::codesign::Pins::of(config).require(false, test.openpgp.is_some())?;
    signing.manifest = test.manifest;
    signing.openpgp = test.openpgp;
    signing.gpg = test.gpg.or(signing.gpg);
    signing.ci_test = true;
    eprintln!(
        "seaworthy: --ci-test-signing: manifests and package signatures by the CI test keys, which only non-release builds trust and the repositories refuse"
    );
    Ok(signing)
}

fn required<T: Clone>(value: &Option<T>, command: &str, name: &str) -> Result<T, Usage> {
    value
        .clone()
        .ok_or_else(|| Usage(format!("{command} needs {name}")))
}

/// `--release` and `--sequence` as a [`Release`].
fn release(args: &Args, command: &str) -> Result<Release, Failure> {
    let version = required(&args.release, command, "--release")?;
    let sequence = required(&args.sequence, command, "--sequence")?;
    if sequence.is_empty() || !sequence.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Usage("--sequence must be a decimal number".to_owned()).into());
    }
    let sequence: u64 = sequence
        .parse()
        .map_err(|_| Usage("--sequence is out of range".to_owned()))?;
    Ok(Release::new(&version, sequence).map_err(DistError::from)?)
}

/// The signers `--signing` names — or, with `--authenticode-only`, its
/// `[authenticode]` alone: a dev build, whose listing `repo` refuses.
fn signing_from(
    file: seaworthy::sign::SigningConfig,
    base: &Path,
    secrets: &seaworthy::sign::EnvSecrets,
    authenticode_only: bool,
) -> Result<package::Signing, DistError> {
    if !authenticode_only {
        return file.signing_with(base, secrets);
    }
    let mut signing = file.authenticode_only()?.signing_with(base, secrets)?;
    signing.authenticode_only = true;
    eprintln!(
        "seaworthy: --authenticode-only: a dev build (Authenticode-signed Windows binaries; no manifests, no OpenPGP signatures), which the repositories refuse"
    );
    Ok(signing)
}

/// The strip options from `--no-strip` and `$STRIP`.
fn strip_options(args: &Args) -> layout::Options {
    // The conventional build-tool override (like CC or AR), not product config.
    let strip_tool =
        // allow-std-env: the $STRIP build-tool override
        std::env::var_os("STRIP").map_or_else(|| PathBuf::from("strip"), PathBuf::from);
    layout::Options {
        strip: !args.no_strip,
        strip_tool,
    }
}

/// The latest `SOURCE_DATE_EPOCH` every format holds: rpm's 32-bit
/// timestamps end at 2106-02-07 (a zip's at 2107-12-31).
const LATEST_EPOCH: u64 = 4_294_967_295;

/// `SOURCE_DATE_EPOCH`, the reproducible-builds convention: decimal
/// seconds, within what every format holds (1980-01-01 to 2106-02-07).
fn source_date_epoch() -> Result<u64, DistError> {
    // allow-std-env: SOURCE_DATE_EPOCH, the reproducible-builds convention
    let Some(value) = std::env::var_os("SOURCE_DATE_EPOCH") else {
        return Ok(seaworthy::archive::ZIP_EPOCH);
    };
    let text = value.to_str().unwrap_or_default();
    let epoch = (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse::<u64>().ok())
        .flatten()
        .filter(|e| (seaworthy::archive::ZIP_EPOCH..=LATEST_EPOCH).contains(e));
    epoch.ok_or_else(|| {
        DistError::Config(format!(
            "SOURCE_DATE_EPOCH {value:?} must be decimal seconds from {} (1980-01-01, the earliest a zip holds) to {LATEST_EPOCH} (2106-02-07, the latest an rpm holds)",
            seaworthy::archive::ZIP_EPOCH,
        ))
    })
}

/// How far ahead of this machine's clock `--date` may be: clock skew,
/// not a scheduled publication (apt refuses a `Release` from the future).
const DATE_SKEW: u64 = 300;

/// `--date`: decimal seconds since the epoch, from 1980-01-01 to at most
/// [`DATE_SKEW`] past now; default now.
fn index_date(args: &Args) -> Result<u64, Failure> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DistError::Config("the clock is before 1970".to_owned()))?
        .as_secs();
    let Some(text) = &args.date else {
        return Ok(now);
    };
    let date = (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse::<u64>().ok())
        .flatten()
        .filter(|d| (seaworthy::archive::ZIP_EPOCH..=now.saturating_add(DATE_SKEW)).contains(d));
    date.ok_or_else(|| {
        Usage(format!(
            "--date {text:?} must be decimal seconds from {} to now ({now}): apt refuses a Release dated in the future",
            seaworthy::archive::ZIP_EPOCH
        ))
        .into()
    })
}

/// `--algorithm` as `seaworthy_updater`'s algorithm.
fn algorithm_arg(
    args: &Args,
    command: &str,
) -> Result<seaworthy_updater::SignatureAlgorithm, Failure> {
    let tag = required(&args.algorithm, command, "--algorithm")?;
    seaworthy_updater::SignatureAlgorithm::from_tag(&tag).ok_or_else(|| {
        Usage(format!(
            "--algorithm {tag:?}: ml-dsa-87, ecdsa-p256 or ed25519"
        ))
        .into()
    })
}

/// Creates `path` with `mode`, never over an existing file.
fn create_new(path: &std::path::Path, mode: u32) -> Result<std::fs::File, DistError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path).map_err(|e| DistError::io(path, e))
}

/// Writes `text` to an open file and makes it durable.
fn write_all(
    file: &mut std::fs::File,
    path: &std::path::Path,
    text: &str,
) -> Result<(), DistError> {
    use std::io::Write as _;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| DistError::io(path, e))
}

/// Makes a directory's entries durable (new files survive a crash).
fn sync_dir(path: &std::path::Path) {
    #[cfg(unix)]
    if let Some(dir) = path.parent().map(|p| {
        if p.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            p
        }
    }) && let Ok(handle) = std::fs::File::open(dir)
    {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// `--build`: build metadata, SemVer's grammar — dot-separated, non-empty
/// identifiers of `[0-9A-Za-z-]` — at most 64 characters, or none.
fn build_arg(args: &Args) -> Result<seaworthy::sign::BuildId, Failure> {
    let build = seaworthy::sign::BuildId {
        metadata: args.build.clone().unwrap_or_default(),
    };
    if !build.is_valid() {
        return Err(Usage(format!(
            "--build {:?}: at most 64 characters of dot-separated, non-empty identifiers of A-Z a-z 0-9 -",
            build.metadata
        ))
        .into());
    }
    Ok(build)
}

/// `seaworthy.toml`, narrowed to `--platforms` when given: a product with no
/// outputs there is skipped, and named — or refused, when `--product`
/// names it.
fn load_config(path: &Path, args: &Args) -> Result<Config, DistError> {
    let mut config = Config::load(path)?;
    if let Some(platforms) = &args.platforms {
        let names = platforms
            .iter()
            .map(|p| p.name())
            .collect::<Vec<_>>()
            .join(",");
        let dropped = config.only_platforms(platforms);
        if let Some(id) = args.product.as_ref().filter(|id| dropped.contains(id)) {
            return Err(DistError::Config(format!(
                "product {id} has no outputs for --platforms {names}"
            )));
        }
        for id in dropped {
            eprintln!("seaworthy: --platforms {names}: product {id} has no outputs there, skipped");
        }
    }
    Ok(config)
}

fn products(config: &Config, only: Option<&String>) -> Result<Vec<String>, DistError> {
    match only {
        Some(id) if config.products.contains_key(id) => Ok(vec![id.clone()]),
        Some(id) => Err(DistError::Config(format!("no product {id:?}"))),
        None => Ok(config.products.keys().cloned().collect()),
    }
}

/// Verifies every selected product, collecting every product's findings
/// before failing.
fn verify_all(
    config: &Config,
    only: Option<&String>,
    artifacts: &std::path::Path,
) -> Result<Vec<verify::Verified>, DistError> {
    let mut verified = Vec::new();
    let mut findings = Vec::new();
    for id in products(config, only)? {
        match verify::verify(config, &id, artifacts) {
            Ok(v) => verified.push(v),
            Err(DistError::Verify(f)) => {
                findings.extend(f.into_iter().map(|f| format!("[{id}] {f}")))
            }
            Err(other) => return Err(other),
        }
    }
    if !findings.is_empty() {
        return Err(DistError::Verify(findings));
    }
    for v in &verified {
        for warning in v.warnings() {
            eprintln!("seaworthy: warning: [{}] {warning}", v.product());
        }
    }
    Ok(verified)
}

enum Failure {
    Usage(Usage),
    Refused(DistError),
}

impl From<Usage> for Failure {
    fn from(usage: Usage) -> Self {
        Self::Usage(usage)
    }
}

impl From<DistError> for Failure {
    fn from(error: DistError) -> Self {
        Self::Refused(error)
    }
}

fn run(command: &str, args: &Args) -> Result<(), Failure> {
    let config_path = || {
        args.config
            .clone()
            .unwrap_or_else(|| PathBuf::from("seaworthy.toml"))
    };
    match command {
        "check" => {
            let config = Config::load(&config_path())?;
            println!(
                "{}: {} product(s), valid",
                config_path().display(),
                config.products.len()
            );
            for (id, note) in config.notes() {
                eprintln!("seaworthy: note: [{id}] {note}");
            }
        }
        "verify" => {
            let artifacts = required(&args.artifacts, command, "--artifacts")?;
            let config = load_config(&config_path(), args)?;
            for v in verify_all(&config, args.product.as_ref(), &artifacts)? {
                for platform in v.platforms() {
                    println!(
                        "{} {}: verified ({} cores)",
                        v.product(),
                        platform.inputs.triple,
                        platform.inputs.cores.len()
                    );
                }
            }
        }
        "layout" => {
            let artifacts = required(&args.artifacts, command, "--artifacts")?;
            let out = required(&args.out, command, "--out")?;
            let config = load_config(&config_path(), args)?;
            let options = strip_options(args);
            for v in verify_all(&config, args.product.as_ref(), &artifacts)? {
                for tree in layout::layout(&config, v.product(), &v, &out, options.clone())? {
                    println!(
                        "{} {}: {} files under {} ({})",
                        v.product(),
                        tree.triple,
                        tree.files.len(),
                        tree.install_root,
                        tree.tree.display()
                    );
                }
            }
        }
        "package" => {
            let out = required(&args.out, command, "--out")?;
            let release = release(args, command)?;
            let config = load_config(&config_path(), args)?;
            let config = if args.ci_test_signing.is_some() {
                config.use_ci_test_keys()?
            } else {
                config
            };
            // `--product repository`: the repository package alone (no
            // artifacts to verify); every product's run without
            // `--product` builds it too — a Linux package, so never
            // without Linux in `--platforms`.
            let linux = args
                .platforms
                .as_ref()
                .is_none_or(|p| p.contains(&Platform::Linux));
            let repository_only = config.defaults.repository.is_some()
                && args.product.as_deref() == Some(seaworthy::config::REPOSITORY_ID);
            if repository_only && !linux {
                return Err(Usage(
                    "package --product repository builds a Linux package: --platforms must name linux".to_owned(),
                )
                .into());
            }
            let with_repository = config.defaults.repository.is_some()
                && linux
                && (repository_only || args.product.is_none());
            if repository_only && (args.artifacts.is_some() || args.no_strip) {
                return Err(Usage(
                    "package --product repository takes no --artifacts or --no-strip: it builds the repository package alone, from seaworthy.toml".to_owned(),
                )
                .into());
            }
            let artifacts = if repository_only {
                None
            } else {
                Some(required(&args.artifacts, command, "--artifacts")?)
            };
            let options = package::Options {
                // Refused before any work: every format must spell it.
                release: {
                    release.package_versions().map_err(DistError::from)?;
                    release
                },
                mtime: source_date_epoch()?,
                nfpm: {
                    // allow-std-env: $NFPM, the packaging tool's path
                    std::env::var_os("NFPM").map_or_else(|| PathBuf::from("nfpm"), PathBuf::from)
                },
                // allow-std-env: $SEAWORTHY_WIX, the MSI build tool's path
                wix: std::env::var_os("SEAWORTHY_WIX").map(PathBuf::from),
                build: build_arg(args)?,
            };
            let selected = if repository_only {
                Vec::new()
            } else {
                products(&config, args.product.as_ref())?
            };
            let linux_packages = with_repository
                || selected.iter().any(|id| {
                    config.products.get(id).is_some_and(|p| {
                        p.outputs
                            .iter()
                            .any(|o| matches!(o, Output::Deb | Output::Rpm | Output::Pacman))
                    })
                });
            if linux_packages {
                // Before any work: the tool must run, and only the pinned
                // release reproduces packages byte for byte.
                let version = seaworthy::nfpm::tool_version(&options.nfpm)?;
                if version != seaworthy::nfpm::PINNED_VERSION {
                    eprintln!(
                        "seaworthy: warning: nFPM {version} is not the pinned {} (scripts/ci/install-nfpm.sh); packages won't match CI's byte for byte",
                        seaworthy::nfpm::PINNED_VERSION
                    );
                }
            }
            let signing = match &args.signing {
                Some(path) => {
                    let (file, base) = seaworthy::sign::SigningConfig::load(path)?;
                    let signing = signing_from(file, &base, &args.secrets, args.authenticode_only)?;
                    // Before any work: a key the clients would refuse never signs.
                    if !signing.manifest.is_empty() {
                        seaworthy::sign::check_policy(&config, &signing.manifest)?;
                        if options.build.metadata.is_empty() {
                            eprintln!(
                                "seaworthy: warning: no --build: the manifests name the bare version {}; when the version-gate server names a build (`version+commit`), no device will match them",
                                options.release.version
                            );
                        }
                    }
                    let pins = seaworthy::codesign::Pins::of(&config);
                    pins.require(signing.authenticode.is_some(), signing.openpgp.is_some())?;
                    // A signed release signs every Windows binary it ships:
                    // an MSI or zip under signed manifests but with
                    // unsigned executables is what SmartScreen, AppLocker
                    // and WDAC refuse. The library keeps every signer
                    // optional; the release command doesn't.
                    if signing.authenticode.is_none() {
                        for id in &selected {
                            let windows: Vec<&str> = config
                                .products
                                .get(id)
                                .map(|p| {
                                    p.outputs
                                        .iter()
                                        .filter(|o| o.is_windows())
                                        .map(|o| o.name())
                                        .collect()
                                })
                                .unwrap_or_default();
                            if !windows.is_empty() {
                                return Err(DistError::Sign(format!(
                                    "product {id} ships Windows outputs ({}) but {} has no [authenticode]: a signed release signs its Windows binaries — add [authenticode] and pin defaults.authenticode, or build it unsigned (no --signing)",
                                    windows.join(", "),
                                    path.display()
                                ))
                                .into());
                            }
                        }
                    }
                    // The same for macOS: a signed release's app is
                    // Developer ID-signed and notarized, which Gatekeeper
                    // requires of a download; the team is pinned.
                    if signing.apple.is_some() && config.defaults.apple.is_none() {
                        return Err(DistError::Sign(format!(
                            "{} has [apple], but seaworthy.toml pins no Developer ID team: set defaults.apple.team-id",
                            path.display()
                        ))
                        .into());
                    }
                    if signing.apple.is_none() && !args.authenticode_only {
                        for id in &selected {
                            let macos: Vec<&str> = config
                                .products
                                .get(id)
                                .map(|p| {
                                    p.outputs
                                        .iter()
                                        .filter(|o| o.is_macos())
                                        .map(|o| o.name())
                                        .collect()
                                })
                                .unwrap_or_default();
                            if !macos.is_empty() {
                                return Err(DistError::Sign(format!(
                                    "product {id} ships macOS outputs ({}) but {} has no [apple]: a signed release signs its app with a Developer ID and notarizes it — add [apple] and pin defaults.apple, or package macOS unsigned (no --signing)",
                                    macos.join(", "),
                                    path.display()
                                ))
                                .into());
                            }
                        }
                    }
                    signing
                }
                None => {
                    if args.ci_test_signing.is_none() {
                        eprintln!(
                            "seaworthy: no --signing: an unsigned build (no manifests, no signatures)"
                        );
                    }
                    package::Signing::default()
                }
            };
            let signing = match &args.ci_test_signing {
                Some(path) => {
                    let openpgp = with_repository
                        || config.products.values().any(|product| {
                            product
                                .outputs
                                .iter()
                                .any(|output| matches!(output, Output::Rpm | Output::Pacman))
                        });
                    with_ci_test_signing(path, &config, signing, openpgp)?
                }
                None => signing,
            };
            let strip = strip_options(args);
            let print = |id: &str, artifact: &package::Artifact| {
                println!(
                    "{id} {:?}: {} (sha256 {})",
                    artifact.kind,
                    artifact.path.display(),
                    artifact.sha256
                );
            };
            if let Some(artifacts) = &artifacts {
                for v in verify_all(&config, args.product.as_ref(), artifacts)? {
                    let trees = layout::layout(&config, v.product(), &v, &out, strip.clone())?;
                    for artifact in
                        package::package(&config, v.product(), &trees, &out, &options, &signing)?
                    {
                        print(v.product(), &artifact);
                    }
                }
            }
            if with_repository {
                for artifact in package::repository(&config, &out, &options, &signing)? {
                    print(seaworthy::config::REPOSITORY_ID, &artifact);
                }
            }
        }
        "adopt-msi" => {
            // The MSI WiX built on Windows from package's .wxs:
            // checked against the signed tree, signed, listed.
            let out = required(&args.out, command, "--out")?;
            let id = required(&args.product, command, "--product")?;
            let msi = required(&args.msi, command, "--msi")?;
            let config = Config::load(&config_path())?;
            let config = if args.ci_test_signing.is_some() {
                config.use_ci_test_keys()?
            } else {
                config
            };
            let signing = match &args.signing {
                Some(path) => {
                    let (file, base) = seaworthy::sign::SigningConfig::load(path)?;
                    let signing = signing_from(file, &base, &args.secrets, args.authenticode_only)?;
                    let pins = seaworthy::codesign::Pins::of(&config);
                    pins.require(signing.authenticode.is_some(), false)?;
                    // A signed release signs its MSI.
                    if signing.authenticode.is_none() {
                        return Err(DistError::Sign(format!(
                            "{} has no [authenticode]: a signed release's MSI is Authenticode-signed, or adopt it unsigned (no --signing)",
                            path.display()
                        ))
                        .into());
                    }
                    signing
                }
                None => {
                    if args.ci_test_signing.is_none() {
                        eprintln!(
                            "seaworthy: no --signing: an unsigned MSI (no manifest, no signature)"
                        );
                    }
                    package::Signing::default()
                }
            };
            let signing = match &args.ci_test_signing {
                // An MSI carries no OpenPGP signature.
                Some(path) => with_ci_test_signing(path, &config, signing, false)?,
                None => signing,
            };
            let tools = package::MsiTools {
                // allow-std-env: $MSIEXTRACT, msitools' extractor
                msiextract: std::env::var_os("MSIEXTRACT")
                    .map_or_else(|| PathBuf::from("msiextract"), PathBuf::from),
                // allow-std-env: $MSIINFO, msitools' table reader
                msiinfo: std::env::var_os("MSIINFO")
                    .map_or_else(|| PathBuf::from("msiinfo"), PathBuf::from),
            };
            let mtime = source_date_epoch()?;
            for artifact in package::adopt_msi(&config, &id, &out, &msi, mtime, &signing, &tools)? {
                println!(
                    "{id} {:?}: {} (sha256 {})",
                    artifact.kind,
                    artifact.path.display(),
                    artifact.sha256
                );
            }
        }
        "repo" => {
            let packages = required(&args.packages, command, "--packages")?;
            let out = required(&args.out, command, "--out")?;
            let signing_path = required(&args.signing, command, "--signing")?;
            let date = index_date(args)?;
            let config = Config::load(&config_path())?;
            let (file, base) = seaworthy::sign::SigningConfig::load(&signing_path)?;
            // The OpenPGP signer alone: a manifest key the file names is
            // `package`'s, never needed (or required) here.
            let (openpgp_signer, gpg_tool) = file.openpgp_with(&base, &args.secrets)?;
            let Some(openpgp) = openpgp_signer.as_deref() else {
                return Err(DistError::Sign(format!(
                    "{}: no [openpgp] signer for the repositories' indexes",
                    signing_path.display()
                ))
                .into());
            };
            let mut pins = seaworthy::codesign::Pins::of(&config);
            if let Some(tool) = &gpg_tool {
                pins.gpg.clone_from(tool);
            }
            pins.require(false, true)?;
            // Every product's, and the repository package's when seaworthy.toml
            // sets it up.
            let listings = config
                .products
                .keys()
                .map(String::as_str)
                .chain(
                    config
                        .defaults
                        .repository
                        .as_ref()
                        .map(|_| seaworthy::config::REPOSITORY_ID),
                )
                .map(|id| {
                    seaworthy::repo::read_listing(&packages.join(id)).map_err(|e| {
                        if id == seaworthy::config::REPOSITORY_ID {
                            DistError::Layout(format!(
                                "{e} (seaworthy.toml sets [defaults.repository]: `seaworthy package` without --product, or with --product repository, builds the repository package)"
                            ))
                        } else {
                            e
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let previous = args
                .previous
                .as_deref()
                .map(seaworthy::repo::Plan::read)
                .transpose()?;
            let plan = seaworthy::repo::build(
                &config,
                &listings,
                &out,
                &seaworthy::repo::Tools::default(),
                &seaworthy::repo::Signers {
                    openpgp,
                    pins: &pins,
                },
                &seaworthy::repo::Options {
                    date,
                    previous: previous.as_ref(),
                    allow_older: args.allow_older,
                },
            )?;
            for listing in &listings {
                println!("{} {}: published", listing.package, listing.token);
            }
            let indexes = plan
                .files
                .iter()
                .filter(|f| f.class == seaworthy::repo::Class::Index)
                .count();
            println!(
                "repository {} ({}): {} files, {} of them indexes, under {} (upload order: {})",
                plan.repository,
                plan.channel,
                plan.files.len(),
                indexes,
                out.display(),
                out.join(seaworthy::repo::PLAN_FILE).display()
            );
        }
        #[cfg(not(feature = "publish-s3"))]
        "publish" => {
            return Err(DistError::Tool(
                "publish: this seaworthy was built without the publish-s3 feature".to_owned(),
            )
            .into());
        }
        #[cfg(feature = "publish-s3")]
        "publish" => {
            let repo = required(&args.repo, command, "--repo")?;
            let target_path = required(&args.target, command, "--target")?;
            let target = seaworthy::publish::Target::load(&target_path)?;
            let credentials = seaworthy::publish::Credentials::from_env()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| DistError::Config("the clock is before 1970".to_owned()))?
                .as_secs();
            let report = seaworthy::publish::publish(
                &repo,
                &target,
                &credentials,
                &seaworthy::publish::Options {
                    dry_run: args.dry_run,
                    // A dry run previews the pruning too (and deletes
                    // nothing).
                    prune: !args.no_prune,
                    now,
                },
            )?;
            let place = format!("s3://{}/{}", target.bucket, target.prefix);
            if report.already_published {
                println!("{place}: this plan is already published (its indexes go up again)");
            }
            let (put, delete) = if args.dry_run {
                ("would upload", "would delete")
            } else {
                ("uploaded", "deleted")
            };
            for key in &report.uploaded {
                println!("{put} {key}");
            }
            for key in &report.deleted {
                println!("{delete} {key}");
            }
            for key in &report.foreign {
                eprintln!(
                    "seaworthy: warning: {key} isn't a key this publisher writes: left alone"
                );
            }
            for key in &report.unrecognized {
                eprintln!(
                    "seaworthy: warning: {key}: no plan lists it and it predates this repository's first plan here: not pruned (delete it yourself if it's yours)"
                );
            }
            println!(
                "{place}: {} {put}, {} already published, {} {delete}, {} checked through the public URL",
                report.uploaded.len(),
                report.skipped.len(),
                report.deleted.len(),
                report.verified
            );
            if let Some(why) = &report.prune_error {
                return Err(
                    DistError::Tool(format!("published, but pruning was refused: {why}")).into(),
                );
            }
        }
        "ci-order" => {
            let ci = required(&args.ci, command, "--ci")?;
            let list = |value: &Option<String>| -> Vec<String> {
                value
                    .as_deref()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            };
            let servers = list(&args.server);
            let clients = list(&args.client);
            if args.server.is_none() || args.client.is_none() {
                return Err(Usage("ci-order needs --server and --client (comma-separated job names; empty for none)".to_owned()).into());
            }
            let root = match &args.root {
                Some(root) => root.clone(),
                None => ci
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf),
            };
            let include: Vec<PathBuf> =
                list(&args.include).into_iter().map(PathBuf::from).collect();
            let pipeline = seaworthy::ci_order::load(&root, &ci, &include)?;
            // An include the --include files stand for (seaworthy's template,
            // by file name) is read, not warned about.
            let given: BTreeSet<String> = include
                .iter()
                .filter_map(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect();
            for unresolved in &pipeline.unresolved {
                let covered = !unresolved.files.is_empty()
                    && unresolved.files.iter().all(|f| {
                        f.rsplit('/')
                            .next()
                            .is_some_and(|name| given.contains(name))
                    });
                if !covered {
                    eprintln!(
                        "seaworthy: warning: include not read ({unresolved}): pass the file with --include if a job named here is defined there"
                    );
                }
            }
            if servers.is_empty() {
                println!("release order: no server deploy job named, nothing to order");
                return Ok(());
            }
            let report = seaworthy::ci_order::check(&pipeline, &servers, &clients);
            if !report.findings.is_empty() {
                return Err(DistError::Order(report.findings).into());
            }
            for (server, clients) in &report.ordered {
                println!("release order: {server} waits for {}", clients.join(", "));
            }
        }
        "build-plan" => {
            let triple = required(&args.triple, command, "--triple")?;
            let config = Config::load(&config_path())?;
            let manifest = args
                .manifest
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("Cargo.toml"));
            let steps = seaworthy::build_plan::plan_for(
                &config,
                &triple,
                args.product.as_deref(),
                manifest,
            )?;
            seaworthy::build_plan::check_cargo_config(manifest)?;
            print!("{}", seaworthy::build_plan::render(&steps));
        }
        "version" => {
            let v = release(args, command)?
                .package_versions()
                .map_err(DistError::from)?;
            if args.json {
                let json = serde_json::json!({
                    "deb": v.deb,
                    "rpm_version": v.rpm_version,
                    "rpm_release": v.rpm_release,
                    "pacman_pkgver": v.pacman_pkgver,
                    "pacman_pkgrel": v.pacman_pkgrel,
                    "msi": v.msi,
                });
                println!("{json}");
            } else {
                println!(
                    "deb     {}\nrpm     {}-{}\npacman  {}-{}\nmsi     {}",
                    v.deb, v.rpm_version, v.rpm_release, v.pacman_pkgver, v.pacman_pkgrel, v.msi
                );
            }
        }
        "manifest-version" => {
            let manifest = required(&args.manifest, command, "--manifest")?;
            println!("{}", seaworthy::build_plan::manifest_version(&manifest)?);
        }
        "apple-team" => {
            let config = Config::load(&config_path())?;
            if let Some(apple) = &config.defaults.apple {
                println!("{}", apple.team_id);
            }
        }
        "keygen" => {
            let algorithm = algorithm_arg(args, command)?;
            let secret = required(&args.secret, command, "--secret")?;
            let public = required(&args.public, command, "--public")?;
            // The key first: a generation failure leaves no files.
            let key = seaworthy::sign::generate_key(algorithm)?;
            // Both files are created before either is written: an existing
            // public file never leaves an orphan secret behind.
            let mut public_file = create_new(&public, 0o644)?;
            let mut secret_file = match create_new(&secret, 0o600) {
                Ok(file) => file,
                Err(e) => {
                    drop(public_file);
                    let _ = std::fs::remove_file(&public);
                    return Err(e.into());
                }
            };
            // Sized up front: the copy with its newline never reallocates,
            // and is wiped on drop.
            let mut secret_text =
                zeroize::Zeroizing::new(String::with_capacity(key.secret_hex.len() + 1));
            secret_text.push_str(&key.secret_hex);
            secret_text.push('\n');
            // A failed write leaves neither file: half a key pair is worse
            // than none.
            let written = write_all(&mut secret_file, &secret, &secret_text).and_then(|()| {
                write_all(
                    &mut public_file,
                    &public,
                    &format!("{}\n", hex::encode(&key.public_key)),
                )
            });
            if let Err(e) = written {
                drop((secret_file, public_file));
                let _ = std::fs::remove_file(&secret);
                let _ = std::fs::remove_file(&public);
                return Err(e.into());
            }
            sync_dir(&secret);
            sync_dir(&public);
            println!(
                "{} key {}: secret {}, public {}",
                algorithm.tag(),
                hex::encode(key.key_id),
                secret.display(),
                public.display()
            );
        }
        "sign-statement" => {
            use seaworthy::sign::ManifestSigner as _;
            use std::io::Read as _;
            let algorithm = algorithm_arg(args, command)?;
            let path = required(&args.key, command, "--key")?;
            let key = seaworthy::sign::LocalKey::from_file(algorithm, &path)?;
            let mut statement = Vec::new();
            std::io::stdin()
                .take(64 << 10)
                .read_to_end(&mut statement)
                .map_err(|e| DistError::Sign(format!("reading the statement: {e}")))?;
            // The reference signer signs release statements and nothing else.
            seaworthy_updater::ReleaseManifest::from_statement(&statement).map_err(|e| {
                DistError::Sign(format!(
                    "stdin is not a canonical seaworthy-release-manifest:1 statement: {e}"
                ))
            })?;
            let signature = key.sign(&statement)?;
            if args.raw {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(&signature)
                    .map_err(|e| DistError::Sign(format!("writing the signature: {e}")))?;
            } else {
                println!("{}", hex::encode(signature));
            }
        }
        other => return Err(Usage(format!("unknown command {other:?}")).into()),
    }
    Ok(())
}

/// `fips-check FILE…`: every file must pass; prints each verdict.
fn fips_check(files: &[String]) -> ExitCode {
    if files.is_empty() || files.iter().any(|f| f.starts_with('-')) {
        eprintln!("fips-check needs one or more files\n{USAGE}");
        return ExitCode::from(2);
    }
    let prefix = seaworthy_crypto::module::FIPS_SYMBOL_PREFIX;
    let mut failed = false;
    for file in files {
        let findings = match std::fs::read(file) {
            Ok(bytes) => verify::fips_symbol_findings(&bytes, prefix),
            Err(e) => vec![format!("cannot read: {e}")],
        };
        if findings.is_empty() {
            println!("{file}: ok — links only the pinned AWS-LC FIPS module ({prefix}*)");
        } else {
            failed = true;
            for finding in findings {
                eprintln!("{file}: FAIL: {finding}");
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `glibc-check [--floor X.Y] FILE…`: each file's glibc needs against the
/// floor, as `verify` checks a product's binaries.
fn glibc_check(args: &[String]) -> ExitCode {
    let mut floor = seaworthy::config::DEFAULT_GLIBC_FLOOR;
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--floor" {
            match iter
                .next()
                .and_then(|v| seaworthy::config::parse_glibc_version(v))
            {
                Some(parsed) => floor = parsed,
                None => {
                    eprintln!("glibc-check: --floor needs a glibc version (2.34)\n{USAGE}");
                    return ExitCode::from(2);
                }
            }
        } else if arg.starts_with('-') {
            eprintln!("glibc-check: unknown option {arg:?}\n{USAGE}");
            return ExitCode::from(2);
        } else {
            files.push(arg);
        }
    }
    if files.is_empty() {
        eprintln!("glibc-check needs one or more files\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut failed = false;
    for file in files {
        let needs = match std::fs::read(file) {
            Ok(bytes) => verify::elf_glibc_needs(&bytes),
            Err(e) => Err(format!("cannot read: {e}")),
        };
        match needs {
            Ok(needs) => {
                let beyond: Vec<String> = needs
                    .iter()
                    .filter(|need| need.since.is_none_or(|since| since > floor))
                    .map(|need| match need.since {
                        Some((major, minor)) => format!("{} (glibc {major}.{minor})", need.name),
                        None => format!("{} (unknown to this check)", need.name),
                    })
                    .collect();
                if beyond.is_empty() {
                    let newest = needs.iter().filter_map(|n| n.since).max();
                    println!(
                        "{file}: ok — needs glibc {} at most (floor {}.{})",
                        newest.map_or_else(|| "nothing".to_owned(), |(a, b)| format!("{a}.{b}")),
                        floor.0,
                        floor.1
                    );
                } else {
                    failed = true;
                    eprintln!(
                        "{file}: FAIL: needs {}, past the glibc floor {}.{}",
                        beyond.join(", "),
                        floor.0,
                        floor.1
                    );
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("{file}: FAIL: {e}");
            }
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// The secrets `--signing`'s file names (`key-env`, `secret-key-env`: a
/// key a custody system's wrapper hands over in the environment), read and
/// then removed from this process's environment before anything runs, so
/// no program `seaworthy` starts (nFPM, strip, gpg, rpmsign, a signing
/// command, the checks' gpg and rpmkeys) inherits them. Beyond these, a
/// tool gets only an allowlisted environment ([`seaworthy::process::tool`]),
/// and the runner's and clouds' credentials are set aside for signing
/// commands alone ([`withhold_signer_credentials`]). Every variable the
/// file names is removed; those `command` uses (`repo`: the OpenPGP key
/// alone; `package`: all) are required, and a required one that's unset,
/// empty, not UTF-8 or oversized is refused (after its removal). Removing
/// a variable doesn't erase its bytes from the process's initial
/// environment block, which `/proc/<pid>/environ` serves: `main` makes the
/// process non-dumpable first ([`protect_process`]), so only root reads
/// that file.
fn take_secrets(command: &str, args: &Args) -> Result<seaworthy::sign::EnvSecrets, DistError> {
    let mut secrets = seaworthy::sign::EnvSecrets::new();
    let Some(path) = &args.signing else {
        return Ok(secrets);
    };
    let (file, _) = seaworthy::sign::SigningConfig::load(path)?;
    // A dev build (--authenticode-only) takes no manifest or OpenPGP
    // key: none is required or kept, though every one is still scrubbed.
    let required = if args.authenticode_only {
        Vec::new()
    } else if command == "repo" {
        file.openpgp_variables()
    } else {
        file.secret_variables()
    };
    for name in file.secret_variables() {
        // allow-std-env: a key the secrets wrapper hands over (signing.toml's key-env)
        let value = std::env::var_os(name);
        // SAFETY: called from `main` before anything else runs: nothing but
        // argument parsing and reading signing.toml has happened, and
        // seaworthy starts no thread before this returns, so nothing reads
        // or writes the environment concurrently.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(name);
        }
        let value = value
            .and_then(|v| v.into_string().ok())
            .map(seaworthy::sign::EnvSecret::new)
            .filter(|v| !v.is_empty() && v.len() <= seaworthy::sign::MAX_ENV_SECRET);
        match value {
            Some(_) if args.authenticode_only => {}
            Some(value) => {
                secrets.insert(name.to_owned(), value);
            }
            None if required.contains(&name) => {
                return Err(DistError::Sign(format!(
                    "{}: names the environment variable {name}, which is unset, empty, not UTF-8 or over {} bytes (the secrets wrapper hands the key over in it)",
                    path.display(),
                    seaworthy::sign::MAX_ENV_SECRET
                )));
            }
            None => {}
        }
    }
    Ok(secrets)
}

/// Takes the runner's and clouds' credentials (GitHub's OIDC request token
/// and URL, `AZURE_*`, `AWS_*`, CI job tokens:
/// [`seaworthy::process::is_signer_credential`]) out of this process's
/// environment and sets them aside for signing commands alone
/// ([`seaworthy::process::signer`]): a cloud signer's client needs them; no
/// tool, and no check a library runs (the OpenPGP checks' gpg and
/// rpmkeys), ever sees them. Runs after [`take_secrets`], which may read a
/// key under such a name first.
fn withhold_signer_credentials() {
    let mut withheld = Vec::new();
    // allow-std-env: the credentials set aside for signing commands
    for (name, value) in std::env::vars_os() {
        if name
            .to_str()
            .is_some_and(seaworthy::process::is_signer_credential)
        {
            // SAFETY: called from `main` before any command runs: nothing
            // but argument parsing and reading signing.toml has happened,
            // and seaworthy starts no thread before this returns, so
            // nothing reads or writes the environment concurrently.
            #[allow(unsafe_code)]
            unsafe {
                std::env::remove_var(&name);
            }
            withheld.push((name, value));
        }
    }
    seaworthy::process::set_signer_environment(withheld);
}

/// Makes this process non-dumpable (Linux), first thing: its
/// `/proc/<pid>/environ` and `/proc/<pid>/mem` become root's only, no
/// same-user process can ptrace it, and it never dumps core — so a key
/// handed over in the environment (or the store's credentials) can't be
/// read back out of it by a tool it runs or another job of the same user.
/// The programs it starts are dumpable again (execve resets it).
fn protect_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointers and changes
        // only this process's dumpable flag.
        #[allow(unsafe_code)]
        let done = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if done != 0 {
            eprintln!(
                "seaworthy: warning: couldn't make the process non-dumpable ({}): a same-user process could read secrets from /proc",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn main() -> ExitCode {
    protect_process();
    let mut argv = Vec::new();
    for arg in std::env::args_os().skip(1) {
        match arg.into_string() {
            Ok(arg) => argv.push(arg),
            Err(arg) => {
                eprintln!("argument {arg:?} is not valid UTF-8\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some((command, rest)) = argv.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    // The tool's own version (what a release archive holds), and the
    // usage on stdout when asked for.
    match (command.as_str(), rest.is_empty()) {
        ("--version" | "-V", true) => {
            println!("seaworthy {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ("--help" | "-h", true) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ("--version" | "-V" | "--help" | "-h", false) => {
            eprintln!("{command} takes no arguments\n{USAGE}");
            return ExitCode::from(2);
        }
        _ => {}
    }
    if command == "fips-check" {
        return fips_check(rest);
    }
    if command == "glibc-check" {
        return glibc_check(rest);
    }
    if accepted(command).is_empty() {
        eprintln!("unknown command {command:?}\n{USAGE}");
        return ExitCode::from(2);
    }
    let result = parse(command, rest)
        .map_err(Failure::from)
        .and_then(|mut args| {
            args.secrets = take_secrets(command, &args)?;
            withhold_signer_credentials();
            run(command, &args)
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(Usage(why))) => {
            eprintln!("{why}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failure::Refused(e)) => {
            eprintln!("seaworthy: {e}");
            ExitCode::from(1)
        }
    }
}
