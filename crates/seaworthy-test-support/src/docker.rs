//! Docker daemon detection + the skip contract (three-state): suites
//! compile everywhere and SKIP only when NO daemon exists; a daemon that exists but cannot be used
//! (EACCES on the socket, a stale socket, a refused/unanswering TCP
//! daemon, an unsupported `DOCKER_HOST` scheme, a TLS setup testcontainers
//! would panic on) is a misconfiguration and FAILS loudly, naming the
//! cause.
//!
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED` ([`crate::REQUIRED_ENV`]):
//! - unset/empty (auto) — skip on [`Probe::Absent`], panic on
//!   [`Probe::Unusable`];
//! - `1`/`true`/`yes`/`on` — panic on both (the CI guardrail);
//! - `0`/`false`/`no`/`off` — skip on both (the explicit escape hatch —
//!   still announced, naming the cause).
//!
//! Any other value is a loud panic (malformed configuration never silently
//! defaults).
//!
//! Daemon resolution follows testcontainers' own `Config::docker_host()`
//! order EXACTLY (the containers and this probe must talk to the same
//! daemon): `DOCKER_HOST`, else the first existing socket of
//! `/var/run/docker.sock`, `$XDG_RUNTIME_DIR/.docker/run/docker.sock`,
//! `$HOME/.docker/run/docker.sock`, `$HOME/.docker/desktop/docker.sock`;
//! TLS is `DOCKER_TLS_VERIFY == "1"` (testcontainers' parse) or an
//! `https://` host, with certificates from `DOCKER_CERT_PATH` (which
//! testcontainers REQUIRES for TLS — it panics without it, so the probe
//! reports that as `Unusable` instead). The `~/.testcontainers.properties`
//! file is not consulted: this crate builds testcontainers without its
//! `properties-config` feature, so testcontainers never reads it either.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// The skip notice is printed once per process, not once per skipped test.
/// A runner that gives every test its own process (nextest) prints it once
/// per test; a passing test's stderr is hidden by default there, so make
/// it visible (`success-output = "final"`) where a skip must be noticed.
static NOTICED: AtomicBool = AtomicBool::new(false);

/// The ping budget. The first ping on a cold or loaded daemon routinely
/// exceeds a few seconds (a 3 s budget read a busy daemon as "no daemon");
/// 15 s is generous for a healthy daemon and still bounded for a wedged
/// one, whose expiry is `Unusable`, never a skip.
pub const PING_TIMEOUT: Duration = Duration::from_secs(15);

/// The bollard client's own request timeout (testcontainers' value).
const CLIENT_TIMEOUT_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// The REQUIRED knob
// ---------------------------------------------------------------------------

/// `SEAWORTHY_TEST_CONTAINERS_REQUIRED`, parsed (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredMode {
    /// Unset/empty: skip when no daemon exists, fail when one exists but
    /// is unusable.
    Auto,
    /// `1`/`true`: every unavailability is a failure (CI).
    Always,
    /// `0`/`false`: every unavailability is a skip (the escape hatch).
    Never,
}

impl RequiredMode {
    /// Parse the knob's value (`None` = unset). A malformed value is an
    /// `Err` naming it, never a silent default.
    ///
    /// # Errors
    /// The malformed value, named, with the accepted spellings.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self::Auto);
        };
        match value.trim().to_ascii_lowercase().as_str() {
            "" => Ok(Self::Auto),
            "1" | "true" | "yes" | "on" => Ok(Self::Always),
            "0" | "false" | "no" | "off" => Ok(Self::Never),
            _ => Err(format!(
                "{}={value:?} is not a recognized value \
                 (expected unset, 1/true/yes/on, or 0/false/no/off)",
                crate::REQUIRED_ENV
            )),
        }
    }
}

/// The knob from the process environment. Panics on a malformed value.
#[must_use]
pub fn required_mode() -> RequiredMode {
    let value = std::env::var(crate::REQUIRED_ENV).ok();
    RequiredMode::parse(value.as_deref()).unwrap_or_else(|e| panic!("seaworthy-test-support: {e}"))
}

/// Whether containers are explicitly REQUIRED (`SEAWORTHY_TEST_CONTAINERS_REQUIRED=1`).
#[must_use]
pub fn required() -> bool {
    required_mode() == RequiredMode::Always
}

// ---------------------------------------------------------------------------
// Daemon resolution (testcontainers' order)
// ---------------------------------------------------------------------------

/// The docker-relevant environment, snapshotted (tests construct it
/// directly instead of mutating the process environment).
#[derive(Clone, Debug, Default)]
pub(crate) struct DockerEnv {
    pub(crate) docker_host: Option<String>,
    pub(crate) tls_verify: Option<String>,
    pub(crate) cert_path: Option<PathBuf>,
    pub(crate) home: Option<PathBuf>,
    pub(crate) xdg_runtime_dir: Option<PathBuf>,
}

impl DockerEnv {
    pub(crate) fn from_process() -> Self {
        let var = |key: &str| std::env::var(key).ok();
        Self {
            docker_host: var("DOCKER_HOST"),
            tls_verify: var("DOCKER_TLS_VERIFY"),
            cert_path: var("DOCKER_CERT_PATH").map(PathBuf::from),
            home: var("HOME").map(PathBuf::from),
            xdg_runtime_dir: var("XDG_RUNTIME_DIR").map(PathBuf::from),
        }
    }

    /// The candidate sockets testcontainers tries when `DOCKER_HOST` is
    /// unset, in its order.
    fn candidate_sockets(&self) -> Vec<PathBuf> {
        let mut out = vec![PathBuf::from("/var/run/docker.sock")];
        if let Some(dir) = &self.xdg_runtime_dir {
            out.push(dir.join(".docker/run/docker.sock"));
        }
        if let Some(home) = &self.home {
            out.push(home.join(".docker/run/docker.sock"));
            out.push(home.join(".docker/desktop/docker.sock"));
        }
        out
    }
}

/// Where the daemon is, per the resolution order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DaemonAddr {
    /// `DOCKER_HOST` unset and no candidate socket exists.
    None { tried: Vec<PathBuf> },
    /// A unix socket (`unix:///path`, or a found candidate).
    Unix(PathBuf),
    /// `tcp://`/`http://`/`https://` — `host` is bracket-free (an IPv6
    /// literal is `::1`, never `[::1]`), `tls` per testcontainers' rule.
    Tcp {
        url: String,
        host: String,
        port: Option<u16>,
        tls: bool,
    },
    /// Something testcontainers cannot connect to (`ssh://`, garbage).
    Unsupported { value: String, why: String },
}

impl DaemonAddr {
    /// Whether this is a loopback TCP daemon (its published ports are on
    /// OUR loopback: the same host, or a netns-sharing sidecar).
    pub(crate) fn is_loopback_tcp(&self) -> bool {
        match self {
            Self::Tcp { host, .. } => {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }
            _ => false,
        }
    }
}

/// Resolve the daemon address from an environment snapshot.
pub(crate) fn resolve(env: &DockerEnv) -> DaemonAddr {
    let Some(host) = env.docker_host.as_deref() else {
        let tried = env.candidate_sockets();
        return match tried.iter().find(|path| socket_present(path)) {
            Some(path) => DaemonAddr::Unix(path.clone()),
            None => DaemonAddr::None { tried },
        };
    };
    parse_docker_host(host, env.tls_verify.as_deref() == Some("1"))
}

/// Present = anything but "does not exist" (a socket inside a directory
/// we cannot traverse is PRESENT-but-unusable, never absent — `exists()`
/// would fold the EACCES into `false`).
fn socket_present(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Parse a `DOCKER_HOST` value (bracket-aware: `tcp://[::1]:2375` names
/// host `::1`).
pub(crate) fn parse_docker_host(value: &str, tls_verify: bool) -> DaemonAddr {
    let unsupported = |why: &str| DaemonAddr::Unsupported {
        value: value.to_string(),
        why: why.to_string(),
    };
    if value.trim().is_empty() {
        return unsupported("DOCKER_HOST is set but empty");
    }
    let Ok(url) = url::Url::parse(value) else {
        return unsupported("DOCKER_HOST is not a URL (expected unix:///path or tcp://host:port)");
    };
    match url.scheme() {
        "unix" => DaemonAddr::Unix(PathBuf::from(url.path())),
        scheme @ ("tcp" | "http" | "https") => {
            let Some(host) = url.host() else {
                return unsupported("DOCKER_HOST names no host");
            };
            let host = match host {
                url::Host::Ipv6(ip) => ip.to_string(),
                other => other.to_string(),
            };
            DaemonAddr::Tcp {
                url: value.to_string(),
                host,
                port: url.port(),
                tls: tls_verify || scheme == "https",
            }
        }
        other => unsupported(&format!(
            "scheme {other}:// is not supported by testcontainers (unix, tcp, http, https only — \
             for a remote daemon over ssh, forward its socket: \
             `ssh -NL /tmp/docker.sock:/var/run/docker.sock host` + DOCKER_HOST=unix:///tmp/docker.sock)"
        )),
    }
}

/// A bollard client for a resolved address.
fn connect_addr(env: &DockerEnv, addr: &DaemonAddr) -> Result<bollard::Docker, Probe> {
    let map_err = |e: bollard::errors::Error| classify_error(addr, &e);
    match addr {
        DaemonAddr::None { tried } => Err(Probe::Absent(absent_reason(tried))),
        DaemonAddr::Unsupported { value, why } => {
            Err(Probe::Unusable(format!("DOCKER_HOST={value:?}: {why}")))
        }
        DaemonAddr::Unix(path) => bollard::Docker::connect_with_unix(
            &format!("unix://{}", path.display()),
            CLIENT_TIMEOUT_SECS,
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(map_err),
        DaemonAddr::Tcp { url, tls: true, .. } => {
            let Some(cert_path) = env.cert_path.as_ref() else {
                return Err(Probe::Unusable(format!(
                    "DOCKER_HOST={url:?} needs TLS (DOCKER_TLS_VERIFY=1 or https://) but \
                     DOCKER_CERT_PATH is unset — testcontainers panics without it; point it at \
                     the directory holding key.pem/cert.pem/ca.pem"
                )));
            };
            bollard::Docker::connect_with_ssl(
                url,
                &cert_path.join("key.pem"),
                &cert_path.join("cert.pem"),
                &cert_path.join("ca.pem"),
                CLIENT_TIMEOUT_SECS,
                bollard::API_DEFAULT_VERSION,
            )
            .map_err(map_err)
        }
        DaemonAddr::Tcp { url, .. } => bollard::Docker::connect_with_http(
            url,
            CLIENT_TIMEOUT_SECS,
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(map_err),
    }
}

fn absent_reason(tried: &[PathBuf]) -> String {
    let tried: Vec<String> = tried.iter().map(|p| p.display().to_string()).collect();
    format!(
        "no docker daemon: DOCKER_HOST is unset and no socket exists at {}",
        tried.join(", ")
    )
}

/// A bollard client for the process's daemon — the SAME resolution the
/// probe and testcontainers use. Panics naming the cause when there is no
/// usable daemon (callers run after [`docker_or_skip`]).
pub(crate) fn connect() -> bollard::Docker {
    try_connect().unwrap_or_else(|reason| panic!("seaworthy-test-support: docker client: {reason}"))
}

/// [`connect`] without the panic: the cause, for a caller that reports it
/// (the pull path, [`crate::pull`]).
pub(crate) fn try_connect() -> Result<bollard::Docker, String> {
    let env = DockerEnv::from_process();
    connect_addr(&env, &resolve(&env)).map_err(|probe| probe.reason().to_string())
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/// The classified daemon probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    /// No daemon exists (nothing configured, no socket anywhere): the
    /// skip case.
    Absent(String),
    /// A daemon/socket exists but cannot be used — a misconfiguration,
    /// never a skip in auto mode. Names the cause (and the fix).
    Unusable(String),
    /// The daemon answered a ping.
    Ready,
}

impl Probe {
    /// The human-readable cause (`"ready"` for [`Probe::Ready`]).
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            Self::Absent(reason) | Self::Unusable(reason) => reason,
            Self::Ready => "ready",
        }
    }
}

/// Probe the process's daemon (a real ping, bounded by [`PING_TIMEOUT`]).
pub async fn probe() -> Probe {
    probe_env(&DockerEnv::from_process(), PING_TIMEOUT).await
}

/// Whether a daemon answers a ping: [`probe`] collapsed to a bool (for
/// custom gates; the skip contract itself uses the classification).
pub async fn docker_available() -> bool {
    probe().await == Probe::Ready
}

pub(crate) async fn probe_env(env: &DockerEnv, timeout: Duration) -> Probe {
    let addr = resolve(env);
    let docker = match connect_addr(env, &addr) {
        Ok(docker) => docker,
        Err(probe) => return probe,
    };
    match tokio::time::timeout(timeout, docker.ping()).await {
        Ok(Ok(_)) => Probe::Ready,
        Ok(Err(e)) => classify_error(&addr, &e),
        Err(_) => Probe::Unusable(format!(
            "{} did not answer a ping within {}s — the daemon exists but is wedged or \
             overloaded (a slow daemon is a misconfiguration, never a skip)",
            describe(&addr),
            timeout.as_secs()
        )),
    }
}

/// Human name of the address, for messages.
fn describe(addr: &DaemonAddr) -> String {
    match addr {
        DaemonAddr::None { .. } => "no daemon".into(),
        DaemonAddr::Unix(path) => format!("the docker socket {}", path.display()),
        DaemonAddr::Tcp { url, .. } => format!("the docker daemon at {url}"),
        DaemonAddr::Unsupported { value, .. } => format!("DOCKER_HOST={value:?}"),
    }
}

/// The first `std::io::Error` kind in an error's chain (the bollard enum's
/// own `IOError` variant first — `#[error(transparent)]` forwards
/// `source()` PAST the wrapped io error, so a chain walk alone misses it).
fn io_kind(e: &bollard::errors::Error) -> Option<std::io::ErrorKind> {
    if let bollard::errors::Error::IOError { err } = e {
        return Some(err.kind());
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = current {
        if let Some(io) = err.downcast_ref::<std::io::Error>() {
            return Some(io.kind());
        }
        current = err.source();
    }
    None
}

/// Classify a connect/ping failure. Only a missing socket is `Absent`;
/// everything else is a daemon that EXISTS (or was explicitly configured)
/// and cannot be used.
pub(crate) fn classify_error(addr: &DaemonAddr, e: &bollard::errors::Error) -> Probe {
    if let bollard::errors::Error::SocketNotFoundError(path) = e {
        return Probe::Absent(format!(
            "no docker daemon: the socket {path} does not exist"
        ));
    }
    let what = describe(addr);
    let full = error_chain(e);
    let hint = match io_kind(e) {
        Some(std::io::ErrorKind::PermissionDenied) => match addr {
            DaemonAddr::Unix(path) => format!(
                " — permission denied: add your user to the socket's group \
                 (`sudo usermod -aG $(stat -c %G {p}) $USER`, then re-login) or grant it \
                 directly (`sudo setfacl -m u:$USER:rw {p}`)",
                p = path.display()
            ),
            _ => " — permission denied".into(),
        },
        Some(std::io::ErrorKind::NotFound) => match addr {
            DaemonAddr::Unix(path) => {
                return Probe::Absent(format!(
                    "no docker daemon: the socket {} does not exist",
                    path.display()
                ));
            }
            _ => " — not found".into(),
        },
        Some(std::io::ErrorKind::ConnectionRefused) => match addr {
            DaemonAddr::Unix(_) => " — connection refused: the socket file exists but no daemon \
                                    is listening (a stale socket; start the daemon)"
                .into(),
            _ => " — connection refused: nothing listens there (is the daemon up?)".into(),
        },
        _ => String::new(),
    };
    Probe::Unusable(format!("{what} is unusable: {full}{hint}"))
}

/// `err: source: source…` for a message (bollard's Display alone drops
/// the io cause behind hyper's wrappers).
fn error_chain(e: &bollard::errors::Error) -> String {
    let mut out = e.to_string();
    let mut current = std::error::Error::source(e);
    while let Some(err) = current {
        let text = err.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        current = err.source();
    }
    out
}

// ---------------------------------------------------------------------------
// The skip gate
// ---------------------------------------------------------------------------

/// Install the process-default rustls provider (aws-lc): reqwest's
/// `rustls-no-provider` unification makes EVERY default client build in the
/// workspace panic without one (testcontainers' readiness probes
/// included). Idempotent; an already-installed provider is respected.
pub fn ensure_crypto_provider() {
    // The ONE canonical provider, never a second construction.
    seaworthy_crypto::install_default_tls_provider();
}

/// What the gate does with a probe under a mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Run,
    Skip(String),
    Fail(String),
}

/// The pure gate decision (matrix-tested).
pub(crate) fn decide(probe: &Probe, mode: RequiredMode) -> Decision {
    match (probe, mode) {
        (Probe::Ready, _) => Decision::Run,
        (Probe::Absent(reason), RequiredMode::Always) => Decision::Fail(format!(
            "{reason} — and {}=1 (containers are required)",
            crate::REQUIRED_ENV
        )),
        (Probe::Unusable(reason), RequiredMode::Always) => Decision::Fail(format!(
            "{reason} — and {}=1 (containers are required)",
            crate::REQUIRED_ENV
        )),
        (Probe::Unusable(reason), RequiredMode::Auto) => Decision::Fail(format!(
            "{reason}\n  A docker daemon/socket EXISTS but is unusable — that is a \
             misconfiguration, not a skip. Fix it, or set {}=0 \
             to skip the container suites explicitly.",
            crate::REQUIRED_ENV
        )),
        (Probe::Absent(reason), RequiredMode::Auto) => Decision::Skip(format!(
            "{reason} — container tests SKIP \
             (set {}=1 to make this a hard failure)",
            crate::REQUIRED_ENV
        )),
        (probe, RequiredMode::Never) => Decision::Skip(format!(
            "{} — container tests SKIP because {}=0",
            probe.reason(),
            crate::REQUIRED_ENV
        )),
    }
}

/// The skip gate every container suite starts with: `true` when tests may
/// run, `false` when the caller must return early (skip announced on
/// stderr, once per process). Panics, naming the cause, when the
/// three-state contract says so (see the module docs). On a `Ready`
/// daemon the first call per process also sweeps containers leaked by
/// dead test processes ([`crate::launch`]).
pub async fn docker_or_skip() -> bool {
    ensure_crypto_provider();
    let mode = required_mode();
    match decide(&probe().await, mode) {
        Decision::Run => {
            crate::launch::sweep_once().await;
            true
        }
        Decision::Fail(message) => panic!("seaworthy-test-support: {message}"),
        Decision::Skip(message) => {
            if !NOTICED.swap(true, Ordering::Relaxed) {
                eprintln!("seaworthy-test-support: {message}");
            }
            false
        }
    }
}

/// The compiled-out-suite guard: a container suite hidden behind a cargo
/// feature compiles to NOTHING without it, which no skip gate can see.
/// Each such suite carries a sibling test, gated on the feature's ABSENCE,
/// that calls this: under `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` it FAILS
/// naming the build flag; otherwise it announces the gap on stderr.
pub fn assert_suite_compiled_in(suite: &str, enable_with: &str) {
    let message = format!(
        "the container suite `{suite}` is COMPILED OUT of this build — its tests do not \
         exist, so nothing ran; build with {enable_with}"
    );
    assert!(
        !required(),
        "seaworthy-test-support: {message} ({}=1 forbids a silently missing suite)",
        crate::REQUIRED_ENV
    );
    eprintln!("seaworthy-test-support: {message}");
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, time::Duration};

    use super::{DaemonAddr, Decision, DockerEnv, Probe, RequiredMode, decide};

    #[tokio::test]
    async fn detection_never_panics() {
        // On a docker host this is true, elsewhere false — both are fine;
        // the contract is "answers, never panics".
        let _ = super::docker_available().await;
    }

    fn scratch(tag: &str) -> PathBuf {
        // A socket's path must fit sockaddr_un (104 bytes on macOS), which
        // macOS's per-user temporary directory alone nearly fills.
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let dir = base.join(format!(
            "sw-tc-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn env_with_host(host: &str) -> DockerEnv {
        DockerEnv {
            docker_host: Some(host.to_string()),
            ..DockerEnv::default()
        }
    }

    /// A socket that EXISTS but denies us (mode 000: the shape of a
    /// `root:docker 0660` socket for a user outside the group) is
    /// `Unusable` naming EACCES and the fix, never the missing-daemon skip.
    #[tokio::test]
    async fn an_eacces_socket_is_unusable_and_names_the_fix() {
        let dir = scratch("eacces");
        let path = dir.join("docker.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::os::unix::net::UnixStream::connect(&path).is_ok() {
            eprintln!("running as root: mode 000 does not deny us — nothing to pin");
            return;
        }
        let probe = super::probe_env(
            &env_with_host(&format!("unix://{}", path.display())),
            Duration::from_secs(5),
        )
        .await;
        let Probe::Unusable(reason) = &probe else {
            panic!("an EACCES socket must be Unusable, got {probe:?}");
        };
        assert!(reason.contains("ermission denied"), "{reason}");
        assert!(reason.contains("setfacl"), "names the fix: {reason}");
        assert!(
            matches!(decide(&probe, RequiredMode::Auto), Decision::Fail(_)),
            "auto mode FAILS on a present-but-unusable daemon"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A socket file with no listener (a stale socket after the daemon
    /// stopped) exists — `Unusable`, naming the refusal.
    #[tokio::test]
    async fn a_stale_socket_is_unusable() {
        let dir = scratch("stale");
        let path = dir.join("docker.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).expect("bind"));
        let probe = super::probe_env(
            &env_with_host(&format!("unix://{}", path.display())),
            Duration::from_secs(5),
        )
        .await;
        let Probe::Unusable(reason) = &probe else {
            panic!("a stale socket must be Unusable, got {probe:?}");
        };
        assert!(reason.contains("refused"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No socket at the configured path: the one skip case.
    #[tokio::test]
    async fn a_missing_socket_is_absent() {
        let dir = scratch("missing");
        let probe = super::probe_env(
            &env_with_host(&format!("unix://{}", dir.join("nope.sock").display())),
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(probe, Probe::Absent(_)), "{probe:?}");
        assert!(matches!(
            decide(&probe, RequiredMode::Auto),
            Decision::Skip(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nothing configured, no candidate socket anywhere: `Absent`, naming
    /// every path tried.
    #[test]
    fn no_host_and_no_candidate_socket_is_absent() {
        let dir = scratch("nocand");
        let env = DockerEnv {
            home: Some(dir.join("home")),
            xdg_runtime_dir: Some(dir.join("run")),
            ..DockerEnv::default()
        };
        match super::resolve(&env) {
            DaemonAddr::Unix(path) => {
                // This host has /var/run/docker.sock — the first
                // candidate wins, exactly testcontainers' order.
                assert_eq!(path, PathBuf::from("/var/run/docker.sock"));
            }
            DaemonAddr::None { tried } => {
                assert_eq!(tried.len(), 4, "{tried:?}");
            }
            other => panic!("unexpected {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// testcontainers' fallback sockets (Docker Desktop on Linux, rootless)
    /// are probed in its order: a probe trying only `/var/run/docker.sock`
    /// would skip where testcontainers works.
    #[test]
    fn candidate_sockets_follow_testcontainers_order() {
        let env = DockerEnv {
            home: Some(PathBuf::from("/home/u")),
            xdg_runtime_dir: Some(PathBuf::from("/run/user/1000")),
            ..DockerEnv::default()
        };
        assert_eq!(
            env.candidate_sockets(),
            vec![
                PathBuf::from("/var/run/docker.sock"),
                PathBuf::from("/run/user/1000/.docker/run/docker.sock"),
                PathBuf::from("/home/u/.docker/run/docker.sock"),
                PathBuf::from("/home/u/.docker/desktop/docker.sock"),
            ]
        );
        // A found fallback resolves to it.
        let dir = scratch("fallback");
        let sock = dir.join(".docker/run/docker.sock");
        std::fs::create_dir_all(sock.parent().expect("parent")).expect("dirs");
        std::fs::write(&sock, "").expect("placeholder");
        let env = DockerEnv {
            xdg_runtime_dir: Some(dir.clone()),
            ..DockerEnv::default()
        };
        if !std::path::Path::new("/var/run/docker.sock").exists() {
            assert_eq!(super::resolve(&env), DaemonAddr::Unix(sock));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unsupported schemes and TLS-without-certs are `Unusable` with the
    /// cause, never a skip.
    #[tokio::test]
    async fn unsupported_schemes_and_certless_tls_are_unusable() {
        let probe =
            super::probe_env(&env_with_host("ssh://build-box"), Duration::from_secs(1)).await;
        let Probe::Unusable(reason) = &probe else {
            panic!("{probe:?}");
        };
        assert!(reason.contains("ssh://"), "{reason}");

        let env = DockerEnv {
            docker_host: Some("tcp://127.0.0.1:2376".into()),
            tls_verify: Some("1".into()),
            ..DockerEnv::default()
        };
        let probe = super::probe_env(&env, Duration::from_secs(1)).await;
        let Probe::Unusable(reason) = &probe else {
            panic!("{probe:?}");
        };
        assert!(reason.contains("DOCKER_CERT_PATH"), "{reason}");
    }

    /// testcontainers' TLS parse is `DOCKER_TLS_VERIFY == "1"`: a probe
    /// using `!= "0"` would disagree on e.g. `true`.
    #[test]
    fn tls_verify_parses_like_testcontainers() {
        for (value, tls) in [
            (Some("1"), true),
            (Some("true"), false),
            (Some("0"), false),
            (None, false),
        ] {
            let env = DockerEnv {
                docker_host: Some("tcp://docker:2375".into()),
                tls_verify: value.map(str::to_string),
                ..DockerEnv::default()
            };
            let DaemonAddr::Tcp { tls: got, .. } = super::resolve(&env) else {
                panic!("tcp");
            };
            assert_eq!(got, tls, "DOCKER_TLS_VERIFY={value:?}");
        }
    }

    /// A refused TCP daemon (explicitly configured) is `Unusable`.
    #[tokio::test]
    async fn a_refused_tcp_daemon_is_unusable() {
        // Bind then drop: the port is (almost certainly) closed.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let probe = super::probe_env(
            &env_with_host(&format!("tcp://127.0.0.1:{port}")),
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(probe, Probe::Unusable(_)), "{probe:?}");
    }

    /// A daemon that accepts but never answers is `Unusable` at the ping
    /// budget, never a "no daemon" skip.
    #[tokio::test]
    async fn a_silent_daemon_times_out_as_unusable() {
        let dir = scratch("silent");
        let path = dir.join("docker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let _hold = std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(4).collect();
            std::thread::sleep(Duration::from_secs(3));
            drop(held);
        });
        let probe = super::probe_env(
            &env_with_host(&format!("unix://{}", path.display())),
            Duration::from_millis(500),
        )
        .await;
        let Probe::Unusable(reason) = &probe else {
            panic!("{probe:?}");
        };
        assert!(reason.contains("did not answer a ping"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The three-state matrix.
    #[test]
    fn the_gate_decision_matrix() {
        let absent = Probe::Absent("gone".into());
        let unusable = Probe::Unusable("EACCES".into());
        use RequiredMode::{Always, Auto, Never};
        for mode in [Auto, Always, Never] {
            assert_eq!(decide(&Probe::Ready, mode), Decision::Run);
        }
        assert!(matches!(decide(&absent, Auto), Decision::Skip(m) if m.contains("gone")));
        assert!(matches!(decide(&unusable, Auto), Decision::Fail(m) if m.contains("EACCES")));
        assert!(matches!(decide(&absent, Always), Decision::Fail(m) if m.contains("gone")));
        assert!(matches!(decide(&unusable, Always), Decision::Fail(m) if m.contains("EACCES")));
        assert!(matches!(decide(&absent, Never), Decision::Skip(m) if m.contains("gone")));
        assert!(matches!(decide(&unusable, Never), Decision::Skip(m) if m.contains("EACCES")));
    }

    #[test]
    fn the_required_knob_is_three_state_and_loud() {
        assert_eq!(RequiredMode::parse(None), Ok(RequiredMode::Auto));
        assert_eq!(RequiredMode::parse(Some("")), Ok(RequiredMode::Auto));
        for v in ["1", "true", "TRUE", "yes", "on"] {
            assert_eq!(
                RequiredMode::parse(Some(v)),
                Ok(RequiredMode::Always),
                "{v}"
            );
        }
        for v in ["0", "false", "no", "off"] {
            assert_eq!(RequiredMode::parse(Some(v)), Ok(RequiredMode::Never), "{v}");
        }
        let err = RequiredMode::parse(Some("maybe")).expect_err("malformed");
        assert!(err.contains("\"maybe\""), "{err}");
    }

    /// `tcp://[::1]:2375` names host `::1` (a naive `':'` split answers
    /// `"["`).
    #[test]
    fn docker_host_parsing_is_bracket_aware() {
        let cases = [
            ("tcp://[::1]:2375", "::1", Some(2375)),
            ("tcp://docker:2375", "docker", Some(2375)),
            ("tcp://10.0.0.5:2376/", "10.0.0.5", Some(2376)),
            ("http://build-box", "build-box", None),
        ];
        for (value, host, port) in cases {
            let DaemonAddr::Tcp {
                host: got,
                port: got_port,
                ..
            } = super::parse_docker_host(value, false)
            else {
                panic!("{value} must parse as tcp");
            };
            assert_eq!(got, host, "{value}");
            assert_eq!(got_port, port, "{value}");
        }
        assert_eq!(
            super::parse_docker_host("unix:///custom/docker.sock", false),
            DaemonAddr::Unix(PathBuf::from("/custom/docker.sock"))
        );
        assert!(super::parse_docker_host("tcp://[::1]:2375", false).is_loopback_tcp());
        assert!(super::parse_docker_host("tcp://localhost:2375", false).is_loopback_tcp());
        assert!(!super::parse_docker_host("tcp://docker:2375", false).is_loopback_tcp());
    }

    /// The missing-feature guard passes (announcing) outside REQUIRED.
    #[test]
    fn the_compiled_out_guard_is_quiet_unless_required() {
        if super::required() {
            assert!(
                std::panic::catch_unwind(|| super::assert_suite_compiled_in("x", "--features y"))
                    .is_err()
            );
        } else {
            super::assert_suite_compiled_in("x", "--features y");
        }
    }
}
