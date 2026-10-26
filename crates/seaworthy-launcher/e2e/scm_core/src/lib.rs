//! The Windows lab's service, as a product's core: the `scm` launcher and
//! these cores, laid out and registered by the seaworthy CLI's MSI
//! (seaworthy.toml beside the launcher: `[product.scm]`, the SCM suite's
//! service, and `[product.agent]`, the update lane's). It runs
//! seaworthy-service's run loop (`run_windows_service`: the SCM dispatcher,
//! the status protocol, the console fallback) and asks for updates through
//! seaworthy-updater's request API. `scripts/windows-scm-e2e.ps1` drives it
//! (the version-gate stub and the lifecycle commands are seaworthy-service's
//! `windows_scm_e2e` example); docs/testing-windows.md has the lanes.
//!
//! ```text
//! scm version                         this build's version (1.0.0)
//! scm target-triple                   seaworthy_updater::TARGET_TRIPLE
//! scm fips                            "fips=<true|false>" (seaworthy_crypto::is_fips)
//! scm run --name <svc> [--state-dir <dir>]
//!                                     THE SERVICE (the MSI's launch arguments)
//! ```
//!
//! The state directory defaults to the MSI's: the launcher is installed as
//! `%ProgramFiles%\<Vendor>\<Directory>\scm.exe`, and the MSI creates
//! `%ProgramData%\<Vendor>\<Directory>\state`, which the service's account
//! may modify.
//!
//! # The version gate, simulated
//!
//! A real product's server checks the client's version in its own
//! protocol; this fixture keeps the transport out of the SCM test and asks
//! the stub instead: `GET /required` answers the version the "server"
//! demands (404 = no demand). A demand for another version is a version
//! rejection, handed to `seaworthy_updater::UpdateRequester` (at connect
//! and inside the running service), and the service KEEPS RUNNING: a
//! service never exits to update. The SCM product ships no update helper,
//! so starting `<name>-update` fails and the request logs that failure:
//! the evidence the script asserts on.
//!
//! * **Connect** (the run loop's init, raced against STOP): the gate,
//!   retried forever ("server not up yet": 0.5 s doubling to 5 s; after a
//!   rejection, 5 s).
//! * **The body**: two loops every `poll_ms`. The gate loop asks the stub
//!   again (a rejection asks for an update, at most once per minute); the
//!   control loop writes the heartbeat and acts on control files.
//!
//! # Test-controlled behaviors
//!
//! `run` reads `<state-dir>\service.conf` (`key=value` lines): `stub_addr`
//! (`127.0.0.1:<port>`), `poll_ms`, `gate` (`on` default; `off` = no
//! version gate, no stub needed). Without the file (the MSI starts the
//! service as it installs it, before the suite writes one) the gate is off.
//! One-shot commands are files in `<state-dir>\control\` the running
//! service CONSUMES (deletes) when it acts, so the SCM-restarted process
//! runs normally:
//!
//! * `fatal` — the body ends `Outcome::Fatal`: the run loop reports
//!   `Stopped` + the service-specific `EXIT_CODE_FATAL`, and the SCM's
//!   non-crash failure actions restart it.
//! * `panic` — the body panics: the run loop reports the same
//!   (`RunError::TaskPanicked`).
//! * `abort` — `std::process::abort()`: a real crash, no `Stopped` report;
//!   the SCM's crash recovery restarts it.
//!
//! Evidence files (all in the state directory): `starts.log` (one line per
//! process start: pid, version, user and SID, exe, the FIPS posture),
//! `exits.log` (one line per exit the process itself saw: pid, code, the
//! `ServiceExit` or `RunError` text), `status.txt` (the latest heartbeat),
//! `logs\service-<pid>.log` (every `tracing` event of the process, the
//! crates' own included).

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use seaworthy_service::{Outcome, RunError, ServiceExit, ShutdownRx};
use seaworthy_updater::{Product, ServiceNames, UpdateRequester};

mod line_log;

use line_log::{line_safe, unix_ms};

/// This build's version: what the simulated gate compares the server's
/// demand with.
const VERSION: &str = "1.0.0";
/// Exit code for usage errors (distinct from the service's 1).
const EXIT_USAGE: i32 = 2;
/// Exit code for a failed command.
const EXIT_FAILED: i32 = 3;
/// The connect's backoff while the gate can't be reached.
const RETRY_INITIAL: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(5);
/// How long a refused connect waits before it asks the gate again.
const MISMATCH_RETRY: Duration = Duration::from_secs(5);
/// At most one update request per this interval: the suite counts exactly
/// one in each of its windows.
const REQUEST_INTERVAL: Duration = Duration::from_secs(60);

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{}", usage());
        return EXIT_USAGE;
    };
    let flags = match Flags::parse(rest) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("acme-e2e-error: Usage: {error}\n{}", usage());
            return EXIT_USAGE;
        }
    };
    let result = match command.as_str() {
        "version" => {
            println!("{VERSION}");
            Ok(())
        }
        "target-triple" => {
            println!("{}", seaworthy_updater::TARGET_TRIPLE);
            Ok(())
        }
        "fips" => {
            println!("fips={}", fips_posture());
            Ok(())
        }
        "run" => cmd_run(&flags),
        other => {
            // Never start anything on an unexpected invocation.
            eprintln!(
                "acme-e2e-error: Usage: unknown command {other:?}\n{}",
                usage()
            );
            return EXIT_USAGE;
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("acme-e2e-error: {error}");
            EXIT_FAILED
        }
    }
}

seaworthy_launcher::core_main!(main);

fn usage() -> &'static str {
    "usage: scm <version|target-triple|fips|run> [--flag value]...\n\
     (see the docs of crates/seaworthy-launcher/e2e/scm_core/src/lib.rs)"
}

// ---------------------------------------------------------------------------
// Flags: `--name value` pairs.

struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut out = Vec::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            if !flag.starts_with("--") {
                return Err(format!("unexpected argument {flag:?}"));
            }
            let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
            out.push((flag.clone(), value.clone()));
        }
        Ok(Self(out))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
    }

    fn require(&self, name: &str) -> Result<&str, BoxError> {
        self.get(name)
            .ok_or_else(|| format!("Usage: missing required flag {name}").into())
    }
}

// ---------------------------------------------------------------------------

/// Append one line to `path` (created if missing), flushed.
fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    file.flush()
}

/// A minimal HTTP/1.1 GET against the loopback stub (the fixture carries no
/// HTTP client of its own).
fn http_get(addr: &str, path: &str) -> io::Result<(u16, Vec<u8>)> {
    let socket = addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad stub address"))?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.take(64 * 1024).read_to_end(&mut response)?;
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header terminator"))?;
    let (head, body) = response.split_at(split);
    let status = String::from_utf8_lossy(head)
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status code"))?;
    Ok((status, body.get(4..).unwrap_or_default().to_vec()))
}

// ---------------------------------------------------------------------------
// The service

#[derive(Clone, Debug)]
struct ServiceConf {
    /// The stub's address; `None` exactly when the gate is off.
    stub_addr: Option<String>,
    poll: Duration,
}

impl ServiceConf {
    /// `service.conf`, or the gate off without one (the MSI starts the
    /// service as it installs it, before the suite configures it).
    fn load(path: &Path) -> Result<Self, BoxError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    stub_addr: None,
                    poll: Duration::from_millis(1000),
                });
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display()).into()),
        };
        let mut stub_addr = None;
        let mut poll = Duration::from_millis(1000);
        let mut gate = true;
        // Windows PowerShell 5.1's `Out-File -Encoding utf8` writes a BOM:
        // tolerate it.
        for line in text.trim_start_matches('\u{feff}').lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("service.conf: malformed line {line:?}"))?;
            match key.trim() {
                "stub_addr" => stub_addr = Some(value.trim().to_owned()),
                "poll_ms" => poll = Duration::from_millis(value.trim().parse()?),
                "gate" => {
                    gate = match value.trim() {
                        "on" => true,
                        "off" => false,
                        other => {
                            return Err(format!("service.conf: gate {other:?} (on|off)").into());
                        }
                    }
                }
                other => return Err(format!("service.conf: unknown key {other:?}").into()),
            }
        }
        if poll.is_zero() {
            return Err("service.conf: poll_ms must be at least 1".into());
        }
        if gate && stub_addr.is_none() {
            return Err("service.conf: stub_addr is required while the gate is on".into());
        }
        Ok(Self {
            stub_addr: stub_addr.filter(|_| gate),
            poll,
        })
    }
}

/// The app error the run loop is generic over (its `Debug` form is what
/// `exits.log` records for a fatal exit).
#[derive(Debug)]
enum AppError {
    /// The (simulated) version gate refused us.
    Mismatch { local: String, remote: String },
    /// The stub could not be asked (the "server not up yet" case: retried).
    Gate(String),
    /// A test-injected failure.
    Injected(&'static str),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { local, remote } => {
                write!(f, "version gate: running {local}, server requires {remote}")
            }
            Self::Gate(detail) => write!(f, "version gate unreachable: {detail}"),
            Self::Injected(what) => write!(f, "injected failure: {what}"),
        }
    }
}

/// Everything the service's loops share.
#[derive(Clone)]
struct Service {
    state_dir: PathBuf,
    conf: ServiceConf,
    requester: Arc<UpdateRequester>,
}

/// Ask the stub what the "server" requires; `Err(Mismatch)` when it differs
/// from this build's version.
async fn check_gate(stub_addr: &str) -> Result<(), AppError> {
    let stub_addr = stub_addr.to_owned();
    let answer = tokio::task::spawn_blocking(move || http_get(&stub_addr, "/required"))
        .await
        .map_err(|e| AppError::Gate(e.to_string()))?
        .map_err(|e| AppError::Gate(e.to_string()))?;
    match answer {
        (200, body) => {
            let remote = String::from_utf8_lossy(&body).trim().to_owned();
            if remote.is_empty() || remote == VERSION {
                Ok(())
            } else {
                Err(AppError::Mismatch {
                    local: VERSION.to_owned(),
                    remote,
                })
            }
        }
        (404, _) => Ok(()),
        (status, _) => Err(AppError::Gate(format!("HTTP {status}"))),
    }
}

/// Hands a version rejection to the update requester, off the runtime's
/// threads (on Windows the request is `StartServiceW`, which may block).
/// The requester logs what it did, and asks at most once per interval.
async fn request_update(requester: &Arc<UpdateRequester>, local: String, remote: String) {
    let requester = Arc::clone(requester);
    let asked =
        tokio::task::spawn_blocking(move || requester.on_version_mismatch(&local, &remote)).await;
    if let Err(error) = asked {
        tracing::error!("the update request's task failed: {error}");
    }
}

/// Consume a one-shot control command (the delete IS the claim).
fn take_control(state_dir: &Path, command: &str) -> bool {
    fs::remove_file(state_dir.join("control").join(command)).is_ok()
}

/// `seaworthy_crypto::is_fips()`, with the process-default provider
/// installed first, since the posture requires one.
fn fips_posture() -> bool {
    let _ = seaworthy_crypto::install_default_tls_provider();
    seaworthy_crypto::is_fips()
}

/// The process's user and SID as `whoami /user` reports them (the token the
/// SCM started us with).
fn whoami() -> String {
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let whoami = Path::new(&system_root).join("System32").join("whoami.exe");
        match std::process::Command::new(whoami)
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
        {
            // `"nt service\acme-e2e","S-1-5-80-…"`
            Ok(output) => {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut fields = text.trim().split(',').map(|f| f.trim_matches('"'));
                let user = fields.next().unwrap_or("?").to_owned();
                let sid = fields.next().unwrap_or("?").to_owned();
                format!("user={}\tsid={}", line_safe(&user), line_safe(&sid))
            }
            Err(error) => format!(
                "user=?\tsid=?\twhoami_error={}",
                line_safe(&error.to_string())
            ),
        }
    }
    #[cfg(not(windows))]
    {
        "user=?\tsid=n/a".to_owned()
    }
}

/// The MSI's state directory for the installed launcher: the launcher is
/// `%ProgramFiles%\<Vendor>\<Directory>\scm.exe`, the state directory
/// `%ProgramData%\<Vendor>\<Directory>\state`.
fn default_state_dir() -> Result<PathBuf, BoxError> {
    let exe = std::env::current_exe()?;
    let install_dir = exe
        .parent()
        .ok_or("no --state-dir, and the launcher has no directory")?;
    let directory = install_dir
        .file_name()
        .ok_or("no --state-dir, and the launcher's directory has no name")?;
    let vendor = install_dir
        .parent()
        .and_then(Path::file_name)
        .ok_or("no --state-dir, and the launcher's directory has no vendor directory above it")?;
    let program_data =
        std::env::var_os("ProgramData").ok_or("no --state-dir, and %ProgramData% is not set")?;
    Ok(PathBuf::from(program_data)
        .join(vendor)
        .join(directory)
        .join("state"))
}

fn cmd_run(flags: &Flags) -> Result<(), BoxError> {
    let name = flags.require("--name")?.to_owned();
    let state_dir = match flags.get("--state-dir") {
        Some(dir) => PathBuf::from(dir),
        None => default_state_dir()?,
    };
    let logs = state_dir.join("logs");
    fs::create_dir_all(&logs)?;
    fs::create_dir_all(state_dir.join("control"))?;
    let pid = std::process::id();
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs.join(format!("service-{pid}.log")))?;
    line_log::install(vec![Box::new(log_file)]);

    let conf = ServiceConf::load(&state_dir.join("service.conf"))?;
    let exe = std::env::current_exe()?;
    append_line(
        &state_dir.join("starts.log"),
        &format!(
            "start\tpid={pid}\tversion={VERSION}\t{}\texe={}\tfips={}\tunix_ms={}",
            whoami(),
            line_safe(&exe.display().to_string()),
            fips_posture(),
            unix_ms()
        ),
    )?;
    tracing::info!(version = VERSION, exe = %exe.display(), "acme-e2e service starting");

    // The product the fixture asks updates for (its policy key,
    // HKLM\SOFTWARE\Acme\E2e, is absent: `auto`). The SCM product ships no
    // helper, so a request fails and is logged (the script's evidence).
    let product = Product::new("Acme", "e2e", "E2e", "stable")?.with_service(ServiceNames {
        name: name.clone(),
        state_directory: None,
    })?;
    let service = Service {
        state_dir: state_dir.clone(),
        conf,
        requester: Arc::new(UpdateRequester::new(product).interval(REQUEST_INTERVAL)),
    };
    let result = run(&name, service);

    // The exit the PROCESS saw: the script cross-checks it against the
    // SCM's recorded exit code.
    let (code, reason) = match &result {
        Ok(exit) => (exit.code(), format!("{exit:?}")),
        Err(error) => (error.exit_code(), error.to_string()),
    };
    tracing::info!(code, reason = %reason, "acme-e2e service exiting");
    let _ = append_line(
        &state_dir.join("exits.log"),
        &format!(
            "exit\tpid={pid}\tversion={VERSION}\tcode={code}\treason={}\tunix_ms={}",
            line_safe(&reason),
            unix_ms()
        ),
    );
    std::process::exit(code);
}

/// The run loop: the SCM dispatcher on Windows (the console shape when not
/// started by the SCM), the signal loop elsewhere.
fn run(name: &str, service: Service) -> Result<ServiceExit, RunError<AppError>> {
    let init = connect(service.clone());
    let body = move |(), shutdown: ShutdownRx| serve(service, shutdown);
    #[cfg(windows)]
    {
        seaworthy_service::run_windows_service(name, init, body)
    }
    #[cfg(not(windows))]
    {
        seaworthy_service::run_service(name, init, body)
    }
}

/// Init: the simulated version gate, retried forever ("server not up
/// yet"); a demand for another version asks for an update and retries.
/// The run loop races it against STOP.
async fn connect(service: Service) -> Outcome<(), AppError> {
    let Some(stub) = service.conf.stub_addr.clone() else {
        return Outcome::Success(());
    };
    let mut backoff = RETRY_INITIAL;
    loop {
        match check_gate(&stub).await {
            Ok(()) => {
                tracing::info!("connected: the version gate accepts {VERSION}");
                return Outcome::Success(());
            }
            Err(AppError::Mismatch { local, remote }) => {
                tracing::warn!(
                    "connect refused: the server requires {} (this is {local})",
                    line_safe(&remote)
                );
                request_update(&service.requester, local, remote).await;
                tokio::time::sleep(MISMATCH_RETRY).await;
                backoff = RETRY_INITIAL;
            }
            Err(error) => {
                tracing::warn!(
                    "connect failed ({}); retrying in {} ms",
                    line_safe(&error.to_string()),
                    backoff.as_millis()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RETRY_MAX);
            }
        }
    }
}

/// The body: the gate loop and the control loop, until STOP (a clean
/// exit) or the control loop's injected failure. Both loops run inside
/// this future, on the run loop's thread, so a panic in either reaches
/// the run loop.
async fn serve(service: Service, mut shutdown: ShutdownRx) -> Outcome<(), AppError> {
    let stop = async move {
        // A closed channel (no handler holds the sender) means no stop can
        // come.
        if shutdown.recv().await.is_none() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        () = stop => {
            tracing::info!("stop requested");
            Outcome::Success(())
        }
        outcome = control_loop(&service) => outcome,
        () = gate_loop(&service) => Outcome::Success(()),
    }
}

/// The heartbeat and the control files, every `poll_ms`.
async fn control_loop(service: &Service) -> Outcome<(), AppError> {
    let state_dir = &service.state_dir;
    let mut tick = tokio::time::interval(service.conf.poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let pid = std::process::id();
        let _ = fs::write(
            state_dir.join("status.txt"),
            format!(
                "pid={pid}\tversion={VERSION}\theartbeat_unix_ms={}\n",
                unix_ms()
            ),
        );
        if take_control(state_dir, "abort") {
            let _ = append_line(
                &state_dir.join("exits.log"),
                &format!(
                    "exit\tpid={pid}\tversion={VERSION}\tcode=abort\treason=injected abort\tunix_ms={}",
                    unix_ms()
                ),
            );
            tracing::error!("injected abort: crashing without a Stopped report");
            std::process::abort();
        }
        if take_control(state_dir, "panic") {
            tracing::error!("injected panic");
            panic!("acme-e2e injected panic");
        }
        if take_control(state_dir, "fatal") {
            tracing::error!("injected fatal failure");
            return Outcome::Fatal(AppError::Injected("fatal"));
        }
    }
}

/// The running service's version gate, every `poll_ms` (never returns; with
/// the gate off it waits forever). A rejection asks for an update and the
/// service keeps running; an unreachable stub is logged.
async fn gate_loop(service: &Service) {
    let Some(stub) = service.conf.stub_addr.as_deref() else {
        return std::future::pending().await;
    };
    let mut tick = tokio::time::interval(service.conf.poll);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match check_gate(stub).await {
            Ok(()) => {}
            Err(AppError::Mismatch { local, remote }) => {
                request_update(&service.requester, local, remote).await;
            }
            Err(error) => tracing::warn!("{}", line_safe(&error.to_string())),
        }
    }
}
