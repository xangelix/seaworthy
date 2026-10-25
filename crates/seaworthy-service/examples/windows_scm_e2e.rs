//! The Windows SCM end-to-end fixture's tool: the version-gate stub and
//! the lifecycle commands `scripts/windows-scm-e2e.ps1` drives on a Windows
//! machine with a real Service Control Manager (a GitHub-hosted
//! `windows-2025` runner); the script's header says what the lane needs and
//! what it proves.
//!
//! The service under test is a product: an SCM fixture service (a launcher
//! and its per-CPU-level cores) that the seaworthy CLI's MSI lays out and
//! registers as the `acme-e2e` service. This tool drives it through the
//! crate's WindowsBackend (never raw sc.exe).
//!
//! ```text
//! windows_scm_e2e version                          this build's version (1.0.0)
//! windows_scm_e2e target-triple                    the target this tool was built for
//! windows_scm_e2e fips                             "fips=<true|false>" (seaworthy_crypto::is_fips)
//! windows_scm_e2e serve --root <dir> --log <file> --ready-file <file>
//!                       [--port <n>] [--lifetime-secs <s>]
//!                                                  the version-gate stub (loopback)
//! # Windows only — the crate's WindowsBackend:
//! windows_scm_e2e start|stop|status --name <svc> [--timeout-secs <s>]
//! ```
//!
//! # The version gate, simulated
//!
//! A real product's server checks the client's version in its own
//! protocol; the fixture keeps the transport out of the SCM test and
//! simulates the gate with this stub: `GET /required` answers the version
//! the "server" demands (404 = no demand), and the service compares it with
//! its own.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ---------------------------------------------------------------------------

/// This build's version (the service's is `scm_core`'s, the same).
const VERSION: &str = "1.0.0";
/// Exit code for usage errors (distinct from the service's 1).
const EXIT_USAGE: u8 = 2;
/// Exit code for a failed CLI operation (start/stop/…).
const EXIT_FAILED: u8 = 3;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{}", usage());
        return ExitCode::from(EXIT_USAGE);
    };
    let flags = match Flags::parse(rest) {
        Ok(flags) => flags,
        Err(error) => {
            eprintln!("e2e-error: Usage: {error}\n{}", usage());
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let result = match command.as_str() {
        "version" => {
            println!("{VERSION}");
            Ok(())
        }
        "target-triple" => {
            println!("{}", target_triple());
            Ok(())
        }
        "fips" => {
            println!("fips={}", fips_posture());
            Ok(())
        }
        "serve" => cmd_serve(&flags),
        #[cfg(windows)]
        "start" | "stop" | "status" => scm::command(command, &flags),
        other => {
            // Never start anything on an unexpected invocation.
            eprintln!("e2e-error: Usage: unknown command {other:?}\n{}", usage());
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e-error: {error}");
            ExitCode::from(EXIT_FAILED)
        }
    }
}

fn usage() -> &'static str {
    "usage: windows_scm_e2e <version|target-triple|fips|serve|start|stop|status> [--flag value]...\n\
     (see the module docs of crates/seaworthy-service/examples/windows_scm_e2e.rs)"
}

// ---------------------------------------------------------------------------
// Flags: `--name value` pairs.

struct Flags(Vec<(String, Option<String>)>);

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut out = Vec::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            if !flag.starts_with("--") {
                return Err(format!("unexpected argument {flag:?}"));
            }
            let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
            out.push((flag.clone(), Some(value.clone())));
        }
        Ok(Self(out))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.as_deref())
    }

    fn require(&self, name: &str) -> Result<&str, BoxError> {
        self.get(name)
            .ok_or_else(|| format!("Usage: missing required flag {name}").into())
    }

    fn number(&self, name: &str, default: u64) -> Result<u64, BoxError> {
        match self.get(name) {
            Some(text) => text
                .parse()
                .map_err(|_| format!("Usage: {name} {text:?} is not a number").into()),
            None => Ok(default),
        }
    }
}

// ---------------------------------------------------------------------------
// The version-gate stub

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// Append one line to `path` (created if missing), flushed.
fn append_line(path: &Path, line: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    file.flush()
}

fn cmd_serve(flags: &Flags) -> Result<(), BoxError> {
    let root = PathBuf::from(flags.require("--root")?);
    let log = PathBuf::from(flags.require("--log")?);
    let ready = PathBuf::from(flags.require("--ready-file")?);
    let port = u16::try_from(flags.number("--port", 0)?)?;
    let lifetime = Duration::from_secs(flags.number("--lifetime-secs", 3 * 60 * 60)?);

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let addr = listener.local_addr()?;
    // A safety net: an orphaned stub never outlives the job by much.
    std::thread::spawn(move || {
        std::thread::sleep(lifetime);
        std::process::exit(0);
    });
    let log = Arc::new(Mutex::new(log));
    // Written LAST: the script waits for this file, so its presence means
    // the listener is accepting.
    fs::write(&ready, format!("{addr}\n"))?;
    eprintln!("serving {} on {addr}", root.display());
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let root = root.clone();
        let log = log.clone();
        std::thread::spawn(move || {
            if let Err(error) = handle_request(stream, &root, &log) {
                eprintln!("request failed: {error}");
            }
        });
    }
    Ok(())
}

fn handle_request(mut stream: TcpStream, root: &Path, log: &Mutex<PathBuf>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut buf)?;
        if read == 0 || head.len() > 16 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..read]);
    }
    let head = String::from_utf8_lossy(&head);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split(['?', '#']).next().unwrap_or("");

    let body = if method != "GET" && method != "HEAD" {
        None
    } else if path == "/required" {
        fs::read(root.join("required.txt"))
            .ok()
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_start_matches('\u{feff}')
                    .trim()
                    .as_bytes()
                    .to_vec()
            })
            .filter(|b| !b.is_empty())
    } else if path.contains("..") || path.contains('\\') || !path.starts_with('/') {
        None
    } else {
        fs::read(root.join(path.trim_start_matches('/'))).ok()
    };
    let (status, reason, body) = match body {
        Some(body) => (200, "OK", body),
        None => (404, "Not Found", b"not found".to_vec()),
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    if method == "GET" {
        stream.write_all(&body)?;
    }
    stream.flush()?;
    let log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    append_line(
        &log,
        &format!("{}\t{method}\t{path}\t{status}\t{}", unix_ms(), body.len()),
    )
}

// ---------------------------------------------------------------------------

/// The target triple this tool was built for, composed from the compiler's
/// `cfg` values (the script asserts the msvc build); `<arch>-unknown-<os>`
/// for a target the list doesn't name.
fn target_triple() -> String {
    let arch = std::env::consts::ARCH;
    let rest = if cfg!(all(windows, target_env = "msvc")) {
        "pc-windows-msvc"
    } else if cfg!(all(windows, target_env = "gnu")) {
        "pc-windows-gnu"
    } else if cfg!(target_vendor = "apple") && cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(all(target_os = "linux", target_env = "gnu")) {
        "unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_env = "musl")) {
        "unknown-linux-musl"
    } else {
        return format!("{arch}-unknown-{}", std::env::consts::OS);
    };
    format!("{arch}-{rest}")
}

/// `seaworthy_crypto::is_fips()` — with the process-default provider installed
/// first, since the posture requires one.
fn fips_posture() -> bool {
    let _ = seaworthy_crypto::install_default_tls_provider();
    seaworthy_crypto::is_fips()
}

// ---------------------------------------------------------------------------
// The SCM lifecycle through the crate's WindowsBackend (never raw sc.exe).

#[cfg(windows)]
mod scm {
    use std::time::Duration;

    use seaworthy_service::{ServiceBackend, ServiceError, backend::windows::WindowsBackend};

    use super::{BoxError, Flags};

    /// Run a lifecycle command; a `ServiceError` is printed with its variant
    /// name first (`e2e-error: StartTimeout: …`) so the script can
    /// assert on the kind.
    pub(super) fn command(command: &str, flags: &Flags) -> Result<(), BoxError> {
        let name = flags.require("--name")?;
        let timeout = Duration::from_secs(flags.number("--timeout-secs", 60)?);
        let backend =
            WindowsBackend::new(name).with_poll_timing(Duration::from_millis(250), timeout);
        let result = match command {
            "start" => backend.start(),
            "stop" => backend.stop(),
            "status" => backend.status().map(|state| match state {
                Some(state) => println!("{state:?}"),
                None => println!("NotInstalled"),
            }),
            _ => unreachable!("dispatched by main"),
        };
        result.map_err(|error| format!("{}: {error}", kind(&error)).into())
    }

    fn kind(error: &ServiceError) -> &'static str {
        match error {
            ServiceError::DoesNotExist => "DoesNotExist",
            ServiceError::StartTimeout => "StartTimeout",
            ServiceError::StopTimeout => "StopTimeout",
            ServiceError::InvalidName(_) => "InvalidName",
            ServiceError::InvalidSpec(_) => "InvalidSpec",
            ServiceError::Io(_) => "Io",
            ServiceError::Platform(_) => "Platform",
        }
    }
}
