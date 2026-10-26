//! The lab server: a release tree and the required-version endpoint, over
//! HTTP/1.1 (plain, or TLS on seaworthy-crypto's provider).
//!
//! - **Files.** `GET` (or `HEAD`) `/<path>` answers the file `<root>/<path>`
//!   ([`crate::request`] decodes and confines the path), `404` when there is
//!   none. The lanes lay out what a static store would publish there: the
//!   signed APT, DNF and pacman repositories, and the update helper's
//!   release tree (`releases/<package>/<channel>/<token>/<target>/`).
//! - **The required-version endpoint.** `GET /_lab/required-version`
//!   answers the version token (`text/plain`, one line): the token given
//!   on the command line, or the contents of a token file read on every
//!   request, so a lane can name another release without a restart. With a
//!   hold, each request first writes the "held" file and waits until the
//!   hold file exists (two minutes at most; then the connection is dropped
//!   unanswered, never answered late).
//!
//! One request per connection (`Connection: close`), a thread per
//! connection (at most [`MAX_CONNECTIONS`] at once), read and write
//! deadlines, and one log line per request on stderr (control characters
//! escaped). Lab machines only: the server binds where it is told, and the
//! lanes bind loopback.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::request::{self, MAX_HEAD_BYTES, Method, Request, Route};
use crate::{LabError, MAX_TOKEN_BYTES};

/// Where the server listens by default (the conformance lane's address).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8470";

/// The longest a held request waits for its release.
pub const HOLD_LIMIT: Duration = Duration::from_secs(120);

/// The most connections served at once; more are closed unanswered.
pub const MAX_CONNECTIONS: usize = 128;

/// How long the server waits for a request head.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one write may block (a package to a slow reader).
const WRITE_TIMEOUT: Duration = Duration::from_secs(300);

/// Where the version token comes from.
#[derive(Clone, Debug)]
pub enum Token {
    /// This token, for the server's life.
    Fixed(String),
    /// This file's contents (whitespace trimmed), read on every request.
    File(PathBuf),
}

/// The required-version endpoint's hold.
#[derive(Clone, Debug)]
pub struct Hold {
    /// Requests wait until this file exists.
    pub until: PathBuf,
    /// Written when a request starts waiting.
    pub held: Option<PathBuf>,
}

/// The TLS certificate chain and key (PEM files).
#[derive(Clone, Debug)]
pub struct TlsFiles {
    /// The chain, leaf first.
    pub cert: PathBuf,
    /// The leaf's private key (PKCS#8, SEC1 or PKCS#1).
    pub key: PathBuf,
}

/// What the server serves, where and how.
#[derive(Clone, Debug)]
pub struct Options {
    /// The release tree's root directory.
    pub root: PathBuf,
    /// The required-version endpoint's token.
    pub token: Token,
    /// The addresses to listen on (`127.0.0.1:8470`, `[::1]:443`); empty
    /// means [`DEFAULT_LISTEN`].
    pub listen: Vec<String>,
    /// The endpoint's hold, if any.
    pub hold: Option<Hold>,
    /// TLS, if any.
    pub tls: Option<TlsFiles>,
    /// A file written once every listener is bound: `ready`, then one
    /// `listen <address>` line per bound address.
    pub ready: Option<PathBuf>,
}

/// What every connection shares.
struct Shared {
    root: PathBuf,
    token: Token,
    hold: Option<Hold>,
    tls: Option<Arc<rustls::ServerConfig>>,
    active: AtomicUsize,
}

/// A bound lab server ([`Server::bind`]), not yet serving.
pub struct Server {
    listeners: Vec<TcpListener>,
    shared: Arc<Shared>,
    ready: Option<PathBuf>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("addrs", &self.local_addrs())
            .field("root", &self.shared.root)
            .field("tls", &self.shared.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Checks `options` and binds every listener.
    ///
    /// # Errors
    /// [`LabError::Invalid`] for a root that isn't a directory or a token
    /// (or token file) that isn't a version token; [`LabError::Tls`] for
    /// an unusable chain or key; [`LabError::Io`] for an address that
    /// can't be bound.
    pub fn bind(options: Options) -> Result<Self, LabError> {
        if !options.root.is_dir() {
            return Err(LabError::Invalid(format!(
                "the root {} is not a directory",
                options.root.display()
            )));
        }
        match &options.token {
            Token::Fixed(token) => check_token(token)?,
            Token::File(path) => {
                read_token_file(path)?;
            }
        }
        let tls = match &options.tls {
            Some(files) => Some(crate::tls::server_config(&files.cert, &files.key)?),
            None => None,
        };
        let addresses = if options.listen.is_empty() {
            vec![DEFAULT_LISTEN.to_owned()]
        } else {
            options.listen.clone()
        };
        let mut listeners = Vec::with_capacity(addresses.len());
        for address in &addresses {
            let listener = TcpListener::bind(address.as_str())
                .map_err(|e| LabError::io(format!("listening on {address}"), e))?;
            listeners.push(listener);
        }
        Ok(Self {
            listeners,
            shared: Arc::new(Shared {
                root: options.root,
                token: options.token,
                hold: options.hold,
                tls,
                active: AtomicUsize::new(0),
            }),
            ready: options.ready,
        })
    }

    /// The bound addresses (a port 0 resolved).
    #[must_use]
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }

    /// Writes the ready file, then serves on background threads; the
    /// bound addresses.
    ///
    /// # Errors
    /// [`LabError::Io`] when the ready file can't be written.
    pub fn spawn(self) -> Result<Vec<SocketAddr>, LabError> {
        let mut addrs = Vec::with_capacity(self.listeners.len());
        for listener in &self.listeners {
            addrs.push(
                listener
                    .local_addr()
                    .map_err(|e| LabError::io("a listener's address", e))?,
            );
        }
        self.write_ready(&addrs)?;
        let protocol = if self.shared.tls.is_some() {
            "https"
        } else {
            "http"
        };
        for (listener, addr) in self.listeners.into_iter().zip(&addrs) {
            eprintln!(
                "seaworthy-lab: serving {} as {protocol}://{addr}/",
                self.shared.root.display()
            );
            let shared = Arc::clone(&self.shared);
            std::thread::Builder::new()
                .name(format!("lab-accept-{addr}"))
                .spawn(move || accept_loop(&listener, &shared))
                .map_err(|e| LabError::io("starting a listener thread", e))?;
        }
        Ok(addrs)
    }

    /// [`spawn`](Self::spawn), then serves until the process ends.
    ///
    /// # Errors
    /// As [`spawn`](Self::spawn).
    pub fn run(self) -> Result<(), LabError> {
        self.spawn()?;
        loop {
            std::thread::park();
        }
    }

    fn write_ready(&self, addrs: &[SocketAddr]) -> Result<(), LabError> {
        let Some(ready) = &self.ready else {
            return Ok(());
        };
        let mut text = String::from("ready\n");
        for addr in addrs {
            text.push_str(&format!("listen {addr}\n"));
        }
        // Whole or absent: written beside, then renamed into place.
        let mut partial = ready.as_os_str().to_owned();
        partial.push(".partial");
        let partial = PathBuf::from(partial);
        std::fs::write(&partial, text).map_err(|e| LabError::io(partial.display(), e))?;
        std::fs::rename(&partial, ready).map_err(|e| LabError::io(ready.display(), e))
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("seaworthy-lab: accept failed: {error}");
                // Out of descriptors, say: never a busy loop.
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if shared.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            shared.active.fetch_sub(1, Ordering::SeqCst);
            eprintln!("seaworthy-lab: {MAX_CONNECTIONS} connections already: closing one");
            continue;
        }
        let shared = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("lab-connection".to_owned())
            .spawn(move || {
                connection(&shared, stream);
                shared.active.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(error) = spawned {
            eprintln!("seaworthy-lab: starting a connection thread failed: {error}");
        }
    }
}

fn connection(shared: &Shared, stream: TcpStream) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "?".to_owned(), |addr| addr.to_string());
    // Best effort: a socket that refuses its options still gets served.
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let result = match &shared.tls {
        Some(config) => match rustls::ServerConnection::new(Arc::clone(config)) {
            Ok(tls) => {
                let mut stream = rustls::StreamOwned::new(tls, stream);
                let result = exchange(shared, &mut stream, &peer);
                // A TLS stream ends with its close_notify.
                stream.conn.send_close_notify();
                let _ = stream.flush();
                linger(&stream.sock);
                result
            }
            Err(error) => Err(io::Error::other(error)),
        },
        None => {
            let mut stream = stream;
            let result = exchange(shared, &mut stream, &peer);
            linger(&stream);
            result
        }
    };
    if let Err(error) = result {
        eprintln!("seaworthy-lab: {peer}: {error}");
    }
}

/// Closes gracefully: the write side first, then whatever the client
/// still sends (a pipelined request, the rest of an oversized head) is
/// read and dropped for a moment, so the close doesn't reset the
/// connection before the client has read the answer.
fn linger(stream: &TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0_u8; 4096];
    let mut drained = 0_usize;
    let mut reader = stream;
    while drained < 64 * 1024 {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => drained = drained.saturating_add(read),
        }
    }
}

/// One request read and answered.
fn exchange<S: Read + Write>(shared: &Shared, stream: &mut S, peer: &str) -> io::Result<()> {
    let mut head = Vec::new();
    let mut buf = [0_u8; 4096];
    let len = loop {
        if let Some(len) = request::head_len(&head) {
            break len;
        }
        if head.len() >= MAX_HEAD_BYTES {
            log(peer, &head, 400, 0);
            return respond(stream, 400, "text/plain", b"request head too long\n");
        }
        let read = stream.read(&mut buf)?;
        if read == 0 {
            // Closed before a whole head (a port probe, a TLS client that
            // gave up): nothing to answer.
            return Ok(());
        }
        head.extend_from_slice(buf.get(..read).unwrap_or_default());
    };
    let head = head.get(..len).unwrap_or_default();
    match request::parse(head) {
        Err(error) => {
            log(peer, head, error.status(), 0);
            respond(
                stream,
                error.status(),
                "text/plain",
                format!("{error}\n").as_bytes(),
            )
        }
        Ok(Request {
            route: Route::RequiredVersion,
            ..
        }) => required_version(shared, stream, peer, head),
        Ok(Request {
            method,
            route: Route::File(relative),
        }) => serve_file(shared, stream, peer, head, method, &relative),
    }
}

fn required_version<S: Write>(
    shared: &Shared,
    stream: &mut S,
    peer: &str,
    head: &[u8],
) -> io::Result<()> {
    if let Some(hold) = &shared.hold {
        if let Some(held) = &hold.held
            && let Err(error) = std::fs::write(held, "held\n")
        {
            eprintln!("seaworthy-lab: writing {}: {error}", held.display());
        }
        eprintln!("seaworthy-lab: {peer}: holding the required-version request");
        let deadline = Instant::now() + HOLD_LIMIT;
        while !hold.until.exists() {
            if Instant::now() >= deadline {
                // Never answered late: a request released by the timeout
                // would pass or fail a case for the wrong reason.
                eprintln!("seaworthy-lab: {peer}: the hold expired; dropping the request");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!("seaworthy-lab: {peer}: request released");
    }
    let token = match &shared.token {
        Token::Fixed(token) => Ok(token.clone()),
        Token::File(path) => read_token_file(path),
    };
    match token {
        Ok(token) => {
            let body = format!("{token}\n");
            log(peer, head, 200, body.len());
            respond(stream, 200, "text/plain; charset=utf-8", body.as_bytes())
        }
        Err(error) => {
            eprintln!("seaworthy-lab: {error}");
            log(peer, head, 503, 0);
            respond(stream, 503, "text/plain", b"no version token\n")
        }
    }
}

fn serve_file<S: Write>(
    shared: &Shared,
    stream: &mut S,
    peer: &str,
    head: &[u8],
    method: Method,
    relative: &Path,
) -> io::Result<()> {
    let path = shared.root.join(relative);
    let opened = File::open(&path).and_then(|file| {
        let metadata = file.metadata()?;
        Ok((file, metadata))
    });
    let (file, metadata) = match opened {
        Ok((file, metadata)) if metadata.is_file() => (file, metadata),
        _ => {
            log(peer, head, 404, 0);
            return respond(stream, 404, "text/plain", b"not found\n");
        }
    };
    let length = metadata.len();
    write_head(stream, 200, "application/octet-stream", length)?;
    if method == Method::Get {
        let copied = io::copy(&mut file.take(length), stream)?;
        if copied != length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{} shrank while it was served", path.display()),
            ));
        }
    }
    stream.flush()?;
    log(
        peer,
        head,
        200,
        usize::try_from(length).unwrap_or(usize::MAX),
    );
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Service Unavailable",
    }
}

fn write_head<S: Write>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    length: u64,
) -> io::Result<()> {
    let allow = if status == 405 {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    stream.write_all(
        format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\n{allow}Cache-Control: no-store\r\nConnection: close\r\n\r\n",
            reason(status)
        )
        .as_bytes(),
    )
}

fn respond<S: Write>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write_head(
        stream,
        status,
        content_type,
        u64::try_from(body.len()).unwrap_or(u64::MAX),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

/// One line per request: the peer, the request line (escaped), the
/// status and the body's length.
fn log(peer: &str, head: &[u8], status: u16, bytes: usize) {
    let line = head.split(|&byte| byte == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let shown = line.get(..512).unwrap_or(line);
    let cut = if shown.len() < line.len() { "..." } else { "" };
    eprintln!(
        "seaworthy-lab: {peer} {}{cut} {status} {bytes}",
        printable(shown)
    );
}

/// `bytes` with everything but printable ASCII as `\xNN`.
fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if (0x20..0x7f).contains(&byte) && byte != b'\\' {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

fn check_token(token: &str) -> Result<(), LabError> {
    seaworthy_formats::validate_version(token)
        .map_err(|e| LabError::Invalid(format!("the version token {token:?}: {e}")))
}

/// The token file's contents, trimmed and checked.
fn read_token_file(path: &Path) -> Result<String, LabError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(u64::try_from(MAX_TOKEN_BYTES).unwrap_or(u64::MAX) + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|e| LabError::io(path.display(), e))?;
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(LabError::Invalid(format!(
            "{}: longer than a version token",
            path.display()
        )));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| LabError::Invalid(format!("{}: not UTF-8", path.display())))?;
    let token = text.trim();
    check_token(token)?;
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain server over `root` on an ephemeral loopback port.
    fn start(root: &Path, token: Token, hold: Option<Hold>) -> SocketAddr {
        let server = Server::bind(Options {
            root: root.to_owned(),
            token,
            listen: vec!["127.0.0.1:0".to_owned()],
            hold,
            tls: None,
            ready: Some(root.join("ready")),
        })
        .unwrap();
        let addrs = server.spawn().unwrap();
        assert!(
            std::fs::read_to_string(root.join("ready"))
                .unwrap()
                .starts_with("ready\nlisten 127.0.0.1:")
        );
        addrs[0]
    }

    /// The raw response to `request`.
    fn ask(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    fn get(addr: SocketAddr, target: &str) -> String {
        ask(addr, &format!("GET {target} HTTP/1.1\r\nHost: lab\r\n\r\n"))
    }

    #[test]
    fn serves_files_and_refuses_what_isnt_one() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("repo/releases/acme-agent/stable/1.0.0+g1");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("acme-agent.deb"), b"package bytes").unwrap();
        std::fs::create_dir_all(dir.path().join("_lab")).unwrap();
        std::fs::write(dir.path().join("_lab/secret"), b"never served").unwrap();
        let addr = start(dir.path(), Token::Fixed("1.0.0+g1".to_owned()), None);

        let ok = get(
            addr,
            "/repo/releases/acme-agent/stable/1.0.0%2Bg1/acme-agent.deb",
        );
        assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
        assert!(ok.contains("Content-Length: 13\r\n"), "{ok}");
        assert!(ok.ends_with("\r\n\r\npackage bytes"), "{ok}");

        let head = ask(
            addr,
            "HEAD /repo/releases/acme-agent/stable/1.0.0+g1/acme-agent.deb HTTP/1.1\r\n\r\n",
        );
        assert!(
            head.contains("Content-Length: 13\r\n") && head.ends_with("\r\n\r\n"),
            "{head}"
        );

        for (target, status) in [
            ("/missing", "404"),
            ("/repo", "404"),
            ("/_lab/secret", "404"),
            ("/../etc/passwd", "400"),
            ("/a%00b", "400"),
        ] {
            let answer = get(addr, target);
            assert!(
                answer.starts_with(&format!("HTTP/1.1 {status} ")),
                "{target}: {answer}"
            );
        }
        let post = ask(addr, "POST /x HTTP/1.1\r\n\r\n");
        assert!(
            post.starts_with("HTTP/1.1 405 ") && post.contains("Allow: GET, HEAD\r\n"),
            "{post}"
        );
        // A head that never ends is cut off.
        let long = ask(
            addr,
            &format!("GET /{} HTTP/1.1\r\n", "a".repeat(MAX_HEAD_BYTES)),
        );
        assert!(long.starts_with("HTTP/1.1 400 "), "{long}");
    }

    #[test]
    fn the_endpoint_answers_the_token_or_the_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let fixed = start(dir.path(), Token::Fixed("v1.2.0+lab".to_owned()), None);
        let answer = get(fixed, "/_lab/required-version");
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(answer.ends_with("\r\n\r\nv1.2.0+lab\n"), "{answer}");

        let token = dir.path().join("token");
        std::fs::write(&token, "1.0.0+a\n").unwrap();
        let file = start(dir.path(), Token::File(token.clone()), None);
        assert!(get(file, "/_lab/required-version").ends_with("\r\n\r\n1.0.0+a\n"));
        std::fs::write(&token, "1.1.0+b").unwrap();
        assert!(get(file, "/_lab/required-version").ends_with("\r\n\r\n1.1.0+b\n"));
        // A token file turned invalid: no answer but 503.
        std::fs::write(&token, "../etc").unwrap();
        assert!(get(file, "/_lab/required-version").starts_with("HTTP/1.1 503 "));
    }

    #[test]
    fn bad_options_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let options = |token: Token| Options {
            root: dir.path().to_owned(),
            token,
            listen: vec!["127.0.0.1:0".to_owned()],
            hold: None,
            tls: None,
            ready: None,
        };
        assert!(Server::bind(options(Token::Fixed("a b".to_owned()))).is_err());
        assert!(Server::bind(options(Token::File(dir.path().join("none")))).is_err());
        let mut no_root = options(Token::Fixed("1.0.0".to_owned()));
        no_root.root = dir.path().join("none");
        assert!(Server::bind(no_root).is_err());
        let mut bad_tls = options(Token::Fixed("1.0.0".to_owned()));
        bad_tls.tls = Some(TlsFiles {
            cert: dir.path().join("none.pem"),
            key: dir.path().join("none.key"),
        });
        assert!(matches!(Server::bind(bad_tls), Err(LabError::Tls(_))));
    }

    #[test]
    fn a_hold_waits_for_its_release() {
        let dir = tempfile::tempdir().unwrap();
        let (until, held) = (dir.path().join("release"), dir.path().join("held"));
        let addr = start(
            dir.path(),
            Token::Fixed("1.0.0".to_owned()),
            Some(Hold {
                until: until.clone(),
                held: Some(held.clone()),
            }),
        );
        let waiting = std::thread::spawn(move || get(addr, "/_lab/required-version"));
        let start = Instant::now();
        while !held.exists() {
            assert!(start.elapsed() < Duration::from_secs(10), "never held");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Files are served meanwhile.
        assert!(get(addr, "/missing").starts_with("HTTP/1.1 404 "));
        assert!(!waiting.is_finished(), "answered before its release");
        std::fs::write(&until, "").unwrap();
        assert!(waiting.join().unwrap().ends_with("\r\n\r\n1.0.0\n"));
    }

    #[test]
    fn printable_escapes_controls() {
        assert_eq!(printable(b"GET /a\x1b[2J\\b"), "GET /a\\x1b[2J\\x5cb");
    }
}
