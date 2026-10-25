//! Shared test harness: a minimal raw HTTP/1.1 loopback server.
//!
//! Not every test binary uses every helper.
//!
//! Deliberately hand-rolled (no framework): the S3 stub needs to see the
//! exact wire request (raw target, header casing preserved) to re-validate
//! signatures, and the tests need to script hostile answers (oversized
//! bodies, black holes, redirects, lying checksums).
#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    reason = "a test harness shared by several test binaries: helpers some binaries do not \
              use, and a broken fixture is a test failure"
)]

use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A parsed wire request (header names lowercased; duplicates preserved).
#[derive(Clone, Debug)]
pub struct RawRequest {
    /// The HTTP method.
    pub method: String,
    /// The raw request target (path + query, un-decoded).
    pub target: String,
    /// Headers as (lowercase-name, value) pairs, order preserved.
    pub headers: Vec<(String, String)>,
    /// The body (content-length framed; chunked not supported — our
    /// clients always send sized bodies).
    pub body: Vec<u8>,
}

impl RawRequest {
    /// The first value of a header (case-insensitive name).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == &name.to_ascii_lowercase())
            .map(|(_, v)| v.as_str())
    }

    /// The path portion of the target.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    /// Query pairs, percent-decoded, duplicates preserved.
    #[must_use]
    pub fn query(&self) -> Vec<(String, String)> {
        let Some((_, query)) = self.target.split_once('?') else {
            return Vec::new();
        };
        query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k), percent_decode(v)),
                None => (percent_decode(pair), String::new()),
            })
            .collect()
    }
}

/// Percent-decode `%XX` (`+` stays literal — SigV4 semantics).
#[must_use]
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 3 <= bytes.len()
            && let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A canned response.
pub struct RawResponse {
    /// The status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl RawResponse {
    /// A plain response.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// An S3-shaped XML error.
    #[must_use]
    pub fn s3_error(status: u16, code: &str, message: &str) -> Self {
        Self::new(
            status,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message></Error>"
            ),
        )
        .with_header("content-type", "application/xml")
    }
}

/// A running stub server.
pub struct StubServer {
    /// The bound address (`127.0.0.1:port`).
    pub addr: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl StubServer {
    /// The `http://` base URL.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop the server.
    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
    }
}

/// Spawn a server answering each request with `handler` (one request per
/// connection; `Connection: close` — reqwest simply opens fresh ones).
pub async fn spawn(
    handler: impl Fn(RawRequest) -> RawResponse + Send + Sync + 'static,
) -> StubServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let handler = Arc::new(handler);

    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = &mut rx => break,
            };
            let Ok((mut socket, _)) = accepted else {
                continue;
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut socket).await else {
                    return;
                };
                let response = handler(request);
                // The handler's own content-length wins (HEAD responses
                // carry the object's length with an empty body).
                let declared = response
                    .headers
                    .iter()
                    .find(|(n, _)| n == "content-length")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(|| response.body.len().to_string());
                let mut out = format!(
                    "HTTP/1.1 {}\r\nconnection: close\r\ncontent-length: {declared}\r\n",
                    status_line(response.status),
                );
                for (name, value) in &response.headers {
                    if name == "content-length" {
                        continue;
                    }
                    out.push_str(&format!("{name}: {value}\r\n"));
                }
                out.push_str("\r\n");
                let _ = socket.write_all(out.as_bytes()).await;
                let _ = socket.write_all(&response.body).await;
                let _ = socket.flush().await;
            });
        }
    });

    StubServer {
        addr,
        shutdown: Some(tx),
        task,
    }
}

/// Read one request head + content-length body.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<RawRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    // Read until end-of-headers.
    let head_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 1024 * 1024 {
            return None; // header blowup guard
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut body = buf.split_off(head_end + 4);

    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();

    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }

    let content_length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while body.len() < content_length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);

    Some(RawRequest {
        method,
        target,
        headers,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn status_line(code: u16) -> &'static str {
    match code {
        200 => "200 OK",
        204 => "204 No Content",
        206 => "206 Partial Content",
        307 => "307 Temporary Redirect",
        308 => "308 Permanent Redirect",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        409 => "409 Conflict",
        412 => "412 Precondition Failed",
        416 => "416 Range Not Satisfiable",
        500 => "500 Internal Server Error",
        503 => "503 Service Unavailable",
        _ => "500 Internal Server Error",
    }
}

/// A raw HTTP server that accepts connections and NEVER responds (the
/// timeout tests' black hole). Sockets are held until `stop`.
pub async fn spawn_hanging() -> StubServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = &mut rx => break,
            };
            if let Ok((socket, _)) = accepted {
                held.push(socket); // hold the connection open, say nothing
            }
        }
    });
    StubServer {
        addr,
        shutdown: Some(tx),
        task,
    }
}
