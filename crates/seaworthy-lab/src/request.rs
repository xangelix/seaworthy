//! The lab server's request head: the request line of an HTTP/1.x `GET`
//! or `HEAD`, its target percent-decoded as a static store decodes it, and
//! the route it names. Pure (no I/O), panic-free on any input, and fuzzed
//! (`fuzz/`, target `lab_request`): the server reads it from whoever
//! connects, which on a lab machine is the package managers and the update
//! helper under test.
//!
//! A file route is a relative path of plain components only: no `..` or
//! `.`, no empty component, no NUL, control character, backslash or colon
//! (a drive or stream on Windows), and no Windows device name, so joining
//! it to the served root never leaves the root on any platform. Header
//! lines are not interpreted.

#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Component, PathBuf};

use crate::REQUIRED_VERSION_PATH;

/// The longest request head the server reads (request line and headers).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The longest request target accepted, before decoding.
pub const MAX_TARGET_BYTES: usize = 4096;

/// The prefix of the lab's own endpoints: never served from the root.
const RESERVED_PREFIX: &str = "/_lab/";

/// A request's method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`: the headers and the body.
    Get,
    /// `HEAD`: the headers only.
    Head,
}

impl Method {
    /// The method as sent.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

/// What a request asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// The required-version endpoint ([`REQUIRED_VERSION_PATH`]).
    RequiredVersion,
    /// A file below the served root: a relative path of plain components.
    File(PathBuf),
}

/// A parsed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The route.
    pub route: Route,
}

/// Why a request head was refused, and the status it is answered with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The head isn't an HTTP/1.x request line this server takes (400).
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    /// A method other than `GET` and `HEAD`, or `HEAD` on an endpoint (405).
    #[error("method not allowed")]
    Method,
    /// A path no file can have here: the root, a directory, the lab's
    /// reserved prefix (404).
    #[error("not found")]
    NotFound,
}

impl RequestError {
    /// The HTTP status the server answers with.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::Malformed(_) => 400,
            Self::Method => 405,
            Self::NotFound => 404,
        }
    }
}

/// The length of the request head at the start of `buf` (through the
/// blank line that ends it), or `None` while it is incomplete.
#[must_use]
pub fn head_len(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|at| at.checked_add(4))
}

/// Parses a request head (at least its request line).
///
/// # Errors
/// [`RequestError`] for anything but a `GET` or `HEAD` of an origin-form
/// target over HTTP/1.0 or 1.1 naming a route this server has.
pub fn parse(head: &[u8]) -> Result<Request, RequestError> {
    if head.len() > MAX_HEAD_BYTES {
        return Err(RequestError::Malformed("the request head is too long"));
    }
    let line = head
        .split(|&byte| byte == b'\n')
        .next()
        .ok_or(RequestError::Malformed("no request line"))?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = std::str::from_utf8(line).map_err(|_| RequestError::Malformed("not UTF-8"))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(RequestError::Malformed(
            "the request line isn't METHOD TARGET VERSION",
        ));
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(RequestError::Malformed("not HTTP/1.0 or HTTP/1.1"));
    }
    if target.is_empty() || target.len() > MAX_TARGET_BYTES || !target.starts_with('/') {
        return Err(RequestError::Malformed("the target isn't an absolute path"));
    }
    let method = match method {
        "GET" => Method::Get,
        "HEAD" => Method::Head,
        "" => return Err(RequestError::Malformed("no method")),
        _ => return Err(RequestError::Method),
    };
    let path = target.split(['?', '#']).next().unwrap_or_default();
    let decoded = decode_path(path)?;
    let route = route(&decoded)?;
    if route == Route::RequiredVersion && method != Method::Get {
        return Err(RequestError::Method);
    }
    Ok(Request { method, route })
}

/// `%XX`-decodes a target path, as a static store decodes object keys
/// (apt sends `+` and `~` escaped; the update helper sends a version
/// token's `+` as `%2B`).
///
/// # Errors
/// [`RequestError::Malformed`] for a malformed escape, a result that isn't
/// UTF-8, or one carrying NUL, a control character or a backslash.
pub fn decode_path(path: &str) -> Result<String, RequestError> {
    let mut out = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let (Some(high), Some(low)) = (
                bytes.next().and_then(hex_value),
                bytes.next().and_then(hex_value),
            ) else {
                return Err(RequestError::Malformed("a malformed percent escape"));
            };
            out.push(high.wrapping_shl(4) | low);
        } else {
            out.push(byte);
        }
    }
    if out
        .iter()
        .any(|&byte| byte < 0x20 || byte == 0x7f || byte == b'\\')
    {
        return Err(RequestError::Malformed(
            "a control character or backslash in the path",
        ));
    }
    String::from_utf8(out).map_err(|_| RequestError::Malformed("the decoded path isn't UTF-8"))
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// The route a decoded path names.
fn route(decoded: &str) -> Result<Route, RequestError> {
    if decoded == REQUIRED_VERSION_PATH {
        return Ok(Route::RequiredVersion);
    }
    if decoded == "/_lab" || decoded.starts_with(RESERVED_PREFIX) {
        return Err(RequestError::NotFound);
    }
    let relative = decoded.strip_prefix('/').unwrap_or(decoded);
    if relative.is_empty() {
        return Err(RequestError::NotFound);
    }
    let mut path = PathBuf::new();
    for segment in relative.split('/') {
        if segment.is_empty() {
            // `a//b`, or a trailing slash (a directory).
            return Err(RequestError::NotFound);
        }
        if segment == "." || segment == ".." {
            return Err(RequestError::Malformed("a dot segment in the path"));
        }
        if segment.contains(':') || is_windows_device(segment) {
            return Err(RequestError::Malformed(
                "a segment Windows reads as a drive, stream or device",
            ));
        }
        path.push(segment);
    }
    // Defense in depth: what the platform's path parser makes of it.
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(RequestError::Malformed("not a plain relative path"));
    }
    Ok(Route::File(path))
}

/// `CON`, `NUL`, `COM1`, … with or without an extension, any case: names
/// Windows opens as devices in every directory.
fn is_windows_device(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        _ => {
            let (Some(prefix), Some(digit)) = (stem.get(..3), stem.get(3..)) else {
                return false;
            };
            matches!(prefix, "COM" | "LPT")
                && digit.len() == 1
                && digit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() && byte != b'0')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(target: &str) -> Result<Request, RequestError> {
        parse(format!("GET {target} HTTP/1.1\r\nHost: lab\r\n\r\n").as_bytes())
    }

    fn file(path: &str) -> Route {
        Route::File(path.split('/').collect())
    }

    #[test]
    fn a_file_route_is_the_decoded_relative_path() {
        assert_eq!(
            get("/repo/releases/acme-agent/stable/1.0.0%2Bg1/x86_64-unknown-linux-gnu/acme-agent.deb")
                .unwrap()
                .route,
            file("repo/releases/acme-agent/stable/1.0.0+g1/x86_64-unknown-linux-gnu/acme-agent.deb")
        );
        assert_eq!(
            get("/apt/pool/acme%7E1.deb?x=1#frag").unwrap().route,
            file("apt/pool/acme~1.deb")
        );
        let head = parse(b"HEAD /a/b HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(head.method, Method::Head);
        assert_eq!(head.route, file("a/b"));
    }

    #[test]
    fn the_endpoint_takes_get_only_and_shadows_its_prefix() {
        assert_eq!(
            get(REQUIRED_VERSION_PATH).unwrap().route,
            Route::RequiredVersion
        );
        assert_eq!(
            get("/_lab/required-version?probe=1").unwrap().route,
            Route::RequiredVersion
        );
        assert_eq!(
            parse(b"HEAD /_lab/required-version HTTP/1.1\r\n\r\n"),
            Err(RequestError::Method)
        );
        for reserved in ["/_lab", "/_lab/", "/_lab/other", "/_lab/required-version/x"] {
            assert_eq!(get(reserved), Err(RequestError::NotFound), "{reserved}");
        }
    }

    #[test]
    fn traversal_and_platform_tricks_are_refused() {
        for target in [
            "/../etc/passwd",
            "/a/../../b",
            "/a/%2e%2e/b",
            "/a/./b",
            "/a%5cb",
            "/a\\b",
            "/a%00b",
            "/a%0ab",
            "/C:/Windows",
            "/a/file.txt:stream",
            "/a/NUL",
            "/a/con.txt",
            "/a/COM1",
            "/a/lpt9.log",
            "/%zz",
            "/%4",
            "/%ff%fe",
        ] {
            let result = get(target);
            assert!(
                matches!(result, Err(RequestError::Malformed(_))),
                "{target}: {result:?}"
            );
        }
        for target in ["/", "//a", "/a//b", "/a/"] {
            assert_eq!(get(target), Err(RequestError::NotFound), "{target}");
        }
        // Device-like names that aren't devices are files.
        for name in ["COM0", "COM10", "console", "nul2", "LPT"] {
            assert!(get(&format!("/{name}")).is_ok(), "{name}");
        }
    }

    #[test]
    fn only_origin_form_get_and_head_over_http_1() {
        assert_eq!(
            parse(b"POST /a HTTP/1.1\r\n\r\n"),
            Err(RequestError::Method)
        );
        for head in [
            &b"GET /a HTTP/2\r\n\r\n"[..],
            b"GET http://lab/a HTTP/1.1\r\n\r\n",
            b"GET  /a HTTP/1.1\r\n\r\n",
            b"GET /a HTTP/1.1 extra\r\n\r\n",
            b"GET /a\r\n\r\n",
            b" /a HTTP/1.1\r\n\r\n",
            b"GET \xff HTTP/1.1\r\n\r\n",
            b"",
        ] {
            assert!(
                matches!(parse(head), Err(RequestError::Malformed(_))),
                "{head:?}"
            );
        }
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_TARGET_BYTES));
        assert!(matches!(
            parse(long.as_bytes()),
            Err(RequestError::Malformed(_))
        ));
    }

    #[test]
    fn head_len_finds_the_blank_line() {
        assert_eq!(head_len(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_len(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(head_len(b""), None);
    }

    #[test]
    fn statuses() {
        assert_eq!(RequestError::Malformed("x").status(), 400);
        assert_eq!(RequestError::Method.status(), 405);
        assert_eq!(RequestError::NotFound.status(), 404);
    }
}
