//! The published AWS SigV4 test suite, vendored byte-for-byte at
//! `tests/vectors/sigv4/` (Apache-2.0; from the botocore mirror of the
//! awslabs suite, LICENSE/NOTICE included there).
//!
//! Each case directory holds `name.req` (the raw HTTP request), `name.creq`
//! (expected canonical request), `name.sts` (expected string to sign), and
//! `name.authz` (expected Authorization header). The harness rebuilds the
//! request through `seaworthy::s3::sigv4` and compares all three stages
//! byte-for-byte.
//!
//! Unlike botocore's runner, the duplicate-query cases
//! (`get-vanilla-query-order-*`) are NOT skipped: this signer keeps query
//! params as a vector, so duplicates survive.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a panic is a test failure"
)]

use std::path::{Path, PathBuf};

use seaworthy::s3::sigv4::{Credentials, Payload, SignRequest, Signer};
use seaworthy_crypto::digest::sha256_hex;
use zeroize::Zeroizing;

/// The vendored suite. `CARGO_MANIFEST_DIR` is read at RUN time first:
/// nextest sets it per test binary, remapped (`--workspace-remap`) when an
/// archive built elsewhere runs on another machine. The compile-time path
/// is only the fallback: it names the build machine's directory.
fn suite_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("tests")
        .join("vectors")
        .join("sigv4")
}
const ACCESS_KEY: &str = "AKIDEXAMPLE";
const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const SERVICE: &str = "service";

/// Percent-decode `%XX` sequences (query values arrive pre-encoded in the
/// suite; the signer re-encodes). `+` stays `+` (SigV4 does not treat it
/// as space).
fn percent_decode(input: &str) -> String {
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

struct ParsedRequest {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    host: String,
    amz_datetime: String,
    session_token: Option<String>,
    body: Vec<u8>,
}

/// Parse a `.req` file: `METHOD target HTTP/1.1`, headers (`Name:Value`,
/// multiline continuations folded), blank line, body.
fn parse_req(raw: &str) -> ParsedRequest {
    let mut lines = raw.split('\n');
    let request_line = lines.next().expect("request line");
    // Method = up to the first space; target = everything between it and
    // the trailing ` HTTP/1.1` (the suite's get-space case has a literal
    // space in the path, which forbids naive whitespace splitting).
    let (method, rest) = request_line.split_once(' ').expect("method");
    let target = rest.strip_suffix(" HTTP/1.1").unwrap_or(rest);
    let method = method.to_owned();

    let (path, query) = match target.split_once('?') {
        Some((path, query)) => {
            let pairs = query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| match pair.split_once('=') {
                    Some((k, v)) => (percent_decode(k), percent_decode(v)),
                    None => (percent_decode(pair), String::new()),
                })
                .collect();
            (path.to_owned(), pairs)
        }
        None => (target.to_owned(), Vec::new()),
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host = String::new();
    let mut amz_datetime = String::new();
    let mut session_token = None;
    let mut body_lines = Vec::new();
    let mut in_body = false;
    for line in lines {
        if in_body {
            body_lines.push(line);
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Multiline header continuation: fold onto the last value.
            if let Some((_, value)) = headers.last_mut() {
                value.push('\n');
                value.push_str(line);
            }
            continue;
        }
        let (name, value) = line.split_once(':').expect("header line");
        match name.to_ascii_lowercase().as_str() {
            "host" => host = value.to_owned(),
            "x-amz-date" => amz_datetime = value.to_owned(),
            "x-amz-security-token" => session_token = Some(value.to_owned()),
            _ => headers.push((name.to_owned(), value.to_owned())),
        }
    }

    ParsedRequest {
        method,
        path,
        query,
        headers,
        host,
        amz_datetime,
        session_token,
        body: body_lines.join("\n").into_bytes(),
    }
}

/// All case directories (recursively, so `normalize-path/*` and
/// `post-sts-token/*` are found).
fn collect_cases(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("suite dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            if path.extension().is_none()
                && path
                    .join(format!(
                        "{}.req",
                        path.file_name().expect("name").to_string_lossy()
                    ))
                    .exists()
            {
                out.push(path);
            } else {
                collect_cases(&path, out);
            }
        }
    }
}

/// Read one vendored vector file. The vectors are byte-exact (every byte
/// is signed over) and contain no carriage returns; a CRLF copy means the
/// checkout converted line endings: `.gitattributes` marks
/// `**/tests/vectors/**` `-text` for exactly that (Git for Windows'
/// `core.autocrlf=true`).
fn read_vector(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(
        !text.contains('\r'),
        "{} contains a carriage return: the checkout converted line endings \
         (the vectors are `-text` in .gitattributes: re-clone, or run \
         `git rm --cached -r . && git reset --hard`)",
        path.display()
    );
    text
}

#[test]
fn aws_sigv4_official_test_suite() {
    let mut cases = Vec::new();
    collect_cases(&suite_dir(), &mut cases);
    cases.sort();
    assert!(cases.len() >= 30, "suite vendored ({} cases)", cases.len());

    let mut failures = Vec::new();
    for case in &cases {
        let name = case
            .file_name()
            .expect("name")
            .to_string_lossy()
            .to_string();
        let read = |ext: &str| read_vector(&case.join(format!("{name}.{ext}")));
        let req = parse_req(&read("req"));

        // The suite's session-token cases don't carry the token in the
        // .req; it's recoverable from the expected .creq (the botocore
        // runner's trick).
        let expected_creq = read("creq");
        let session_token = req.session_token.clone().or_else(|| {
            expected_creq
                .lines()
                .find_map(|line| line.strip_prefix("x-amz-security-token:"))
                .map(str::to_owned)
        });

        // The suite signs the service "service" without the S3-specific
        // x-amz-content-sha256 header.
        let case_signer = Signer::new(
            Credentials {
                access_key_id: ACCESS_KEY.to_owned(),
                secret_access_key: Zeroizing::new(SECRET_KEY.to_owned()),
                session_token: session_token.map(Zeroizing::new),
            },
            REGION.to_owned(),
            SERVICE.to_owned(),
        );

        let payload_hash = sha256_hex(&req.body);
        let request = SignRequest {
            method: &req.method,
            host: &req.host,
            path: &req.path,
            query: req.query.clone(),
            headers: req.headers.clone(),
            payload: Payload::Sha256Hex(&payload_hash),
            normalize_path: true,
            content_sha256_header: false,
            amz_datetime: &req.amz_datetime,
        };

        let canonical =
            case_signer.canonical_request(&case_signer.augment_for_header_mode(&request));
        let sts = case_signer.string_to_sign(&req.amz_datetime, &canonical.text);
        let signed = case_signer.signed_headers(&request).expect("sign");
        let authz = signed
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| value.clone())
            .expect("authorization header");

        let expected_sts = read("sts");
        let expected_authz = read("authz");

        if canonical.text != expected_creq {
            failures.push(format!(
                "{name}: canonical request mismatch\n--- expected ---\n{expected_creq}\n--- actual ---\n{}",
                canonical.text
            ));
            continue;
        }
        if sts != expected_sts {
            failures.push(format!("{name}: string-to-sign mismatch"));
            continue;
        }
        if authz != expected_authz {
            failures.push(format!(
                "{name}: authorization mismatch\nexpected: {expected_authz}\nactual:   {authz}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} cases failed:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// The `.sreq` files pin the fully-signed request (headers included);
/// spot-check one end-to-end.
#[test]
fn vanilla_signed_request_headers() {
    let case = suite_dir().join("get-vanilla");
    let req = parse_req(&read_vector(&case.join("get-vanilla.req")));
    let signer = Signer::new(
        Credentials {
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: Zeroizing::new(SECRET_KEY.to_owned()),
            session_token: None,
        },
        REGION.to_owned(),
        SERVICE.to_owned(),
    );
    let payload_hash = sha256_hex(&req.body);
    let signed = signer
        .signed_headers(&SignRequest {
            method: &req.method,
            host: &req.host,
            path: &req.path,
            query: req.query.clone(),
            headers: req.headers.clone(),
            payload: Payload::Sha256Hex(&payload_hash),
            normalize_path: true,
            content_sha256_header: false,
            amz_datetime: &req.amz_datetime,
        })
        .expect("sign");
    assert!(
        signed
            .iter()
            .any(|(n, v)| n == "x-amz-date" && v == "20150830T123600Z")
    );
    let authz = signed
        .iter()
        .find(|(n, _)| n == "authorization")
        .expect("authorization");
    assert!(authz.1.starts_with(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"
    ));
}

/// Percent-decoding edge cases in the harness itself.
#[test]
fn percent_decode_edges() {
    assert_eq!(percent_decode("a%20b"), "a b");
    assert_eq!(percent_decode("a+b"), "a+b", "plus is literal in SigV4");
    assert_eq!(percent_decode("%E1%88%B4"), "ሴ");
    assert_eq!(percent_decode("plain"), "plain");
    assert_eq!(
        percent_decode("%2"),
        "%2",
        "truncated escape passes through"
    );
}
